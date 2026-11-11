package agent

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/notifier"
	"github.com/ptrinh/bordercheck/internal/notify"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/update"
)

const (
	pageLink  = "https://r.example.com/r/secret-page-id"
	pageHost  = "r.example.com"
	reportURL = "https://r.example.com/report"
	team      = "ABCDE12345"
)

// fakeApp stands in for Bordercheck.app: it answers each mode as told and
// records every launch, its arguments and the request it was handed.
type fakeApp struct {
	mu       sync.Mutex
	answers  map[notifier.Mode]string // the JSON it writes; "" = fail to launch
	modes    []notifier.Mode
	args     [][]string
	requests []notifier.Request
	perms    []fs.FileMode
	onRun    func(notifier.Mode)
}

func (f *fakeApp) run(ctx context.Context, app string, mode notifier.Mode, in, out string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onRun != nil {
		f.onRun(mode)
	}
	f.modes = append(f.modes, mode)
	f.args = append(f.args, []string{"/usr/bin/open", "-a", app, "--stdin", in, "--stdout", out, "--args", string(mode)})
	if in != os.DevNull {
		data, err := os.ReadFile(in)
		if err != nil {
			return err
		}
		st, _ := os.Stat(in)
		f.perms = append(f.perms, st.Mode().Perm())
		var r notifier.Request
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		f.requests = append(f.requests, r)
	}
	a, ok := f.answers[mode]
	if !ok || a == "" {
		return errors.New("the app did not start")
	}
	if a == "hang" {
		<-ctx.Done()
		return ctx.Err()
	}
	return os.WriteFile(out, []byte(a), 0o600)
}

func answer(s string) string { return `{"v":1,"status":"` + s + `"}` }

func goodSignature(_ context.Context, _, want string) (string, error) {
	if want != "" && want != team {
		return "", errors.New("wrong team")
	}
	return team, nil
}

// appZip is a release-like archive of a minimal app bundle.
func appZip(t *testing.T, exe string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, e := range []struct {
		name, body string
		mode       fs.FileMode
	}{
		{notifier.AppName + "/", "", fs.ModeDir | 0o755},
		{notifier.AppName + "/Contents/Info.plist", "<plist/>", 0o644},
		{notifier.AppName + "/Contents/MacOS/bordercheck-notifier", exe, 0o755},
	} {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(e.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(e.body))
	}
	zw.Close()
	return b.Bytes()
}

// withApp turns on the macOS path with fake app, and installs a bundle in
// env.Dir the way install does, recording it in config.json.
func withApp(t *testing.T, env Env, f *fakeApp) {
	t.Helper()
	useFakes(t, f)
	var cfg Config
	_ = readJSON(filepath.Join(env.Dir, "config.json"), &cfg)
	if err := os.MkdirAll(env.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installNotifier(t.Context(), env, &cfg, appZip(t, "#!/bin/sh\n")); err != nil {
		t.Fatal(err)
	}
}

func useFakes(t *testing.T, f *fakeApp) {
	t.Helper()
	oldMac, oldRun, oldVerify, oldShow, oldOpen := macNotifier, ntfRun, ntfVerify, showNotification, openURL
	macNotifier, ntfRun, ntfVerify = true, f.run, goodSignature
	t.Cleanup(func() {
		macNotifier, ntfRun, ntfVerify, showNotification, openURL = oldMac, oldRun, oldVerify, oldShow, oldOpen
	})
}

// shown records what went through osascript (showNotification) and the browser.
type shown struct {
	osascript []notify.Message
	opened    []string
}

func record(t *testing.T) *shown {
	t.Helper()
	s := &shown{}
	showNotification = func(_ context.Context, m notify.Message) error { s.osascript = append(s.osascript, m); return nil }
	openURL = func(_ context.Context, l string) error { s.opened = append(s.opened, l); return nil }
	return s
}

var highProblem = []check.Result{{ID: "firewall", Status: check.Fail, Severity: check.High, Summary: "The macOS firewall is off."}}

func TestOwnNotificationIsClickableAndOpensNothing(t *testing.T) {
	out := &strings.Builder{}
	env := Env{Dir: t.TempDir(), GitHub: "https://releases.invalid", Out: out}
	f := &fakeApp{answers: map[notifier.Mode]string{notifier.ModePost: answer("posted")}}
	withApp(t, env, f)
	s := record(t)
	st := State{ReportPage: pageLink}

	notifyUser(t.Context(), env, policy.Default().Notify, highProblem, &st, time.Now(), false, reportURL)
	if len(s.osascript) != 0 || len(s.opened) != 0 {
		t.Fatalf("osascript %v, opened %v: a clickable notification must not open the page by itself", s.osascript, s.opened)
	}
	if len(f.requests) != 1 {
		t.Fatalf("requests %+v", f.requests)
	}
	r := f.requests[0]
	if r.Link != pageLink || r.AllowedHost != pageHost || r.Title != "1 problem on this computer" ||
		!strings.Contains(r.Body, "firewall: The macOS firewall is off.") || !strings.HasSuffix(r.Body, "Click to open your report page.") {
		t.Errorf("request %+v", r)
	}
	if strings.Contains(r.Title+r.Body, "secret-page-id") {
		t.Error("the link is in the visible text")
	}
	if runtime.GOOS != "windows" && f.perms[0] != 0o600 {
		t.Errorf("request file mode %o", f.perms[0])
	}
	for _, a := range f.args {
		if slices.ContainsFunc(a, func(s string) bool { return strings.Contains(s, "secret-page-id") }) {
			t.Errorf("the link is in the app's arguments: %q", a)
		}
	}
	if strings.Contains(out.String(), "secret-page-id") || !strings.Contains(out.String(), "notified: 1 problem(s)") {
		t.Errorf("log: %s", out)
	}
	if st.Notifications != "authorized" || st.Notified["firewall:fail"].IsZero() {
		t.Errorf("state %+v", st)
	}
	if left, _ := filepath.Glob(filepath.Join(env.Dir, ".notifier-*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}

	// Without a report page: posted, no link, no hint.
	st = State{}
	notifyUser(t.Context(), env, policy.Default().Notify, highProblem, &st, time.Now(), false, reportURL)
	if r := f.requests[1]; r.Link != "" || r.AllowedHost != "" || strings.Contains(r.Body, "report page") {
		t.Errorf("no page: %+v", r)
	}
	// A page that is not https (a local test receiver): not clickable; the old hint.
	st = State{ReportPage: "http://localhost:8787/r/x"}
	notifyUser(t.Context(), env, policy.Default().Notify, highProblem, &st, time.Now(), false, "http://localhost:8787/report")
	if r := f.requests[2]; r.Link != "" || !strings.Contains(r.Body, "Run bordercheck status for the link") {
		t.Errorf("http page: %+v", r)
	}
	if len(s.opened) != 0 {
		t.Errorf("opened %v", s.opened)
	}
}

func TestTurnedOffShowsNothing(t *testing.T) {
	out := &strings.Builder{}
	env := Env{Dir: t.TempDir(), GitHub: "https://releases.invalid", Out: out}
	f := &fakeApp{answers: map[notifier.Mode]string{notifier.ModePost: answer("denied"), notifier.ModeStatus: answer("denied")}}
	withApp(t, env, f)
	s := record(t)
	st := State{ReportPage: pageLink}
	notifyUser(t.Context(), env, policy.Default().Notify, highProblem, &st, time.Now(), false, reportURL)
	if len(s.osascript)+len(s.opened) != 0 {
		t.Fatalf("declined, yet osascript %v, opened %v", s.osascript, s.opened)
	}
	if st.Notifications != "denied" || st.Notified["firewall:fail"].IsZero() || !strings.Contains(out.String(), "turned off for bordercheck") {
		t.Errorf("state %+v, log %s", st, out)
	}
	// An hour later, nothing new: not even a log line.
	before := out.Len()
	notifyUser(t.Context(), env, policy.Default().Notify, highProblem, &st, time.Now().Add(time.Hour), false, reportURL)
	if out.Len() != before || len(f.modes) != 1 {
		t.Errorf("nagged: %d launches, log %s", len(f.modes), out.String()[before:])
	}
	// The revoked notice does not get through either, and is not retried.
	st = State{}
	notifyRevoked(t.Context(), env, &st, time.Now(), false)
	if len(s.osascript) != 0 || !st.RevokedNotified {
		t.Errorf("revoked: osascript %v, state %+v", s.osascript, st)
	}
}

// Not allowed yet, or the app failing in any way: notifications come through
// Script Editor and the page opens by itself, exactly as before.
func TestFallsBackToScriptEditor(t *testing.T) {
	for name, c := range map[string]struct {
		post   string
		breakf func(env Env)
		state  string
	}{
		"not determined": {post: answer("not_determined"), state: "not_determined"},
		"error answer":   {post: `{"v":1,"status":"error","error":"UNErrorDomain 1"}`, state: "error"},
		"garbage":        {post: "Segmentation fault", state: "error"},
		"oversize":       {post: strings.Repeat(" ", notifier.MaxAnswer+1) + answer("posted"), state: "error"},
		"no launch":      {post: "", state: "error"},
		"timeout":        {post: "hang", state: "error"},
		"tampered": {post: answer("posted"), state: "error", breakf: func(env Env) {
			exe := filepath.Join(notifier.Path(env.Dir), "Contents", "MacOS", "bordercheck-notifier")
			os.WriteFile(exe, []byte("#!/bin/sh\necho evil\n"), 0o755)
		}},
		"wrong signature": {post: answer("posted"), state: "error", breakf: func(Env) {
			ntfVerify = func(context.Context, string, string) (string, error) { return "", errors.New("not signed by us") }
		}},
		"missing": {post: answer("posted"), state: "", breakf: func(env Env) { os.RemoveAll(notifier.Path(env.Dir)) }},
	} {
		t.Run(name, func(t *testing.T) {
			out := &strings.Builder{}
			env := Env{Dir: t.TempDir(), GitHub: "https://releases.invalid", Out: out}
			f := &fakeApp{answers: map[notifier.Mode]string{notifier.ModePost: c.post}}
			withApp(t, env, f)
			if c.breakf != nil {
				c.breakf(env)
			}
			s := record(t)
			st := State{ReportPage: pageLink}
			ctx := t.Context()
			if c.post == "hang" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			notifyUser(ctx, env, policy.Default().Notify, highProblem, &st, time.Now(), false, reportURL)
			if len(s.osascript) != 1 || len(s.opened) != 1 || s.opened[0] != pageLink {
				t.Fatalf("osascript %v, opened %v", s.osascript, s.opened)
			}
			if st.Notifications != c.state {
				t.Errorf("state %q (%s)", st.Notifications, st.NotificationsError)
			}
			if strings.Contains(out.String(), "secret-page-id") {
				t.Errorf("the link is in the log: %s", out)
			}
			if c.state == "error" && !strings.Contains(out.String(), "using Script Editor") {
				t.Errorf("log: %s", out)
			}
			if (name == "tampered" || name == "wrong signature" || name == "missing") && len(f.modes) != 0 {
				t.Errorf("ran an app it should have refused: %v", f.modes)
			}
		})
	}
}

// Windows and Linux (and macOS without the app) are untouched: no app is run
// even if one were installed.
func TestOtherSystemsNeverRunTheApp(t *testing.T) {
	out := &strings.Builder{}
	env := Env{Dir: t.TempDir(), GitHub: "https://releases.invalid", Out: out}
	f := &fakeApp{answers: map[notifier.Mode]string{notifier.ModePost: answer("posted")}}
	withApp(t, env, f)
	macNotifier = false
	s := record(t)
	st := State{ReportPage: pageLink}
	notifyUser(t.Context(), env, policy.Default().Notify, highProblem, &st, time.Now(), false, reportURL)
	if len(f.modes) != 0 || len(s.osascript) != 1 || len(s.opened) != 1 {
		t.Errorf("app %v, shown %v, opened %v", f.modes, s.osascript, s.opened)
	}
	if err := Notifications(t.Context(), Env{Dir: env.Dir, Out: out}, ""); err != nil || len(f.modes) != 0 {
		t.Errorf("notifications command: %v, %v", err, f.modes)
	}
}

// installServer serves a policy with every check off, reporting to itself.
func installServer(t *testing.T, notifyEnabled bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/policies.json" {
			fmt.Fprintf(w, `{"name": "T", "report": {"url": %q}, "notify": {"enabled": %t}, %s}`, srv.URL+"/report", notifyEnabled, allChecksOff)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// With a person at the terminal, install says what notifications are for and
// that macOS will ask, and only then lets the app ask.
func TestInstallAsksOnceWithAPersonAtTheTerminal(t *testing.T) {
	srv := installServer(t, true)
	out := &strings.Builder{}
	env := Env{Dir: filepath.Join(t.TempDir(), "bc"), Version: "test", Client: srv.Client(), GitHub: srv.URL, Out: out, Term: &strings.Builder{}}
	var said string
	f := &fakeApp{answers: map[notifier.Mode]string{notifier.ModeStatus: answer("not_determined"), notifier.ModeAuthorize: answer("authorized")}}
	f.onRun = func(m notifier.Mode) {
		if m == notifier.ModeAuthorize {
			said = out.String()
		}
	}
	useFakes(t, f)
	if err := Install(t.Context(), env, InstallOptions{Policy: srv.URL + "/policies.json", Email: "an@example.com",
		NotifierZip: writeZip(t)}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.modes, []notifier.Mode{notifier.ModeStatus, notifier.ModeAuthorize}) {
		t.Fatalf("modes %v", f.modes)
	}
	if !strings.Contains(said, "shows a notification when it finds a new problem") || !strings.Contains(said, `macOS will now ask whether "bordercheck" may send notifications`) {
		t.Errorf("asked before saying why:\n%s", said)
	}
	if !strings.Contains(out.String(), "Notifications: allowed") {
		t.Errorf("out:\n%s", out)
	}
	if cfg := readCfg(t, env); cfg.NotifierTeam != team || cfg.NotifierDigest == "" {
		t.Errorf("config %+v", cfg)
	}
	if st := readState(t, env); st.Notifications != "authorized" {
		t.Errorf("state %+v", st)
	}

	// Installing again: macOS already has an answer, so nothing is asked.
	f.modes = nil
	f.answers[notifier.ModeStatus] = answer("denied")
	if err := Install(t.Context(), env, InstallOptions{Policy: srv.URL + "/policies.json", Email: "an@example.com"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.modes, []notifier.Mode{notifier.ModeStatus}) || !strings.Contains(out.String(), "turned off for bordercheck") {
		t.Errorf("reinstall: modes %v\n%s", f.modes, out)
	}
	// status shows it.
	if s, err := Status(env); err != nil || !strings.Contains(s, "Notifications: turned off for bordercheck in System Settings") {
		t.Errorf("status: %v\n%s", err, s)
	}

	// Uninstall removes the app.
	if err := Uninstall(env); err != nil || notifier.Installed(env.Dir) {
		t.Errorf("uninstall: %v", err)
	}
}

func writeZip(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "notifier.zip")
	if err := os.WriteFile(p, appZip(t, "#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A scripted install (no terminal) asks nothing; notifications come through
// Script Editor until the person runs bordercheck notifications, and the
// hourly runs never ask either.
func TestScriptedInstallAndBackgroundNeverAsk(t *testing.T) {
	srv := installServer(t, true)
	out := &strings.Builder{}
	env := Env{Dir: filepath.Join(t.TempDir(), "bc"), Version: "test", Client: srv.Client(), GitHub: srv.URL, Out: out}
	f := &fakeApp{answers: map[notifier.Mode]string{notifier.ModeStatus: answer("not_determined"),
		notifier.ModePost: answer("not_determined"), notifier.ModeAuthorize: answer("authorized")}}
	useFakes(t, f)
	if err := Install(t.Context(), env, InstallOptions{Policy: srv.URL + "/policies.json", Email: "an@example.com",
		NotifierZip: writeZip(t)}); err != nil {
		t.Fatal(err)
	}
	if len(f.modes) != 0 || !strings.Contains(out.String(), "There is no terminal, so macOS was not asked") ||
		!strings.Contains(out.String(), "notifications") {
		t.Fatalf("modes %v\n%s", f.modes, out)
	}
	s, _ := Status(env)
	if !strings.Contains(s, "Notifications: through Script Editor (osascript) until you allow bordercheck's own; run: bordercheck notifications") {
		t.Errorf("status:\n%s", s)
	}
	// Hourly runs, in every state the app can be in: never authorize.
	shownVia := record(t)
	for _, a := range []string{answer("not_determined"), answer("denied"), answer("posted"), "garbage", ""} {
		f.answers[notifier.ModePost] = a
		st := State{ReportPage: pageLink}
		notifyUser(t.Context(), env, policy.Default().Notify, highProblem, &st, time.Now(), false, reportURL)
		_ = checkOnly(t.Context(), env, readCfg(t, env), mustPolicy(t, env), &st, time.Now(), nil)
		notifyRevoked(t.Context(), env, &State{}, time.Now(), false)
		if err := Send(t.Context(), env, false); err != nil {
			t.Fatal(err)
		}
	}
	if slices.Contains(f.modes, notifier.ModeAuthorize) {
		t.Fatalf("the background asked: %v", f.modes)
	}
	if len(shownVia.osascript) == 0 {
		t.Error("not determined should have gone through Script Editor")
	}
	// bordercheck notifications needs a terminal; with one, it asks.
	if err := Notifications(t.Context(), env, ""); err == nil {
		t.Error("asked without a terminal")
	}
	env.Term = &strings.Builder{}
	if err := Notifications(t.Context(), env, ""); err != nil || f.modes[len(f.modes)-1] != notifier.ModeAuthorize {
		t.Errorf("notifications: %v, %v", err, f.modes)
	}
}

func mustPolicy(t *testing.T, env Env) policy.Policy {
	t.Helper()
	p, err := policy.Load(filepath.Join(env.Dir, policy.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A release without the app (or a download that fails) leaves notifications
// on Script Editor; install goes on.
func TestInstallWithoutTheApp(t *testing.T) {
	srv := installServer(t, true)
	out := &strings.Builder{}
	env := Env{Dir: filepath.Join(t.TempDir(), "bc"), Version: "v9.9.9", Client: srv.Client(), GitHub: srv.URL, Out: out, Term: &strings.Builder{}}
	f := &fakeApp{}
	useFakes(t, f)
	var fetched []string
	oldFetch := ntfFetch
	ntfFetch = func(_ context.Context, _ *http.Client, src update.Source, version, name string, _ int64) ([]byte, error) {
		fetched = append(fetched, src.Repo+" "+version+" "+name)
		return nil, errors.New("release v9.9.9: bordercheck-notifier-v9.9.9-darwin-universal.zip is not listed in SHA256SUMS")
	}
	t.Cleanup(func() { ntfFetch = oldFetch })
	if err := Install(t.Context(), env, InstallOptions{Policy: srv.URL + "/policies.json", Email: "an@example.com"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fetched, []string{"ptrinh/bordercheck v9.9.9 bordercheck-notifier-v9.9.9-darwin-universal.zip"}) {
		t.Errorf("fetched %v", fetched)
	}
	if len(f.modes) != 0 || notifier.Installed(env.Dir) || !strings.Contains(out.String(), "Notifications come through Script Editor") {
		t.Errorf("modes %v\n%s", f.modes, out)
	}
	// An app that is not Developer ID signed is refused at install.
	ntfVerify = func(context.Context, string, string) (string, error) {
		return "", errors.New("not signed by bordercheck's Developer ID")
	}
	env.Term = &strings.Builder{}
	if err := Notifications(t.Context(), env, writeZip(t)); err == nil || notifier.Installed(env.Dir) {
		t.Errorf("an unsigned app was installed: %v", err)
	}
}

// After a self-update the installed app is replaced by the new version's,
// with the Team ID pinned at first install.
func TestRefreshAfterUpdate(t *testing.T) {
	out := &strings.Builder{}
	env := Env{Dir: t.TempDir(), GitHub: "https://releases.invalid", Out: out}
	f := &fakeApp{}
	withApp(t, env, f)
	before := readCfg(t, env).NotifierDigest
	oldFetch := ntfFetch
	t.Cleanup(func() { ntfFetch = oldFetch })
	ntfFetch = func(context.Context, *http.Client, update.Source, string, string, int64) ([]byte, error) {
		return appZip(t, "#!/bin/sh\n# v2\n"), nil
	}
	refreshNotifier(t.Context(), env, "v2.0.0", time.Now())
	if after := readCfg(t, env).NotifierDigest; after == before || !strings.Contains(out.String(), "notification app updated to v2.0.0") {
		t.Errorf("digest %s → %s\n%s", before, after, out)
	}
	// Another team's build is refused and the current app kept.
	ntfVerify = func(context.Context, string, string) (string, error) { return "ZZZZZ99999", nil }
	cur := readCfg(t, env).NotifierDigest
	refreshNotifier(t.Context(), env, "v3.0.0", time.Now())
	if readCfg(t, env).NotifierDigest != cur || !strings.Contains(out.String(), "keeping the current one") {
		t.Errorf("another team's app replaced it\n%s", out)
	}
}
