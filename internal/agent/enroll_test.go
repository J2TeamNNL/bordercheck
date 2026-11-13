package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/notify"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/report"
)

const (
	testToken     = "tok_9f8e7d6c5b4a39281706f5e4d3c2b1a0"
	testInstallID = "0123456789abcdef0123456789abcdef"
	allChecksOff  = `"checks": {"firewall": {"enabled": false}, "disk-encryption": {"enabled": false},
  "listeners": {"enabled": false}, "tailscale": {"enabled": false}, "mesh-vpn": {"enabled": false}, "docker": {"enabled": false},
  "secrets": {"enabled": false}, "ssh-keys": {"enabled": false}, "tunnels": {"enabled": false},
  "ai-agents": {"enabled": false}, "os-updates": {"enabled": false}, "screen-lock": {"enabled": false},
  "remote-access": {"enabled": false}}`
)

// portal plays the enrollment portal of the receiver.
type portal struct {
	srv *httptest.Server
	mu  sync.Mutex

	enrollStatus  int    // 0 = 200
	enrollError   string // the error kind for a refusal
	enrolls       []map[string]any
	enrollAuth    []string
	token         string
	installID     string
	policyHits    int
	policyAuth    []string
	policyStatus  int    // 0 = 200
	policyError   string // body error kind with policyStatus
	reportStatus  int
	reportError   string
	reports       []string // raw bodies
	reportAuth    []string
	reportPageURL string
	// policy returns the policy body; by default reports and refresh on this portal.
	policy func(p *portal) string
}

func (p *portal) url() string { return p.srv.URL }

func enrolledPolicy(reportURL, policyURL, update, extra string) string {
	return fmt.Sprintf(`{"name": "Engineering", "report": {"url": %q, "interval": "24h"%s},
 "update": {"policy_url": %q%s},
 "waivers": [{"check": "listeners", "install_id": %q, "until": %q, "reason": "Postgres for the migration"}],
 %s}`, reportURL, extra, policyURL, update, testInstallID, time.Now().AddDate(0, 1, 0).Format(policy.DateFormat), allChecksOff)
}

func newPortal(t *testing.T) *portal {
	t.Helper()
	p := &portal{token: testToken, installID: testInstallID}
	p.policy = func(p *portal) string { return enrolledPolicy(p.url()+"/report", p.url()+"/policy", "", "") }
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/enroll":
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			p.enrolls = append(p.enrolls, req)
			p.enrollAuth = append(p.enrollAuth, r.Header.Get("Authorization"))
			if p.enrollStatus != 0 {
				w.WriteHeader(p.enrollStatus)
				fmt.Fprintf(w, `{"error": %q, "message": "see IT\u0007"}`, p.enrollError)
				return
			}
			fmt.Fprintf(w, `{"install_id": %q, "email": "An@Example.com", "role": "engineering", "token": %q,
				"policy_url": %q, "report_url": %q}`, p.installID, p.token, p.url()+"/policy", p.url()+"/report")
		case "/policy":
			p.policyHits++
			p.policyAuth = append(p.policyAuth, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer "+p.token {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error": "unauthorized"}`)
				return
			}
			if p.policyStatus != 0 {
				w.WriteHeader(p.policyStatus)
				fmt.Fprintf(w, `{"error": %q}`, p.policyError)
				return
			}
			fmt.Fprint(w, p.policy(p))
		case "/report":
			p.reports = append(p.reports, string(body))
			p.reportAuth = append(p.reportAuth, r.Header.Get("Authorization"))
			if p.reportStatus != 0 {
				w.WriteHeader(p.reportStatus)
				fmt.Fprintf(w, `{"error": %q}`, p.reportError)
				return
			}
			if p.reportPageURL != "" {
				fmt.Fprintf(w, `{"ok": true, "report_url": %q}`, p.reportPageURL)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// enrollEnv is a fresh, not yet created install folder.
func enrollEnv(t *testing.T, p *portal) (Env, *strings.Builder) {
	t.Helper()
	out := &strings.Builder{}
	// GitHub points at the fake portal too: a test must never reach the real
	// github.com for an update, which it would with an empty GitHub.
	return Env{Dir: filepath.Join(t.TempDir(), "bordercheck"), Version: "v1.0.0", Client: p.srv.Client(), Out: out, GitHub: p.url()}, out
}

func readCfg(t *testing.T, env Env) Config {
	t.Helper()
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func readState(t *testing.T, env Env) State {
	t.Helper()
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
	return st
}

// noToken fails if the token appears in any file of the install folder but
// the token file, or in any of texts.
func noToken(t *testing.T, env Env, token string, texts ...string) {
	t.Helper()
	entries, _ := os.ReadDir(env.Dir)
	for _, e := range entries {
		if e.Name() == TokenFile || e.Name() == binName() {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(env.Dir, e.Name()))
		if strings.Contains(string(data), token) {
			t.Errorf("the token is in %s", e.Name())
		}
	}
	for i, s := range texts {
		if strings.Contains(s, token) {
			t.Errorf("the token is in output %d: %s", i, s)
		}
	}
}

func TestEnrollInstallHappyPath(t *testing.T) {
	p := newPortal(t)
	env, out := enrollEnv(t, p)
	err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/Inv1te-code_ok"})
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}

	// The enrollment request: the code, the host, the version, and no auth.
	if len(p.enrolls) != 1 || p.enrolls[0]["code"] != "Inv1te-code_ok" || p.enrolls[0]["version"] != "v1.0.0" || p.enrollAuth[0] != "" {
		t.Fatalf("enroll requests %v, auth %q", p.enrolls, p.enrollAuth)
	}
	if h, _ := p.enrolls[0]["host"].(map[string]any); h["os"] != runtime.GOOS || h["arch"] != runtime.GOARCH {
		t.Errorf("host %v", p.enrolls[0]["host"])
	}

	cfg := readCfg(t, env)
	e := cfg.Enrollment
	if cfg.Email != "an@example.com" || cfg.InstallID != testInstallID || e == nil || e.Role != "engineering" ||
		e.Portal != p.url() || e.PolicyURL != p.url()+"/policy" || e.Pending || e.Invite == "" {
		t.Fatalf("config %+v %+v", cfg, e)
	}
	tokPath := filepath.Join(env.Dir, TokenFile)
	data, err := os.ReadFile(tokPath)
	if err != nil || strings.TrimSpace(string(data)) != testToken {
		t.Fatalf("token file: %q %v", data, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(tokPath); fi.Mode().Perm() != 0o600 {
			t.Errorf("token file mode %v", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(env.Dir); fi.Mode().Perm() != 0o700 {
			t.Errorf("install folder mode %v", fi.Mode().Perm())
		}
	}

	// The policy came with the token; the first report went with it too.
	if p.policyHits != 2 || p.policyAuth[0] != "Bearer "+testToken || p.policyAuth[1] != "Bearer "+testToken {
		t.Errorf("policy fetches %d, auth %q", p.policyHits, p.policyAuth)
	}
	if len(p.reports) != 1 || p.reportAuth[0] != "Bearer "+testToken {
		t.Fatalf("reports %d, auth %q", len(p.reports), p.reportAuth)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(p.reports[0]), &rep); err != nil || rep.Email != "an@example.com" ||
		rep.InstallID != testInstallID || rep.Policy != "Engineering" {
		t.Errorf("report %+v %v", rep, err)
	}

	// A scheduled run refreshes the policy with the token.
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if p.policyHits != 3 || p.policyAuth[2] != "Bearer "+testToken || len(p.reports) != 2 {
		t.Errorf("refresh: %d policy fetches, %d reports", p.policyHits, len(p.reports))
	}

	status, err := Status(env)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(p.url(), "https://")
	for _, want := range []string{"Enrolled:   with " + host + ", role engineering", "Install ID: " + testInstallID,
		"Waiver:     listeners until", "Sends:      results, anything you ignored with your reason, and files set aside as likely sample keys; evidence off, IP addresses off, location off"} {
		if !strings.Contains(status, want) {
			t.Errorf("status lacks %q:\n%s", want, status)
		}
	}
	noToken(t, env, testToken, out.String(), status, strings.Join(p.reports, "\n"))
	if !strings.Contains(out.String(), "enrolled with "+host) {
		t.Errorf("install output: %s", out)
	}

	// The waiver keyed by the install ID applies to this machine.
	pol, err := policy.Load(filepath.Join(env.Dir, policy.FileName))
	if err != nil {
		t.Fatal(err)
	}
	res := pol.Waive([]check.Result{{ID: "listeners", Status: check.Fail}}, identity(cfg), time.Now())
	if res[0].Status != check.Waived {
		t.Errorf("waiver by install_id not applied: %+v", res[0])
	}

	if err := Uninstall(env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tokPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("uninstall left the token: %v", err)
	}
}

func TestEnrollFailures(t *testing.T) {
	for _, c := range []struct {
		status int
		kind   string
		want   string
	}{
		{404, "invalid_code", "not valid"},
		{410, "expired", "expired"},
		{409, "used", "already been used"},
		{410, "revoked", "cancelled this invite"},
		{400, "bad_request", "could not read"},
		{429, "", "Too many attempts"},
		{500, "", "answered 500"},
	} {
		p := newPortal(t)
		p.enrollStatus, p.enrollError = c.status, c.kind
		env, out := enrollEnv(t, p)
		err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/abc"})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%d %s: got %v", c.status, c.kind, err)
			continue
		}
		if strings.ContainsRune(err.Error(), '\a') {
			t.Errorf("control character from the server reached the message: %q", err)
		}
		if len(p.enrolls) != 1 || p.policyHits != 0 {
			t.Errorf("%s: %d enroll attempts (no retries allowed), %d policy fetches", c.kind, len(p.enrolls), p.policyHits)
		}
		if _, err := os.Stat(env.Dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a failed enrollment left %s behind (%v)\n%s", c.kind, env.Dir, err, out)
		}
	}
}

func TestEnrollRefusesEmailHTTPAndBadAnswers(t *testing.T) {
	p := newPortal(t)
	env, _ := enrollEnv(t, p)
	if err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/abc", Email: "an@example.com"}); err == nil ||
		!strings.Contains(err.Error(), "-email") {
		t.Errorf("-email with an invite: %v", err)
	}
	if err := Install(t.Context(), env, InstallOptions{Policy: "http://portal.example.com/i/abc"}); err == nil ||
		!strings.Contains(err.Error(), "https") {
		t.Errorf("http invite: %v", err)
	}
	if len(p.enrolls) != 0 {
		t.Errorf("refused installs must not spend the code: %d", len(p.enrolls))
	}

	p.installID = "not-an-id"
	err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/abc"})
	if err == nil || !strings.Contains(err.Error(), "install_id") || strings.Contains(err.Error(), testToken) {
		t.Errorf("bad install_id: %v", err)
	}
}

func TestParseInvite(t *testing.T) {
	for in, want := range map[string]string{
		"https://portal.example.com/i/abc_DEF-1":   "https://portal.example.com abc_DEF-1",
		"https://Portal.Example.com:443/i/abc/":    "https://portal.example.com abc",
		"https://portal.example.com/policies.json": "",
		"https://portal.example.com/x/i/abc":       "",
		"https://user@portal.example.com/i/abc":    "",
		"https://portal.example.com/i/a b":         "",
		"/i/abc":                                   "",
	} {
		portal, code, ok := ParseInvite(in)
		got := ""
		if ok {
			got = portal + " " + code
		}
		if got != want {
			t.Errorf("ParseInvite(%q) = %q, want %q", in, got, want)
		}
	}
}

// enrolledEnv is a finished enrolled install on p, without going through Install.
func enrolledEnv(t *testing.T, p *portal) (Env, *strings.Builder) {
	t.Helper()
	env, out := enrollEnv(t, p)
	if err := prepareDir(env.Dir); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Email: "an@example.com", InstallID: testInstallID, UpdateRepo: "ptrinh/bordercheck",
		Enrollment: &Enrollment{Portal: p.url(), Role: "engineering", PolicyURL: p.url() + "/policy"}}
	if err := writeJSON(filepath.Join(env.Dir, "config.json"), cfg); err != nil {
		t.Fatal(err)
	}
	if err := writeToken(env.Dir, p.token); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.Dir, policy.FileName), []byte(p.policy(p)), 0o600); err != nil {
		t.Fatal(err)
	}
	return env, out
}

func TestTokenOnlyGoesToItsPortal(t *testing.T) {
	var strayAuth []string
	stray := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strayAuth = append(strayAuth, r.Header.Get("Authorization"))
	}))
	defer stray.Close()

	p := newPortal(t)
	env, out := enrolledEnv(t, p)
	// The portal's policy now sends reports to another host: refused, the saved one is kept.
	p.policy = func(p *portal) string { return enrolledPolicy(stray.URL+"/report", p.url()+"/policy", "", "") }
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatalf("send with the saved policy: %v\n%s", err, out)
	}
	if len(strayAuth) != 0 || len(p.reports) != 1 || !strings.Contains(out.String(), "refusing it") {
		t.Errorf("stray got %d requests, portal %d reports; log %s", len(strayAuth), len(p.reports), out)
	}
	saved, _ := os.ReadFile(filepath.Join(env.Dir, policy.FileName))
	if strings.Contains(string(saved), stray.URL) {
		t.Error("the refused policy was saved")
	}

	// update.policy_url on another host: refused too.
	p.policy = func(p *portal) string { return enrolledPolicy(p.url()+"/report", stray.URL+"/policy", "", "") }
	out.Reset()
	if err := Send(t.Context(), env, true); err != nil || !strings.Contains(out.String(), "refusing it") || len(strayAuth) != 0 {
		t.Errorf("policy_url elsewhere: %v, stray %d, log %s", err, len(strayAuth), out)
	}

	// A report URL on plain http, even on the portal's host, never gets the token.
	tok := &bearer{token: testToken, portal: p.url()}
	if err := tok.allows(strings.Replace(p.url(), "https://", "http://", 1) + "/report"); err == nil {
		t.Error("the token may not go over http")
	}
	if err := (&bearer{token: testToken, portal: "http://127.0.0.1:1"}).allows("http://127.0.0.1:1/report"); err == nil {
		t.Error("a portal on http is never trusted with the token")
	}
	pol := policy.Default()
	pol.Report.URL = stray.URL + "/report"
	if _, err := post(t.Context(), env, pol.Report, report.Report{}, tok); err == nil || len(strayAuth) != 0 {
		t.Errorf("post to another host with the token: %v, stray %d", err, len(strayAuth))
	}
}

func TestTokenNotFollowedThroughRedirects(t *testing.T) {
	var strayAuth []string
	stray := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strayAuth = append(strayAuth, r.Header.Get("Authorization"))
	}))
	defer stray.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, stray.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	tok := &bearer{token: testToken, portal: redirect.URL}
	if _, _, err := readPolicy(t.Context(), redirect.Client(), redirect.URL+"/policy", tok); err == nil {
		t.Error("a redirected policy fetch should fail")
	}
	if len(strayAuth) != 0 {
		t.Errorf("the redirect target was contacted: %q", strayAuth)
	}
}

func TestRevokedBacksOffAndNotifiesOnce(t *testing.T) {
	var shown []notify.Message
	showNotification = func(_ context.Context, m notify.Message) error { shown = append(shown, m); return nil }
	t.Cleanup(func() {
		showNotification = func(context.Context, notify.Message) error { return errors.New("not in tests") }
	})

	p := newPortal(t)
	env, out := enrolledEnv(t, p)
	p.policyStatus, p.policyError = http.StatusUnauthorized, "revoked"

	if err := Send(t.Context(), env, false); !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v", err)
	}
	st := readState(t, env)
	if st.Revoked.IsZero() || !st.RevokedNotified || len(shown) != 1 || !strings.Contains(shown[0].Title, "revoked") {
		t.Fatalf("state %+v, shown %v", st, shown)
	}
	if len(p.reports) != 0 {
		t.Error("a revoked install must not report")
	}

	// The next hourly runs leave the portal alone and do not notify again.
	for range 3 {
		if err := Send(t.Context(), env, false); !errors.Is(err, ErrRevoked) {
			t.Fatalf("got %v", err)
		}
	}
	if p.policyHits != 1 || len(shown) != 1 {
		t.Errorf("backoff: %d policy fetches, %d notifications", p.policyHits, len(shown))
	}
	status, _ := Status(env)
	if !strings.Contains(status, "Revoked:    by IT") {
		t.Errorf("status:\n%s", status)
	}

	// A day later it asks once more; still revoked, still one notification.
	st = readState(t, env)
	st.RevokedChecked = st.RevokedChecked.Add(-25 * time.Hour)
	if err := writeJSON(filepath.Join(env.Dir, "state.json"), st); err != nil {
		t.Fatal(err)
	}
	_ = Send(t.Context(), env, false)
	if p.policyHits != 2 || len(shown) != 1 {
		t.Errorf("after a day: %d policy fetches, %d notifications", p.policyHits, len(shown))
	}

	// Revoked at the report endpoint counts too; a working report clears it.
	p.policyStatus = 0
	p.reportStatus, p.reportError = http.StatusUnauthorized, "revoked"
	if err := Send(t.Context(), env, true); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked report: %v", err)
	}
	p.reportStatus = 0
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if st := readState(t, env); !st.Revoked.IsZero() || st.RevokedNotified {
		t.Errorf("a report that got through should clear revoked: %+v", st)
	}
	noToken(t, env, testToken, out.String(), status)
}

func TestOther401IsAnOrdinaryError(t *testing.T) {
	p := newPortal(t)
	env, out := enrolledEnv(t, p)
	p.reportStatus, p.reportError = http.StatusUnauthorized, "unauthorized"
	err := Send(t.Context(), env, true)
	if err == nil || errors.Is(err, ErrRevoked) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("got %v", err)
	}
	if st := readState(t, env); !st.Revoked.IsZero() {
		t.Errorf("a plain 401 is not a revocation: %+v", st)
	}
	noToken(t, env, testToken, out.String(), err.Error())
}

func TestEnrolledPinsIgnoreThePortal(t *testing.T) {
	const evilKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	p := newPortal(t)
	p.policy = func(p *portal) string {
		return enrolledPolicy(p.url()+"/report", p.url()+"/policy",
			`, "binary": true, "interval": "48h", "repo": "evil/fork", "public_key": "`+evilKey+`"`, "")
	}
	env, _ := enrollEnv(t, p)
	if err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/abc"}); err != nil {
		t.Fatal(err)
	}
	cfg := readCfg(t, env)
	if cfg.UpdateRepo != "ptrinh/bordercheck" || cfg.UpdateKey != "" {
		t.Fatalf("the portal chose the update source: %q %q", cfg.UpdateRepo, cfg.UpdateKey)
	}
	tok, err := credentials(env, cfg)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := currentPolicy(t.Context(), env, cfg, tok)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Update.Repo != "ptrinh/bordercheck" || pol.Update.PublicKey != "" || !pol.Update.Binary || pol.Update.Interval != "48h" {
		t.Errorf("refreshed update settings: %+v", pol.Update)
	}

	// The person installing may name another source; re-running keeps it.
	other := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
	env2, _ := enrollEnv(t, p)
	if err := Install(t.Context(), env2, InstallOptions{Policy: p.url() + "/i/abc", UpdateRepo: "sample/bordercheck", UpdateKey: other}); err != nil {
		t.Fatal(err)
	}
	if err := Install(t.Context(), env2, InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if cfg := readCfg(t, env2); cfg.UpdateRepo != "sample/bordercheck" || cfg.UpdateKey != other {
		t.Errorf("explicit source: %q %q", cfg.UpdateRepo, cfg.UpdateKey)
	}
	if err := Install(t.Context(), env2, InstallOptions{Policy: p.url() + "/i/abc", UpdateKey: "short"}); err == nil {
		t.Error("a bad -update-key should be refused")
	}
}

func TestEnrollResumesAfterAFailure(t *testing.T) {
	p := newPortal(t)
	env, out := enrollEnv(t, p)
	services.register = func(string, string) error { return errors.New("launchctl is unhappy") }
	t.Cleanup(func() { services.register = func(string, string) error { return nil } })

	err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/abc"})
	if err == nil || !strings.Contains(err.Error(), "finish with") || !strings.Contains(err.Error(), filepath.Join(env.Dir, binName())+" install") {
		t.Fatalf("got %v", err)
	}
	if cfg := readCfg(t, env); cfg.Enrollment == nil || !cfg.Enrollment.Pending {
		t.Fatalf("the enrollment should be saved as pending: %+v", cfg)
	}
	if err := Send(t.Context(), env, true); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("send on an unfinished install: %v", err)
	}
	if s, err := Status(env); err != nil || !strings.Contains(s, "Unfinished:") {
		t.Errorf("status: %q %v", s, err)
	}

	services.register = func(string, string) error { return nil }
	// The same link again resumes instead of spending a used code.
	if err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/abc"}); err != nil {
		t.Fatalf("resume with the same link: %v", err)
	}
	// And so does a plain `bordercheck install`.
	if err := Install(t.Context(), env, InstallOptions{}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if len(p.enrolls) != 1 {
		t.Errorf("the code was sent %d times", len(p.enrolls))
	}
	if cfg := readCfg(t, env); cfg.Enrollment.Pending {
		t.Error("still pending")
	}
	noToken(t, env, testToken, out.String())
}

func TestLocalFailureKeepsTheInviteUnused(t *testing.T) {
	p := newPortal(t)
	env, _ := enrollEnv(t, p)
	services.check = func() error { return errors.New("no launchctl") }
	t.Cleanup(func() { services.check = func() error { return nil } })
	err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/abc"})
	if err == nil || !strings.Contains(err.Error(), "still unused") || len(p.enrolls) != 0 {
		t.Fatalf("got %v with %d enrollments", err, len(p.enrolls))
	}
	if _, err := os.Stat(env.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("left %s behind", env.Dir)
	}
}

func TestNewInviteReplacesEnrollment(t *testing.T) {
	p := newPortal(t)
	env, out := enrollEnv(t, p)
	if err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/first"}); err != nil {
		t.Fatal(err)
	}
	p.token, p.installID = "tok_second_0000000000000000000000", "fedcba9876543210fedcba9876543210"
	if err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/i/second"}); err != nil {
		t.Fatal(err)
	}
	if cfg := readCfg(t, env); cfg.InstallID != p.installID || len(p.enrolls) != 2 {
		t.Errorf("replace: %+v, %d enrollments", cfg, len(p.enrolls))
	}
	if tok, _ := readToken(env.Dir); tok != p.token {
		t.Error("the new token was not saved")
	}
	if !strings.Contains(out.String(), "replaces that enrollment") {
		t.Errorf("output: %s", out)
	}
	// A policies.json install on an enrolled machine is refused.
	if err := Install(t.Context(), env, InstallOptions{Policy: p.url() + "/policies.json", Email: "an@example.com"}); err == nil ||
		!strings.Contains(err.Error(), "uninstall first") {
		t.Errorf("static over enrolled: %v", err)
	}
}

// The policies.json mode works as before: shared header token, typed email, no token file.
func TestStaticInstallUnchanged(t *testing.T) {
	var auth []string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/policies.json":
			fmt.Fprintf(w, `{"name": "Static", "report": {"url": %q, "headers": {"Authorization": "Bearer shared-token"},
				"interval": "24h", "email_domains": ["example.com"]}, %s}`, srv.URL+"/report", allChecksOff)
		case "/report":
			auth = append(auth, r.Header.Get("Authorization"))
		}
	}))
	defer srv.Close()
	out := &strings.Builder{}
	env := Env{Dir: filepath.Join(t.TempDir(), "bc"), Version: "test", Client: srv.Client(), Out: out}

	if err := Install(t.Context(), env, InstallOptions{Policy: srv.URL + "/policies.json", Email: "an@example.com",
		UpdateRepo: "x/y"}); err == nil {
		t.Error("-update-repo is for invite links")
	}
	if err := Install(t.Context(), env, InstallOptions{Policy: srv.URL + "/policies.json", In: strings.NewReader("an@example.com\n"), Ask: true}); err != nil {
		t.Fatal(err)
	}
	cfg := readCfg(t, env)
	if cfg.Email != "an@example.com" || cfg.Enrollment != nil || len(cfg.InstallID) != 32 || cfg.UpdateRepo != "ptrinh/bordercheck" {
		t.Errorf("config %+v", cfg)
	}
	if _, err := os.Stat(filepath.Join(env.Dir, TokenFile)); !errors.Is(err, os.ErrNotExist) {
		t.Error("a static install has no token file")
	}
	if len(auth) != 1 || auth[0] != "Bearer shared-token" {
		t.Errorf("report auth %q", auth)
	}
	if strings.Contains(out.String(), "also sends") {
		t.Errorf("nothing extra is sent by default: %s", out)
	}
}

func TestReportPageLink(t *testing.T) {
	for _, c := range []struct{ link, report, want string }{
		{"https://r.example.com/r/abc", "https://r.example.com/report", "https://r.example.com/r/abc"},
		{"https://evil.example.com/r/abc", "https://r.example.com/report", ""},
		{"http://r.example.com/r/abc", "https://r.example.com/report", ""},
		{"https://r.example.com:8443/r/abc", "https://r.example.com/report", ""},
		{"javascript:alert(1)", "https://r.example.com/report", ""},
		{"http://localhost:8787/r/abc", "http://localhost:8787/report", "http://localhost:8787/r/abc"},
		{"", "https://r.example.com/report", ""},
	} {
		if got := reportPage(c.link, c.report); got != c.want {
			t.Errorf("reportPage(%q, %q) = %q, want %q", c.link, c.report, got, c.want)
		}
	}
}

func TestSendKeepsReportPageOutOfTheLog(t *testing.T) {
	p := newPortal(t)
	env, out := enrolledEnv(t, p)
	p.reportPageURL = p.url() + "/r/secret-page-id"
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if st := readState(t, env); st.ReportPage != p.reportPageURL {
		t.Errorf("state report page %q", st.ReportPage)
	}
	if strings.Contains(out.String(), "secret-page-id") {
		t.Errorf("the link is in the log: %s", out)
	}
	if s, _ := Status(env); !strings.Contains(s, "Report page: "+p.reportPageURL) {
		t.Errorf("status:\n%s", s)
	}
	// A link on another host is ignored.
	p.reportPageURL = "https://elsewhere.example.com/r/x"
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if st := readState(t, env); st.ReportPage != p.url()+"/r/secret-page-id" {
		t.Errorf("a foreign link replaced the page: %q", st.ReportPage)
	}
}

func TestStaticReceiverWithoutReportPage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	env, _ := setup(t, srv)
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if st := readState(t, env); st.ReportPage != "" {
		t.Errorf("report page %q", st.ReportPage)
	}
}

func TestNotifyOpensReportPageForNewHighProblems(t *testing.T) {
	var shown []notify.Message
	var opened []string
	showNotification = func(_ context.Context, m notify.Message) error { shown = append(shown, m); return nil }
	openURL = func(_ context.Context, link string) error { opened = append(opened, link); return nil }
	t.Cleanup(func() {
		showNotification = func(context.Context, notify.Message) error { return errors.New("not in tests") }
		openURL = func(context.Context, string) error { return errors.New("not in tests") }
	})
	const link = "https://r.example.com/r/abc"
	const reportURL = "https://r.example.com/report"
	out, term := &strings.Builder{}, &strings.Builder{}
	env := Env{Out: out, Term: term}
	n := policy.Default().Notify
	high := []check.Result{{ID: "firewall", Status: check.Fail, Severity: check.High, Summary: "off"}}
	medium := []check.Result{{ID: "docker", Status: check.Fail, Severity: check.Medium, Summary: "open"}}
	t0 := time.Now()

	st := State{ReportPage: link}
	notifyUser(t.Context(), env, n, high, &st, t0, false, reportURL)
	if len(opened) != 1 || opened[0] != link || len(shown) != 1 || strings.Contains(shown[0].Body, "bordercheck status") {
		t.Fatalf("new high problem: opened %v, shown %v", opened, shown)
	}
	notifyUser(t.Context(), env, n, high, &st, t0.Add(time.Hour), false, reportURL)
	if len(opened) != 1 {
		t.Error("opened again before the reminder was due")
	}
	// The reminder a day later notifies again, with a hint for the link, but
	// does not open the page a second time.
	notifyUser(t.Context(), env, n, high, &st, t0.Add(25*time.Hour), false, reportURL)
	if len(opened) != 1 || len(shown) != 2 || !strings.Contains(shown[1].Body, "Run bordercheck status for the link") {
		t.Errorf("reminder: opened %d, shown %d %q", len(opened), len(shown), shown[len(shown)-1].Body)
	}
	// A second high problem appearing later is new: the page opens for it.
	both := append([]check.Result{{ID: "secrets", Status: check.Fail, Severity: check.High, Summary: "found"}}, high...)
	notifyUser(t.Context(), env, n, both, &st, t0.Add(26*time.Hour), false, reportURL)
	if len(opened) != 2 {
		t.Errorf("a new high problem beside an old one: opened %d", len(opened))
	}

	st = State{ReportPage: link}
	notifyUser(t.Context(), env, n, medium, &st, t0, false, reportURL)
	if len(opened) != 2 || strings.Contains(shown[len(shown)-1].Body, "bordercheck status") {
		t.Error("a medium-only problem must not open the page or add the hint")
	}

	// Turned off by policy: the notification hints at bordercheck status instead.
	off := n
	off.OpenReport = false
	st = State{ReportPage: link}
	notifyUser(t.Context(), env, off, high, &st, t0, false, reportURL)
	if len(opened) != 2 || !strings.Contains(shown[len(shown)-1].Body, "Run bordercheck status for the link") {
		t.Errorf("open_report off: opened %d, body %q", len(opened), shown[len(shown)-1].Body)
	}
	// The opener failing: the same hint, and the run carries on.
	openURL = func(context.Context, string) error { return errors.New("no browser") }
	st = State{ReportPage: link}
	notifyUser(t.Context(), env, n, high, &st, t0, false, reportURL)
	if !strings.Contains(shown[len(shown)-1].Body, "Run bordercheck status for the link") {
		t.Error("a failed open should leave the hint")
	}
	// A link for another host than reports go to is not used.
	st = State{ReportPage: link}
	before := len(shown)
	notifyUser(t.Context(), env, n, high, &st, t0, false, "https://other.example.com/report")
	if len(shown) != before+1 || strings.Contains(shown[len(shown)-1].Body, "bordercheck status") {
		t.Error("a link for another host should change nothing")
	}

	// From a terminal: printed there, never in the log, nothing opened.
	openURL = func(_ context.Context, link string) error { opened = append(opened, link); return nil }
	st = State{ReportPage: link}
	notifyUser(t.Context(), env, n, high, &st, t0, true, reportURL)
	if len(opened) != 2 || !strings.Contains(term.String(), link) || strings.Contains(out.String(), link) {
		t.Errorf("force: opened %d, term %q, log %q", len(opened), term, out)
	}
}

func TestReportCarriesIPsOnlyWhenAsked(t *testing.T) {
	p := newPortal(t)
	env, out := enrolledEnv(t, p)
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.reports[0], `"ips"`) || strings.Contains(p.reports[0], `"location"`) {
		t.Errorf("default report carries IPs or location: %s", p.reports[0])
	}
	p.policy = func(p *portal) string {
		return enrolledPolicy(p.url()+"/report", p.url()+"/policy", "", `, "include_ips": true, "include_location": true`)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var rep struct {
		Host     map[string]any `json:"host"`
		Location any            `json:"location"`
	}
	if err := json.Unmarshal([]byte(p.reports[1]), &rep); err != nil {
		t.Fatal(err)
	}
	// IPs may be absent on a machine with no network; when present they are a list.
	if ips, ok := rep.Host["ips"]; ok {
		if _, isList := ips.([]any); !isList {
			t.Errorf("host.ips = %v", ips)
		}
	}
	if rep.Location != nil {
		t.Errorf("no OS supplies a location yet, got %v", rep.Location)
	}
	s, _ := Status(env)
	if !strings.Contains(s, "IP addresses on, location on (not available") {
		t.Errorf("status:\n%s", s)
	}
}

func TestReportPolicyShowsDisabledChecksAndCanOmitHostname(t *testing.T) {
	p := newPortal(t)
	env, _ := enrolledEnv(t, p)
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if hostname, _ := os.Hostname(); hostname != "" && !strings.Contains(p.reports[0], `"hostname"`) {
		t.Error("default report omitted the hostname")
	}
	p.policy = func(p *portal) string {
		return enrolledPolicy(p.url()+"/report", p.url()+"/policy", "", `, "omit_hostname": true`)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.reports[1], `"hostname"`) {
		t.Error("report contains hostname despite policy")
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(p.reports[1]), &rep); err != nil {
		t.Fatal(err)
	}
	for _, result := range rep.Results {
		if result.ID == "secrets" && result.Status == check.Skip && len(result.SummaryParts) == 1 &&
			result.SummaryParts[0].Key == "check.disabledByPolicy" {
			return
		}
	}
	t.Error("missing explicit policy-disabled result for secrets")
}
