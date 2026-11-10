package notifier

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const link = "https://portal.example.com/r/secret-page-id"

func TestParse(t *testing.T) {
	for _, c := range []struct {
		mode Mode
		in   string
		want Status
	}{
		{ModePost, `{"v":1,"status":"posted"}` + "\n", Posted},
		{ModePost, `{"v":1,"status":"denied"}`, Denied},
		{ModePost, `{"v":1,"status":"not_determined"}`, NotDetermined},
		{ModeStatus, `{"v":1,"status":"authorized"}`, Authorized},
		{ModeAuthorize, `{"status":"denied","v":1}`, Denied},
	} {
		if got, err := Parse(c.mode, []byte(c.in)); err != nil || got != c.want {
			t.Errorf("%s %s: %q %v", c.mode, c.in, got, err)
		}
	}
	bad := map[string]string{
		"empty":            "",
		"garbage":          "Segmentation fault\x00",
		"two answers":      `{"v":1,"status":"posted"}{"v":1,"status":"posted"}`,
		"unknown field":    `{"v":1,"status":"posted","link":"x"}`,
		"version 2":        `{"v":2,"status":"posted"}`,
		"no version":       `{"status":"posted"}`,
		"odd status":       `{"v":1,"status":"maybe"}`,
		"error":            `{"v":1,"status":"error","error":"timed out"}`,
		"invalid":          `{"v":1,"status":"invalid","error":"the link is not https"}`,
		"authorized posts": `{"v":1,"status":"authorized"}`, // post must say posted
		"oversize":         `{"v":1,"status":"denied","error":"` + strings.Repeat("a", MaxAnswer) + `"}`,
	}
	for name, in := range bad {
		if s, err := Parse(ModePost, []byte(in)); err == nil {
			t.Errorf("%s: accepted as %q", name, s)
		}
	}
	if s, err := Parse(ModeStatus, []byte(`{"v":1,"status":"posted"}`)); err == nil {
		t.Errorf("status answered posted: %q", s)
	}
}

func TestNewRequest(t *testing.T) {
	r, err := NewRequest("2 problems\x1b[31m", "firewall: off\n\nsecrets: ‮found\x00", link, "Portal.Example.com")
	if err != nil || r.V != 1 || r.Title != "2 problems[31m" || r.Body != "firewall: off\nsecrets: found" ||
		r.Link != link || r.AllowedHost != "portal.example.com" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = NewRequest(strings.Repeat("t", 500), strings.Repeat("line "+strings.Repeat("b", 400)+"\n", 20), "", "")
	if err != nil || len([]rune(r.Title)) != MaxTitle || strings.Count(r.Body, "\n") != MaxBodyLines-1 || r.Link != "" {
		t.Errorf("caps: %d %d %v", len([]rune(r.Title)), strings.Count(r.Body, "\n"), err)
	}
	for _, l := range strings.Split(r.Body, "\n") {
		if len([]rune(l)) > MaxBodyLine {
			t.Errorf("line of %d", len([]rune(l)))
		}
	}
	if _, err := NewRequest("\x07", "body", "", ""); err == nil {
		t.Error("no title accepted")
	}
	for _, c := range []struct{ link, host string }{
		{"http://portal.example.com/r/x", "portal.example.com"},
		{"https://evil.example.com/r/x", "portal.example.com"},
		{"https://portal.example.com:8443/r/x", "portal.example.com"},
		{"https://portal.example.com.evil.example/r/x", "portal.example.com"},
		{"https://user@portal.example.com/r/x", "portal.example.com"},
		{"https://portal.example.com/r/a b", "portal.example.com"},
		{"https://portal.example.com/r/é", "portal.example.com"},
		{"javascript:alert(1)", "portal.example.com"},
		{"file:///etc/passwd", "portal.example.com"},
		{"https:portal.example.com/x", "portal.example.com"},
		{"https://portal.example.com/" + strings.Repeat("a", MaxLink), "portal.example.com"},
		{link, "portal.example.com/x"},
		{link, ""},
		{link, "evil host"},
	} {
		if _, err := NewRequest("t", "b", c.link, c.host); err == nil {
			t.Errorf("link %.60q on %q accepted", c.link, c.host)
		} else if strings.Contains(err.Error(), "secret-page-id") || strings.Contains(err.Error(), "/r/") {
			t.Errorf("an error carries the link: %v", err)
		}
	}
	if _, err := NewRequest("t", "b", "https://portal.example.com:8443/r/x", "portal.example.com:8443"); err != nil {
		t.Errorf("port: %v", err)
	}
}

func TestRequirement(t *testing.T) {
	r := Requirement("ABCDE12345")
	for _, want := range []string{`anchor apple generic`, `identifier "io.github.ptrinh.bordercheck.notifier"`,
		`1.2.840.113635.100.6.2.6`, `1.2.840.113635.100.6.1.13`, `leaf[subject.OU] = "ABCDE12345"`} {
		if !strings.Contains(r, want) {
			t.Errorf("requirement lacks %s: %s", want, r)
		}
	}
	if strings.Contains(Requirement(""), "subject.OU") {
		t.Error("unpinned requirement names a team")
	}
	if _, err := Codesign(t.Context(), "/nonexistent", `X" or anchor apple`); err == nil {
		t.Error("a malformed pinned Team ID went into a requirement")
	}
}

func TestTeamFromDisplay(t *testing.T) {
	out := []byte("Executable=/x/Bordercheck.app/Contents/MacOS/bordercheck-notifier\n" +
		"Identifier=io.github.ptrinh.bordercheck.notifier\nFormat=app bundle with Mach-O universal (x86_64 arm64)\n" +
		"Authority=Developer ID Application: Example Ltd (ABCDE12345)\nTeamIdentifier=ABCDE12345\n")
	if team, err := TeamFromDisplay(out, ""); err != nil || team != "ABCDE12345" {
		t.Errorf("got %q, %v", team, err)
	}
	if _, err := TeamFromDisplay(out, "ZZZZZ99999"); err == nil {
		t.Error("another team accepted")
	}
	if _, err := TeamFromDisplay(bytes.Replace(out, []byte("ABCDE12345\n"), []byte("not set\n"), 1), ""); err == nil {
		t.Error("ad hoc signature (no team) accepted")
	}
	if _, err := TeamFromDisplay(bytes.Replace(out, []byte("ptrinh.bordercheck.notifier"), []byte("evil.app"), 1), ""); err == nil {
		t.Error("another identifier accepted")
	}
}

// bundle writes a minimal helper bundle (a shell script stands in for the executable).
func bundle(t *testing.T, dir string) string {
	t.Helper()
	app := filepath.Join(dir, AppName)
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>` +
		`<key>CFBundleIdentifier</key><string>` + BundleID + `</string>` +
		`<key>CFBundleExecutable</key><string>bordercheck-notifier</string>` +
		`<key>CFBundlePackageType</key><string>APPL</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "bordercheck-notifier"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return app
}

func goodVerify(_ context.Context, _, team string) (string, error) {
	if team != "" && team != "ABCDE12345" {
		return "", errors.New("wrong team")
	}
	return "ABCDE12345", nil
}

func installed(t *testing.T) Helper {
	t.Helper()
	dir := t.TempDir()
	app := bundle(t, dir)
	d, err := Digest(app)
	if err != nil {
		t.Fatal(err)
	}
	return Helper{Dir: dir, TeamID: "ABCDE12345", Digest: d, Verify: goodVerify}
}

// call is one launch of the fake helper.
type call struct {
	mode    Mode
	args    []string // what would be on the command line
	request []byte   // its stdin
	perm    fs.FileMode
}

// fake answers s and records each launch.
func fake(s string, calls *[]call) Runner {
	return func(_ context.Context, app string, mode Mode, in, out string) error {
		c := call{mode: mode, args: []string{app, string(mode), in, out}}
		if in != os.DevNull {
			st, err := os.Stat(in)
			if err != nil {
				return err
			}
			c.perm = st.Mode().Perm()
			if c.request, err = os.ReadFile(in); err != nil {
				return err
			}
		}
		*calls = append(*calls, c)
		return os.WriteFile(out, []byte(s), 0o600)
	}
}

func TestHelperWithFakeApp(t *testing.T) {
	var calls []call
	h := installed(t)
	req, err := NewRequest("1 problem", "firewall: off", link, "portal.example.com")
	if err != nil {
		t.Fatal(err)
	}

	h.Run = fake(`{"v":1,"status":"posted"}`, &calls)
	if s, err := h.Post(t.Context(), req); err != nil || s != Posted {
		t.Errorf("granted: %q %v", s, err)
	}
	h.Run = fake(`{"v":1,"status":"denied"}`, &calls)
	if s, err := h.Post(t.Context(), req); err != nil || s != Denied {
		t.Errorf("denied: %q %v", s, err)
	}
	h.Run = fake(`{"v":1,"status":"not_determined"}`, &calls)
	if s, err := h.Post(t.Context(), req); err != nil || s != NotDetermined {
		t.Errorf("not determined: %q %v", s, err)
	}
	h.Run = fake(`{"v":1,"status":"authorized"}`, &calls)
	if s, err := h.Status(t.Context()); err != nil || s != Authorized {
		t.Errorf("status: %q %v", s, err)
	}
	h.Run = fake("Segmentation fault", &calls)
	if _, err := h.Post(t.Context(), req); err == nil {
		t.Error("garbage accepted")
	}
	h.Run = fake(strings.Repeat(" ", MaxAnswer)+`{"v":1,"status":"posted"}`, &calls)
	if _, err := h.Post(t.Context(), req); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("oversize: %v", err)
	}
	h.Run = fake("", &calls)
	if _, err := h.Post(t.Context(), req); err == nil {
		t.Error("no answer accepted")
	}
	// Timeout: the app never quits.
	h.Run = func(ctx context.Context, _ string, _ Mode, _, _ string) error { <-ctx.Done(); return ctx.Err() }
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Post(ctx, req); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("timeout: %v", err)
	}

	for _, c := range calls {
		// The link travels only in the request file: never on a command line.
		if slices.ContainsFunc(c.args, func(a string) bool { return strings.Contains(a, "secret-page-id") }) {
			t.Errorf("the link is in the arguments: %q", c.args)
		}
		if c.mode == ModePost {
			if runtime.GOOS != "windows" && c.perm != 0o600 { // Windows has no mode bits
				t.Errorf("request file mode %o", c.perm)
			}
			var got Request
			if err := json.Unmarshal(c.request, &got); err != nil || got != req {
				t.Errorf("request %s: %v", c.request, err)
			}
		}
		if c.mode == ModeAuthorize {
			t.Error("asked for authorization")
		}
	}
	// Nothing lingers in the install folder.
	if left, _ := filepath.Glob(filepath.Join(h.Dir, ".notifier-*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

func TestHelperRefusesWhatItDidNotInstall(t *testing.T) {
	ran := false
	run := func(context.Context, string, Mode, string, string) error { ran = true; return nil }

	// Missing helper, or one never recorded.
	h := Helper{Dir: t.TempDir(), TeamID: "ABCDE12345", Digest: "x", Run: run, Verify: goodVerify}
	if _, err := h.Status(t.Context()); !errors.Is(err, ErrNotInstalled) || h.Ready() {
		t.Errorf("missing: %v", err)
	}
	h = installed(t)
	h.Run = run
	unpinned := h
	unpinned.TeamID = ""
	if _, err := unpinned.Status(t.Context()); !errors.Is(err, ErrNotInstalled) || unpinned.Ready() {
		t.Errorf("unpinned: %v", err)
	}
	// Wrong signature.
	h.Verify = func(context.Context, string, string) (string, error) { return "", errors.New("not signed by us") }
	if _, err := h.Status(t.Context()); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Errorf("wrong signature: %v", err)
	}
	// Changed after install.
	h.Verify = goodVerify
	exe := filepath.Join(Path(h.Dir), "Contents", "MacOS", "bordercheck-notifier")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho evil\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Status(t.Context()); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("tampered: %v", err)
	}
	// A file added to the bundle.
	h2 := installed(t)
	h2.Run = run
	if err := os.WriteFile(filepath.Join(Path(h2.Dir), "Contents", "extra"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h2.Status(t.Context()); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("added file: %v", err)
	}
	// A link in place of the bundle.
	h3 := installed(t)
	h3.Run = run
	real := Path(h3.Dir) + ".real"
	if err := os.Rename(Path(h3.Dir), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, Path(h3.Dir)); err == nil {
		if _, err := h3.Status(t.Context()); err == nil {
			t.Error("ran through a symlink")
		}
	}
	if _, err := installed(t).run(t.Context(), Mode("--evil"), nil); err == nil {
		t.Error("unknown mode accepted")
	}
	if ran {
		t.Error("the helper ran")
	}
}

type entry struct {
	name string
	body string
	mode fs.FileMode
}

func zipOf(t *testing.T, entries []entry) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		hdr.SetMode(e.mode)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(e.body))
	}
	zw.Close()
	return b.Bytes()
}

var goodEntries = []entry{
	{AppName + "/", "", fs.ModeDir | 0o755},
	{AppName + "/Contents/Info.plist", "<plist/>", 0o644},
	{AppName + "/Contents/MacOS/bordercheck-notifier", "#!/bin/sh\n", 0o755},
}

func TestInstallZip(t *testing.T) {
	dir := t.TempDir()
	team, digest, err := InstallZip(t.Context(), dir, zipOf(t, goodEntries), goodVerify, "")
	if err != nil || team != "ABCDE12345" || digest == "" {
		t.Fatalf("%q %q %v", team, digest, err)
	}
	if d, _ := Digest(Path(dir)); d != digest {
		t.Error("digest differs after install")
	}
	st, err := os.Stat(filepath.Join(Path(dir), "Contents", "MacOS", "bordercheck-notifier"))
	if err != nil || (runtime.GOOS != "windows" && st.Mode().Perm()&0o100 == 0) {
		t.Errorf("executable: %v %v", st, err)
	}
	// An update with another team is refused and the installed one kept.
	other := func(context.Context, string, string) (string, error) { return "ZZZZZ99999", nil }
	if _, _, err := InstallZip(t.Context(), dir, zipOf(t, goodEntries), other, "ABCDE12345"); err == nil {
		t.Error("another team replaced the helper")
	}
	if d, _ := Digest(Path(dir)); d != digest {
		t.Error("a refused update changed the helper")
	}
	// A failing signature check installs nothing.
	fresh := t.TempDir()
	bad := func(context.Context, string, string) (string, error) { return "", errors.New("ad hoc") }
	if _, _, err := InstallZip(t.Context(), fresh, zipOf(t, goodEntries), bad, ""); err == nil || Installed(fresh) {
		t.Errorf("unsigned helper installed: %v", err)
	}

	for name, entries := range map[string][]entry{
		"traversal": append(goodEntries[:3:3], entry{AppName + "/../../evil", "x", 0o644}),
		"absolute":  append(goodEntries[:3:3], entry{"/tmp/evil", "x", 0o644}),
		"outside":   append(goodEntries[:3:3], entry{"Other.app/x", "x", 0o644}),
		"macosx":    append(goodEntries[:3:3], entry{"__MACOSX/._x", "x", 0o644}),
		"symlink":   append(goodEntries[:3:3], entry{AppName + "/Contents/link", "/etc/passwd", fs.ModeSymlink | 0o777}),
		"no plist":  {goodEntries[0], goodEntries[2]},
	} {
		d := t.TempDir()
		if _, _, err := InstallZip(t.Context(), d, zipOf(t, entries), goodVerify, ""); err == nil {
			t.Errorf("%s: installed", name)
		}
		if left, _ := os.ReadDir(d); len(left) != 0 {
			t.Errorf("%s: left %v", name, left)
		}
	}
	if _, _, err := InstallZip(t.Context(), t.TempDir(), []byte("not a zip"), goodVerify, ""); err == nil {
		t.Error("garbage installed")
	}
	if err := Remove(dir); err != nil || Installed(dir) {
		t.Errorf("remove: %v", err)
	}
}

// The real codesign check refuses an ad hoc signed bundle with the right
// bundle ID: only a Developer ID signature passes. Ad hoc signing uses no
// keychain or identity.
func TestCodesignRefusesAdHoc(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign is macOS only")
	}
	app := bundle(t, t.TempDir())
	if out, err := exec.Command("/usr/bin/codesign", "--sign", "-", "--identifier", BundleID, app).CombinedOutput(); err != nil {
		t.Skipf("ad hoc signing failed: %s", out)
	}
	if _, err := Codesign(t.Context(), app, ""); err == nil {
		t.Error("an ad hoc signed helper passed")
	}
	if _, err := Codesign(t.Context(), app, "ABCDE12345"); err == nil {
		t.Error("an ad hoc signed helper passed with a pinned team")
	}
}

// With BORDERCHECK_NOTIFIER_ZIP set to a zip from scripts/build-notifier.sh
// --zip, the real archive unpacks with its signature intact and, when it is
// ad hoc signed, the Developer ID check refuses it. It never runs the app.
func TestRealNotifierZip(t *testing.T) {
	p := os.Getenv("BORDERCHECK_NOTIFIER_ZIP")
	if p == "" || runtime.GOOS != "darwin" {
		t.Skip("set BORDERCHECK_NOTIFIER_ZIP to a built notifier zip")
	}
	data, err := ReadCapped(p, MaxZip)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, _, err := InstallZip(t.Context(), dir, data, goodVerify, ""); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", "--deep", "--verbose=2", Path(dir)).CombinedOutput(); err != nil {
		t.Fatalf("signature broken by unpacking: %s", out)
	}
	if _, err := os.Stat(filepath.Join(Path(dir), "Contents", "Resources", "AppIcon.icns")); err != nil {
		t.Errorf("no icon: %v", err)
	}
	team, err := Codesign(t.Context(), Path(dir), "")
	t.Logf("Developer ID check: team %q, %v", team, err)
	out, _ := exec.Command("/usr/bin/codesign", "-dv", Path(dir)).CombinedOutput()
	if strings.Contains(string(out), "TeamIdentifier=not set") && err == nil {
		t.Error("an ad hoc signed helper passed the Developer ID check")
	}
}
