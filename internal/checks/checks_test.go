package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func TestEvalMacFirewall(t *testing.T) {
	for _, tc := range []struct {
		global, stealth string
		want            check.Status
	}{
		{"Firewall is enabled. (State = 1)\n", "Stealth mode enabled\n", check.Pass},
		{"Firewall is enabled. (State = 1)\n", "Firewall stealth mode is on\n", check.Pass},
		{"Firewall is blocking all non-essential incoming connections. (State = 2)\n", "Stealth mode enabled", check.Pass},
		{"Firewall is enabled. (State = 1)\n", "Stealth mode disabled\n", check.Warn},
		{"Firewall is disabled. (State = 0)\n", "Stealth mode enabled\n", check.Fail},
	} {
		if got := evalMacFirewall(tc.global, tc.stealth, true).Status; got != tc.want {
			t.Errorf("evalMacFirewall(%q, %q) = %s, want %s", tc.global, tc.stealth, got, tc.want)
		}
	}
}

func TestEvalWinFirewall(t *testing.T) {
	r := evalWinFirewall(parseWinFirewall("Domain=True\r\nPrivate=False\r\nPublic=False\r\n"))
	if r.Status != check.Fail || !strings.Contains(r.Summary, "Private, Public") {
		t.Errorf("got %s %q", r.Status, r.Summary)
	}
	if r := evalWinFirewall(parseWinFirewall("Domain=True\nPrivate=True\nPublic=True\n")); r.Status != check.Pass {
		t.Errorf("all on: got %s", r.Status)
	}
	if r := evalWinFirewall(parseWinFirewall("")); r.Status != check.Error {
		t.Errorf("empty: got %s", r.Status)
	}
}

func TestEvalDiskEncryption(t *testing.T) {
	for out, want := range map[string]check.Status{
		"FileVault is On.\n":                             check.Pass,
		"FileVault is Off.\n":                            check.Fail,
		"Encryption in progress: Percent completed = 40": check.Warn,
	} {
		if got := evalFileVault(out).Status; got != want {
			t.Errorf("evalFileVault(%q) = %s, want %s", out, got, want)
		}
	}
	for code, want := range map[string]check.Status{"1\r\n": check.Pass, "2": check.Fail, "3": check.Warn, "": check.Skip} {
		if got := evalBitLocker(code).Status; got != want {
			t.Errorf("evalBitLocker(%q) = %s, want %s", code, got, want)
		}
	}
}

func TestListeners(t *testing.T) {
	lsof := `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node      51234 me   23u  IPv6 0x1234567890abcdef      0t0  TCP [::1]:5173 (LISTEN)
node      51235 me   24u  IPv4 0x1234567890abcdef      0t0  TCP *:3000 (LISTEN)
node      51235 me   25u  IPv6 0x1234567890abcdef      0t0  TCP *:3000 (LISTEN)
postgres    999 me    7u  IPv4 0x1234567890abcdef      0t0  TCP 127.0.0.1:5432 (LISTEN)
Code\x20H   777 me    7u  IPv4 0x1234567890abcdef      0t0  TCP 192.168.1.5:9000 (LISTEN)
`
	ls := parseLsof(lsof)
	if len(ls) != 5 {
		t.Fatalf("parseLsof: got %d listeners, want 5: %+v", len(ls), ls)
	}
	r := evalListeners(ls, nil, nil)
	want := []string{"Code H: port 9000 on 192.168.1.5", "node: port 3000 on all interfaces"}
	if r.Status != check.Warn || !slices.Equal(r.Evidence, want) {
		t.Errorf("got %s %q, want warn %q", r.Status, r.Evidence, want)
	}

	win := parseWinListeners("System|0.0.0.0|445\r\nnode|127.0.0.1|5173\r\n|::|135\r\n")
	r = evalListeners(win, nil, nil)
	want = []string{"System: port 445 on all interfaces (Windows file sharing (SMB) and other system services)", "unknown process: port 135 on all interfaces"}
	if !slices.Equal(r.Evidence, want) {
		t.Errorf("windows: got %q, want %q", r.Evidence, want)
	}

	if r := evalListeners(parseLsof(lsof)[:1], nil, nil); r.Status != check.Pass {
		t.Errorf("loopback only: got %s", r.Status)
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "[::1]": true, "::1": true, "localhost": true,
		"*": false, "0.0.0.0": false, "": false, "100.64.0.1": false, "[::]": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v", addr, got)
		}
	}
}

func TestEvalTailscalePrefs(t *testing.T) {
	for out, want := range map[string]check.Status{
		`{"ControlURL":"x","ShieldsUp":true}`:  check.Pass,
		`{"ControlURL":"x","ShieldsUp":false}`: check.Fail,
		`{"ControlURL":"x"}`:                   check.Error,
		`not json`:                             check.Error,
	} {
		if got := evalTailscalePrefs(out).Status; got != want {
			t.Errorf("evalTailscalePrefs(%s) = %s, want %s", out, got, want)
		}
	}
}

func TestEvalDocker(t *testing.T) {
	out := `[
 {"Name":"/db","HostConfig":{"NetworkMode":"bridge","Privileged":false},
  "NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"5432"},{"HostIp":"::","HostPort":"5432"}],
                              "6379/tcp":[{"HostIp":"127.0.0.1","HostPort":"6379"}],"80/tcp":null}},
  "Mounts":[{"Type":"volume","Source":"/var/lib/docker/volumes/x/_data"},{"Type":"bind","Source":"/Users/me/project/data"}]},
 {"Name":"/agent","HostConfig":{"NetworkMode":"host","Privileged":true},"NetworkSettings":{"Ports":{}},
  "Mounts":[{"Type":"bind","Source":"/var/run/docker.sock"},{"Type":"bind","Source":"/Users/me"},{"Type":"bind","Source":"/Users/me/.ssh"}]}
]`
	r := evalDocker(out, "/Users/me", policy.Docker{})
	if r.Status != check.Fail || len(r.Evidence) != 7 {
		t.Fatalf("got %s with %d evidence lines: %q", r.Status, len(r.Evidence), r.Evidence)
	}
	if !strings.Contains(r.Evidence[len(r.Evidence)-1], "5432/tcp") {
		t.Errorf("high-severity lines should come before port lines: %q", r.Evidence)
	}
	clean := `[{"Name":"/db","HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5432"}]}},"Mounts":[]}]`
	if r := evalDocker(clean, "/Users/me", policy.Docker{}); r.Status != check.Pass {
		t.Errorf("clean: got %s %q", r.Status, r.Evidence)
	}
}

func TestRiskyMount(t *testing.T) {
	for _, tc := range []struct{ src, home, want string }{
		{`C:\Users\me`, `C:\Users\me`, "your whole home folder"},
		{"/run/desktop/mnt/host/c/Users/me", `C:\Users\me`, "your whole home folder"},
		{`C:\`, `C:\Users\me`, "the whole disk"},
		{"/", "/Users/me", "the whole disk"},
		{"/Users", "/Users/me", "every user's home folder"},
		{"/Users/me/.aws/", "/Users/me", "credentials folder ~/.aws"},
		{`\\.\pipe\docker_engine`, `C:\Users\me`, "the Docker socket: full control of the host"},
		{"/Users/me/project", "/Users/me", ""},
		{"/Users/me/.sshkeys-backup", "/Users/me", ""},
	} {
		if got := riskyMount(tc.src, tc.home); got != tc.want {
			t.Errorf("riskyMount(%q, %q) = %q, want %q", tc.src, tc.home, got, tc.want)
		}
	}
}

func TestScanSecrets(t *testing.T) {
	// Token-shaped fixtures are split so secret scanners (GitHub push protection) don't flag this file.
	sample := strings.Join([]string{
		"# comment",
		"export PATH=/usr/bin",
		"export OPENAI_API_KEY=sk-" + "proj-abcdefghijklmnopqrstuvwx1234",
		"export DB_PASSWORD=${DB_PASSWORD}",
		"STRIPE_KEY=sk_" + "live_abcdefghijklmnopqrstuvwx",
		"PROD_GITHUB_TOKEN=gh" + "p_abcdefghijklmnopqrstuvwxyz0123456789",
		"GOOGLE_APPLICATION_CREDENTIALS=/Users/me/sa.json",
		"DATABASE_URL=postgres://app:s3cretpw@db.internal:5432/app",
		"API_KEY=your_api_key_here",
		"max_tokens=4096",
		": 1700000000:0;export ANTHROPIC_API_KEY=sk-" + "ant-api03-abcdefghijklmnopqrstuvwxyz",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		`  "client_secret": "q8Zr2LmN4pXv7TbK",`,
	}, "\n")
	s := testScanner(t, policy.Default().Checks.Secrets)
	got := s.scan(strings.NewReader(sample), "~/.env", s.rules)
	want := []secretFinding{
		{"~/.env", 3, "OpenAI API key", "OPENAI_API_KEY", false, "1234", false},
		{"~/.env", 5, "Stripe live key", "STRIPE_KEY", true, "uvwx", true},
		{"~/.env", 6, "GitHub token", "PROD_GITHUB_TOKEN", true, "6789", false},
		{"~/.env", 8, "Password in URL", "DATABASE_URL", false, "", false},
		{"~/.env", 11, "Anthropic API key", "ANTHROPIC_API_KEY", false, "wxyz", false},
		{"~/.env", 12, "Private key", "", false, "", true},
		{"~/.env", 13, "Secret-looking variable", "client_secret", false, "", false},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("scanSecrets:\n got %+v\nwant %+v", got, want)
	}
	for _, f := range got {
		for _, value := range []string{"abcdefghijklmnop", "s3cretpw", "pw@", "q8Zr2LmN", "TbK"} {
			if strings.Contains(f.String(), value) {
				t.Errorf("finding %q leaks the secret value", f)
			}
		}
	}
	if got := s.scan(strings.NewReader("TOKEN=abcdefgh1234"), "~/proj/.env.production", s.rules); len(got) != 1 || !got[0].prod {
		t.Errorf("production path not marked: %+v", got)
	}
}

func TestEvalSecrets(t *testing.T) {
	if r := evalSecrets(nil, nil, false, nil); r.Status != check.Pass {
		t.Errorf("none: got %s", r.Status)
	}
	medium := []secretFinding{{"~/.zshrc", 1, "OpenAI API key", "OPENAI_API_KEY", false, "", false}}
	if r := evalSecrets(medium, nil, false, nil); r.Status != check.Warn {
		t.Errorf("medium: got %s", r.Status)
	}
	high := append(medium, secretFinding{"~/k.pem", 1, "Private key", "", false, "", true})
	r := evalSecrets(high, []string{"~/c.p12"}, true, nil)
	if r.Status != check.Fail || !strings.HasPrefix(r.Evidence[0], "~/k.pem") || !strings.Contains(r.Summary, "time limit") {
		t.Errorf("high: got %s %q %q", r.Status, r.Summary, r.Evidence)
	}
}

func TestFindSecretFiles(t *testing.T) {
	home := t.TempDir()
	for _, rel := range []string{
		".zshrc", "proj/.env", "proj/.env.local", "proj/.env.example", "proj/node_modules/x/.env",
		"a/b/c/d/e/.env", "a/b/c/d/e/f/.env", "certs/x.p12", "keys/k.pem", "notes.txt",
	} {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scan, bundles, incomplete := testScanner(t, policy.Default().Checks.Secrets).find(t.Context(), home)
	for i, p := range scan {
		scan[i] = filepath.ToSlash(tildePath(home, p))
	}
	slices.Sort(scan)
	want := []string{"~/.zshrc", "~/a/b/c/d/e/.env", "~/keys/k.pem", "~/proj/.env", "~/proj/.env.local"}
	if !slices.Equal(scan, want) || len(bundles) != 1 || incomplete {
		t.Errorf("got scan %q bundles %q incomplete %v; want scan %q", scan, bundles, incomplete, want)
	}
}

func testScanner(t *testing.T, p policy.Secrets) *secretScanner {
	t.Helper()
	s, err := newSecretScanner(p, "/home/me")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFirewallWithoutStealth(t *testing.T) {
	if r := evalMacFirewall("Firewall is enabled. (State = 1)", "Stealth mode disabled", false); r.Status != check.Pass {
		t.Errorf("got %s", r.Status)
	}
}

func TestListenerAllow(t *testing.T) {
	ls := []listener{{"node", "*", "3000"}, {"node", "*", "4000"}, {"Dropbox", "*", "17500"}}
	r := evalListeners(ls, nil, []policy.ListenerRule{{Process: "node", Port: "3000"}, {Process: "dropbox"}})
	if !slices.Equal(r.Evidence, []string{"node: port 4000 on all interfaces"}) || !strings.Contains(r.Summary, "2 more allowed") {
		t.Errorf("got %q %q", r.Summary, r.Evidence)
	}
}

func TestDockerAllow(t *testing.T) {
	out := `[{"Name":"/dev","HostConfig":{"NetworkMode":"host"},"NetworkSettings":{},"Mounts":[]},
 {"Name":"/app","HostConfig":{},"NetworkSettings":{},"Mounts":[{"Type":"bind","Source":"/Users/me/.config/app"}]}]`
	opts := policy.Docker{AllowContainers: []string{"dev"}, AllowMounts: []string{"~/.config/app"}}
	if r := evalDocker(out, "/Users/me", opts); r.Status != check.Pass {
		t.Errorf("got %s %q", r.Status, r.Evidence)
	}
}

func TestSecretPolicy(t *testing.T) {
	p := policy.Default().Checks.Secrets
	p.ProductionKeywords = []string{"prd"}
	p.ShowTail = new(bool)
	p.IgnorePaths = []string{"~/demo/**"}
	p.ExtraPatterns = []policy.SecretPattern{{Kind: "Sample token", Regex: `\bsample_[a-z0-9]{24}\b`, High: true}}
	s := testScanner(t, p)
	got := s.scan(strings.NewReader("X=sample_abcdefghijklmnopqrstuvwx\nPRD_KEY=sk-abcdefghijklmnopqrstuvwxyz\nPROD_TOKEN=abcdefgh1234"), "~/.env", s.rules)
	want := []secretFinding{
		{"~/.env", 1, "Sample token", "X", false, "", true},
		{"~/.env", 2, "OpenAI API key", "PRD_KEY", true, "", false},
		{"~/.env", 3, "Secret-looking variable", "PROD_TOKEN", false, "", false},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if !s.ignored("~/demo/a/b/private.pem") || s.ignored("~/demo.pem") {
		t.Error("ignore_paths glob")
	}
}

func TestIsPackageDir(t *testing.T) {
	for name, want := range map[string]bool{
		"Xcode.app": true, "Photos Library.photoslibrary": true, ".old.sparsebundle": true, "Backup.SPARSEBUNDLE": true,
		"projects": false, ".ssh": false, "app": false, "notes.app.d": false,
	} {
		if got := isPackageDir(name); got != want {
			t.Errorf("isPackageDir(%q) = %v", name, got)
		}
	}
}
