package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, body string) (Policy, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestLoadMergesOverDefault(t *testing.T) {
	p, err := load(t, `{"name": "Acme", "checks": {"listeners": {"on_problem": "fail"}, "docker": {"enabled": false}}}`)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Checks
	if p.Name != "Acme" || c.Listeners.OnProblem != "fail" || c.Docker.IsEnabled() || !c.Tailscale.IsEnabled() {
		t.Errorf("got %+v", p)
	}
	if c.Secrets.WalkDepth != 5 || !*c.Firewall.RequireStealth || len(c.Listeners.Allow) != 1 {
		t.Errorf("defaults lost: %+v", c)
	}
}

func TestLoadRejects(t *testing.T) {
	for body, want := range map[string]string{
		`{"checks": {"firewal": {}}}`:                                                "unknown field",
		`{"checks": {"tailscale": {"on_problem": "panic"}}}`:                         "on_problem",
		`{"checks": {"secrets": {"production_keywords": []}}}`:                       "production_keywords",
		`{"checks": {"secrets": {"extra_patterns": [{"kind": "x", "regex": "("}]}}}`: "extra_patterns",
		`{"checks": {"listeners": {"allow": [{"port": "80"}]}}}`:                     "process",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, tc := range []struct {
		glob, path string
		want       bool
	}{
		{"~/demo/**", "~/demo/a/b.pem", true},
		{"~/demo/*", "~/demo/a/b.pem", false},
		{"**/sign/private.pem", "~/x/apps/sign/private.pem", true},
		{"~/.env.?", "~/.env.x", true},
		{"~/a.b", "~/aXb", false},
	} {
		re, err := Glob(tc.glob)
		if err != nil {
			t.Fatal(err)
		}
		if got := re.MatchString(tc.path); got != tc.want {
			t.Errorf("Glob(%q) on %q = %v", tc.glob, tc.path, got)
		}
	}
}
