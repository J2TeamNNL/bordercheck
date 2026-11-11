package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if p.Name != "Acme" || c.Listeners.OnProblem != "fail" || c.Docker.IsEnabled() || !c.TailscaleJudged() {
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

func TestHardeningChecksPolicy(t *testing.T) {
	p, err := load(t, `{"checks": {"os-updates": {"min_os_versions": {"macos": "26", "ubuntu": ""}, "max_pending_days": 7,
		"check_browsers": false, "min_browser_versions": {"chrome": "142.0.7444.175"}},
		"screen-lock": {"max_lock_minutes": 5, "on_problem": "warn"}, "remote-access": {"allow": ["ssh"]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	o := p.Checks.OSUpdates
	if o.MinOSVersions["macos"] != "26" || o.MinOSVersions["ubuntu"] != "" || o.MinOSVersions["windows"] != "26100" ||
		o.MaxPendingDays != 7 || o.MaxCheckAgeDays != 14 || *o.CheckBrowsers || !*o.RequireAutoUpdate {
		t.Errorf("os-updates: %+v", o)
	}
	if p.Checks.ScreenLock.MaxLockMinutes != 5 || !*p.Checks.ScreenLock.RequirePassword || len(p.Checks.RemoteAccess.Allow) != 1 {
		t.Errorf("got %+v %+v", p.Checks.ScreenLock, p.Checks.RemoteAccess)
	}
	for body, want := range map[string]string{
		`{"checks": {"remote-access": {"allow": ["telnet"]}}}`:                   "unknown service",
		`{"checks": {"remote-access": {"on_problem": "nope"}}}`:                  "remote-access.on_problem",
		`{"checks": {"screen-lock": {"max_lock_minutes": -1}}}`:                  "max_lock_minutes",
		`{"checks": {"os-updates": {"max_pending_days": -3}}}`:                   "max_pending_days",
		`{"checks": {"os-updates": {"min_os_versions": {"macos": "Sequoia"}}}}`:  "min_os_versions",
		`{"checks": {"os-updates": {"min_browser_versions": {"opera": "100"}}}}`: "unknown browser",
		`{"checks": {"os-updates": {"require_autoupdate": true}}}`:               "unknown field",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}

func TestCheckInterval(t *testing.T) {
	if p := Default(); p.Report.CheckEvery() != p.Report.Every() {
		t.Error("without check_interval, checks run when a report is due")
	}
	for body, want := range map[string]string{
		`{"report": {"interval": "168h", "check_interval": "24h"}}`: "",
		`{"report": {"interval": "24h", "check_interval": "48h"}}`:  "must not be longer",
		`{"report": {"check_interval": "5m"}}`:                      "at least 15m",
		`{"report": {"check_interval": "daily"}}`:                   "at least 15m",
	} {
		p, err := Parse([]byte(body), "test")
		if want == "" {
			if err != nil || p.Report.CheckEvery() != 24*time.Hour {
				t.Errorf("%s: %v %v", body, p.Report.CheckEvery(), err)
			}
		} else if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", body, want, err)
		}
	}
}
