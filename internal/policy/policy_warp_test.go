package policy

import (
	"strings"
	"testing"
)

func TestWarpPolicy(t *testing.T) {
	if Default().Checks.Warp.IsEnabled() {
		t.Fatal("warp must be off by default")
	}
	p, err := Parse([]byte(`{"checks": {"warp": {"enabled": true, "team": "senprints", "posture_only": true}}}`), "t")
	if err != nil {
		t.Fatal(err)
	}
	if w := p.Checks.Warp; !w.IsEnabled() || w.Team != "senprints" || !w.PostureOnly {
		t.Errorf("not read as written: %+v", w)
	}
	for in, want := range map[string]string{
		`{"checks": {"warp": {"enabled": true}}}`:                                   "checks.warp.team",
		`{"checks": {"warp": {"enabled": true, "team": "a.cloudflareaccess.com"}}}`: "checks.warp.team",
		`{"checks": {"warp": {"team": "-x"}}}`:                                      "not a Zero Trust team name",
		`{"checks": {"warp": {"on_problem": "skip"}}}`:                              "checks.warp.on_problem",
		`{"checks": {"warp": {"tean": "x"}}}`:                                       "tean",
	} {
		if _, err := Parse([]byte(in), "t"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", in, err, want)
		}
	}
	if !checkIDs()["warp"] {
		t.Error("waivers must accept warp")
	}
}
