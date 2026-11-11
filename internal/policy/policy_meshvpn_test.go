package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
)

func TestMeshVPNPolicy(t *testing.T) {
	d := Default().Checks
	if d.Tailscale != nil || !d.TailscaleJudged() || d.TailscaleOnProblem() != "" || len(d.MeshVPN.Allow) != 0 ||
		!d.RemoteAccess.ThirdParty {
		t.Errorf("defaults: %+v %+v", d.MeshVPN, d.RemoteAccess)
	}
	p, err := load(t, `{"checks": {"mesh-vpn": {"allow": ["zerotier", "tailscale"]},
	  "remote-access": {"allow": ["teamviewer", "ssh"], "third_party": false}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c := p.Checks; len(c.MeshVPN.Allow) != 2 || c.RemoteAccess.ThirdParty || len(c.RemoteAccess.Allow) != 2 {
		t.Errorf("got %+v %+v", c.MeshVPN, c.RemoteAccess)
	}
	for body, want := range map[string]string{
		`{"checks": {"mesh-vpn": {"allow": ["zerotire"]}}}`:         "unknown tool",
		`{"checks": {"mesh-vpn": {"on_problem": "panic"}}}`:         "on_problem",
		`{"checks": {"mesh-vpn": {"block": true}}}`:                 "unknown field",
		`{"checks": {"tailscale": {"on_problem": "panic"}}}`:        "on_problem",
		`{"checks": {"tailscale": {"allow": ["x"]}}}`:               "unknown field",
		`{"checks": {"remote-access": {"allow": ["team-viewer"]}}}`: "unknown service",
		`{"checks": {"remote-access": {"third_party": "yes"}}}`:     "third_party",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}

// Policies written for clients up to v0.4 set checks.tailscale.
func TestTailscalePolicyStillLoads(t *testing.T) {
	for body, check := range map[string]func(Checks) bool{
		`{"checks": {"tailscale": {}}}`: func(c Checks) bool { return c.TailscaleJudged() && c.TailscaleOnProblem() == "" },
		`{"checks": {"tailscale": {"enabled": false}}}`: func(c Checks) bool {
			return !c.TailscaleJudged() && c.MeshVPN.IsEnabled()
		},
		`{"checks": {"tailscale": {"on_problem": "warn"}}}`: func(c Checks) bool { return c.TailscaleOnProblem() == "warn" },
		`{"checks": {"tailscale": {"on_problem": "warn"}, "mesh-vpn": {"on_problem": "fail"}}}`: func(c Checks) bool {
			return c.TailscaleOnProblem() == "" && c.MeshVPN.OnProblem == "fail"
		},
		`{"checks": {"tailscale": {"enabled": true}, "mesh-vpn": {"enabled": false}}}`: func(c Checks) bool {
			return !c.MeshVPN.IsEnabled()
		},
	} {
		p, err := load(t, body)
		if err != nil {
			t.Errorf("%s: %v", body, err)
			continue
		}
		if !check(p.Checks) {
			t.Errorf("%s: got %+v / %+v", body, p.Checks.Tailscale, p.Checks.MeshVPN)
		}
	}
}

// -print-policy prints mesh-vpn, and tailscale only when the policy set it.
func TestPrintPolicyShape(t *testing.T) {
	b, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`"tailscale"`)) || !bytes.Contains(b, []byte(`"mesh-vpn":{"allow":[]}`)) ||
		!bytes.Contains(b, []byte(`"third_party":true`)) {
		t.Errorf("%s", b)
	}
	p, _ := load(t, `{"checks": {"tailscale": {"enabled": false}}}`)
	b, _ = json.Marshal(p)
	if !bytes.Contains(b, []byte(`"tailscale":{"enabled":false}`)) {
		t.Errorf("a set tailscale must survive printing: %s", b)
	}
}

// A waiver written for the tailscale check covers mesh-vpn when Tailscale is
// its only finding (the result then carries the alias), and only then.
func TestTailscaleWaiverAppliesToMeshVPN(t *testing.T) {
	p, err := load(t, `{"waivers": [{"check": "tailscale", "email": "an@acme.com", "until": "2026-12-01", "reason": "lab"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	ts := check.Result{ID: "mesh-vpn", Status: check.Fail, Severity: check.High, Aliases: []string{"tailscale"}}
	other := check.Result{ID: "mesh-vpn", Status: check.Warn, Severity: check.Medium}
	got := p.Waive([]check.Result{ts, other}, Identity{Email: "an@acme.com"}, today)
	if got[0].Status != check.Waived || got[1].Status != check.Warn {
		t.Errorf("got %+v / %+v", got[0], got[1])
	}
}
