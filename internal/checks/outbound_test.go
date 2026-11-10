package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
)

func TestWithOutbound(t *testing.T) {
	on := evalMacFirewall("Firewall is enabled. (State = 1)", "Firewall stealth mode is on", true)
	if on.Status != check.Pass {
		t.Fatalf("setup: %+v", on)
	}

	r := withOutbound(on, nil, outboundMac)
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Fix, "objective-see.org/products/lulu.html") {
		t.Errorf("no outbound firewall: %+v", r)
	}

	r = withOutbound(on, []string{"LuLu"}, outboundMac)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "LuLu") || r.Fix != "" {
		t.Errorf("LuLu installed: %+v", r)
	}

	stealthOff := evalMacFirewall("Firewall is enabled. (State = 1)", "Stealth mode disabled", true)
	r = withOutbound(stealthOff, nil, outboundMac)
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Fix, "stealth") || !strings.Contains(r.Fix, "LuLu") {
		t.Errorf("stealth off, no outbound firewall: %+v", r)
	}

	off := evalMacFirewall("Firewall is disabled. (State = 0)", "", true)
	if r := withOutbound(off, nil, outboundMac); r.Status != check.Fail || strings.Contains(r.Fix, "LuLu") {
		t.Errorf("firewall off should only ask to turn it on: %+v", r)
	}
}

// Samples written from the documented output of Get-NetFirewallProfile,
// Get-NetConnectionProfile and the registry, not captured from a machine.
func TestWinOutbound(t *testing.T) {
	const allow = "profile=Domain|NotConfigured\nprofile=Private|NotConfigured\nprofile=Public|NotConfigured\n"
	on := evalWinFirewall(map[string]bool{"Domain": true, "Private": true, "Public": true})
	cases := []struct {
		name  string
		out   string
		dirs  []string
		found string // "" = nothing found, suggest simplewall
	}{
		{"nothing", allow + "active=Private\ninstalled=7-Zip 24.08 (x64)\ninstalled=Mozilla Firefox (x64 en-US)\n", nil, ""},
		{"simplewall installed", allow + "installed=simplewall 3.8.7\n", nil, "simplewall"},
		{"simplewall portable, running", allow + "process=simplewall\n", nil, "simplewall"},
		{"Fort Firewall service", allow + "service=FortFirewallSvc\n", nil, "Fort Firewall"},
		{"Portmaster folder", allow, []string{`Safing\Portmaster`}, "Portmaster"},
		{"TinyWall", allow + "installed=TinyWall\n", nil, "TinyWall"},
		{"Windows Firewall Control", allow, []string{`Malwarebytes\Windows Firewall Control`}, "Windows Firewall Control"},
		{"blocked on the active profile", "profile=Domain|NotConfigured\nprofile=Private|Block\nprofile=Public|NotConfigured\nactive=Private\n", nil, "Windows Firewall"},
		{"blocked on one profile, other in use", "profile=Private|Block\nprofile=Public|Allow\nactive=Public\n", nil, ""},
		{"blocked by Group Policy", allow + "gpo=Domain|1\nactive=DomainAuthenticated\n", nil, "Windows Firewall"},
		{"Group Policy allows over a local block", "profile=Domain|Block\ngpo=Domain|0\nactive=DomainAuthenticated\n", nil, ""},
		{"offline, all blocked", "profile=Domain|Block\nprofile=Private|Block\nprofile=Public|Block\n", nil, "Windows Firewall"},
		{"no profile output", "", nil, ""},
	}
	for _, tc := range cases {
		f := parseWinOutbound(tc.out)
		f.Folders = tc.dirs
		found := evalWinOutbound(f)
		r := withOutbound(on, found, outboundWin)
		if tc.found == "" {
			if len(found) != 0 || r.Status != check.Warn || r.Severity != check.Low ||
				!strings.Contains(r.Fix, "github.com/henrypp/simplewall") || !strings.Contains(r.Fix, "ask you to allow") {
				t.Errorf("%s: found %v, result %+v", tc.name, found, r)
			}
			continue
		}
		if len(found) != 1 || !strings.HasPrefix(found[0], tc.found) || r.Status != check.Pass || r.Fix != "" ||
			!strings.Contains(r.Summary, tc.found) {
			t.Errorf("%s: found %v, result %+v", tc.name, found, r)
		}
	}

	off := evalWinFirewall(map[string]bool{"Domain": true, "Private": false, "Public": true})
	if r := withOutbound(off, nil, outboundWin); r.Status != check.Fail || strings.Contains(r.Fix, "simplewall") {
		t.Errorf("firewall off should only ask to turn it on: %+v", r)
	}
}
