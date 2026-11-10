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

	r := withOutbound(on, nil)
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Fix, "objective-see.org/products/lulu.html") {
		t.Errorf("no outbound firewall: %+v", r)
	}

	r = withOutbound(on, []string{"LuLu"})
	if r.Status != check.Pass || !strings.Contains(r.Summary, "LuLu") || r.Fix != "" {
		t.Errorf("LuLu installed: %+v", r)
	}

	stealthOff := evalMacFirewall("Firewall is enabled. (State = 1)", "Stealth mode disabled", true)
	r = withOutbound(stealthOff, nil)
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Fix, "stealth") || !strings.Contains(r.Fix, "LuLu") {
		t.Errorf("stealth off, no outbound firewall: %+v", r)
	}

	off := evalMacFirewall("Firewall is disabled. (State = 0)", "", true)
	if r := withOutbound(off, nil); r.Status != check.Fail || strings.Contains(r.Fix, "LuLu") {
		t.Errorf("firewall off should only ask to turn it on: %+v", r)
	}
}
