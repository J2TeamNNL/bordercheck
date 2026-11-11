package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func TestListenersLowerSeverity(t *testing.T) {
	lower := policy.Default().Checks.Listeners.LowerSeverity
	airplay := []listener{{Proc: "ControlCenter", Addr: "*", Port: "5000"}, {Proc: "ControlCenter", Addr: "*", Port: "7000"},
		{Proc: "dropboxfileprovider", Addr: "*", Port: "17500"}}
	// Only well-known services: a low warning that says so.
	r := evalListenersWith(airplay, nil, nil, lower)
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Summary, "well-known services") ||
		!strings.Contains(r.Fix, "Turn off the ones you don't use") || len(r.Evidence) != 3 {
		t.Errorf("known services only: %s %s %q %q", r.Status, r.Severity, r.Summary, r.Fix)
	}
	// One other open port makes it medium again, with the ordinary fix.
	r = evalListenersWith(append(airplay, listener{Proc: "node", Addr: "*", Port: "3000"}), nil, nil, lower)
	if r.Severity != check.Medium || strings.Contains(r.Summary, "well-known") || !strings.Contains(r.Fix, "127.0.0.1") {
		t.Errorf("with a dev server: %s %q %q", r.Severity, r.Summary, r.Fix)
	}
	// An empty list keeps the old behaviour.
	if r := evalListenersWith(airplay, nil, nil, nil); r.Severity != check.Medium {
		t.Errorf("no lower_severity list: %s", r.Severity)
	}
}
