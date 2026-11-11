package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func TestListenersInfoOnly(t *testing.T) {
	lower := policy.Default().Checks.Listeners.InfoOnly
	airplay := []listener{{Proc: "ControlCenter", Addr: "*", Port: "5000"}, {Proc: "ControlCenter", Addr: "*", Port: "7000"},
		{Proc: "dropboxfileprovider", Addr: "*", Port: "17500"}}
	// Only well-known services: a pass that lists them, with nothing to fix.
	r := evalListenersWith(airplay, nil, nil, lower)
	if r.Status != check.Pass || r.Severity != "" || !strings.Contains(r.Summary, "3 ports") ||
		!strings.Contains(r.Summary, "listed for information") || r.Fix != "" || len(r.Evidence) != 3 {
		t.Errorf("known services only: %s %s %q %q", r.Status, r.Severity, r.Summary, r.Fix)
	}
	// One other open port makes it medium again, with the ordinary fix.
	r = evalListenersWith(append(airplay, listener{Proc: "node", Addr: "*", Port: "3000"}), nil, nil, lower)
	if r.Severity != check.Medium || strings.Contains(r.Summary, "well-known") || !strings.Contains(r.Fix, "127.0.0.1") {
		t.Errorf("with a dev server: %s %q %q", r.Severity, r.Summary, r.Fix)
	}
	// An empty list makes them findings again.
	if r := evalListenersWith(airplay, nil, nil, nil); r.Status != check.Warn || r.Severity != check.Medium {
		t.Errorf("no info_only list: %s", r.Severity)
	}
}
