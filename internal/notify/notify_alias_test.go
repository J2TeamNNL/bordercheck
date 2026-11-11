package notify

import (
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

// A machine upgrading from a client with the tailscale check: the Tailscale
// problem it was told about is not announced again as a mesh-vpn problem,
// and is remembered under the new key from then on.
func TestPlanRenamedCheck(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	seen := map[string]time.Time{"tailscale:fail": t0}
	mesh := res("mesh-vpn", check.Fail, check.High)
	mesh.Aliases = []string{"tailscale"}
	due, next := Plan([]check.Result{mesh}, on(), seen, t0.Add(time.Hour))
	if len(due) != 0 {
		t.Fatalf("announced again: %v", ids(due))
	}
	if got, ok := next["mesh-vpn:fail"]; !ok || !got.Equal(t0) {
		t.Fatalf("next: %v", next)
	}
	// Another tool's finding in mesh-vpn (no alias) is new.
	other := res("mesh-vpn", check.Fail, check.High)
	if due, _ := Plan([]check.Result{other}, on(), seen, t0.Add(time.Hour)); len(due) != 1 {
		t.Fatalf("not announced: %v", ids(due))
	}
}
