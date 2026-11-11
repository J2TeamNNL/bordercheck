package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
)

// A problem that shows signs of compromise is announced as one: what the signs
// are (never which item), and to stop and tell IT. A fail that turns into one
// is announced again.
func TestComposeCompromise(t *testing.T) {
	sus := res("startup-items", check.Fail, check.High)
	_, seen := Plan([]check.Result{sus}, on(), nil, time.Now())
	sus.Compromise = []check.Indicator{{What: msg.P("compromise.startupDownloadRun"), Detail: "LaunchAgent ~/x.plist (com.x)"}}
	due, _ := Plan([]check.Result{sus, res("firewall", check.Fail, check.High)}, on(), seen, time.Now())
	if len(due) != 2 {
		t.Fatalf("a fail that became a sign of compromise should be announced again: %v", ids(due))
	}
	m := Compose(due)
	if m.Title != "bordercheck: this computer may be compromised" ||
		!strings.HasPrefix(m.Body, "startup-items: A program set to start automatically downloads code") ||
		!strings.Contains(m.Body, "Stop using it for work and tell your IT team now") || strings.Contains(m.Body, "com.x") {
		t.Errorf("got %+v", m)
	}
}
