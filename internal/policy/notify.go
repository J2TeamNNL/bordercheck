package policy

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

// Notify decides when an installed bordercheck shows the person at the machine
// a desktop notification. A scheduled run announces a problem the first time
// it sees it, and again every RemindEvery while it is still there.
type Notify struct {
	Enabled     bool             `json:"enabled"`
	Statuses    []check.Status   `json:"statuses"`     // which results notify: "fail" and/or "warn"
	Severities  []check.Severity `json:"severities"`   // and of which severity; a result without one counts as "medium"
	RemindEvery string           `json:"remind_every"` // re-announce a problem still there after this long; "0" = never
	// OpenReport opens the machine's report page in the browser by itself
	// along with a notification that first announces a high-severity problem,
	// when the receiver returned a link to one. On a Mac where bordercheck's
	// own notifications are allowed it does nothing: every notification there
	// opens the page when clicked (internal/agent/notify.go).
	OpenReport bool `json:"open_report"`
}

func defaultNotify() Notify {
	return Notify{
		Enabled:     true,
		Statuses:    []check.Status{check.Fail},
		Severities:  []check.Severity{check.High, check.Medium},
		RemindEvery: "24h",
		OpenReport:  true,
	}
}

// Remind returns how long until a problem still there is announced again; 0 = never.
func (n Notify) Remind() time.Duration {
	d, _ := time.ParseDuration(n.RemindEvery)
	return d
}

// Wants reports whether a result is worth a notification.
func (n Notify) Wants(r check.Result) bool {
	sev := r.Severity
	if sev == "" {
		sev = check.Medium
	}
	return n.Enabled && slices.Contains(n.Statuses, r.Status) && slices.Contains(n.Severities, sev)
}

func (n Notify) validate() error {
	for _, s := range n.Statuses {
		// Not "error": its summary is raw command output, which has no place in a notification.
		if s != check.Fail && s != check.Warn {
			return fmt.Errorf("notify.statuses may hold \"fail\" and \"warn\", not %q", s)
		}
	}
	for _, s := range n.Severities {
		if s != check.Low && s != check.Medium && s != check.High {
			return fmt.Errorf("notify.severities may hold \"low\", \"medium\" and \"high\", not %q", s)
		}
	}
	if n.Enabled && (len(n.Statuses) == 0 || len(n.Severities) == 0) {
		return errors.New("notify.statuses and notify.severities must not be empty; set notify.enabled to false to turn notifications off")
	}
	if d, err := time.ParseDuration(n.RemindEvery); err != nil || (d != 0 && d < time.Hour) {
		return fmt.Errorf("notify.remind_every must be \"0\" (never) or a duration of at least 1h, like \"24h\", not %q", n.RemindEvery)
	}
	return nil
}
