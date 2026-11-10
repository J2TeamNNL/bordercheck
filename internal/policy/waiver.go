package policy

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

// Waiver exempts one machine from one check until a date, e.g. "this laptop
// may keep port 5432 open until 2026-12-01", without loosening the rule for
// everyone. Every identity field that is set must match; at least one is
// required. Email and InstallID exist only once bordercheck is installed.
type Waiver struct {
	Check     string `json:"check"`                // check ID, see bordercheck -list
	Email     string `json:"email,omitempty"`      // the email bordercheck was installed with
	InstallID string `json:"install_id,omitempty"` // from the report, or bordercheck status
	Hostname  string `json:"hostname,omitempty"`   // as in the report's host.hostname; self-reported, so the weakest
	Until     string `json:"until"`                // YYYY-MM-DD, the last day it applies (machine's local date)
	Reason    string `json:"reason"`
}

// DateFormat is how waiver dates are written.
const DateFormat = "2006-01-02"

// MaxWaiver is how far ahead a waiver may end. Exempting a machine for longer
// is a policy change, not a waiver.
const MaxWaiver = 365 * 24 * time.Hour

// now is the clock waivers are validated against; tests replace it.
var now = time.Now

// Identity is who this machine is, for matching waivers. Email and InstallID
// are empty when bordercheck is not installed.
type Identity struct {
	Email     string
	InstallID string
	Hostname  string
}

func normHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	return strings.TrimSuffix(h, ".local") // macOS reports "name" or "name.local"
}

func (w Waiver) matches(id string, who Identity) bool {
	return w.Check == id &&
		(w.Email == "" || strings.EqualFold(w.Email, who.Email)) &&
		(w.InstallID == "" || w.InstallID == who.InstallID) &&
		(w.Hostname == "" || (who.Hostname != "" && normHost(w.Hostname) == normHost(who.Hostname)))
}

// Waive applies the waivers that match who. A fail or warn with a matching
// waiver that has not ended reports as check.Waived and carries the waiver
// (the one ending last, if several match). An ended waiver changes nothing but
// sets WaiverEnded, so the text report can say so. Waivers are checked against
// the local date, and apply through the whole of their Until day.
func (p Policy) Waive(results []check.Result, who Identity, at time.Time) []check.Result {
	today := at.Format(DateFormat)
	out := append([]check.Result(nil), results...)
	for i, r := range out {
		if r.Status != check.Fail && r.Status != check.Warn {
			continue
		}
		var active, ended *Waiver
		for j := range p.Waivers {
			w := &p.Waivers[j]
			if !w.matches(r.ID, who) {
				continue
			}
			if w.Until >= today { // YYYY-MM-DD compares as text
				if active == nil || w.Until > active.Until {
					active = w
				}
			} else if ended == nil || w.Until > ended.Until {
				ended = w
			}
		}
		switch {
		case active != nil:
			out[i].Status = check.Waived
			out[i].Waived = &check.Waiver{Until: active.Until, Reason: active.Reason}
		case ended != nil:
			out[i].WaiverEnded = ended.Until
		}
	}
	return out
}

// ActiveWaivers are the waivers that apply to who and have not ended, in policy
// order.
func (p Policy) ActiveWaivers(who Identity, at time.Time) []Waiver {
	today := at.Format(DateFormat)
	var out []Waiver
	for _, w := range p.Waivers {
		if w.matches(w.Check, who) && w.Until >= today {
			out = append(out, w)
		}
	}
	return out
}

// checkIDs are the check IDs a policy knows, from the json names in Checks, so
// a check added there can be waived without touching this file.
func checkIDs() map[string]bool {
	ids := map[string]bool{}
	t := reflect.TypeFor[Checks]()
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			ids[name] = true
		}
	}
	return ids
}

func validateWaivers(ws []Waiver, at time.Time) error {
	ids := checkIDs()
	today, _ := time.Parse(DateFormat, at.Format(DateFormat))
	// A day of slack either side of the cap for clocks and time zones, so a
	// waiver written for exactly a year does not break the policy elsewhere.
	latest := today.Add(MaxWaiver + 24*time.Hour)
	for i, w := range ws {
		name := fmt.Sprintf("waivers[%d]", i)
		if w.Check != "" {
			name = fmt.Sprintf("waivers[%d] (%s)", i, w.Check)
		}
		switch {
		case !ids[w.Check]:
			return fmt.Errorf("%s: check must be one of the check IDs (see bordercheck -list), not %q", name, w.Check)
		case w.Email == "" && w.InstallID == "" && w.Hostname == "":
			return fmt.Errorf("%s: say which machine with email, install_id and/or hostname", name)
		case w.Email != "" && !strings.Contains(w.Email, "@"):
			return fmt.Errorf("%s: email %q is not an email address", name, w.Email)
		case strings.ContainsAny(w.Hostname, " \t/\\"):
			return fmt.Errorf("%s: hostname %q is not a hostname", name, w.Hostname)
		case strings.TrimSpace(w.Reason) == "":
			return fmt.Errorf("%s: a reason is required", name)
		case w.Until == "":
			return fmt.Errorf("%s: until (YYYY-MM-DD) is required; waivers must end", name)
		}
		until, err := time.Parse(DateFormat, w.Until)
		if err != nil {
			return fmt.Errorf("%s: until must be a date like \"2026-12-01\", not %q", name, w.Until)
		}
		if until.After(latest) {
			return fmt.Errorf("%s: until %s is more than %d days ahead; waivers are temporary",
				name, w.Until, int(MaxWaiver.Hours()/24))
		}
	}
	return nil
}
