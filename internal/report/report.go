// Package report renders check results as text for people or JSON for machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

type Host struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname,omitempty"`
	// The machine's own interface addresses, sent by the installed service only
	// when the policy sets report.include_ips.
	IPs []string `json:"ips,omitempty"`
}

// Location is a device position, sent by the installed service only when the
// policy sets report.include_location and the OS can give one without asking.
type Location struct {
	Lat       float64   `json:"lat"`
	Lon       float64   `json:"lon"`
	AccuracyM float64   `json:"accuracy_m"`
	Source    string    `json:"source"`
	Time      time.Time `json:"time"`
}

type Counts struct {
	Fail  int `json:"fail"`
	Error int `json:"error"`
	Warn  int `json:"warn"`
	Pass  int `json:"pass"`
	Skip  int `json:"skip"`
	// Fails and warns a policy waiver exempts this machine from.
	Waived int `json:"waived"`
}

type Report struct {
	Tool    string    `json:"tool"`
	Version string    `json:"version"`
	Policy  string    `json:"policy"`
	Time    time.Time `json:"time"`
	Host    Host      `json:"host"`
	// Set when an installed bordercheck sends the report.
	Email     string    `json:"email,omitempty"`
	InstallID string    `json:"install_id,omitempty"`
	Location  *Location `json:"location,omitempty"`
	// Compromised is set when a failing result carries a sign of compromise
	// (check.Indicator); CompromiseChecks are those results' check IDs. Both
	// go whatever report.include_evidence says, and neither when the policy
	// turns report.compromise_alert off (DropCompromise).
	Compromised      bool           `json:"compromised,omitempty"`
	CompromiseChecks []string       `json:"compromise_checks,omitempty"`
	Counts           Counts         `json:"counts"`
	Results          []check.Result `json:"results"`
}

func New(version, policy string, results []check.Result) Report {
	hostname, _ := os.Hostname()
	r := Report{Tool: "bordercheck", Version: version, Policy: policy, Time: time.Now().UTC().Truncate(time.Second),
		Host: Host{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: hostname}, Results: results}
	for i, res := range results {
		res = res.Consistent()
		// Only a fail is a sign of compromise: a waived result is one IT has
		// accepted, and a pass, skip or error has nothing to show.
		if res.Status != check.Fail {
			res.Compromise = nil
		}
		if len(res.Compromise) > 0 && !slices.Contains(r.CompromiseChecks, res.ID) {
			r.Compromised = true
			r.CompromiseChecks = append(r.CompromiseChecks, res.ID)
		}
		results[i] = res
		switch res.Status {
		case check.Fail:
			r.Counts.Fail++
		case check.Error:
			r.Counts.Error++
		case check.Warn:
			r.Counts.Warn++
		case check.Pass:
			r.Counts.Pass++
		case check.Skip:
			r.Counts.Skip++
		case check.Waived:
			r.Counts.Waived++
		}
	}
	return r
}

// DropCompromise removes the signs of compromise from the report, for a
// policy that turns report.compromise_alert off: the findings stay ordinary fails.
func (r *Report) DropCompromise() {
	r.Compromised, r.CompromiseChecks = false, nil
	for i := range r.Results {
		r.Results[i].Compromise = nil
	}
}

// CompromiseLines are the signs of compromise in the report, one line each:
// "check-id: what (detail)", in report order.
func (r Report) CompromiseLines() []string {
	var out []string
	for _, res := range r.Results {
		for _, ind := range res.Compromise {
			out = append(out, res.ID+": "+ind.Line())
		}
	}
	return out
}

// CompromiseAdvice is what the person at the machine is told to do when there
// are signs of compromise, wherever they are shown.
const CompromiseAdvice = "Stop using this computer for work and tell your IT team now. Do not just delete the item: " +
	"IT needs to see it as it is to find out what it did. Once IT has looked, change the passwords and keys you used on it."

// Progress returns a check.Progress that keeps one line on a terminal up to
// date: how many checks are done, the percentage, and which are still
// running, so a slow check is seen for what it is rather than taken for a
// hang. The line is cleared when the last check finishes.
func Progress(w io.Writer) check.Progress {
	return func(done, total int, running []string) {
		if done >= total {
			fmt.Fprint(w, "\r\x1b[K")
			return
		}
		line := fmt.Sprintf("Checking this computer: %d of %d done (%d%%)", done, total, done*100/max(total, 1))
		if len(running) > 0 && len(running) <= 4 {
			line += " · still on: " + strings.Join(running, ", ")
		}
		fmt.Fprintf(w, "\r\x1b[K%s", line)
	}
}

// Credit is shown where a person meets bordercheck: at install and under a
// report in the terminal. (The portal's pages carry it in their footer.)
const Credit = "(c) Phil Trinh - SENPRINTS"

func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

var styles = map[check.Status]struct {
	label, color string
	rank         int
}{
	check.Fail:   {"FAIL", "\x1b[31m", 0},
	check.Error:  {"ERR ", "\x1b[35m", 1},
	check.Warn:   {"WARN", "\x1b[33m", 2},
	check.Waived: {"WAIV", "\x1b[36m", 3},
	check.Pass:   {"PASS", "\x1b[32m", 4},
	check.Skip:   {"SKIP", "\x1b[90m", 5},
}

// expiringSoon is how close to its end a waiver is called out in the text report.
const expiringSoon = 14 * 24 * time.Hour

// WriteText prints the worst results first.
func (r Report) WriteText(w io.Writer, color bool) {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + "\x1b[0m"
	}
	fmt.Fprintf(w, "%s %s · %s/%s · %s · policy: %s\n\n", paint("\x1b[1m", "BorderCheck"), r.Version, r.Host.OS, r.Host.Arch, r.Host.Hostname, r.Policy)
	if r.Compromised {
		fmt.Fprintln(w, paint("\x1b[1;31m", "Signs that this computer may be compromised:"))
		for _, l := range r.CompromiseLines() {
			fmt.Fprintln(w, "  · "+l)
		}
		fmt.Fprintln(w, paint("\x1b[1m", CompromiseAdvice))
		fmt.Fprintln(w)
	}
	results := append([]check.Result(nil), r.Results...)
	sort.SliceStable(results, func(i, j int) bool { return styles[results[i].Status].rank < styles[results[j].Status].rank })
	for _, res := range results {
		st := styles[res.Status]
		line := paint(st.color, st.label) + "  " + res.Title
		if res.Severity != "" && (res.Status == check.Fail || res.Status == check.Warn || res.Status == check.Waived) {
			line += paint("\x1b[90m", " ["+string(res.Severity)+"]")
		}
		fmt.Fprintln(w, line)
		if res.Summary != "" {
			fmt.Fprintln(w, "      "+res.Summary)
		}
		if note := waiverNote(res, r.Time); note != "" {
			code := "\x1b[36m"
			if res.Waived == nil {
				code = "\x1b[33m" // ended
			}
			fmt.Fprintln(w, "      "+paint(code, note))
		}
		for _, e := range res.Evidence {
			fmt.Fprintln(w, "        · "+e)
		}
		if res.Fix != "" {
			fmt.Fprintln(w, "      "+paint("\x1b[1m", "Fix:")+" "+res.Fix)
		}
		if len(res.UserIgnored) > 0 {
			fmt.Fprintf(w, "      %s %d (sent to IT with your reasons; bordercheck unignore puts one back)\n",
				paint("\x1b[1m", "Ignored by you:"), len(res.UserIgnored))
			for _, ig := range res.UserIgnored {
				fmt.Fprintln(w, "        · "+IgnoredLine(ig))
			}
		}
		if line := SamplesLine(res.LikelySamples); line != "" {
			fmt.Fprintf(w, "      %s %s\n", paint("\x1b[1m", "Look like sample keys:"), line)
		}
		fmt.Fprintln(w)
	}
	c := r.Counts
	var parts []string
	for _, p := range []struct {
		n    int
		name string
	}{{c.Fail, "fail"}, {c.Error, "error"}, {c.Warn, "warn"}, {c.Pass, "pass"}, {c.Skip, "skip"}, {c.Waived, "waived"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.name))
		}
	}
	fmt.Fprintln(w, strings.Join(parts, " · "))
	fmt.Fprintln(w, paint("\x1b[90m", "BorderCheck "+r.Version+" · "+Credit))
}

// IgnoredLine shows one ignored finding: file, what it is, the reason and since when.
func IgnoredLine(ig check.Ignored) string {
	s := ig.Path + "  " + ig.Kind
	if ig.Name != "" {
		s += " (" + ig.Name + ")"
	}
	s += ": " + ig.Reason
	if ig.Since != "" {
		s += " (since " + ig.Since + ")"
	}
	return s
}

// UserIgnored counts the findings set aside by the person at the machine, across all results.
func (r Report) UserIgnored() int {
	n := 0
	for _, res := range r.Results {
		n += len(res.UserIgnored)
	}
	return n
}

// waiverNote says until when a result is waived, warning when that is soon, or
// that a waiver for it has ended.
func waiverNote(res check.Result, now time.Time) string {
	switch {
	case res.Waived != nil:
		note := "Waived until " + res.Waived.Until
		if end, err := time.ParseInLocation("2006-01-02", res.Waived.Until, time.Local); err == nil {
			// The waiver covers the whole of its last day.
			if left := end.AddDate(0, 0, 1).Sub(now); left <= expiringSoon {
				note += fmt.Sprintf(" (ends in %s)", days(left))
			}
		}
		if res.Waived.Reason != "" {
			note += ": " + res.Waived.Reason
		}
		return note
	case res.WaiverEnded != "":
		return "A waiver for this check ended on " + res.WaiverEnded + "; ask IT to extend it or fix the problem."
	}
	return ""
}

func days(d time.Duration) string {
	switch n := int(d.Hours() / 24); n {
	case 0:
		return "less than a day"
	case 1:
		return "1 day"
	default:
		return fmt.Sprintf("%d days", n)
	}
}
