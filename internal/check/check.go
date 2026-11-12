// Package check defines a check and the result it reports.
package check

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ptrinh/bordercheck/internal/msg"
)

// Status is the outcome of one check.
type Status string

const (
	Pass  Status = "pass"
	Warn  Status = "warn"
	Fail  Status = "fail"
	Skip  Status = "skip"  // does not apply here, e.g. the software is not installed
	Error Status = "error" // could not tell
	// Waived is a fail or warn that a policy waiver exempts this machine from
	// until a date; the result keeps its severity, summary and fix.
	Waived Status = "waived"
)

// Severity ranks a warn or a fail.
type Severity string

const (
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

// Result is what a check reports. Evidence never holds a secret's value.
type Result struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Status   Status   `json:"status"`
	Severity Severity `json:"severity,omitempty"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence,omitempty"`
	Fix      string   `json:"fix,omitempty"`
	// SummaryParts and FixParts are Summary and Fix as message keys with
	// parameters (see package msg), for showing them in other languages. They
	// are set together with the text by WithSummary and WithFix, and dropped
	// by Consistent when the text was changed some other way.
	SummaryParts msg.Text `json:"summary_parts,omitempty"`
	FixParts     msg.Text `json:"fix_parts,omitempty"`
	// Waived is set when Status is Waived.
	Waived *Waiver `json:"waived,omitempty"`
	// WaiverEnded is the end date (YYYY-MM-DD) of a waiver that matched this
	// fail or warn but has expired. Shown in the text report only.
	WaiverEnded string `json:"-"`
	// UserIgnored lists findings the person at the machine marked as not
	// sensitive (`bordercheck ignore`): they do not count toward the status.
	// Unlike Evidence it is always sent, so IT can see what was set aside.
	// Never holds a value.
	UserIgnored []Ignored `json:"user_ignored,omitempty"`
	// LikelySamples lists findings set aside as sample keys (see samples.go).
	// Always sent, like UserIgnored; never holds a value.
	LikelySamples []LikelySample `json:"likely_samples,omitempty"`
	// Compromise lists signs that hostile code is, or very probably is,
	// already on this computer, as opposed to a door merely being open. Only
	// a few findings set it, where the finding is made (see Indicator); a
	// result that is not a fail never carries it into a report.
	Compromise []Indicator `json:"compromise,omitempty"`
	// Aliases are older check IDs the same finding was reported under, e.g.
	// "tailscale" for a mesh-vpn result whose only finding is Tailscale's.
	// Waivers and remembered notifications written for an old ID still apply.
	// Kept in memory only.
	Aliases []string `json:"-"`
}

// Indicator is one sign of compromise: what was found, as a message part so
// it can be shown translated, and which item, by name or path only. Detail is
// evidence: it is dropped from a report when the policy leaves evidence out.
type Indicator struct {
	What   msg.Part `json:"what"`
	Detail string   `json:"detail,omitempty"`
}

// Line is the indicator in English: "what (detail)".
func (i Indicator) Line() string {
	if i.Detail == "" {
		return i.What.English()
	}
	return i.What.English() + " (" + i.Detail + ")"
}

// Ignored is one finding the person at the machine set aside, with their reason.
type Ignored struct {
	Path   string `json:"path"`
	Name   string `json:"name,omitempty"` // the variable name, if the finding has one
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	Since  string `json:"since,omitempty"` // YYYY-MM-DD
}

// Waiver says until when, and why, a result is waived.
type Waiver struct {
	Until  string `json:"until"` // YYYY-MM-DD, the last day the waiver applies
	Reason string `json:"reason"`
}

// Check is one thing bordercheck looks at. Run only reads; it never changes the machine.
type Check struct {
	ID    string
	Title string
	Run   func(ctx context.Context) Result
}

// WithSummary sets the summary from parts, in English and as parts.
func (r Result) WithSummary(t msg.Text) Result {
	r.SummaryParts, r.Summary = t, t.English()
	if len(t) == 0 {
		r.SummaryParts = nil
	}
	return r
}

// WithFix sets the fix from parts, in English and as parts.
func (r Result) WithFix(t msg.Text) Result {
	r.FixParts, r.Fix = t, t.English()
	if len(t) == 0 {
		r.FixParts = nil
	}
	return r
}

// Consistent drops parts whose English no longer matches the text, so a
// summary or fix edited without its parts is never shown translated as
// something else.
func (r Result) Consistent() Result {
	if r.SummaryParts != nil && r.SummaryParts.English() != r.Summary {
		r.SummaryParts = nil
	}
	if r.FixParts != nil && r.FixParts.English() != r.Fix {
		r.FixParts = nil
	}
	return r
}

// Skipped is a skip whose summary is free text, shown in English everywhere.
func Skipped(summary string) Result { return Result{Status: Skip, Summary: summary} }

// SkippedMsg is a skip whose summary is a message.
func SkippedMsg(t msg.Text) Result { return Result{Status: Skip}.WithSummary(t) }

// Errored reports an error; a msg.Error keeps its parts.
func Errored(err error) Result {
	var m msg.Error
	if errors.As(err, &m) && err.Error() == m.Error() {
		return Result{Status: Error}.WithSummary(msg.Text{m.Part})
	}
	return Result{Status: Error, Summary: err.Error()}
}

// Timeout is how long RunAll waits for the checks. One that is still running
// then (a folder that never answers, a command that hangs) reports an error
// instead of holding up the others and whoever is waiting for the report.
var Timeout = 90 * time.Second

// Progress is called when the checks start and each time one finishes, with how
// many are done and the IDs of those still running, in report order.
type Progress func(done, total int, running []string)

// RunAll runs the checks concurrently and returns their results in the same order.
func RunAll(ctx context.Context, checks []Check) []Result { return RunAllProgress(ctx, checks, nil) }

// RunAllProgress is RunAll that reports how far it is.
func RunAllProgress(ctx context.Context, checks []Check, progress Progress) []Result {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	type finished struct {
		i int
		r Result
	}
	// Buffered, so a check that outlives the time limit can still finish and go away.
	ch := make(chan finished, len(checks))
	pending := make([]bool, len(checks))
	for i, c := range checks {
		pending[i] = true
		go func() { ch <- finished{i, run(ctx, c)} }()
	}
	results := make([]Result, len(checks))
	left := len(checks)
	tell := func() {
		if progress == nil {
			return
		}
		var running []string
		for i, p := range pending {
			if p {
				running = append(running, checks[i].ID)
			}
		}
		progress(len(checks)-left, len(checks), running)
	}
	take := func(f finished) {
		results[f.i], pending[f.i] = f.r, false
		left--
		tell()
	}
	tell()
	for left > 0 {
		select {
		case f := <-ch:
			take(f)
			continue
		case <-ctx.Done():
		}
		// Time is up, or the run was interrupted: keep what has finished, mark the rest.
		for drained := false; !drained; {
			select {
			case f := <-ch:
				take(f)
			default:
				drained = true
			}
		}
		why := msg.Of("check.timeout", "after", int(Timeout.Seconds()))
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			why = msg.Of("check.interrupted")
		}
		for i, p := range pending {
			if p {
				results[i] = Result{ID: checks[i].ID, Title: checks[i].Title, Status: Error}.WithSummary(why)
			}
		}
		break
	}
	return results
}

func run(ctx context.Context, c Check) (r Result) {
	defer func() {
		if p := recover(); p != nil {
			r = Errored(fmt.Errorf("panic: %v", p))
		}
		r.ID, r.Title = c.ID, c.Title
	}()
	return c.Run(ctx)
}
