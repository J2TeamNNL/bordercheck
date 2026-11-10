// Package check defines a check and the result it reports.
package check

import (
	"context"
	"errors"
	"fmt"
	"time"
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
	// Waived is set when Status is Waived.
	Waived *Waiver `json:"waived,omitempty"`
	// WaiverEnded is the end date (YYYY-MM-DD) of a waiver that matched this
	// fail or warn but has expired. Shown in the text report only.
	WaiverEnded string `json:"-"`
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

func Skipped(summary string) Result { return Result{Status: Skip, Summary: summary} }

func Errored(err error) Result { return Result{Status: Error, Summary: err.Error()} }

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
		why := fmt.Sprintf("Did not finish within %s and was stopped; the other checks are unaffected.", Timeout)
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			why = "Interrupted before it finished."
		}
		for i, p := range pending {
			if p {
				results[i] = Result{ID: checks[i].ID, Title: checks[i].Title, Status: Error, Summary: why}
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
