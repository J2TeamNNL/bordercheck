// Package check defines a check and the result it reports.
package check

import (
	"context"
	"fmt"
	"sync"
)

// Status is the outcome of one check.
type Status string

const (
	Pass  Status = "pass"
	Warn  Status = "warn"
	Fail  Status = "fail"
	Skip  Status = "skip"  // does not apply here, e.g. the software is not installed
	Error Status = "error" // could not tell
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
}

// Check is one thing bordercheck looks at. Run only reads; it never changes the machine.
type Check struct {
	ID    string
	Title string
	Run   func(ctx context.Context) Result
}

func Skipped(summary string) Result { return Result{Status: Skip, Summary: summary} }

func Errored(err error) Result { return Result{Status: Error, Summary: err.Error()} }

// RunAll runs the checks concurrently and returns their results in the same order.
func RunAll(ctx context.Context, checks []Check) []Result {
	results := make([]Result, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = run(ctx, c)
		}()
	}
	wg.Wait()
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
