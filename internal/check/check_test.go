package check

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRunAllStopsWaitingForAStuckCheck(t *testing.T) {
	old := Timeout
	Timeout = 150 * time.Millisecond
	t.Cleanup(func() { Timeout = old })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	checks := []Check{
		{ID: "quick", Title: "Quick", Run: func(context.Context) Result { return Result{Status: Pass} }},
		// Like a folder that never answers: it ignores the context.
		{ID: "stuck", Title: "Stuck", Run: func(context.Context) Result { <-release; return Result{Status: Pass} }},
		{ID: "fails", Title: "Fails", Run: func(context.Context) Result { return Result{Status: Fail, Severity: High} }},
	}
	var seen [][]string
	start := time.Now()
	got := RunAllProgress(context.Background(), checks, func(done, total int, running []string) {
		if total != 3 || done+len(running) != 3 {
			t.Errorf("progress %d of %d, running %v", done, total, running)
		}
		seen = append(seen, slices.Clone(running))
	})
	if time.Since(start) > 2*time.Second {
		t.Fatalf("waited %s for a stuck check", time.Since(start))
	}
	if got[0].Status != Pass || got[2].Status != Fail || got[2].ID != "fails" {
		t.Errorf("finished checks: %+v", got)
	}
	if got[1].Status != Error || got[1].ID != "stuck" || got[1].Title != "Stuck" || !strings.Contains(got[1].Summary, "Did not finish") {
		t.Errorf("stuck check: %+v", got[1])
	}
	// Told at the start (all three running) and after each one that finished.
	if len(seen) != 3 || len(seen[0]) != 3 || !slices.Equal(seen[2], []string{"stuck"}) {
		t.Errorf("progress calls: %v", seen)
	}
}

func TestRunAllInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	checks := []Check{{ID: "slow", Run: func(context.Context) Result { cancel(); <-release; return Result{} }}}
	if got := RunAll(ctx, checks); got[0].Status != Error || !strings.Contains(got[0].Summary, "Interrupted") {
		t.Errorf("got %+v", got[0])
	}
}
