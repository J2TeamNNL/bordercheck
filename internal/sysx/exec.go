// Package sysx runs the system commands the checks read from.
package sysx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const timeout = 20 * time.Second

// retryPause is how long a command that gave no answer waits before its one
// retry. A Mac waking from sleep can stall every directory lookup (id,
// fdesetup, ps) for a while; a few seconds later they answer at once.
var retryPause = 3 * time.Second

// ErrNoAnswer is wrapped by the error of a command that ran out of time, so a
// check can tell "it did not answer" (unknown) from "it said no".
var ErrNoAnswer = errors.New("no answer")

type noAnswer struct {
	name  string
	limit time.Duration
}

func (e noAnswer) Error() string {
	return fmt.Sprintf("%s: no answer within %d seconds", e.name, int(e.limit.Seconds()))
}
func (e noAnswer) Unwrap() error { return ErrNoAnswer }

// NoAnswer reports whether err is, or wraps, a command that ran out of time.
func NoAnswer(err error) bool { return errors.Is(err, ErrNoAnswer) }

// Run runs name with args and returns its stdout. On failure the error carries
// the first line of stderr.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	return RunFor(ctx, timeout, name, args...)
}

// RunFor is Run with its own time limit, for a command known to be slow. A
// command that gives no answer in time is run once more after a short pause,
// if the caller's own deadline leaves room for a full second try.
func RunFor(ctx context.Context, limit time.Duration, name string, args ...string) (string, error) {
	out, err := runOnce(ctx, limit, name, args...)
	if !NoAnswer(err) || !roomFor(ctx, retryPause+limit) {
		return out, err
	}
	select {
	case <-ctx.Done():
		return out, err
	case <-time.After(retryPause):
	}
	return runOnce(ctx, limit, name, args...)
}

// roomFor is whether ctx is alive and its deadline, if any, is at least d away.
func roomFor(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	dl, ok := ctx.Deadline()
	return !ok || time.Until(dl) >= d
}

func runOnce(parent context.Context, limit time.Duration, name string, args ...string) (string, error) {
	// ownLimit: the time limit that can stop it is this command's, not the caller's.
	pdl, has := parent.Deadline()
	ownLimit := !has || pdl.After(time.Now().Add(limit))
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// A child the command started can keep its output open after the command
	// is killed; stop waiting for it soon after.
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded && ownLimit {
			return stdout.String(), noAnswer{filepath.Base(name), limit}
		}
		if msg := firstLine(stderr.String()); msg != "" {
			return stdout.String(), fmt.Errorf("%s: %s", filepath.Base(name), msg)
		}
		return stdout.String(), fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return stdout.String(), nil
}

// firstLine is the first non-empty line of a command's stderr. PowerShell
// writes its stderr as CLIXML ("#< CLIXML" then XML) when stderr is not a
// console; that is read for its error lines, and progress records are skipped.
func firstLine(stderr string) string {
	if rest, ok := strings.CutPrefix(strings.TrimSpace(stderr), "#< CLIXML"); ok {
		stderr = clixmlErrors(rest)
	}
	for _, l := range strings.Split(stderr, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

var (
	clixmlError  = regexp.MustCompile(`<S S="Error">([^<]*)</S>`)
	clixmlEscape = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)
)

// clixmlErrors returns the text of the error records in PowerShell's CLIXML.
func clixmlErrors(x string) string {
	var b strings.Builder
	for _, m := range clixmlError.FindAllStringSubmatch(x, -1) {
		b.WriteString(html.UnescapeString(m[1]))
	}
	return clixmlEscape.ReplaceAllStringFunc(b.String(), func(e string) string {
		n, err := strconv.ParseUint(e[2:6], 16, 16)
		if err != nil {
			return e
		}
		return string(rune(n))
	})
}

// progressOff stops PowerShell's progress records ("Preparing modules for
// first use"), which cost time and fill stderr when nobody watches.
const progressOff = "$ProgressPreference = 'SilentlyContinue'\n"

// PowerShell runs a Windows PowerShell script and returns its stdout.
func PowerShell(ctx context.Context, script string) (string, error) {
	return Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ProgressPreference = 'SilentlyContinue'; "+script)
}

// Find returns name as found in PATH, or else the first fallback path that exists.
func Find(name string, fallbacks ...string) (string, bool) {
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	for _, p := range fallbacks {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}
