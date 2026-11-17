// Package sysx runs the system commands the checks read from.
package sysx

import (
	"bytes"
	"context"
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

// Run runs name with args and returns its stdout. On failure the error carries
// the first line of stderr.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	return RunFor(ctx, timeout, name, args...)
}

// RunFor is Run with its own time limit, for a command known to be slow.
func RunFor(ctx context.Context, limit time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return stdout.String(), fmt.Errorf("%s: no answer within %d seconds", filepath.Base(name), int(limit.Seconds()))
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
