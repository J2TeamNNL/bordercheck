// Package sysx runs the system commands the checks read from.
package sysx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const timeout = 20 * time.Second

// Run runs name with args and returns its stdout. On failure the error carries
// the first line of stderr.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if msg, _, _ := strings.Cut(strings.TrimSpace(stderr.String()), "\n"); msg != "" {
			return stdout.String(), fmt.Errorf("%s: %s", filepath.Base(name), msg)
		}
		return stdout.String(), fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return stdout.String(), nil
}

// PowerShell runs a Windows PowerShell script and returns its stdout.
func PowerShell(ctx context.Context, script string) (string, error) {
	return Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
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
