package checks

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

func tailscale(ctx context.Context) check.Result {
	var fallbacks []string
	switch runtime.GOOS {
	case "darwin":
		fallbacks = []string{"/Applications/Tailscale.app/Contents/MacOS/Tailscale"}
	case "windows":
		fallbacks = []string{`C:\Program Files\Tailscale\tailscale.exe`}
	case "linux": // the service's PATH may lack sbin or snap
		fallbacks = []string{"/usr/bin/tailscale", "/usr/sbin/tailscale", "/usr/local/bin/tailscale", "/snap/bin/tailscale"}
	}
	bin, ok := sysx.Find("tailscale", fallbacks...)
	if !ok {
		return check.SkippedMsg(msg.Of("tailscale.notInstalled"))
	}
	if runtime.GOOS == "darwin" {
		// The app's CLI can sit without answering when Tailscale is not
		// running; nothing comes in through a Tailscale that is not running.
		if procs, err := listProcs(ctx); err == nil && !tailscaleRunningMac(procs) {
			return check.SkippedMsg(msg.Of("tailscale.notRunning"))
		}
	}
	out, err := sysx.Run(ctx, bin, "debug", "prefs")
	if sysx.NoAnswer(err) {
		return check.Errored(err) // running, but its settings could not be read
	}
	if err != nil && runtime.GOOS == "linux" && strings.Contains(strings.ToLower(err.Error()), "denied") {
		return check.SkippedMsg(msg.Of("tailscale.denied", "err", err.Error()))
	}
	if err != nil {
		return check.SkippedMsg(msg.Of("tailscale.unreadable", "err", err.Error()))
	}
	return evalTailscalePrefs(out)
}

// tailscaleRunningMac is whether any part of Tailscale runs: the app, its
// network extension (standalone or App Store) or the open-source tailscaled.
func tailscaleRunningMac(procs []proc) bool {
	for _, p := range procs {
		switch filepath.Base(p.exe) {
		case "Tailscale", "IPNExtension", "tailscaled",
			"io.tailscale.ipn.macsys.network-extension", "io.tailscale.ipn.macos.network-extension":
			return true
		}
	}
	return false
}

// evalTailscalePrefs judges `tailscale debug prefs`. ShieldsUp is the inverse of
// "Allow incoming connections" in the app.
func evalTailscalePrefs(out string) check.Result {
	var p struct{ ShieldsUp *bool }
	if err := json.Unmarshal([]byte(out), &p); err != nil || p.ShieldsUp == nil {
		return check.Errored(msg.Err("tailscale.badPrefs"))
	}
	if *p.ShieldsUp {
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("tailscale.shieldsUp"))
	}
	return check.Result{Status: check.Fail, Severity: check.High}.
		WithSummary(msg.Of("tailscale.open")).WithFix(msg.Of("tailscale.open.fix"))
}
