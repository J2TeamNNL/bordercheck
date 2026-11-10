package checks

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
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
		return check.Skipped("Tailscale is not installed.")
	}
	out, err := sysx.Run(ctx, bin, "debug", "prefs")
	if err != nil && runtime.GOOS == "linux" && strings.Contains(strings.ToLower(err.Error()), "denied") {
		return check.Skipped("Only root or the Tailscale operator may read Tailscale's settings here. Run " +
			"sudo tailscale set --operator=$USER once, or sudo bordercheck -only tailscale. (" + err.Error() + ")")
	}
	if err != nil {
		return check.Skipped("Could not read Tailscale settings; is Tailscale running? (" + err.Error() + ")")
	}
	return evalTailscalePrefs(out)
}

// evalTailscalePrefs judges `tailscale debug prefs`. ShieldsUp is the inverse of
// "Allow incoming connections" in the app.
func evalTailscalePrefs(out string) check.Result {
	var p struct{ ShieldsUp *bool }
	if err := json.Unmarshal([]byte(out), &p); err != nil || p.ShieldsUp == nil {
		return check.Errored(errors.New("unexpected output from `tailscale debug prefs`"))
	}
	if *p.ShieldsUp {
		return check.Result{Status: check.Pass,
			Summary: "Shields up: other devices on the tailnet cannot open connections to this machine."}
	}
	return check.Result{Status: check.Fail, Severity: check.High,
		Summary: "Tailscale accepts incoming connections. Tailscale traffic may bypass the OS firewall, so any " +
			"device on the tailnet, including a hacked one, can reach every port this machine listens on.",
		Fix: "Tailscale → Settings → untick \"Allow incoming connections\". Or: tailscale set --shields-up. " +
			"Admins: also limit who can reach whom with tailnet ACLs."}
}
