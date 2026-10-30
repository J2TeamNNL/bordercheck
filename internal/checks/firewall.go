package checks

import (
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
)

var fwStateRe = regexp.MustCompile(`State = (\d)`)

// evalMacFirewall judges `socketfilterfw --getglobalstate` and `--getstealthmode`.
func evalMacFirewall(global, stealth string, requireStealth bool) check.Result {
	on := strings.Contains(global, "enabled")
	if m := fwStateRe.FindStringSubmatch(global); m != nil {
		on = m[1] != "0" // 1 = on, 2 = block all
	}
	if !on {
		return check.Result{Status: check.Fail, Severity: check.High,
			Summary: "The macOS firewall is off.",
			Fix: "System Settings → Network → Firewall → turn it on. " +
				"Or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"}
	}
	s := strings.ToLower(strings.TrimSpace(stealth))
	if requireStealth && !strings.Contains(s, "enabled") && !strings.HasSuffix(s, " on") {
		return check.Result{Status: check.Warn, Severity: check.Low,
			Summary: "The firewall is on, but stealth mode is off: this Mac answers probes from the network.",
			Fix: "System Settings → Network → Firewall → Options → turn on stealth mode. " +
				"Or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"}
	}
	if !requireStealth {
		return check.Result{Status: check.Pass, Summary: "Firewall is on."}
	}
	return check.Result{Status: check.Pass, Summary: "Firewall and stealth mode are on."}
}

// parseWinFirewall reads lines of "Profile=True|False".
func parseWinFirewall(out string) map[string]bool {
	profiles := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		name, on, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && name != "" {
			profiles[name] = strings.EqualFold(on, "True")
		}
	}
	return profiles
}

func evalWinFirewall(profiles map[string]bool) check.Result {
	if len(profiles) == 0 {
		return check.Errored(errors.New("Windows reported no firewall profiles"))
	}
	var off []string
	for name, on := range profiles {
		if !on {
			off = append(off, name)
		}
	}
	if len(off) == 0 {
		return check.Result{Status: check.Pass, Summary: "Windows Firewall is on for every profile."}
	}
	sort.Strings(off)
	return check.Result{Status: check.Fail, Severity: check.High,
		Summary: "Windows Firewall is off for: " + strings.Join(off, ", ") + ".",
		Fix: "Windows Security → Firewall & network protection → turn it on for every network. " +
			"Or, as administrator: Set-NetFirewallProfile -All -Enabled True"}
}
