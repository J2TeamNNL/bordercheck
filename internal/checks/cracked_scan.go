package checks

import (
	"regexp"
	"strings"
)

// crackTaskRe names the scheduled tasks closed-source activators add to keep
// re-activating: KMSpico and Microsoft Toolkit (AutoKMS), KMSAuto, AAct.
var crackTaskRe = regexp.MustCompile(`(?i)(kmspico|autokms|kmsauto|\baact)`)

// parseCrackScan reads winCrackScanScript's lines: outbound block rules on a
// known paid program, and the scheduled tasks of closed-source activators.
// Portable, so it is tested everywhere.
func parseCrackScan(out string) (rules []crackFirewall, tasks []string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		switch {
		case len(f) == 3 && f[0] == "fw":
			if v := crackFirewallVendor(f[2]); v != "" && !seen["fw"+f[2]] {
				seen["fw"+f[2]] = true
				rules = append(rules, crackFirewall{Vendor: v, Program: f[2], Rule: f[1]})
			}
		case len(f) == 2 && f[0] == "task":
			if crackTaskRe.MatchString(f[1]) && !seen["task"+f[1]] {
				seen["task"+f[1]] = true
				tasks = append(tasks, f[1])
			}
		}
	}
	return rules, tasks
}
