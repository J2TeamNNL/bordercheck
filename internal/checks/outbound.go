package checks

import (
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
)

// The built-in macOS firewall only filters incoming connections. An outbound
// firewall asks before an app connects out, which is how malware phones home
// and how data leaves. outboundApps are the ones bordercheck recognises, by
// their app bundle in /Applications or ~/Applications.
var outboundApps = []string{"LuLu", "Little Snitch", "Radio Silence", "Vallum"}

const outboundFix = "Install a free outbound firewall such as LuLu from Objective-See " +
	"(https://objective-see.org/products/lulu.html, open source): it asks before an app connects out, " +
	"so malware phoning home or a program sending your data somewhere shows up."

// withOutbound adds the outbound-firewall suggestion to a macOS firewall
// result when none of outboundApps is installed. A passing firewall becomes a
// low-severity warn; a warn gains the advice; a fail is left alone, since
// turning the firewall on comes first.
func withOutbound(r check.Result, found []string) check.Result {
	if len(found) > 0 {
		if r.Status == check.Pass {
			r.Summary = strings.TrimSuffix(r.Summary, ".") + "; outgoing connections are filtered by " +
				strings.Join(found, ", ") + "."
		}
		return r
	}
	const none = "no outbound firewall (such as LuLu or Little Snitch) controls which apps connect out."
	switch r.Status {
	case check.Pass:
		r.Status, r.Severity = check.Warn, check.Low
		r.Summary = strings.TrimSuffix(r.Summary, ".") + ", but " + none
		r.Fix = outboundFix
	case check.Warn:
		r.Summary += " Also, " + none
		r.Fix += " " + outboundFix
	}
	return r
}
