package checks

import (
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
)

// The built-in firewalls of macOS and (by default) Windows only filter
// incoming connections. An outbound firewall decides which apps may connect
// out, which is how malware phones home and how data leaves. When none is
// found, the firewall check suggests a free one.

// outboundAdvice is what the suggestion says on one OS.
type outboundAdvice struct {
	examples string // "such as …" in the summary
	fix      string
}

// outboundApps are the macOS outbound firewalls bordercheck recognises, by
// their app bundle in /Applications or ~/Applications.
var outboundApps = []string{"LuLu", "Little Snitch", "Radio Silence", "Vallum"}

var outboundMac = outboundAdvice{examples: "LuLu or Little Snitch",
	fix: "Install a free outbound firewall such as LuLu from Objective-See " +
		"(https://objective-see.org/products/lulu.html, open source): it asks before an app connects out, " +
		"so malware phoning home or a program sending your data somewhere shows up."}

var outboundWin = outboundAdvice{examples: "simplewall, or Windows Firewall blocking outgoing connections by default",
	fix: "Install simplewall (https://github.com/henrypp/simplewall, free and open source). Once its filters " +
		"are enabled it blocks every app you have not allowed, so it will ask you to allow each app the first " +
		"time it connects; then malware phoning home or a program sending your data somewhere shows up. " +
		"Or ask IT to set Windows Firewall to block outgoing connections by default."}

// withOutbound adds the outbound-firewall suggestion to a firewall result when
// found is empty. A passing firewall becomes a low-severity warn; a warn gains
// the advice; a fail is left alone, since turning the firewall on comes first.
// When something was found, a pass names it and nothing is suggested.
func withOutbound(r check.Result, found []string, adv outboundAdvice) check.Result {
	if len(found) > 0 {
		if r.Status == check.Pass {
			r.Summary = strings.TrimSuffix(r.Summary, ".") + "; outgoing connections are filtered by " +
				strings.Join(found, ", ") + "."
		}
		return r
	}
	none := "no outbound firewall (such as " + adv.examples + ") controls which apps connect out."
	switch r.Status {
	case check.Pass:
		r.Status, r.Severity = check.Warn, check.Low
		r.Summary = strings.TrimSuffix(r.Summary, ".") + ", but " + none
		r.Fix = adv.fix
	case check.Warn:
		r.Summary += " Also, " + none
		r.Fix += " " + adv.fix
	}
	return r
}

// winOutboundApps are the Windows outbound firewalls bordercheck recognises,
// with the names they go by in each place it looks. Display names are
// matched as prefixes of uninstall entries; folders (below %ProgramFiles%,
// %ProgramFiles(x86)% or %ProgramData%), services and processes exactly,
// ignoring case.
var winOutboundApps = []struct {
	name     string
	display  []string // uninstall entry DisplayName prefixes
	folders  []string
	services []string
	procs    []string
}{
	{name: "simplewall", display: []string{"simplewall"}, folders: []string{"simplewall"}, procs: []string{"simplewall"}},
	{name: "Fort Firewall", display: []string{"Fort Firewall"}, folders: []string{"Fort Firewall", "FortFirewall"},
		services: []string{"FortFirewallSvc"}},
	{name: "Portmaster", display: []string{"Portmaster"}, folders: []string{"Portmaster", `Safing\Portmaster`},
		services: []string{"PortmasterCore"}},
	{name: "TinyWall", display: []string{"TinyWall"}, folders: []string{"TinyWall"}, services: []string{"TinyWall"}},
	{name: "Windows Firewall Control", display: []string{"Windows Firewall Control"},
		folders: []string{"Windows Firewall Control", `Malwarebytes\Windows Firewall Control`}},
}

// winOutboundFacts is what the Windows script and folder probe report.
type winOutboundFacts struct {
	Profiles map[string]string // firewall profile → DefaultOutboundAction from Get-NetFirewallProfile
	GPO      map[string]string // firewall profile → DefaultOutboundAction set by Group Policy ("0" allow, "1" block)
	Active   []string          // NetworkCategory of each connected network
	Lines    map[string][]string
	Folders  []string // winOutboundApps folders that exist, as given there
}

// parseWinOutbound reads winOutboundScript's "key=value" lines.
func parseWinOutbound(out string) winOutboundFacts {
	f := winOutboundFacts{Profiles: map[string]string{}, GPO: map[string]string{}, Lines: map[string][]string{}}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || v == "" {
			continue
		}
		switch k {
		case "profile", "gpo":
			name, action, _ := strings.Cut(v, "|")
			if k == "profile" {
				f.Profiles[name] = action
			} else if action != "" {
				f.GPO[name] = action
			}
		case "active":
			f.Active = append(f.Active, v)
		default:
			f.Lines[k] = append(f.Lines[k], v)
		}
	}
	return f
}

// winOutboundBlocked reports whether Windows Firewall blocks outgoing
// connections by default on every profile in use: the connected networks'
// profiles, or all three when none is connected. Group Policy wins over the
// local setting.
func winOutboundBlocked(f winOutboundFacts) bool {
	var profiles []string
	for _, c := range f.Active {
		switch strings.ToLower(c) {
		case "domainauthenticated", "domain":
			profiles = append(profiles, "Domain")
		case "private":
			profiles = append(profiles, "Private")
		case "public":
			profiles = append(profiles, "Public")
		}
	}
	if len(profiles) == 0 {
		profiles = []string{"Domain", "Private", "Public"}
	}
	for _, p := range profiles {
		switch g := f.GPO[p]; {
		case g == "1":
			continue
		case g != "":
			return false
		case !strings.EqualFold(f.Profiles[p], "Block"):
			return false
		}
	}
	return true
}

// evalWinOutbound names the outbound firewalls found on a Windows machine.
func evalWinOutbound(f winOutboundFacts) []string {
	var found []string
	has := func(list []string, want []string, prefix bool) bool {
		for _, v := range list {
			for _, w := range want {
				if strings.EqualFold(v, w) || (prefix && len(v) >= len(w) && strings.EqualFold(v[:len(w)], w)) {
					return true
				}
			}
		}
		return false
	}
	for _, a := range winOutboundApps {
		if has(f.Lines["installed"], a.display, true) || has(f.Folders, a.folders, false) ||
			has(f.Lines["service"], a.services, false) || has(f.Lines["process"], a.procs, false) {
			found = append(found, a.name)
		}
	}
	if len(f.Profiles)+len(f.GPO) > 0 && winOutboundBlocked(f) {
		found = append(found, "Windows Firewall (blocks outgoing connections by default)")
	}
	return found
}
