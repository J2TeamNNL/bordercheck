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

// The services that load firewall rules on Linux, in the order they are judged.
var linuxFirewallServices = []string{"firewalld", "nftables", "netfilter-persistent", "iptables"}

// linuxFirewall is what Linux shows about its firewall. Without root that is
// the configuration and which services are running, not the live rules.
type linuxFirewall struct {
	Root          bool
	UFW           bool              // ufw is installed
	UFWConf       string            // /etc/ufw/ufw.conf
	UFWStatus     string            // `ufw status`, root only
	Services      map[string]string // `systemctl is-active` per linuxFirewallServices; "" = unknown
	FirewalldZone string            // `firewall-cmd --get-default-zone`
	Nft           string            // `nft list ruleset`, root only
	Iptables      string            // `iptables -S INPUT`, root only
}

// Zones whose defaults let the network in. Fedora Workstation's own zone opens
// every port from 1025 up, so apps that listen on all interfaces are reachable.
var openFirewalldZones = map[string]string{
	"FedoraWorkstation": "lets in every port from 1025 to 65535",
	"trusted":           "lets everything in",
}

const linuxFirewallFix = "Ubuntu/Debian: sudo ufw enable (it blocks incoming connections and allows outgoing). " +
	"Fedora/RHEL/openSUSE: sudo systemctl enable --now firewalld."

// evalLinuxFirewall judges what linuxFirewall gathered. Without root it trusts
// configuration (ufw.conf, running services) and says so; it never guesses
// about rules it cannot read.
func evalLinuxFirewall(fw linuxFirewall) check.Result {
	if fw.Services["firewalld"] == "active" {
		if why, open := openFirewalldZones[fw.FirewalldZone]; open {
			return check.Result{Status: check.Warn, Severity: check.Medium,
				Summary: "firewalld is on, but its default zone " + fw.FirewalldZone + " " + why + ".",
				Fix:     "sudo firewall-cmd --set-default-zone=public (allows SSH and DHCPv6 only); open what you need with --add-service."}
		}
		s := "firewalld is on."
		if fw.FirewalldZone != "" {
			s = "firewalld is on (default zone " + fw.FirewalldZone + ")."
		}
		return check.Result{Status: check.Pass, Summary: s}
	}

	ufwOn, ufwKnown := false, false
	if fw.Root && fw.UFWStatus != "" {
		ufwOn, ufwKnown = strings.Contains(fw.UFWStatus, "Status: active"), true
	} else if m := ufwEnabledRe.FindStringSubmatch(fw.UFWConf); m != nil {
		ufwOn, ufwKnown = strings.EqualFold(m[1], "yes"), true
	}
	if ufwOn {
		s := "ufw is on."
		if !fw.Root {
			s = "ufw is on (enabled in /etc/ufw/ufw.conf)."
		}
		return check.Result{Status: check.Pass, Summary: s}
	}

	if fw.Root {
		if nftInputDrops(fw.Nft) || iptablesInputDrops(fw.Iptables) {
			return check.Result{Status: check.Pass, Summary: "The firewall drops incoming connections by default (input policy)."}
		}
		return check.Result{Status: check.Fail, Severity: check.High,
			Summary: "No firewall drops incoming connections: no nftables or iptables input chain defaults to drop.",
			Fix:     linuxFirewallFix}
	}

	var loaders []string
	for _, unit := range linuxFirewallServices[1:] {
		if fw.Services[unit] == "active" {
			loaders = append(loaders, unit)
		}
	}
	if len(loaders) > 0 {
		return check.Skipped("The " + strings.Join(loaders, ", ") + " service loads firewall rules, but they can only be " +
			"read as root, so bordercheck cannot tell whether they block incoming connections. " +
			"Run sudo bordercheck -only firewall to check them.")
	}
	if fw.Services["firewalld"] == "" && !ufwKnown {
		return check.Skipped("Could not tell without root: there is no ufw configuration and systemd did not say which " +
			"firewall services run. Run sudo bordercheck -only firewall to check the rules.")
	}
	s := "No firewall is on: "
	if fw.UFW {
		s += "ufw is installed but off, "
	} else {
		s += "ufw is not installed, "
	}
	return check.Result{Status: check.Fail, Severity: check.High,
		Summary: s + "and no firewalld, nftables or iptables service is running. " +
			"(If you load rules some other way, sudo bordercheck -only firewall checks them.)",
		Fix: linuxFirewallFix}
}

var ufwEnabledRe = regexp.MustCompile(`(?m)^\s*ENABLED\s*=\s*"?(\w+)"?`)

// nftInputDrops reports whether `nft list ruleset` has an input hook whose policy is drop.
func nftInputDrops(ruleset string) bool {
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, "hook input") && strings.Contains(line, "policy drop") {
			return true
		}
	}
	return false
}

// iptablesInputDrops reports whether `iptables -S INPUT` drops what no rule accepts.
func iptablesInputDrops(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		switch f := strings.Fields(line); {
		case len(f) == 3 && f[0] == "-P" && f[1] == "INPUT" && (f[2] == "DROP" || f[2] == "REJECT"):
			return true
		case len(f) >= 4 && f[0] == "-A" && f[1] == "INPUT" && f[2] == "-j" &&
			(f[3] == "DROP" && len(f) == 4 || f[3] == "REJECT" && (len(f) == 4 || f[4] == "--reject-with")):
			return true // a catch-all rule, usually last in the chain
		}
	}
	return false
}
