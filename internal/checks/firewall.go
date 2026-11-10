package checks

import (
	"regexp"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
)

var fwStateRe = regexp.MustCompile(`State = (\d)`)

// evalMacFirewall judges `socketfilterfw --getglobalstate` and `--getstealthmode`.
func evalMacFirewall(global, stealth string, requireStealth bool) check.Result {
	on := strings.Contains(global, "enabled")
	if m := fwStateRe.FindStringSubmatch(global); m != nil {
		on = m[1] != "0" // 1 = on, 2 = block all
	}
	if !on {
		return check.Result{Status: check.Fail, Severity: check.High}.
			WithSummary(msg.Of("firewall.mac.off")).WithFix(msg.Of("firewall.mac.off.fix"))
	}
	s := strings.ToLower(strings.TrimSpace(stealth))
	if requireStealth && !strings.Contains(s, "enabled") && !strings.HasSuffix(s, " on") {
		return check.Result{Status: check.Warn, Severity: check.Low}.
			WithSummary(msg.Of("firewall.mac.stealthOff")).WithFix(msg.Of("firewall.mac.stealthOff.fix"))
	}
	if !requireStealth {
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("firewall.mac.on"))
	}
	return check.Result{Status: check.Pass}.WithSummary(msg.Of("firewall.mac.onStealth"))
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
		return check.Errored(msg.Err("firewall.win.noProfiles"))
	}
	var off []string
	for name, on := range profiles {
		if !on {
			off = append(off, name)
		}
	}
	if len(off) == 0 {
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("firewall.win.on"))
	}
	sort.Strings(off)
	return check.Result{Status: check.Fail, Severity: check.High}.
		WithSummary(msg.Of("firewall.win.off", "profiles", strings.Join(off, ", "))).
		WithFix(msg.Of("firewall.win.off.fix"))
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
	"FedoraWorkstation": "firewall.linux.zoneOpenPorts",
	"trusted":           "firewall.linux.zoneTrusted",
}

var linuxFirewallFix = msg.Of("firewall.linux.fix")

// evalLinuxFirewall judges what linuxFirewall gathered. Without root it trusts
// configuration (ufw.conf, running services) and says so; it never guesses
// about rules it cannot read.
func evalLinuxFirewall(fw linuxFirewall) check.Result {
	if fw.Services["firewalld"] == "active" {
		if key, open := openFirewalldZones[fw.FirewalldZone]; open {
			return check.Result{Status: check.Warn, Severity: check.Medium}.
				WithSummary(msg.Of(key, "zone", fw.FirewalldZone)).WithFix(msg.Of("firewall.linux.zone.fix"))
		}
		s := msg.Of("firewall.linux.firewalldOn")
		if fw.FirewalldZone != "" {
			s = msg.Of("firewall.linux.firewalldOnZone", "zone", fw.FirewalldZone)
		}
		return check.Result{Status: check.Pass}.WithSummary(s)
	}

	ufwOn, ufwKnown := false, false
	if fw.Root && fw.UFWStatus != "" {
		ufwOn, ufwKnown = strings.Contains(fw.UFWStatus, "Status: active"), true
	} else if m := ufwEnabledRe.FindStringSubmatch(fw.UFWConf); m != nil {
		ufwOn, ufwKnown = strings.EqualFold(m[1], "yes"), true
	}
	if ufwOn {
		s := msg.Of("firewall.linux.ufwOn")
		if !fw.Root {
			s = msg.Of("firewall.linux.ufwOnConf")
		}
		return check.Result{Status: check.Pass}.WithSummary(s)
	}

	if fw.Root {
		if nftInputDrops(fw.Nft) || iptablesInputDrops(fw.Iptables) {
			return check.Result{Status: check.Pass}.WithSummary(msg.Of("firewall.linux.inputDrops"))
		}
		return check.Result{Status: check.Fail, Severity: check.High}.
			WithSummary(msg.Of("firewall.linux.noDrop")).WithFix(linuxFirewallFix)
	}

	var loaders []string
	for _, unit := range linuxFirewallServices[1:] {
		if fw.Services[unit] == "active" {
			loaders = append(loaders, unit)
		}
	}
	if len(loaders) > 0 {
		return check.SkippedMsg(msg.Of("firewall.linux.rootOnly", "services", strings.Join(loaders, ", ")))
	}
	if fw.Services["firewalld"] == "" && !ufwKnown {
		return check.SkippedMsg(msg.Of("firewall.linux.unknown"))
	}
	s := msg.Of("firewall.linux.noneNoUfw")
	if fw.UFW {
		s = msg.Of("firewall.linux.noneUfwOff")
	}
	return check.Result{Status: check.Fail, Severity: check.High}.WithSummary(s).WithFix(linuxFirewallFix)
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
