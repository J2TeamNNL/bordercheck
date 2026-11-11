package checks

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The sharing check looks at what the machine offers nearby devices and the
// local network: AirDrop, file, printer, media and Bluetooth sharing, Internet
// Sharing, content caching, Windows network discovery and Nearby sharing, Samba
// and NFS. Remote login, screen sharing, Remote Apple Events and guest
// accounts are remote-access's.

type shareService struct {
	ID   string // its name in the policy's allow list (policy.SharingServices)
	Name string // what the OS calls it
	On   bool
	How  string         // why it looks on, for the evidence
	Sev  check.Severity // how bad it is when on
	Open bool           // anyone on the network gets in without a password
	Fix  msg.Part
}

func sharing(opts policy.Sharing) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		svcs, notes, err := shareServicesOS(ctx)
		if errors.Is(err, errUnsupported) {
			return unsupported()
		}
		if err != nil {
			return check.Errored(err)
		}
		return evalSharing(svcs, notes, opts.Allow)
	}
}

func evalSharing(svcs []shareService, notes msg.Text, allow []string) check.Result {
	var problems, fixes msg.Text
	var evidence, off, allowed []string
	worst := check.Severity("")
	rank := map[check.Severity]int{check.Low: 1, check.Medium: 2, check.High: 3}
	for _, s := range svcs {
		if !s.On {
			off = append(off, s.Name)
			continue
		}
		line := s.Name
		if s.How != "" {
			line += ": " + s.How
		}
		if slices.Contains(allow, s.ID) {
			allowed = append(allowed, s.Name)
			evidence = append(evidence, line+" (allowed by policy)")
			continue
		}
		evidence = append(evidence, line)
		key := "sharing.on"
		if s.Open {
			key = "sharing.onOpen"
		}
		problems = append(problems, msg.Of(key, "service", s.Name)...)
		if s.Fix.Key != "" && !slices.ContainsFunc(fixes, func(f msg.Part) bool { return fmt.Sprint(f) == fmt.Sprint(s.Fix) }) {
			fixes = append(fixes, s.Fix)
		}
		if rank[s.Sev] > rank[worst] {
			worst = s.Sev
		}
	}
	if len(allowed) > 0 {
		notes = append(msg.Of("sharing.allowed", "services", strings.Join(allowed, ", ")), notes...)
	}
	if len(problems) == 0 {
		var pass msg.Text
		if len(off) > 0 {
			pass = msg.Of("sharing.off", "services", strings.Join(off, ", "))
		}
		return check.Result{Status: check.Pass, Evidence: evidence}.WithSummary(slices.Concat(pass, notes))
	}
	status := check.Warn
	if worst == check.High {
		status = check.Fail
	}
	return check.Result{Status: status, Severity: worst, Evidence: evidence}.
		WithSummary(slices.Concat(problems, notes)).WithFix(fixes)
}

// ---- macOS ----

// macShareFacts are the settings read on a Mac, each as the OS printed it ("" if unset):
// airdrop (sharingd DiscoverableMode), cups (`cupsctl` output), nat (NAT.Enabled
// in com.apple.nat), media_home and media_public (mediasharingd), bluetooth
// (PrefKeyServicesEnabled), assetcache (AssetCache Activated).
func macShareServices(f map[string]string, disabled, netstat string) []shareService {
	truthy := func(v string) bool { v = strings.TrimSpace(v); return v == "1" || v == "true" || v == "YES" }
	fix := func(name string) msg.Part { return msg.P("sharing.fix.macSharing", "service", name) }
	var out []shareService

	ad := shareService{ID: "airdrop", Name: "AirDrop (Everyone)", Sev: check.Medium, Fix: msg.P("sharing.fix.macAirDrop")}
	if strings.TrimSpace(f["airdrop"]) == "Everyone" {
		ad.On, ad.How = true, "discoverable by everyone nearby"
	}
	out = append(out, ad)

	smb := shareService{ID: "file-sharing", Name: "File Sharing", Sev: check.Medium, Fix: fix("File Sharing")}
	var how []string
	if parseLaunchctlDisabled(disabled)["com.apple.smbd"] {
		how = append(how, "enabled in launchd")
	}
	if openPorts(parseNetstatListen(netstat))[445] {
		how = append(how, "port 445 open")
	}
	smb.On, smb.How = len(how) > 0, strings.Join(how, ", ")
	out = append(out, smb)

	pr := shareService{ID: "printer-sharing", Name: "Printer Sharing", Sev: check.Medium, Fix: fix("Printer Sharing")}
	if cupsSharesPrinters(f["cups"]) {
		pr.On, pr.How = true, "_share_printers=1"
	}
	out = append(out, pr)

	is := shareService{ID: "internet-sharing", Name: "Internet Sharing", Sev: check.High, Fix: fix("Internet Sharing")}
	if truthy(f["nat"]) {
		is.On, is.How = true, "NAT enabled"
	}
	out = append(out, is)

	ms := shareService{ID: "media-sharing", Name: "Media Sharing", Sev: check.Low, Fix: fix("Media Sharing")}
	how = nil
	if truthy(f["media_public"]) {
		how = append(how, "shared with guests")
		ms.Sev = check.Medium
	}
	if truthy(f["media_home"]) {
		how = append(how, "Home Sharing")
	}
	ms.On, ms.How = len(how) > 0, strings.Join(how, ", ")
	out = append(out, ms)

	bt := shareService{ID: "bluetooth-sharing", Name: "Bluetooth Sharing", Sev: check.Medium, Fix: fix("Bluetooth Sharing")}
	if truthy(f["bluetooth"]) {
		bt.On, bt.How = true, "PrefKeyServicesEnabled"
	}
	out = append(out, bt)

	cc := shareService{ID: "content-caching", Name: "Content Caching", Sev: check.Low, Fix: fix("Content Caching")}
	if truthy(f["assetcache"]) {
		cc.On, cc.How = true, "activated"
	}
	return append(out, cc)
}

// cupsSharesPrinters reads `cupsctl`: _share_printers=1 shares this machine's
// printers on the network.
func cupsSharesPrinters(out string) bool {
	return kvLines(out)["_share_printers"] == "1"
}

// ---- Windows ----

// winShareScript prints how many inbound File and Printer Sharing and Network
// Discovery firewall rules are on for the Public profile (rule groups are named
// by their language-neutral resource strings), the folders this PC shares
// (Type 0, without the hidden admin shares, which are Type 2147483648),
// the shared printers, and the Nearby sharing setting. No admin rights needed.
const winShareScript = `$ErrorActionPreference = 'SilentlyContinue'
function pub($g) { @(Get-NetFirewallRule -Group $g -Direction Inbound -Enabled True | Where-Object { $p = [int]$_.Profile; $p -eq 0 -or ($p -band 4) }).Count }
"fps_public=$(pub '@FirewallAPI.dll,-28502')"
"discovery_public=$(pub '@FirewallAPI.dll,-32752')"
$sh = Get-CimInstance Win32_Share | Where-Object { $_.Type -eq 0 -and $_.Name -ne 'print$' } | ForEach-Object Name
"shares=$($sh -join '|')"
"printers=$(@(Get-CimInstance Win32_Printer -Filter 'Shared=True').Count)"
"nearby=$((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP').NearShareChannelUserAuthzPolicy)"`

func winShareServices(kv map[string]string) []shareService {
	n := func(k string) int { v, _ := strconv.Atoi(kv[k]); return v }
	var shares []string
	for _, s := range strings.Split(kv["shares"], "|") {
		if s = strings.TrimSpace(s); s != "" {
			shares = append(shares, s)
		}
	}
	fpsPublic := n("fps_public") > 0
	fs := shareService{ID: "file-sharing", Name: "Shared folders", Sev: check.Medium, Fix: msg.P("sharing.fix.winShares")}
	if len(shares) > 0 {
		fs.On, fs.How = true, strings.Join(shares, ", ")
		if fpsPublic {
			// Reachable from café and hotel networks too.
			fs.Sev, fs.How = check.High, fs.How+"; allowed through the firewall on public networks"
		}
	}
	nd := shareService{ID: "network-discovery", Name: "Network discovery or file and printer sharing on public networks",
		Sev: check.Medium, Fix: msg.P("sharing.fix.winPublic")}
	var how []string
	if n("discovery_public") > 0 {
		how = append(how, "Network Discovery rules on for Public")
	}
	if fpsPublic {
		how = append(how, "File and Printer Sharing rules on for Public")
	}
	nd.On, nd.How = len(how) > 0, strings.Join(how, ", ")
	pr := shareService{ID: "printer-sharing", Name: "Printer sharing", Sev: check.Low, Fix: msg.P("sharing.fix.winPrinters")}
	if c := n("printers"); c > 0 {
		pr.On, pr.How = true, fmt.Sprintf("%d shared printer(s)", c)
	}
	ns := shareService{ID: "nearby-sharing", Name: "Nearby sharing (Everyone nearby)", Sev: check.Medium,
		Fix: msg.P("sharing.fix.winNearby")}
	if kv["nearby"] == "2" {
		ns.On, ns.How = true, "NearShareChannelUserAuthzPolicy = 2"
	}
	return []shareService{fs, nd, pr, ns}
}

// ---- Linux ----

// sambaGuestShares reads smb.conf and returns the shares that let guests in
// (guest ok = yes, or its synonym public = yes). Printer shares are left out.
func sambaGuestShares(conf string) []string {
	var out []string
	section := ""
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.Join(strings.Fields(k), " "))
		v = strings.ToLower(strings.TrimSpace(v))
		lower := strings.ToLower(section)
		if (k == "guest ok" || k == "public") && (v == "yes" || v == "true" || v == "1") &&
			lower != "global" && lower != "printers" && lower != "print$" && !slices.Contains(out, section) {
			out = append(out, section)
		}
	}
	return out
}

// nfsOpenExports reads /etc/exports and returns the paths exported to any
// host (a client of * or no client at all).
func nfsOpenExports(exports string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(exports, "\\\n", " "), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		open := len(f) == 1
		for _, c := range f[1:] {
			if c == "*" || strings.HasPrefix(c, "*(") || strings.HasPrefix(c, "(") {
				open = true
			}
		}
		if open {
			out = append(out, f[0])
		}
	}
	return out
}

// hasExports says whether /etc/exports exports anything.
func hasExports(exports string) bool {
	for _, line := range strings.Split(exports, "\n") {
		line, _, _ = strings.Cut(line, "#")
		if strings.TrimSpace(line) != "" {
			return true
		}
	}
	return false
}

// linuxShareFacts is what Linux gathering found.
type linuxShareFacts struct {
	Active     map[string]string // systemd unit → `systemctl is-active`
	Listeners  []listener
	SambaConf  string
	Exports    string
	Cups       string // `cupsctl` output; "" if not installed
	GnomeShare bool   // gnome-user-share-webdav.service active for this user
}

func linuxShareServices(f linuxShareFacts) []shareService {
	ports := openPorts(f.Listeners)
	unitsOn := func(units ...string) []string {
		var how []string
		for _, u := range units {
			if f.Active[u] == "active" {
				how = append(how, u+" active")
			}
		}
		return how
	}
	smb := shareService{ID: "file-sharing", Name: "Samba file sharing", Sev: check.Medium, Fix: msg.P("sharing.fix.linuxSamba")}
	how := unitsOn("smbd.service", "smb.service")
	if ports[445] {
		how = append(how, "port 445 open")
	}
	if len(how) > 0 {
		if guests := sambaGuestShares(f.SambaConf); len(guests) > 0 {
			smb.Sev, smb.Open = check.High, true
			how = append(how, "guest access to "+strings.Join(guests, ", "))
		}
	}
	smb.On, smb.How = len(how) > 0, strings.Join(how, ", ")

	nfs := shareService{ID: "nfs", Name: "NFS server", Sev: check.Medium, Fix: msg.P("sharing.fix.linuxNFS")}
	how = unitsOn("nfs-server.service", "nfs-kernel-server.service")
	if ports[2049] {
		how = append(how, "port 2049 open")
	}
	if len(how) > 0 && hasExports(f.Exports) {
		if open := nfsOpenExports(f.Exports); len(open) > 0 {
			nfs.Sev, nfs.Open = check.High, true
			how = append(how, "exported to any host: "+strings.Join(open, ", "))
		}
	}
	nfs.On, nfs.How = len(how) > 0, strings.Join(how, ", ")

	pr := shareService{ID: "printer-sharing", Name: "Printer sharing (CUPS)", Sev: check.Low, Fix: msg.P("sharing.fix.cups")}
	if cupsSharesPrinters(f.Cups) {
		pr.On, pr.How = true, "_share_printers=1"
	}
	gn := shareService{ID: "gnome-file-sharing", Name: "GNOME File Sharing", Sev: check.Medium, Fix: msg.P("sharing.fix.linuxGnome")}
	if f.GnomeShare {
		gn.On, gn.How = true, "gnome-user-share-webdav.service active"
	}
	return []shareService{smb, nfs, pr, gn}
}
