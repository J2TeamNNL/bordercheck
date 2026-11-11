package checks

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// remoteService is one way in from the network (or, for the guest account, from
// the login screen) that a laptop should not offer.
type remoteService struct {
	ID   string // its name in the policy's allow list
	Name string // what the OS calls it
	On   bool
	How  string // why it looks on, e.g. "port 22 open"
	Fix  msg.Part
	// For other vendors' tools: the severity (otherwise high, or medium for
	// remoteMedium) and the summary (otherwise remote.on).
	High, Medium bool
	Text         msg.Text
}

// Guest logins and Remote Apple Events need someone at the keyboard or a
// password; the others hand out a shell or the screen.
var remoteMedium = []string{"remote-apple-events", "guest"}

func remoteAccess(opts policy.RemoteAccess) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		svcs, notes, err := remoteServicesOS(ctx)
		if errors.Is(err, errUnsupported) {
			return unsupported()
		}
		if err != nil {
			return check.Errored(err)
		}
		var installed []string
		if opts.ThirdParty {
			if raw, err := remoteToolsOS(ctx); err == nil {
				t, inst, n := remoteTools(raw)
				svcs, notes, installed = append(svcs, t...), append(notes, n...), inst
			}
		}
		return evalRemoteAccessAll(svcs, notes, opts.Allow, installed)
	}
}

func evalRemoteAccess(svcs []remoteService, notes msg.Text, allow []string) check.Result {
	return evalRemoteAccessAll(svcs, notes, allow, nil)
}

// evalRemoteAccessAll also lists, in the evidence, the remote-control apps
// that are only installed.
func evalRemoteAccessAll(svcs []remoteService, notes msg.Text, allow, installedOnly []string) check.Result {
	var p issueList
	var evidence, off, allowed []string
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
		high, text := !slices.Contains(remoteMedium, s.ID), msg.Of("remote.on", "service", s.Name)
		if s.High || s.Medium {
			high = s.High
		}
		if s.Text != nil {
			text = s.Text
		}
		p.add(high, text, s.Fix)
	}
	evidence = append(evidence, installedOnly...)
	if len(allowed) > 0 {
		notes = append(msg.Of("remote.allowed", "services", strings.Join(allowed, ", ")), notes...)
	}
	pass := msg.Of("remote.off", "services", strings.Join(off, ", "))
	return p.result(pass, notes, evidence)
}

// ---- macOS ----

var launchctlDisabledRe = regexp.MustCompile(`"([^"]+)"\s*=>\s*(\w+)`)

// parseLaunchctlDisabled reads `launchctl print-disabled system`, which lists
// only services whose on/off state was changed from the default (Sharing in
// System Settings does that). true = enabled.
func parseLaunchctlDisabled(out string) map[string]bool {
	m := map[string]bool{}
	for _, g := range launchctlDisabledRe.FindAllStringSubmatch(out, -1) {
		switch g[2] {
		case "enabled", "false":
			m[g[1]] = true
		case "disabled", "true":
			m[g[1]] = false
		}
	}
	return m
}

// parseNetstatListen reads `netstat -an -p tcp` (macOS), whose Local Address is
// "addr.port"; unlike lsof it shows root's sockets without root.
func parseNetstatListen(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") || !slices.Contains(f, "LISTEN") {
			continue
		}
		i := strings.LastIndex(f[3], ".")
		if i < 0 {
			continue
		}
		ls = append(ls, listener{Addr: f[3][:i], Port: f[3][i+1:]})
	}
	return ls
}

// openPorts returns the ports listening beyond localhost.
func openPorts(ls []listener) map[int]bool {
	ports := map[int]bool{}
	for _, l := range ls {
		addr, _, _ := strings.Cut(l.Addr, "%") // fe80::1%lo0
		if isLoopback(addr) || strings.HasPrefix(addr, "fe80::1") && strings.HasSuffix(l.Addr, "%lo0") {
			continue
		}
		if n, err := strconv.Atoi(l.Port); err == nil {
			ports[n] = true
		}
	}
	return ports
}

// macRemoteServices judges Sharing settings from launchd's overrides (all
// three daemons ship disabled), what listens, whether Remote Management's
// launchd flag file says "enabled", and loginwindow's GuestEnabled.
func macRemoteServices(disabled, netstat string, ardOn bool, guest string) []remoteService {
	overrides := parseLaunchctlDisabled(disabled)
	ports := openPorts(parseNetstatListen(netstat))
	svc := func(id, name, label string, port int, fix string) remoteService {
		s := remoteService{ID: id, Name: name, Fix: msg.P("remote.fix.macSharing", "service", fix)}
		var how []string
		if overrides[label] {
			how = append(how, "enabled in launchd")
		}
		if ports[port] {
			how = append(how, fmt.Sprintf("port %d open", port))
		}
		s.On, s.How = len(how) > 0, strings.Join(how, ", ")
		return s
	}
	ssh := svc("ssh", "Remote Login (SSH)", "com.openssh.sshd", 22, "Remote Login")
	screen := svc("screen-sharing", "Screen Sharing", "com.apple.screensharing", 5900, "Screen Sharing")
	ae := svc("remote-apple-events", "Remote Application Scripting", "com.apple.AEServer", 3031, "Remote Application Scripting")
	ard := svc("remote-management", "Remote Management", "", 3283, "Remote Management")
	if ardOn {
		ard.On, ard.How = true, strings.TrimPrefix(strings.Join([]string{ard.How, "turned on in Remote Management"}, ", "), ", ")
		if !overrides["com.apple.screensharing"] {
			screen.On = false // Remote Management runs the screen sharing server itself
		}
	}
	g := remoteService{ID: "guest", Name: "Guest user", On: strings.TrimSpace(guest) == "true",
		Fix: msg.P("remote.fix.macGuest")}
	if g.On {
		g.How = "guests can log in"
	}
	return []remoteService{ssh, screen, ard, ae, g}
}

// ---- Windows ----

// winRemoteScript prints the Remote Desktop switch (and its policy override),
// the OpenSSH server service, the remote-access ports listening beyond
// localhost, and whether the built-in Guest account (SID ending -501) is
// disabled. None of it needs admin rights.
const winRemoteScript = `$ErrorActionPreference = 'SilentlyContinue'
"rdp_deny=$((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections)"
"rdp_deny_policy=$((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fDenyTSConnections)"
$s = Get-Service sshd; if ($s) { "sshd=$($s.Status)/$($s.StartType)" }
$l = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 22,3389,5985,5986 -and $_.LocalAddress -notin '127.0.0.1','::1' } | ForEach-Object LocalPort | Sort-Object -Unique
"listen=$($l -join ',')"
$g = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'"
"guest_disabled=$($g.Disabled)"`

func winRemoteServices(kv map[string]string) []remoteService {
	ports := map[int]bool{}
	for _, p := range strings.Split(kv["listen"], ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			ports[n] = true
		}
	}
	deny := kv["rdp_deny"]
	if v := kv["rdp_deny_policy"]; v != "" {
		deny = v
	}
	rdp := remoteService{ID: "rdp", Name: "Remote Desktop",
		Fix: msg.P("remote.fix.winRDP")}
	var how []string
	if deny == "0" {
		how = append(how, "allowed in settings")
	}
	if ports[3389] {
		how = append(how, "port 3389 open")
	}
	rdp.On, rdp.How = len(how) > 0, strings.Join(how, ", ")

	winrm := remoteService{ID: "winrm", Name: "WinRM (PowerShell remoting)", On: ports[5985] || ports[5986],
		Fix: msg.P("remote.fix.winRM")}
	if winrm.On {
		winrm.How = "port 5985/5986 open"
	}

	ssh := remoteService{ID: "ssh", Name: "OpenSSH Server",
		Fix: msg.P("remote.fix.winSSH")}
	status, start, _ := strings.Cut(kv["sshd"], "/")
	how = nil
	if status == "Running" {
		how = append(how, "service running")
	} else if start == "Automatic" {
		how = append(how, "service starts automatically")
	}
	if ports[22] {
		how = append(how, "port 22 open")
	}
	ssh.On, ssh.How = len(how) > 0, strings.Join(how, ", ")

	guest := remoteService{ID: "guest", Name: "Guest account", On: strings.EqualFold(kv["guest_disabled"], "False"),
		Fix: msg.P("remote.fix.winGuest")}
	if guest.On {
		guest.How = "enabled"
	}
	return []remoteService{ssh, rdp, winrm, guest}
}

// ---- Linux ----

// procNetListen reads /proc/net/tcp or /proc/net/tcp6: listening sockets
// (state 0A) with their local address, which is hex, 32-bit words in host
// (little-endian) byte order.
func procNetListen(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		addrHex, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		raw, err := hex.DecodeString(addrHex)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		for i := 0; i+4 <= len(raw); i += 4 {
			raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		ls = append(ls, listener{Addr: net.IP(raw).String(), Port: strconv.Itoa(int(port))})
	}
	return ls
}

// lightdmGuest reads LightDM's config files in load order; the last
// allow-guest wins. Guest sessions also need the guest-account script.
func lightdmGuest(confs []string, hasGuestScript bool) bool {
	if !hasGuestScript {
		return false
	}
	allow := true // LightDM's default
	for _, c := range confs {
		for _, line := range strings.Split(c, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.TrimSpace(k) == "allow-guest" {
				allow = strings.TrimSpace(v) == "true"
			}
		}
	}
	return allow
}

// linuxRemoteServices judges systemd unit states (unit → `systemctl is-active`)
// and what listens beyond localhost.
func linuxRemoteServices(active map[string]string, ls []listener, guest bool) []remoteService {
	ports := openPorts(ls)
	svc := func(id, name string, units []string, portLo, portHi int, fix string) remoteService {
		s := remoteService{ID: id, Name: name, Fix: msg.P(fix)}
		var how []string
		for _, u := range units {
			if active[u] == "active" {
				how = append(how, u+" active")
			}
		}
		for p := portLo; p <= portHi; p++ {
			if ports[p] {
				how = append(how, fmt.Sprintf("port %d open", p))
			}
		}
		s.On, s.How = len(how) > 0, strings.Join(how, ", ")
		return s
	}
	ssh := svc("ssh", "SSH server", []string{"ssh.service", "sshd.service", "ssh.socket", "sshd.socket"}, 22, 22,
		"remote.fix.linuxSSH")
	rdp := svc("rdp", "Remote desktop (RDP)", []string{"xrdp.service", "gnome-remote-desktop.service"}, 3389, 3389,
		"remote.fix.linuxRDP")
	vnc := svc("screen-sharing", "Screen sharing (VNC)", nil, 5900, 5909,
		"remote.fix.linuxVNC")
	g := remoteService{ID: "guest", Name: "Guest session", On: guest,
		Fix: msg.P("remote.fix.linuxGuest")}
	if guest {
		g.How = "LightDM offers a guest session"
	}
	return []remoteService{ssh, rdp, vnc, g}
}
