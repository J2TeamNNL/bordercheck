package checks

// mesh-vpn: private networks (mesh VPNs, overlay networks) whose other members
// can open connections to this machine. Tailscale's rule is the old
// "tailscale" check (tailscale.go), unchanged; the other tools are judged from
// what a normal user can read without asking their daemon anything: the
// process table, network interfaces, the tool's state files where they are
// readable, and on macOS the VPN list of `scutil --nc list`.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// meshInbound is whether a connected tool lets its network's members in.
type meshInbound int

const (
	inboundNoControl meshInbound = iota // the tool has no switch for it: they can come in
	inboundOpen                         // it has one, and it is off
	inboundBlocked                      // it has one, and it is on
	inboundUnknown                      // it has one, but it could not be read
)

// meshTool is one private-network tool found on this machine.
type meshTool struct {
	ID, Name    string // ID is its name in policy.MeshVPNTools
	Connected   bool
	ConnUnknown bool // running, but whether it has joined a network could not be read
	Inbound     meshInbound
	How         string // evidence: interfaces, network counts; never a key or a network secret
}

// meshFacts is what mesh-vpn judges. Tailscale is the result of the old
// tailscale check, nil when the policy leaves Tailscale out.
type meshFacts struct {
	Tailscale *check.Result
	Tools     []meshTool
}

var meshFix = map[string]string{
	"zerotier": "mesh.fix.zerotier", "netbird": "mesh.fix.netbird", "wireguard": "mesh.fix.wireguard",
	"nebula": "mesh.fix.nebula", "hamachi": "mesh.fix.hamachi",
}

func meshVPN(c policy.Checks) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		var f meshFacts
		if c.TailscaleJudged() {
			r := tailscale(ctx)
			f.Tailscale = &r
		}
		tools, err := meshToolsOS(ctx)
		if err != nil && !errors.Is(err, errUnsupported) {
			return check.Errored(err)
		}
		f.Tools = tools
		r, found := evalMeshVPN(f, c.MeshVPN.Allow)
		return meshLegacy(r, found, c.TailscaleOnProblem())
	}
}

// meshLegacy keeps policies written for the old tailscale check working: when
// Tailscale is the only tool with a finding, the result also answers to the
// ID "tailscale" (waivers, remembered notifications) and takes
// checks.tailscale.on_problem (mesh-vpn's own on_problem is applied later and
// wins).
func meshLegacy(r check.Result, found []string, tsOnProblem check.Status) check.Result {
	if len(found) != 1 || found[0] != "tailscale" {
		return r
	}
	r.Aliases = []string{"tailscale"}
	if tsOnProblem != "" && (r.Status == check.Fail || r.Status == check.Warn) {
		r.Status = tsOnProblem
	}
	return r
}

// evalMeshVPN judges the tools; found lists those with a finding.
func evalMeshVPN(f meshFacts, allow []string) (r check.Result, found []string) {
	var p issueList
	var pass, notes msg.Text
	var evidence, allowed []string
	any := false
	if ts := f.Tailscale; ts != nil && !(ts.Status == check.Skip && partKey(ts.SummaryParts) == "tailscale.notInstalled") {
		any = true
		switch ts.Status {
		case check.Pass:
			pass = append(pass, ts.SummaryParts...)
			evidence = append(evidence, "Tailscale: shields up")
		case check.Fail, check.Warn:
			if slices.Contains(allow, "tailscale") {
				allowed = append(allowed, "Tailscale")
				evidence = append(evidence, "Tailscale: accepts incoming connections (allowed by policy)")
				break
			}
			evidence = append(evidence, "Tailscale: accepts incoming connections")
			p.add(ts.Severity == check.High, ts.SummaryParts, firstPart(ts.FixParts))
			found = append(found, "tailscale")
		default: // could not read Tailscale's settings: say why
			notes = append(notes, ts.SummaryParts...)
		}
	}
	for _, t := range f.Tools {
		any = true
		line := t.Name
		if t.How != "" {
			line += ": " + t.How
		}
		switch {
		case t.ConnUnknown:
			notes = append(notes, msg.P("mesh.connUnknown", "tool", t.Name))
		case !t.Connected:
			pass = append(pass, msg.P("mesh.notConnected", "tool", t.Name))
			line += " (not connected)"
		case t.Inbound == inboundBlocked:
			pass = append(pass, msg.P("mesh.blocked", "tool", t.Name))
		case t.Inbound == inboundUnknown:
			notes = append(notes, msg.P("mesh.inboundUnknown", "tool", t.Name))
		case slices.Contains(allow, t.ID):
			allowed = append(allowed, t.Name)
			line += " (allowed by policy)"
		default:
			p.add(false, msg.Of("mesh.open", "tool", t.Name), msg.P(meshFix[t.ID]))
			found = append(found, t.ID)
		}
		evidence = append(evidence, line)
	}
	if !any {
		return check.SkippedMsg(msg.Of("mesh.none")), nil
	}
	if len(allowed) > 0 {
		notes = append(notes, msg.P("mesh.allowed", "tools", strings.Join(allowed, ", ")))
	}
	if len(pass) == 0 && len(p.high)+len(p.medium) == 0 && len(notes) == 0 {
		pass = msg.Of("mesh.none") // unreachable: a tool always says something
	}
	return p.result(pass, notes, evidence), found
}

func partKey(t msg.Text) string {
	if len(t) == 0 {
		return ""
	}
	return t[0].Key
}

func firstPart(t msg.Text) msg.Part {
	if len(t) == 0 {
		return msg.Part{}
	}
	return t[0]
}

// ---- gathering, shared by the per-OS files --------------------------------

// meshRaw is what the per-OS gatherers read; meshTools judges which tool is
// installed, running and connected from it.
type meshRaw struct {
	GOOS      string
	Procs     []proc
	Ifaces    []string          // network interfaces that are up
	IfaceType map[string]string // Linux: interface → DEVTYPE from /sys/class/net/*/uevent
	NCList    string            // macOS: `scutil --nc list`
	Services  map[string]string // Windows: service name → status ("Running", "Stopped")
	Installed map[string]bool   // tool ID → its files are on this machine

	ZTNetworks      int  // ZeroTier: networks.d/*.conf files
	ZTNetworksKnown bool // networks.d could be listed
	WGQuick         int  // macOS: wg-quick tunnels up (/var/run/wireguard/*.name)
	NetbirdBlock    *bool
	NebulaRules     int // Nebula: rules under firewall.inbound, -1 when unknown
}

func (m meshRaw) running(names ...string) bool {
	return slices.ContainsFunc(m.Procs, func(p proc) bool {
		n := procName(p.exe)
		return slices.ContainsFunc(names, func(want string) bool { return n == procName(want) })
	})
}

func (m meshRaw) serviceRunning(names ...string) bool {
	for name, st := range m.Services {
		for _, want := range names {
			if (strings.EqualFold(name, want) || strings.HasSuffix(want, "*") && strings.HasPrefix(strings.ToLower(name), strings.ToLower(strings.TrimSuffix(want, "*")))) &&
				strings.EqualFold(st, "Running") {
				return true
			}
		}
	}
	return false
}

func (m meshRaw) ifaces(match func(string) bool) []string {
	var out []string
	for _, i := range m.Ifaces {
		if match(i) {
			out = append(out, i)
		}
	}
	return out
}

// macConnectedVPNs counts the connected VPNs of `scutil --nc list` made by an
// app, e.g. "com.wireguard.macos". A line looks like (captured on a Mac, ID
// and name changed):
//
//   - (Connected)      90E0AE3F-0000-0000-0000-000000000000 VPN (io.tailscale.ipn.macsys) "Tailscale"   [VPN:io.tailscale.ipn.macsys]
func macConnectedVPNs(out, provider string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "(Connected)") && strings.Contains(line, "[VPN:"+provider+"]") {
			n++
		}
	}
	return n
}

// meshTools turns what was read into the tools found. A tool that is neither
// installed nor running is left out.
func meshTools(m meshRaw) []meshTool {
	var out []meshTool
	add := func(t meshTool, installed bool) {
		if installed || t.Connected || t.ConnUnknown {
			out = append(out, t)
		}
	}

	// ZeroTier: the service is zerotier-one; joined networks are files in
	// networks.d, and each has a zt… interface on Linux (feth… on macOS,
	// "ZeroTier One [network]" on Windows). Nothing on the computer blocks
	// inbound traffic: only the network's flow rules, set by its admin.
	zt := meshTool{ID: "zerotier", Name: "ZeroTier", Inbound: inboundNoControl}
	ztRun := m.running("zerotier-one", "zerotier-one_x64.exe", "zerotier-one_x86.exe") || m.serviceRunning("ZeroTierOneService")
	ztIf := m.ifaces(func(i string) bool {
		switch m.GOOS {
		case "linux":
			return strings.HasPrefix(i, "zt")
		case "windows":
			return strings.HasPrefix(i, "ZeroTier")
		}
		return false
	})
	switch {
	case !ztRun:
	case m.ZTNetworksKnown:
		zt.Connected = m.ZTNetworks > 0
		zt.How = fmt.Sprintf("%d network(s) joined", m.ZTNetworks)
	case len(ztIf) > 0:
		zt.Connected, zt.How = true, "interface "+strings.Join(ztIf, ", ")
	default:
		zt.ConnUnknown = true
	}
	add(zt, m.Installed["zerotier"] || ztRun)

	// NetBird: the daemon is `netbird service run`; its WireGuard interface is
	// wt0 by default. "Block inbound connections" is BlockInbound in its
	// config, read only where the file is readable.
	nb := meshTool{ID: "netbird", Name: "NetBird", Inbound: inboundUnknown}
	nbRun := m.serviceRunning("netbird") || slices.ContainsFunc(m.Procs, func(p proc) bool {
		return procName(p.exe) == "netbird" && hasArg(p.args, "service") && hasArg(p.args, "run")
	})
	if nbIf := m.ifaces(func(i string) bool { return i == "wt0" }); nbRun && len(nbIf) > 0 {
		nb.Connected, nb.How = true, "interface wt0"
	} else if nbRun {
		nb.ConnUnknown = true
	}
	if b := m.NetbirdBlock; b != nil {
		nb.Inbound = inboundOpen
		if *b {
			nb.Inbound = inboundBlocked
		}
	}
	add(nb, m.Installed["netbird"] || nbRun)

	// WireGuard: Linux kernel interfaces (DEVTYPE=wireguard; NetBird's wt0
	// aside), the macOS app's tunnels and wg-quick's on macOS, and the Windows
	// app's tunnel services WireGuardTunnel$name. WireGuard itself has no
	// inbound switch: a peer can reach whatever the firewall lets through.
	wg := meshTool{ID: "wireguard", Name: "WireGuard", Inbound: inboundNoControl}
	var wgHow []string
	switch m.GOOS {
	case "linux":
		for _, i := range m.Ifaces {
			if m.IfaceType[i] == "wireguard" && i != "wt0" {
				wgHow = append(wgHow, "interface "+i)
			}
		}
	case "darwin":
		if n := macConnectedVPNs(m.NCList, "com.wireguard.macos"); n > 0 {
			wgHow = append(wgHow, fmt.Sprintf("%d tunnel(s) active in the WireGuard app", n))
		}
		if m.WGQuick > 0 {
			wgHow = append(wgHow, fmt.Sprintf("%d wg-quick tunnel(s) up", m.WGQuick))
		}
	case "windows":
		n := 0
		for name, st := range m.Services {
			if strings.HasPrefix(strings.ToLower(name), "wireguardtunnel$") && strings.EqualFold(st, "Running") {
				n++
			}
		}
		if n > 0 {
			wgHow = append(wgHow, fmt.Sprintf("%d tunnel(s) active", n))
		}
	}
	wg.Connected, wg.How = len(wgHow) > 0, strings.Join(wgHow, ", ")
	add(wg, m.Installed["wireguard"])

	// Nebula: the nebula process; its own firewall lets in only what
	// firewall.inbound in its config lists.
	nbl := meshTool{ID: "nebula", Name: "Nebula", Inbound: inboundUnknown}
	if m.running("nebula", "nebula.exe") {
		nbl.Connected = true
		switch {
		case m.NebulaRules == 0:
			nbl.Inbound, nbl.How = inboundBlocked, "no inbound firewall rules"
		case m.NebulaRules > 0:
			nbl.Inbound, nbl.How = inboundOpen, fmt.Sprintf("%d inbound firewall rule(s)", m.NebulaRules)
		}
	}
	add(nbl, m.Installed["nebula"])

	// LogMeIn Hamachi: hamachid (macOS, Linux) or the Hamachi2Svc service, and
	// its ham0 (Linux) or "Hamachi" (Windows) interface. No inbound switch.
	hm := meshTool{ID: "hamachi", Name: "Hamachi", Inbound: inboundNoControl}
	hmRun := m.running("hamachid") || m.serviceRunning("Hamachi2Svc")
	if hmIf := m.ifaces(func(i string) bool { return i == "ham0" || i == "Hamachi" }); hmRun && len(hmIf) > 0 {
		hm.Connected, hm.How = true, "interface "+strings.Join(hmIf, ", ")
	} else if hmRun {
		hm.ConnUnknown = true
	}
	add(hm, m.Installed["hamachi"] || hmRun)
	return out
}

// nebulaInboundRules counts the rules under firewall.inbound in a Nebula
// YAML config, -1 if there is no such section. It reads only that structure.
func nebulaInboundRules(yaml string) int {
	inFirewall, inInbound := false, false
	keyIndent, itemIndent, n := 0, -1, -1
	for _, raw := range strings.Split(yaml, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if c := strings.Index(line, "#"); c >= 0 {
			line = strings.TrimRight(line[:c], " \t")
		}
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" {
			continue
		}
		indent := len(line) - len(trimmed)
		if indent == 0 {
			inFirewall, inInbound = trimmed == "firewall:", false
			continue
		}
		if !inFirewall {
			continue
		}
		item := strings.HasPrefix(trimmed, "- ") || trimmed == "-"
		if inInbound {
			switch {
			case item && (itemIndent < 0 || indent == itemIndent) && indent >= keyIndent:
				itemIndent = indent
				n++
				continue
			case indent > itemIndent && itemIndent >= 0:
				continue // a field of the current rule
			case indent > keyIndent:
				continue
			}
			inInbound = false
		}
		if k, v, ok := strings.Cut(trimmed, ":"); ok && k == "inbound" {
			keyIndent, itemIndent, n = indent, -1, 0
			switch strings.TrimSpace(v) {
			case "":
				inInbound = true
			case "[]":
			default: // a flow-style list: not worth parsing, so unknown
				n = -1
			}
		}
	}
	return n
}

// nebulaConfigArg is the -config path of a nebula process, "" if none.
func nebulaConfigArg(p proc) string {
	for i, a := range p.args {
		if a == "-config" || a == "--config" {
			return next(p.args, i)
		}
		if v, ok := strings.CutPrefix(a, "-config="); ok {
			return v
		}
	}
	return ""
}
