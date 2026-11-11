package checks

import (
	"slices"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// `scutil --nc list` captured on a Mac (IDs and names changed), plus a
// WireGuard app tunnel line in the same format.
const ncListSample = `Available network connection services in the current set (*=enabled):
* (Disconnected)   01C994A1-0000-0000-0000-000000000001 VPN (com.demo.vpn) "Demo VPN"                      [VPN:com.demo.vpn]
* (Connected)      90E0AE3F-0000-0000-0000-000000000002 VPN (io.tailscale.ipn.macsys) "Tailscale"                      [VPN:io.tailscale.ipn.macsys]
* (Connected)      5A1B2C3D-0000-0000-0000-000000000003 VPN (com.wireguard.macos) "office"                      [VPN:com.wireguard.macos]
`

func tsResult(shieldsUp bool) *check.Result {
	r := evalTailscalePrefs(map[bool]string{true: `{"ShieldsUp": true}`, false: `{"ShieldsUp": false}`}[shieldsUp])
	return &r
}

func tsSkip(key string, params ...any) *check.Result {
	r := check.SkippedMsg(msg.Of(key, params...))
	return &r
}

// sampleMesh is a made-up machine per OS for the message samples.
func sampleMesh(goos string) check.Result {
	var f meshFacts
	var allow []string
	switch goos {
	case "darwin":
		f.Tailscale = tsResult(false)
		f.Tools = meshTools(meshRaw{GOOS: "darwin", Procs: []proc{{exe: "/Library/Application Support/ZeroTier/One/zerotier-one"}},
			ZTNetworks: 2, ZTNetworksKnown: true, NCList: ncListSample, NebulaRules: -1})
	case "windows":
		f.Tailscale = tsResult(true)
		f.Tools = meshTools(meshRaw{GOOS: "windows", Ifaces: []string{"Ethernet", "Hamachi"}, NebulaRules: -1,
			Services: map[string]string{"WireGuardTunnel$office": "Running", "Hamachi2Svc": "Running"}})
		allow = []string{"hamachi"}
	default:
		f.Tailscale = tsSkip("tailscale.denied", "err", "exit status 1: Access denied: prefs read access denied")
		f.Tools = meshTools(meshRaw{GOOS: "linux", Ifaces: []string{"eth0", "wt0", "wg0", "nebula1"},
			IfaceType: map[string]string{"wt0": "wireguard", "wg0": "wireguard"}, NebulaRules: 0,
			Procs: []proc{{exe: "/usr/bin/netbird", args: []string{"service", "run"}}, {exe: "/usr/bin/nebula", args: []string{"-config", "/etc/nebula/config.yml"}}}})
	}
	r, _ := evalMeshVPN(f, allow)
	return r
}

func toolIDs(ts []meshTool) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

func TestMeshSamples(t *testing.T) {
	mac := sampleMesh("darwin")
	if mac.Status != check.Fail || mac.Severity != check.High || !strings.Contains(mac.Summary, "Tailscale accepts incoming") ||
		!strings.Contains(mac.Summary, "ZeroTier is connected and does not block") || !strings.Contains(mac.Summary, "WireGuard is connected") ||
		!strings.Contains(mac.Fix, "shields-up") || !strings.Contains(mac.Fix, "zerotier-cli leave") {
		t.Errorf("mac: %+v", mac)
	}
	win := sampleMesh("windows")
	if win.Status != check.Warn || win.Severity != check.Medium || !slices.Contains(win.Evidence, "Tailscale: shields up") ||
		!strings.Contains(win.Summary, "WireGuard is connected") || !strings.Contains(win.Summary, "Allowed by policy to accept incoming connections: Hamachi") {
		t.Errorf("windows: %+v", win)
	}
	lin := sampleMesh("linux")
	if lin.Status != check.Warn || !strings.Contains(lin.Summary, "WireGuard is connected") ||
		!strings.Contains(lin.Summary, "NetBird is connected; whether it blocks") || !slices.Contains(lin.Evidence, "Nebula: no inbound firewall rules") ||
		!strings.Contains(lin.Summary, "tailscale set --operator") || strings.Contains(strings.Join(lin.Evidence, " "), "wt0, wg0") {
		t.Errorf("linux: %+v", lin)
	}
	// NetBird's wt0 is not counted as a plain WireGuard tunnel.
	if !slices.Contains(lin.Evidence, "WireGuard: interface wg0") {
		t.Errorf("linux evidence: %q", lin.Evidence)
	}
}

func TestEvalMeshVPN(t *testing.T) {
	// Nothing installed, Tailscale included.
	r, found := evalMeshVPN(meshFacts{Tailscale: tsSkip("tailscale.notInstalled")}, nil)
	if r.Status != check.Skip || r.Summary != "No private-network (mesh VPN) software was found." || found != nil {
		t.Errorf("none: %+v", r)
	}
	// Tailscale left out by the policy, nothing else.
	if r, _ := evalMeshVPN(meshFacts{}, nil); r.Status != check.Skip {
		t.Errorf("left out: %+v", r)
	}
	// Installed but not connected passes, with a word.
	zt := meshTools(meshRaw{GOOS: "linux", Installed: map[string]bool{"zerotier": true}, NebulaRules: -1})
	r, _ = evalMeshVPN(meshFacts{Tailscale: tsSkip("tailscale.notInstalled"), Tools: zt}, nil)
	if r.Status != check.Pass || r.Summary != "ZeroTier is installed but not connected." {
		t.Errorf("not connected: %+v", r)
	}
	// Running, but networks.d unreadable and no zt interface: a note, not a finding.
	zt = meshTools(meshRaw{GOOS: "linux", Procs: []proc{{exe: "zerotier-one"}}, NebulaRules: -1})
	r, _ = evalMeshVPN(meshFacts{Tools: zt}, nil)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "could not be read without admin rights") {
		t.Errorf("zerotier unknown: %+v", r)
	}
	// ...a zt interface tells.
	zt = meshTools(meshRaw{GOOS: "linux", Procs: []proc{{exe: "zerotier-one"}}, Ifaces: []string{"ztabcdef12"}, NebulaRules: -1})
	if r, found := evalMeshVPN(meshFacts{Tools: zt}, nil); r.Status != check.Warn || r.Severity != check.Medium || !slices.Equal(found, []string{"zerotier"}) {
		t.Errorf("zerotier interface: %+v %v", r, found)
	}
	// ZeroTier joined to no network.
	zt = meshTools(meshRaw{GOOS: "darwin", Procs: []proc{{exe: "zerotier-one"}}, ZTNetworksKnown: true, NebulaRules: -1})
	if r, _ := evalMeshVPN(meshFacts{Tools: zt}, nil); r.Status != check.Pass {
		t.Errorf("zerotier no network: %+v", r)
	}
	// NetBird with Block inbound connections on, and off.
	on, off := true, false
	nb := meshRaw{GOOS: "linux", Ifaces: []string{"wt0"}, Procs: []proc{{exe: "netbird", args: []string{"service", "run"}}}, NebulaRules: -1}
	nb.NetbirdBlock = &on
	if r, _ := evalMeshVPN(meshFacts{Tools: meshTools(nb)}, nil); r.Status != check.Pass || r.Summary != "NetBird is connected and blocks incoming connections." {
		t.Errorf("netbird blocked: %+v", r)
	}
	nb.NetbirdBlock = &off
	if r, _ := evalMeshVPN(meshFacts{Tools: meshTools(nb)}, nil); r.Status != check.Warn || !strings.Contains(r.Fix, "--block-inbound") {
		t.Errorf("netbird open: %+v", r)
	}
	if r, _ := evalMeshVPN(meshFacts{Tools: meshTools(nb)}, []string{"netbird"}); r.Status != check.Pass {
		t.Errorf("netbird allowed: %+v", r)
	}
	// netbird-ui alone is not the daemon.
	if ts := meshTools(meshRaw{GOOS: "linux", Procs: []proc{{exe: "netbird-ui"}}, NebulaRules: -1}); len(ts) != 0 {
		t.Errorf("netbird-ui: %v", toolIDs(ts))
	}
	// Tailscale allowed by policy.
	r, found = evalMeshVPN(meshFacts{Tailscale: tsResult(false)}, []string{"tailscale"})
	if r.Status != check.Pass || !strings.Contains(r.Summary, "Allowed by policy to accept incoming connections: Tailscale") || found != nil {
		t.Errorf("tailscale allowed: %+v", r)
	}
	// Tailscale's bad output is a note.
	bad := check.Errored(msg.Err("tailscale.badPrefs"))
	if r, _ := evalMeshVPN(meshFacts{Tailscale: &bad}, nil); r.Status != check.Pass || !strings.Contains(r.Summary, "unexpected output") {
		t.Errorf("tailscale bad prefs: %+v", r)
	}
	// Nebula with inbound rules, and one whose config could not be read.
	if r, _ := evalMeshVPN(meshFacts{Tools: meshTools(meshRaw{GOOS: "linux", Procs: []proc{{exe: "nebula"}}, NebulaRules: 3})}, nil); r.Status != check.Warn ||
		!strings.Contains(strings.Join(r.Evidence, " "), "3 inbound firewall rule(s)") {
		t.Errorf("nebula rules: %+v", r)
	}
	if r, _ := evalMeshVPN(meshFacts{Tools: meshTools(meshRaw{GOOS: "linux", Procs: []proc{{exe: "nebula"}}, NebulaRules: -1})}, nil); r.Status != check.Pass {
		t.Errorf("nebula unknown: %+v", r)
	}
}

// TestMeshLegacy: a policy written for the old tailscale check.
func TestMeshLegacy(t *testing.T) {
	ts, _ := evalMeshVPN(meshFacts{Tailscale: tsResult(false)}, nil)
	r := meshLegacy(ts, []string{"tailscale"}, check.Warn)
	if r.Status != check.Warn || !slices.Equal(r.Aliases, []string{"tailscale"}) {
		t.Errorf("tailscale only: %+v", r)
	}
	r = meshLegacy(ts, []string{"tailscale", "zerotier"}, check.Warn)
	if r.Status != check.Fail || r.Aliases != nil {
		t.Errorf("tailscale and zerotier: %+v", r)
	}
	r = meshLegacy(ts, []string{"tailscale"}, "")
	if r.Status != check.Fail || len(r.Aliases) != 1 {
		t.Errorf("no on_problem: %+v", r)
	}

	// The policy side: mesh-vpn's on_problem wins over tailscale's.
	p := policy.Default()
	p.Checks.Tailscale = &policy.Common{OnProblem: check.Warn}
	if p.Checks.TailscaleOnProblem() != check.Warn || !p.Checks.TailscaleJudged() {
		t.Error("tailscale on_problem not passed on")
	}
	p.Checks.MeshVPN.OnProblem = check.Fail
	if p.Checks.TailscaleOnProblem() != "" {
		t.Error("mesh-vpn on_problem must win")
	}
	off := false
	p.Checks.Tailscale = &policy.Common{Enabled: &off}
	if p.Checks.TailscaleJudged() {
		t.Error("checks.tailscale.enabled false must leave Tailscale out")
	}
	// mesh-vpn is in the report where tailscale was, and tailscale is gone.
	var ids []string
	for _, c := range All(policy.Default()) {
		ids = append(ids, c.ID)
	}
	if i := slices.Index(ids, "mesh-vpn"); i != slices.Index(ids, "listeners")+1 || slices.Contains(ids, "tailscale") {
		t.Errorf("order: %v", ids)
	}
}

func TestNebulaInboundRules(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want int
	}{
		{"pki:\n  ca: /etc/nebula/ca.crt\n", -1},
		{"firewall:\n  outbound:\n    - port: any\n      proto: any\n      host: any\n", -1},
		{"firewall:\n  inbound: []\n", 0},
		{"firewall:\n  inbound:\n  outbound:\n    - port: any\n      host: any\n", 0},
		{`firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    # ICMP from anyone
    - port: any
      proto: icmp
      host: any
    - port: 443
      proto: tcp
      groups:
        - laptop
        - home
tun:
  dev: nebula1
`, 2},
		{"firewall:\n  inbound:\n  - port: 22\n    host: any\n  - port: 80\n    host: any\n", 2},
		{"firewall:\n  inbound: [{port: any, host: any}]\n", -1},
	} {
		if got := nebulaInboundRules(tc.yaml); got != tc.want {
			t.Errorf("%q: got %d, want %d", tc.yaml, got, tc.want)
		}
	}
	if c := nebulaConfigArg(proc{exe: "nebula", args: []string{"-config", "/etc/nebula/config.yml"}}); c != "/etc/nebula/config.yml" {
		t.Errorf("config arg %q", c)
	}
}

func TestMeshParsers(t *testing.T) {
	if n := macConnectedVPNs(ncListSample, "com.wireguard.macos"); n != 1 {
		t.Errorf("wireguard tunnels: %d", n)
	}
	if n := macConnectedVPNs(ncListSample, "com.demo.vpn"); n != 0 {
		t.Errorf("disconnected counted: %d", n)
	}
	// Synthetic NetBird configs; the key value is made up and must not matter.
	for body, want := range map[string]string{
		`{"PrivateKey":"x","BlockInbound":true}`:  "true",
		`{"PrivateKey":"x","BlockInbound":false}`: "false",
		`{"PrivateKey":"x"}`:                      "false",
		`not json`:                                "nil",
	} {
		got := "nil"
		if v := parseNetbirdBlockInbound([]byte(body)); v != nil {
			got = map[bool]string{true: "true", false: "false"}[*v]
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", body, got, want)
		}
	}
	if d := linuxDevType("INTERFACE=wg0\nIFINDEX=5\nDEVTYPE=wireguard\n"); d != "wireguard" {
		t.Errorf("devtype %q", d)
	}
	if s := parseNameStatus("WireGuardTunnel$office|Running\r\nHamachi2Svc|Stopped\n\n"); s["WireGuardTunnel$office"] != "Running" || s["Hamachi2Svc"] != "Stopped" {
		t.Errorf("services %v", s)
	}
	// Windows: a stopped tunnel service is not a tunnel.
	if ts := meshTools(meshRaw{GOOS: "windows", Services: map[string]string{"WireGuardTunnel$x": "Stopped"}, NebulaRules: -1}); len(ts) != 0 {
		t.Errorf("stopped tunnel: %v", toolIDs(ts))
	}
}
