package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// meshToolsOS reads the process table, the interfaces, `scutil --nc list`
// (the VPN configurations and whether each is connected; no root, no
// prompt), ZeroTier's networks.d and wg-quick's run folder.
func meshToolsOS(ctx context.Context) ([]meshTool, error) {
	home, _ := os.UserHomeDir()
	procs, _ := listProcs(ctx)
	m := meshRaw{GOOS: "darwin", Procs: procs, Ifaces: upInterfaces(), NebulaRules: nebulaRules(procs)}
	m.NCList, _ = sysx.Run(ctx, "/usr/sbin/scutil", "--nc", "list")
	const ztHome = "/Library/Application Support/ZeroTier/One"
	m.ZTNetworks, m.ZTNetworksKnown = zeroTierNetworks(ztHome)
	if names, err := filepath.Glob("/var/run/wireguard/*.name"); err == nil {
		m.WGQuick = len(names)
	}
	m.NetbirdBlock = netbirdBlockInbound("/etc/netbird/config.json")
	apps := func(names ...string) []string {
		var out []string
		for _, n := range names {
			out = append(out, filepath.Join("/Applications", n), filepath.Join(home, "Applications", n))
		}
		return out
	}
	m.Installed = map[string]bool{
		"zerotier":  anyExists(append(apps("ZeroTier.app", "ZeroTier One.app"), filepath.Join(ztHome, "zerotier-one"))...),
		"netbird":   anyExists(append(apps("NetBird.app", "Netbird.app"), "/usr/local/bin/netbird", "/opt/homebrew/bin/netbird")...),
		"wireguard": anyExists(append(apps("WireGuard.app"), "/usr/local/bin/wg-quick", "/opt/homebrew/bin/wg-quick")...),
		"nebula":    anyExists("/usr/local/bin/nebula", "/opt/homebrew/bin/nebula"),
		"hamachi":   anyExists("/Library/Application Support/LogMeIn Hamachi"),
	}
	// A WireGuard app tunnel that is configured counts as installed even if
	// the app was moved.
	if strings.Contains(m.NCList, "[VPN:com.wireguard.macos]") {
		m.Installed["wireguard"] = true
	}
	return meshTools(m), nil
}
