package checks

import (
	"context"
	"path/filepath"
)

// meshToolsOS reads the process table, /sys/class/net (interfaces and their
// DEVTYPE, which is "wireguard" for WireGuard), ZeroTier's networks.d (often
// root-only) and NetBird's config (often root-only).
func meshToolsOS(ctx context.Context) ([]meshTool, error) {
	procs, _ := listProcs(ctx)
	m := meshRaw{GOOS: "linux", Procs: procs, Ifaces: upInterfaces(), IfaceType: map[string]string{}, NebulaRules: nebulaRules(procs)}
	for _, i := range m.Ifaces {
		if b, err := readCapped(filepath.Join("/sys/class/net", i, "uevent")); err == nil {
			m.IfaceType[i] = linuxDevType(string(b))
		}
	}
	const ztHome = "/var/lib/zerotier-one"
	m.ZTNetworks, m.ZTNetworksKnown = zeroTierNetworks(ztHome)
	m.NetbirdBlock = netbirdBlockInbound("/etc/netbird/config.json")
	bins := func(name string) []string {
		return []string{"/usr/bin/" + name, "/usr/sbin/" + name, "/usr/local/bin/" + name, "/snap/bin/" + name}
	}
	m.Installed = map[string]bool{
		"zerotier":  anyExists(append(bins("zerotier-one"), ztHome)...),
		"netbird":   anyExists(bins("netbird")...),
		"wireguard": anyExists(append(bins("wg-quick"), "/etc/wireguard")...),
		"nebula":    anyExists(append(bins("nebula"), "/etc/nebula")...),
		"hamachi":   anyExists(append(bins("hamachi"), "/opt/logmein-hamachi")...),
	}
	return meshTools(m), nil
}
