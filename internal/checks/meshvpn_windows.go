package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winMeshServices prints "name|status" for the private-network services; a
// standard user may read service states.
const winMeshServices = `Get-Service -Name 'ZeroTierOneService','netbird','Hamachi2Svc','WireGuardTunnel$*' -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}' -f $_.Name, $_.Status }`

// meshToolsOS reads the process table, service states, the interfaces (their
// Windows names: "ZeroTier One [network]", "wt0", "Hamachi"), and the
// ZeroTier and NetBird folders under ProgramData where they are readable.
func meshToolsOS(ctx context.Context) ([]meshTool, error) {
	procs, _ := listProcs(ctx)
	m := meshRaw{GOOS: "windows", Procs: procs, Ifaces: upInterfaces(), NebulaRules: nebulaRules(procs)}
	out, _ := sysx.PowerShell(ctx, winMeshServices)
	m.Services = parseNameStatus(out)
	pd, pf, pf86 := os.Getenv("ProgramData"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")
	join := func(base string, parts ...string) string {
		if base == "" {
			return ""
		}
		return filepath.Join(append([]string{base}, parts...)...)
	}
	ztHome := join(pd, "ZeroTier", "One")
	if ztHome != "" {
		m.ZTNetworks, m.ZTNetworksKnown = zeroTierNetworks(ztHome)
	}
	m.NetbirdBlock = netbirdBlockInbound(join(pd, "Netbird", "config.json"))
	m.Installed = map[string]bool{
		"zerotier":  anyExists(ztHome, join(pf86, "ZeroTier", "One"), join(pf, "ZeroTier", "One")),
		"netbird":   anyExists(join(pf, "Netbird", "netbird.exe")),
		"wireguard": anyExists(join(pf, "WireGuard", "wireguard.exe")),
		"hamachi":   anyExists(join(pf86, "LogMeIn Hamachi"), join(pf, "LogMeIn Hamachi")),
	}
	for name := range m.Services {
		switch n := strings.ToLower(name); {
		case n == "zerotieroneservice":
			m.Installed["zerotier"] = true
		case n == "netbird":
			m.Installed["netbird"] = true
		case n == "hamachi2svc":
			m.Installed["hamachi"] = true
		case strings.HasPrefix(n, "wireguardtunnel$"):
			m.Installed["wireguard"] = true
		}
	}
	return meshTools(m), nil
}
