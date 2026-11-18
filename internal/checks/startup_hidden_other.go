//go:build !darwin && !windows

package checks

import (
	"context"
	"os"
	"path/filepath"
)

// gatherHidden elsewhere: the hosts file, and on Linux this user's programs
// running from /tmp, /var/tmp or /dev/shm (Linux has no code signatures to
// tell an installer from a dropper, so any program there counts).
func gatherHidden(_ context.Context, home string) hiddenFacts {
	x := hiddenFacts{HostsPath: "/etc/hosts", ExclusionsRead: true}
	if b, err := os.ReadFile(x.HostsPath); err == nil {
		x.Hosts = string(b)
	}
	env := startupEnv{home: home, goos: "linux"}
	exes, _ := filepath.Glob("/proc/[0-9]*/exe")
	seen := map[string]bool{}
	for _, l := range exes {
		p, err := os.Readlink(l)
		if err != nil || seen[p] {
			continue
		}
		seen[p] = true
		if why := env.suspiciousPlace(p); why == "a temporary folder" {
			x.Running = append(x.Running, p)
		}
	}
	return x
}
