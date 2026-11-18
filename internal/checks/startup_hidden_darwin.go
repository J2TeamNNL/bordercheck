package checks

import (
	"context"
	"os"
	"strings"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// gatherHidden on a Mac: the hosts file, and this user's programs running from
// a temporary or download folder (or /Users/Shared) that are not signed by
// Apple or a Developer ID. Defender is not here.
func gatherHidden(ctx context.Context, home string) hiddenFacts {
	x := hiddenFacts{HostsPath: "/etc/hosts", ExclusionsRead: true}
	if b, err := os.ReadFile(x.HostsPath); err == nil {
		x.Hosts = string(b)
	}
	out, err := sysx.Run(ctx, "/bin/ps", "-xww", "-o", "comm=")
	if err != nil {
		return x
	}
	env := startupEnv{home: home, goos: "darwin"}
	seen := map[string]bool{}
	for _, p := range strings.Split(out, "\n") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] || !strings.HasPrefix(p, "/") {
			continue
		}
		seen[p] = true
		if env.suspiciousPlace(p) == "" || strings.HasPrefix(env.suspiciousPlace(p), "a hidden folder") {
			continue
		}
		if strings.Contains(p, "/go-build") { // `go run` builds here
			continue
		}
		// Apple Silicon runs nothing unsigned, so ad-hoc signatures (which
		// anyone can make) don't count: Apple's or a Developer ID's do.
		if _, err := sysx.Run(ctx, "/usr/bin/codesign", "-v", "-R=anchor apple generic", p); err != nil {
			x.Running = append(x.Running, p)
		}
	}
	return x
}
