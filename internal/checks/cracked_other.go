//go:build !windows

package checks

import "context"

// On macOS and Linux the lasting trace a crack leaves is in the hosts file.
func crackFactsOS(context.Context) crackFacts {
	return crackFacts{HostsPath: "/etc/hosts"}
}
