//go:build !darwin && !windows

package checks

import "context"

// The outbound-firewall suggestion is for macOS and Windows.
func outboundFirewalls(context.Context) ([]string, outboundAdvice, bool) {
	return nil, outboundAdvice{}, false
}
