//go:build !darwin

package checks

// The outbound-firewall suggestion is for macOS only.
func outboundFirewalls() ([]string, bool) { return nil, false }
