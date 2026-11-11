package checks

// File reading shared by the mesh-vpn gatherers of every OS. Only names,
// counts and one boolean are kept; config files that also hold keys are
// parsed for that boolean alone and never stored or shown.

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// readCapped reads a regular file of at most 1 MiB.
func readCapped(p string) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, os.ErrInvalid
	}
	return os.ReadFile(p)
}

// upInterfaces lists the network interfaces that are up, by name.
func upInterfaces() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 {
			out = append(out, i.Name)
		}
	}
	return out
}

// zeroTierNetworks counts the networks.d/*.conf files in ZeroTier's home
// folder (one per joined network); ok is false when the folder can't be listed.
func zeroTierNetworks(home string) (n int, ok bool) {
	entries, err := os.ReadDir(filepath.Join(home, "networks.d"))
	if err != nil {
		return 0, false
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".conf") && !strings.HasSuffix(e.Name(), ".local.conf") {
			n++
		}
	}
	return n, true
}

// netbirdBlockInbound reads BlockInbound ("Block inbound connections",
// `netbird up --block-inbound`) from the first readable NetBird config. The
// file also holds the WireGuard private key, which is never kept: only this
// field is decoded.
func netbirdBlockInbound(paths ...string) *bool {
	for _, p := range paths {
		b, err := readCapped(p)
		if err != nil {
			continue
		}
		if v := parseNetbirdBlockInbound(b); v != nil {
			return v
		}
	}
	return nil
}

func parseNetbirdBlockInbound(b []byte) *bool {
	var c struct{ BlockInbound *bool }
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	if c.BlockInbound == nil {
		f := false // NetBird's default, and how older clients without the setting behave
		return &f
	}
	return c.BlockInbound
}

// nebulaRules counts the inbound firewall rules of the first running nebula
// whose config (-config) is a readable file, -1 if none could be read.
func nebulaRules(procs []proc) int {
	for _, p := range procs {
		if procName(p.exe) != "nebula" {
			continue
		}
		c := nebulaConfigArg(p)
		if c == "" {
			continue
		}
		if b, err := readCapped(c); err == nil {
			return nebulaInboundRules(string(b))
		}
	}
	return -1
}

// anyExists reports whether any of the paths exists.
func anyExists(paths ...string) bool {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// parseNameStatus reads lines of "name|status" (Windows services).
func parseNameStatus(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if name, st, ok := strings.Cut(strings.TrimSpace(line), "|"); ok && name != "" {
			m[name] = strings.TrimSpace(st)
		}
	}
	return m
}

// linuxDevType reads DEVTYPE from a /sys/class/net/*/uevent file.
func linuxDevType(uevent string) string {
	for _, line := range strings.Split(uevent, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "DEVTYPE="); ok {
			return v
		}
	}
	return ""
}
