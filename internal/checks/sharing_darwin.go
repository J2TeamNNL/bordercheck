package checks

// OS gathering for sharing on macOS. Each setting is read as one key (never a
// whole preferences file, some of which hold network passwords or device
// names), without root and without a privacy prompt.

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// plistKey returns one key of a property list file as text, or "".
func plistKey(ctx context.Context, path, key string) string {
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	out, err := sysx.Run(ctx, plutil, "-extract", key, "raw", "-o", "-", path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// defaultsKey reads one key of the user's preferences through cfprefsd.
func defaultsKey(ctx context.Context, args ...string) string {
	out, err := sysx.Run(ctx, "/usr/bin/defaults", args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func shareServicesOS(ctx context.Context) ([]shareService, msg.Text, error) {
	disabled, err := sysx.Run(ctx, "/bin/launchctl", "print-disabled", "system")
	if err != nil {
		return nil, nil, err
	}
	ns, _ := sysx.Run(ctx, "/usr/sbin/netstat", "-an", "-p", "tcp")
	f := map[string]string{}

	// AirDrop: a configuration profile wins over the user's own choice.
	var managed []string
	if u, err := user.Current(); err == nil {
		managed = append(managed, filepath.Join("/Library/Managed Preferences", u.Username, "com.apple.sharingd.plist"))
	}
	managed = append(managed, "/Library/Managed Preferences/com.apple.sharingd.plist")
	for _, p := range managed {
		if v := plistKey(ctx, p, "DiscoverableMode"); v != "" {
			f["airdrop"] = v
			break
		}
	}
	if f["airdrop"] == "" {
		f["airdrop"] = defaultsKey(ctx, "read", "com.apple.sharingd", "DiscoverableMode")
	}

	var notes msg.Text
	if cups, err := sysx.Run(ctx, "/usr/sbin/cupsctl"); err == nil {
		f["cups"] = cups
	} else {
		notes = append(notes, msg.P("sharing.note.unknown", "what", "Printer Sharing"))
	}
	f["nat"] = plistKey(ctx, "/Library/Preferences/SystemConfiguration/com.apple.nat.plist", "NAT.Enabled")
	f["media_home"] = defaultsKey(ctx, "read", "com.apple.amp.mediasharingd", "home-sharing-enabled")
	f["media_public"] = defaultsKey(ctx, "read", "com.apple.amp.mediasharingd", "public-sharing-enabled")
	f["bluetooth"] = defaultsKey(ctx, "-currentHost", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled")
	f["assetcache"] = plistKey(ctx, "/Library/Preferences/com.apple.AssetCache.plist", "Activated")
	return macShareServices(f, disabled, ns), notes, nil
}
