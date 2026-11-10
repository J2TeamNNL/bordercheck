package checks

// OS gathering for os-updates, screen-lock and remote-access on macOS. Every
// source here is readable without root and without a privacy (TCC) prompt.

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

const plutil = "/usr/bin/plutil"

// plistXML returns a property list file as XML, or "" if it doesn't exist.
func plistXML(ctx context.Context, path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", nil
	}
	return sysx.Run(ctx, plutil, "-convert", "xml1", "-o", "-", path)
}

func updateFactsOS(ctx context.Context) (updateFacts, error) {
	ver, err := sysx.Run(ctx, "/usr/bin/sw_vers", "-productVersion")
	if err != nil {
		return updateFacts{}, err
	}
	su, err := plistXML(ctx, "/Library/Preferences/com.apple.SoftwareUpdate.plist")
	if err != nil || su == "" {
		f := updateFacts{Family: "macos", Key: "macos", Version: strings.TrimSpace(ver), Name: "macOS " + strings.TrimSpace(ver)}
		f.Notes = append(f.Notes, "Could not read Software Update's settings.")
		return f, nil
	}
	managed, _ := plistXML(ctx, "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist")
	return macUpdateFacts(ver, su, managed)
}

func browsersOS(ctx context.Context) []browserInfo {
	home, _ := os.UserHomeDir()
	apps := []struct{ id, app, exe string }{
		{"chrome", "Google Chrome.app", "Google Chrome"},
		{"edge", "Microsoft Edge.app", "Microsoft Edge"},
		{"firefox", "Firefox.app", "firefox"},
		{"brave", "Brave Browser.app", "Brave Browser"},
	}
	var out []browserInfo
	for _, a := range apps {
		for _, dir := range []string{"/Applications", filepath.Join(home, "Applications")} {
			bundle := filepath.Join(dir, a.app)
			exe := filepath.Join(bundle, "Contents", "MacOS", a.exe)
			if _, err := os.Stat(exe); err != nil {
				continue
			}
			v, _ := sysx.Run(ctx, plutil, "-extract", "CFBundleShortVersionString", "raw", "-o", "-",
				filepath.Join(bundle, "Contents", "Info.plist"))
			if b, ok := browserAt(a.id, exe, strings.TrimSpace(v)); ok {
				out = append(out, b)
			}
		}
	}
	return out
}

func screenLockOS(ctx context.Context) (lockFacts, error) {
	// sysadminctl -screenLock status needs neither root nor a password; it
	// answers on stderr.
	sa, err := sysx.RunCombined(ctx, "/usr/sbin/sysadminctl", "-screenLock", "status")
	if err != nil {
		return lockFacts{}, err
	}
	pm, err := sysx.Run(ctx, "/usr/bin/pmset", "-g", "custom")
	if err != nil {
		return lockFacts{}, err
	}
	return macLockFacts(sa, pm, macScreenSaverIdle(ctx))
}

// macScreenSaverIdle returns the screen saver's idle time in seconds from a
// configuration profile or the user's ByHost preferences, or -1 if unset.
func macScreenSaverIdle(ctx context.Context) int {
	var managed []string
	if u, err := user.Current(); err == nil {
		managed = append(managed, filepath.Join("/Library/Managed Preferences", u.Username, "com.apple.screensaver.plist"))
	}
	managed = append(managed, "/Library/Managed Preferences/com.apple.screensaver.plist")
	for _, p := range managed {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if out, err := sysx.Run(ctx, plutil, "-extract", "idleTime", "raw", "-o", "-", p); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil {
				return n
			}
		}
	}
	out, err := sysx.Run(ctx, "/usr/bin/defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime")
	if err != nil {
		return -1
	}
	if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil {
		return n
	}
	return -1
}

func remoteServicesOS(ctx context.Context) ([]remoteService, []string, error) {
	disabled, err := sysx.Run(ctx, "/bin/launchctl", "print-disabled", "system")
	if err != nil {
		return nil, nil, err
	}
	ns, err := sysx.Run(ctx, "/usr/sbin/netstat", "-an", "-p", "tcp")
	if err != nil {
		return nil, nil, err
	}
	ard := false
	if b, err := os.ReadFile("/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd"); err == nil {
		ard = strings.Contains(string(b), "enabled")
	}
	// Only the GuestEnabled key: the rest of this file can hold personal text.
	guest, _ := sysx.Run(ctx, plutil, "-extract", "GuestEnabled", "raw", "-o", "-", "/Library/Preferences/com.apple.loginwindow.plist")
	return macRemoteServices(disabled, ns, ard, guest), nil, nil
}
