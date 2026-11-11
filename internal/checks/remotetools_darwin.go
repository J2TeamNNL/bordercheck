package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// remoteToolsOS reads the process table, the LaunchAgents and LaunchDaemons
// whose label belongs to a known tool, the apps in /Applications, AnyDesk's
// config files (/etc/anydesk and ~/.anydesk, readable by the user on this
// Mac) and Chrome Remote Desktop's on/off file. Helpers registered through
// the Background Task Management database (SMAppService) are not listed
// there and can only be seen while they run.
func remoteToolsOS(ctx context.Context) (rcRaw, error) {
	home, _ := os.UserHomeDir()
	procs, err := listProcs(ctx)
	if err != nil {
		return rcRaw{}, err
	}
	raw := rcRaw{Procs: procs, Unattended: map[string]string{}}
	pats := rcLaunchdPatterns()
	for _, dir := range []string{filepath.Join(home, "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			name, ok := strings.CutSuffix(e.Name(), ".plist")
			if !ok || !nameMatch(name, pats) || ctx.Err() != nil {
				continue
			}
			doc, err := plistXML(ctx, filepath.Join(dir, e.Name()))
			if err != nil || doc == "" {
				continue
			}
			if label, auto, ok := launchdAuto(doc); ok {
				if label == "" {
					label = name
				}
				raw.Launchd = append(raw.Launchd, rcLaunchd{Label: label, Auto: auto})
			}
		}
	}
	apps := func(names ...string) []string {
		var out []string
		for _, n := range names {
			out = append(out, filepath.Join("/Applications", n), filepath.Join(home, "Applications", n))
		}
		return out
	}
	raw.Installed = rcInstalled(map[string][]string{
		"teamviewer":            apps("TeamViewer.app", "TeamViewerHost.app", "TeamViewer QuickSupport.app"),
		"anydesk":               apps("AnyDesk.app"),
		"rustdesk":              apps("RustDesk.app"),
		"chrome-remote-desktop": {"/Library/LaunchAgents/org.chromium.chromoting.plist"},
		"splashtop":             apps("Splashtop Streamer.app"),
		"screenconnect":         {"/opt/connectwisecontrol-*", "/opt/screenconnect-*"},
		"vnc":                   apps("RealVNC/VNC Server.app", "VNC Server.app"),
	})
	if w := anyDeskUnattendedIn("/etc/anydesk", filepath.Join(home, ".anydesk")); w != "" {
		raw.Unattended["anydesk"] = w
	}
	// Chromium's remoting/host/mac/constants_mac.cc: the host runs only while
	// this file exists, i.e. remote access is turned on for this computer.
	if _, err := os.Stat("/Library/PrivilegedHelperTools/org.chromium.chromoting.me2me_enabled"); err == nil {
		raw.Unattended["chrome-remote-desktop"] = "remote access turned on (host registered to an account)"
	}
	return raw, nil
}
