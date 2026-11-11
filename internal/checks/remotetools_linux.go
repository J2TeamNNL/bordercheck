package checks

import (
	"context"
	"os"
	"path/filepath"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// remoteToolsOS reads the process table, systemd's enabled and active units,
// install folders, AnyDesk's config files where readable, and Chrome Remote
// Desktop's host config (~/.config/chrome-remote-desktop/host#….json, written
// when remote access is turned on for this user).
func remoteToolsOS(ctx context.Context) (rcRaw, error) {
	home, _ := os.UserHomeDir()
	procs, err := listProcs(ctx)
	if err != nil {
		return rcRaw{}, err
	}
	raw := rcRaw{Procs: procs, Unattended: map[string]string{}}
	if _, ok := sysx.Find("systemctl"); ok {
		files, _ := sysx.Run(ctx, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain")
		active, _ := sysx.Run(ctx, "systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--plain")
		raw.Units = systemdUnitStates(files, active)
	}
	raw.Installed = rcInstalled(map[string][]string{
		"teamviewer":            {"/opt/teamviewer", "/usr/bin/teamviewer"},
		"anydesk":               {"/usr/bin/anydesk", "/usr/local/bin/anydesk"},
		"rustdesk":              {"/usr/bin/rustdesk", "/usr/lib/rustdesk"},
		"chrome-remote-desktop": {"/opt/google/chrome-remote-desktop"},
		"screenconnect":         {"/opt/connectwisecontrol-*", "/opt/screenconnect-*"},
		"vnc":                   {"/usr/bin/vncserver-x11-serviced", "/usr/bin/x11vnc", "/usr/bin/x0vncserver"},
	})
	if w := anyDeskUnattendedIn("/etc/anydesk", filepath.Join(home, ".anydesk")); w != "" {
		raw.Unattended["anydesk"] = w
	}
	if p, ok := installedAt(filepath.Join(home, ".config", "chrome-remote-desktop", "host#*.json")); ok {
		raw.Unattended["chrome-remote-desktop"] = "remote access turned on (" + tildePath(home, p) + ")"
	}
	return raw, nil
}
