package checks

import (
	"context"
	"os"
	"path/filepath"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winRCServices prints "name|status|start type" for the remote-control
// services; a standard user may read service states.
const winRCServices = `Get-Service -Name 'TeamViewer','AnyDesk*','RustDesk','chromoting','SplashtopRemoteService','ScreenConnect Client*','vncserver','tvnserver','uvnc_service' -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.Status, $_.StartType }`

// remoteToolsOS reads the process table, the services, install folders and
// AnyDesk's config files where readable.
func remoteToolsOS(ctx context.Context) (rcRaw, error) {
	procs, err := listProcs(ctx)
	if err != nil {
		return rcRaw{}, err
	}
	raw := rcRaw{Procs: procs, Unattended: map[string]string{}}
	out, _ := sysx.PowerShell(ctx, winRCServices)
	raw.Services = parseServiceLines(out)
	pf, pf86, pd, ad := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramData"), os.Getenv("APPDATA")
	in := func(base string, parts ...string) string {
		if base == "" {
			return ""
		}
		return filepath.Join(append([]string{base}, parts...)...)
	}
	raw.Installed = rcInstalled(map[string][]string{
		"teamviewer":            {in(pf, "TeamViewer", "TeamViewer.exe"), in(pf86, "TeamViewer", "TeamViewer.exe")},
		"anydesk":               {in(pf86, "AnyDesk", "AnyDesk.exe"), in(pf, "AnyDesk", "AnyDesk.exe")},
		"rustdesk":              {in(pf, "RustDesk", "rustdesk.exe")},
		"chrome-remote-desktop": {in(pf86, "Google", "Chrome Remote Desktop"), in(pf, "Google", "Chrome Remote Desktop")},
		"splashtop":             {in(pf86, "Splashtop", "Splashtop Remote", "Server"), in(pf, "Splashtop", "Splashtop Remote", "Server")},
		"screenconnect":         {in(pf86, "ScreenConnect Client*"), in(pf, "ScreenConnect Client*")},
		"vnc": {in(pf, "RealVNC", "VNC Server"), in(pf, "TightVNC", "tvnserver.exe"),
			in(pf, "uvnc bvba", "UltraVNC", "winvnc.exe")},
	})
	if w := anyDeskUnattendedIn(in(pd, "AnyDesk"), in(ad, "AnyDesk")); w != "" {
		raw.Unattended["anydesk"] = w
	}
	return raw, nil
}
