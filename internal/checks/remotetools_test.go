package checks

import (
	"slices"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// TeamViewer's helper LaunchDaemon as installed on a Mac (captured, unchanged
// apart from layout): started on demand through its Mach service, so it does
// not make TeamViewer start by itself.
const tvHelperPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>AssociatedBundleIdentifiers</key><array><string>com.teamviewer.TeamViewer</string></array>
<key>Label</key><string>com.teamviewer.Helper</string>
<key>MachServices</key><dict><key>com.teamviewer.Helper.xpc</key><true/></dict>
<key>Program</key><string>/Library/PrivilegedHelperTools/com.teamviewer.Helper</string>
<key>ProgramArguments</key><array><string>/Library/PrivilegedHelperTools/com.teamviewer.Helper</string></array>
</dict></plist>`

// A synthetic service LaunchDaemon in the usual shape.
const tvServicePlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.teamviewer.teamviewer_service</string>
<key>ProgramArguments</key><array><string>/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Service</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>`

// AnyDesk's system.conf keys as found on a Mac where unattended access is
// off (captured, values replaced), and the same with a profile password set
// (synthetic hash).
const anyDeskOff = `ad.anynet.alias=demo@ad
ad.anynet.id=123456789
ad.security.permission_profiles._default.permissions.sas=true
ad.security.permission_profiles._unattended_access.permissions.sas=true
ad.security.permission_profiles.version=1
`

const anyDeskSecretHash = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

func sampleRemoteMac(svcs []remoteService) check.Result {
	raw := rcRaw{
		Procs:      []proc{{exe: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk"}},
		Launchd:    []rcLaunchd{{Label: "com.teamviewer.Helper"}, {Label: "com.teamviewer.teamviewer_service", Auto: true}},
		Installed:  map[string]string{"teamviewer": "/Applications/TeamViewer.app", "anydesk": "/Applications/AnyDesk.app", "rustdesk": "/Applications/RustDesk.app"},
		Unattended: map[string]string{"anydesk": "unattended-access password set in /etc/anydesk/system.conf"},
	}
	t, inst, notes := remoteTools(raw)
	return evalRemoteAccessAll(append(svcs, t...), notes, nil, inst)
}

func TestRemoteToolsSample(t *testing.T) {
	r := sampleRemoteMac(nil)
	if r.Status != check.Fail || r.Severity != check.High ||
		!strings.Contains(r.Summary, "AnyDesk lets people connect without anyone at this computer approving") ||
		!strings.Contains(r.Summary, "TeamViewer is running or starts by itself") ||
		!strings.Contains(r.Summary, "Could not tell whether TeamViewer allows unattended access") ||
		!strings.Contains(r.Fix, "AnyDesk: if it is not needed") || !strings.Contains(r.Fix, "TeamViewer: if it is not needed") {
		t.Errorf("%+v", r)
	}
	ev := strings.Join(r.Evidence, "\n")
	if !strings.Contains(ev, "RustDesk: installed (/Applications/RustDesk.app), not running") ||
		!strings.Contains(ev, "TeamViewer: starts by itself (com.teamviewer.teamviewer_service)") ||
		strings.Contains(ev, "com.teamviewer.Helper") {
		t.Errorf("evidence: %s", ev)
	}
}

func TestRemoteTools(t *testing.T) {
	// Installed only (as on the Mac this was written on: both apps in
	// /Applications, TeamViewer's on-demand helpers, nothing running): pass.
	_, auto, ok := launchdAuto(tvHelperPlist)
	if !ok || auto {
		t.Fatalf("helper plist: ok=%v auto=%v", ok, auto)
	}
	raw := rcRaw{Launchd: []rcLaunchd{{Label: "com.teamviewer.Helper", Auto: auto}},
		Installed: map[string]string{"teamviewer": "/Applications/TeamViewer.app", "anydesk": "/Applications/AnyDesk.app"}}
	svcs, inst, notes := remoteTools(raw)
	r := evalRemoteAccessAll(svcs, notes, nil, inst)
	if r.Status != check.Pass || len(inst) != 2 || len(svcs) != 0 {
		t.Errorf("installed only: %+v", r)
	}
	if label, auto, _ := launchdAuto(tvServicePlist); label != "com.teamviewer.teamviewer_service" || !auto {
		t.Errorf("service plist: %s %v", label, auto)
	}

	// Allowed by policy: counted with the other allowed services.
	raw = rcRaw{Procs: []proc{{exe: "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer"}}}
	svcs, inst, notes = remoteTools(raw)
	r = evalRemoteAccessAll(svcs, notes, []string{"teamviewer"}, inst)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "On but allowed by policy: TeamViewer") {
		t.Errorf("allowed: %+v", r)
	}

	// Windows: a service that starts automatically, a stopped manual one, and
	// a ScreenConnect access agent (service name with its instance ID).
	raw = rcRaw{Services: parseServiceLines("AnyDesk|Stopped|Automatic\r\nTeamViewer|Stopped|Manual\r\n" +
		"ScreenConnect Client (0123456789abcdef)|Running|Automatic\r\n")}
	svcs, _, _ = remoteTools(raw)
	var names []string
	for _, s := range svcs {
		names = append(names, s.ID+": "+s.How)
	}
	if !slices.Equal(names, []string{"anydesk: service AnyDesk starts automatically",
		"screenconnect: service ScreenConnect Client (0123456789abcdef) running"}) {
		t.Errorf("windows: %q", names)
	}

	// Linux: systemd units, with the template unit file itself left out.
	units := systemdUnitStates("anydesk.service enabled enabled\nteamviewerd.service disabled enabled\nvncserver@.service static -\n"+
		"chrome-remote-desktop@.service enabled enabled\nssh.service enabled enabled\n",
		"chrome-remote-desktop@demo.service loaded active running Chrome Remote Desktop\nanydesk.service loaded active running AnyDesk\n")
	if len(units) != 2 || units["anydesk.service"] != "enabled,active" || units["chrome-remote-desktop@demo.service"] != "active" {
		t.Errorf("units: %v", units)
	}
	// Chrome Remote Desktop turned on for unattended access: fail high even
	// when the host is not running right now.
	raw = rcRaw{Installed: map[string]string{"chrome-remote-desktop": "/opt/google/chrome-remote-desktop"},
		Unattended: map[string]string{"chrome-remote-desktop": "remote access turned on (~/.config/chrome-remote-desktop/host#ab.json)"}}
	svcs, _, _ = remoteTools(raw)
	r = evalRemoteAccessAll(svcs, nil, nil, nil)
	if r.Status != check.Fail || r.Severity != check.High || !strings.Contains(r.Fix, "remotedesktop.google.com/access") {
		t.Errorf("crd: %+v", r)
	}
	// Unattended settings left behind by an app that is gone are not a finding.
	raw = rcRaw{Unattended: map[string]string{"anydesk": "unattended-access password set in ~/.anydesk/system.conf"}}
	if svcs, _, _ := remoteTools(raw); len(svcs) != 0 {
		t.Errorf("leftover config: %+v", svcs)
	}
	// A VNC viewer is not a server.
	if svcs, _, _ := remoteTools(rcRaw{Procs: []proc{{exe: "/usr/bin/vncviewer"}, {exe: "/usr/bin/xtigervncviewer"}}}); len(svcs) != 0 {
		t.Errorf("viewer: %+v", svcs)
	}
	// The OS services keep their own severities next to the tools.
	r = evalRemoteAccessAll([]remoteService{{ID: "guest", Name: "Guest user", On: true, Fix: msg.P("remote.fix.macGuest")}}, nil, nil, nil)
	if r.Status != check.Warn || r.Severity != check.Medium {
		t.Errorf("guest: %+v", r)
	}
	if !slices.Contains(policy.RemoteAccessServices, "teamviewer") || !slices.Contains(policy.RemoteAccessServices, "ssh") {
		t.Error("RemoteAccessServices must hold the OS services and the tools")
	}
	for _, tool := range rcTools {
		if !slices.Contains(policy.RemoteControlTools, tool.ID) {
			t.Errorf("%s missing from policy.RemoteControlTools", tool.ID)
		}
	}
}

func TestAnyDeskUnattended(t *testing.T) {
	for conf, want := range map[string]bool{
		anyDeskOff: false,
		anyDeskOff + "ad.security.permission_profiles._unattended_access.pwd=" + anyDeskSecretHash + "\n": true,
		anyDeskOff + "ad.security.permission_profiles._unattended_access.pwd=\n":                          false, // empty = off
		anyDeskOff + "ad.security.permission_profiles.custom1.pwd=" + anyDeskSecretHash + "\n":            true,
		"ad.anynet.pwd_hash=" + anyDeskSecretHash + "\nad.anynet.pwd_salt=abc\n":                          true,
		"ad.anynet.pkey=AAAA\n": false,
	} {
		if got := anyDeskUnattended(conf); got != want {
			t.Errorf("%q: got %v, want %v", conf, got, want)
		}
	}
	// The hash never reaches a result.
	raw := rcRaw{Installed: map[string]string{"anydesk": "/Applications/AnyDesk.app"},
		Unattended: map[string]string{"anydesk": "unattended-access password set in /etc/anydesk/system.conf"}}
	svcs, _, _ := remoteTools(raw)
	r := evalRemoteAccessAll(svcs, nil, nil, nil)
	all := r.Summary + r.Fix + strings.Join(r.Evidence, " ")
	if strings.Contains(all, anyDeskSecretHash) || r.Status != check.Fail {
		t.Errorf("%+v", r)
	}
}
