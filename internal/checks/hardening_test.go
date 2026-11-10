package checks

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Samples marked "captured" are real output from a Mac (macOS 27.2), with
// addresses changed. Windows and Linux samples are written from the documented
// formats of each tool and file, not captured from a machine.

func ptrTo[T any](v T) *T { return &v }

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func TestParsePlist(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
	<key>A</key><true/><key>B</key><false/><key>N</key><integer>4</integer><key>R</key><real>1.5</real>
	<key>S</key><string>x &amp; y</string><key>E</key><array/><key>D</key><dict/>
	<key>T</key><date>2026-11-09T20:10:44Z</date>
	<key>L</key><array><dict><key>k</key><string>v</string></dict><string>w</string></array>
</dict></plist>`
	m, err := plistDict(doc)
	if err != nil {
		t.Fatal(err)
	}
	if m["A"] != true || m["B"] != false || m["N"] != int64(4) || m["R"] != 1.5 || m["S"] != "x & y" ||
		m["T"] != mustTime(t, "2026-11-09T20:10:44Z") || len(m["L"].([]any)) != 2 || m["E"] != nil && len(m["E"].([]any)) != 0 {
		t.Errorf("got %#v", m)
	}
}

func TestMacUpdateFacts(t *testing.T) {
	su, err := os.ReadFile("testdata/macos-softwareupdate.xml") // captured
	if err != nil {
		t.Fatal(err)
	}
	f, err := macUpdateFacts("27.2\n", string(su), "")
	if err != nil {
		t.Fatal(err)
	}
	want := []pendingUpdate{{"macOS 27.2.1", mustTime(t, "2026-11-09T20:10:53Z")}}
	if f.Name != "macOS 27.2" || !*f.AutoUpdate || !f.LastCheck.Equal(mustTime(t, "2026-11-09T20:10:44Z")) ||
		!slices.Equal(f.Pending, want) {
		t.Fatalf("got %+v", f)
	}
	opts := policy.Default().Checks.OSUpdates

	r := evalOSUpdates(f, nil, opts, mustTime(t, "2026-11-11T09:00:00Z"))
	if r.Status != check.Pass || !strings.Contains(r.Summary, "macOS 27.2.1 is ready to install (found 1 day ago)") {
		t.Errorf("fresh update: got %s %q", r.Status, r.Summary)
	}
	r = evalOSUpdates(f, nil, opts, mustTime(t, "2026-12-01T09:00:00Z"))
	if r.Status != check.Fail || !strings.Contains(r.Summary, "macOS 27.2.1 has been waiting to be installed for 21 days") ||
		!strings.Contains(r.Summary, "last checked for updates 21 days ago") {
		t.Errorf("overdue: got %s %q", r.Status, r.Summary)
	}

	// A managed profile that turns downloads off, and an old macOS.
	managed := `<plist version="1.0"><dict><key>AutomaticDownload</key><false/></dict></plist>`
	f, _ = macUpdateFacts("14.7.1", string(su), managed)
	r = evalOSUpdates(f, nil, opts, mustTime(t, "2026-11-10T09:00:00Z"))
	if r.Status != check.Fail || !strings.Contains(r.Summary, "macOS 14.7.1 is older than the minimum version 15") ||
		!strings.Contains(r.Summary, "Automatic updates are off (Download new updates when available)") ||
		!strings.Contains(r.Fix, "Software Update") {
		t.Errorf("old + managed: got %s %q", r.Status, r.Summary)
	}
	opts.RequireAutoUpdate = ptrTo(false)
	opts.MinOSVersions = map[string]string{"macos": ""}
	if r := evalOSUpdates(f, nil, opts, mustTime(t, "2026-11-10T09:00:00Z")); r.Status != check.Pass {
		t.Errorf("rules switched off: got %s %q", r.Status, r.Summary)
	}
}

func TestEvalBrowsers(t *testing.T) {
	now := mustTime(t, "2026-11-10T12:00:00Z")
	f := updateFacts{Family: "macos", Name: "macOS 27.2", Key: "macos", Version: "27.2", PendingKnown: true}
	bs := []browserInfo{
		{"chrome", "Google Chrome", "157.0.8103.39", now.Add(-2 * time.Hour)},
		{"firefox", "Firefox", "156.0", mustTime(t, "2026-09-10T04:09:15Z")}, // captured: 61 days old
	}
	opts := policy.Default().Checks.OSUpdates
	r := evalOSUpdates(f, bs, opts, now)
	if r.Status != check.Fail || !strings.Contains(r.Summary, "Firefox 156.0 has not updated for 61 days") || strings.Contains(r.Summary, "Chrome") {
		t.Errorf("got %s %q", r.Status, r.Summary)
	}
	opts.MaxBrowserAgeDays = 0
	opts.MinBrowserVersions = map[string]string{"chrome": "158"}
	if r := evalOSUpdates(f, bs, opts, now); r.Status != check.Fail || !strings.Contains(r.Summary, "Google Chrome 157.0.8103.39 is older than the minimum 158") {
		t.Errorf("min version: got %s %q", r.Status, r.Summary)
	}
	opts.CheckBrowsers = ptrTo(false) // the caller then passes no browsers
	if r := evalOSUpdates(f, nil, opts, now); r.Status != check.Pass {
		t.Errorf("browsers off: got %s %q", r.Status, r.Summary)
	}
}

func TestVersionLess(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"14.7.1", "15", true}, {"15", "15", false}, {"15.0.1", "15", false}, {"27.2", "15", false},
		{"20.04", "22.04", true}, {"22.04.3 LTS", "22.04", false}, {"156.0b1", "157", true}, {"19045", "26100", true},
	} {
		if got := versionLess(tc.a, tc.b); got != tc.want {
			t.Errorf("versionLess(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

func TestWinUpdateFacts(t *testing.T) {
	// Researched sample of winUpdateScript's output on Windows 11 24H2.
	out := "build=26100\r\nubr=2605\r\ndisplay_version=24H2\r\nno_auto_update=\r\nau_options=\r\nwuauserv_start=Manual\r\n" +
		"pause_until=\r\nreboot_required=False\r\nlast_search=2026-11-09T07:12:40Z\r\nlast_hotfix=2026-10-15\r\n"
	f := winUpdateFacts(kvLines(out))
	opts := policy.Default().Checks.OSUpdates
	r := evalOSUpdates(f, nil, opts, mustTime(t, "2026-11-10T12:00:00Z"))
	if r.Status != check.Pass || !strings.Contains(r.Summary, "Windows 11 24H2 (build 26100.2605)") {
		t.Errorf("current: got %s %q", r.Status, r.Summary)
	}
	// Windows 10, service disabled, paused, restart pending, no patch since July.
	out = "build=19045\nubr=6093\ndisplay_version=22H2\nno_auto_update=1\nwuauserv_start=Disabled\n" +
		"pause_until=2026-12-01T10:00:00Z\nreboot_required=True\nlast_search=2026-08-01T07:00:00Z\nlast_hotfix=2026-07-09\n"
	f = winUpdateFacts(kvLines(out))
	r = evalOSUpdates(f, nil, opts, mustTime(t, "2026-11-10T12:00:00Z"))
	for _, want := range []string{"Windows 10 22H2 (build 19045.6093) is older than the minimum version build 26100",
		"the Windows Update service is disabled; a policy turns automatic updates off", "paused until 1 Dec 2026",
		"last checked for updates 101 days ago", "need a restart", "No OS update has been installed for 124 days"} {
		if !strings.Contains(r.Summary, want) {
			t.Errorf("missing %q in %q", want, r.Summary)
		}
	}
	if r.Status != check.Fail || !strings.Contains(r.Fix, "Resume updates") {
		t.Errorf("got %s fix %q", r.Status, r.Fix)
	}
}

func TestLinuxUpdateParsers(t *testing.T) {
	osr := osReleaseFields(`PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
`)
	if osr["ID"] != "ubuntu" || osr["VERSION_ID"] != "24.04" || linuxFamily(osr) != "debian" {
		t.Errorf("os-release: %v", osr)
	}
	for in, want := range map[string]string{"ID=fedora": "fedora", "ID=rocky\nID_LIKE=\"rhel centos fedora\"": "fedora",
		"ID=arch": "arch", "ID=linuxmint\nID_LIKE=\"ubuntu debian\"": "debian", "ID=nixos": "linux"} {
		if got := linuxFamily(osReleaseFields(in)); got != want {
			t.Errorf("linuxFamily(%q) = %s, want %s", in, got, want)
		}
	}
	dump := "APT::Periodic \"\";\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	if !aptAutoUpgrade(dump) || aptAutoUpgrade(strings.Replace(dump, `Upgrade "1"`, `Upgrade "0"`, 1)) || aptAutoUpgrade("") {
		t.Error("aptAutoUpgrade")
	}
	ua := "\nExpanded Security Maintenance for Applications is not enabled.\n\n12 updates can be applied immediately.\n" +
		"5 of these updates are standard security updates.\nTo see these additional updates run: apt list --upgradable\n\n"
	if n, ok := parseUpdatesAvailable(ua); n != 12 || !ok {
		t.Errorf("updates-available: %d %v", n, ok)
	}
	if n, ok := parseUpdatesAvailable("\n0 updates can be applied immediately.\n"); n != 0 || !ok {
		t.Errorf("updates-available zero: %d %v", n, ok)
	}
	if !anyEnabled("disabled\nenabled\n") || anyEnabled("disabled\n") {
		t.Error("anyEnabled")
	}

	now := mustTime(t, "2026-11-10T12:00:00Z")
	on := true
	f := updateFacts{Family: "debian", Name: "Ubuntu 24.04.1 LTS", Key: "ubuntu", Version: "24.04", AutoUpdate: &on,
		LastCheck: now.Add(-24 * time.Hour), PendingKnown: true, PendingCount: 12, LastInstall: now.Add(-20 * 24 * time.Hour)}
	r := evalOSUpdates(f, nil, policy.Default().Checks.OSUpdates, now)
	if r.Status != check.Fail || !strings.Contains(r.Summary, "12 update(s) are waiting and nothing has been installed for 20 days") ||
		!strings.Contains(r.Fix, "apt full-upgrade") {
		t.Errorf("ubuntu: got %s %q %q", r.Status, r.Summary, r.Fix)
	}
	f.PendingCount, f.LastInstall = 0, now.Add(-90*24*time.Hour) // nothing to install: an old install date is fine
	if r := evalOSUpdates(f, nil, policy.Default().Checks.OSUpdates, now); r.Status != check.Pass {
		t.Errorf("ubuntu current: got %s %q", r.Status, r.Summary)
	}
}

func TestMacLockFacts(t *testing.T) {
	sa := "2026-11-10 18:07:56.456 sysadminctl[82951:13310792] screenLock delay is immediate\n" // captured
	pm := `Battery Power:
 Sleep On Power Button 1
 lowpowermode         0
 standby              1
 hibernatemode        0
 displaysleep         2
 sleep                1
 disksleep            10
AC Power:
 Sleep On Power Button 1
 standby              1
 displaysleep         5
 sleep                0
 disksleep            0
` // captured, trimmed
	opts := policy.Default().Checks.ScreenLock
	f, err := macLockFacts(sa, pm, -1)
	if err != nil {
		t.Fatal(err)
	}
	if r := evalScreenLock(f, opts); r.Status != check.Pass || r.Summary != "A password is needed after sleep and the screen locks after 5 minutes idle." {
		t.Errorf("captured: got %s %q", r.Status, r.Summary)
	}
	// Display sleep after 30 minutes on power, password after 5 minutes.
	f, _ = macLockFacts("screenLock delay is 300 seconds", strings.Replace(pm, "displaysleep         5", "displaysleep         30", 1), -1)
	if r := evalScreenLock(f, opts); r.Status != check.Warn || !strings.Contains(r.Summary, "after 35 minutes idle (policy: 10 minutes)") {
		t.Errorf("slow: got %s %q", r.Status, r.Summary)
	}
	// A 3-minute screen saver locks first.
	f, _ = macLockFacts("screenLock delay is 300 seconds", strings.Replace(pm, "displaysleep         5", "displaysleep         30", 1), 180)
	if r := evalScreenLock(f, opts); r.Status != check.Pass || !strings.Contains(r.Summary, "8 minutes") {
		t.Errorf("screen saver: got %s %q", r.Status, r.Summary)
	}
	f, _ = macLockFacts("screenLock is off", pm, -1)
	if r := evalScreenLock(f, opts); r.Status != check.Fail || !strings.Contains(r.Summary, "No password") || strings.Contains(r.Summary, "never locks") {
		t.Errorf("off: got %s %q", r.Status, r.Summary)
	}
	never := strings.NewReplacer("displaysleep         5", "displaysleep         0").Replace(pm)
	f, _ = macLockFacts(sa, never, 0)
	if r := evalScreenLock(f, opts); r.Status != check.Fail || !strings.Contains(r.Summary, "never locks") {
		t.Errorf("never: got %s %q", r.Status, r.Summary)
	}
	f, _ = macLockFacts(sa, never, -1) // the screen saver's default timer may still lock
	if r := evalScreenLock(f, opts); r.Status != check.Pass || !strings.Contains(r.Summary, "Could not tell when the screen locks") {
		t.Errorf("unknown: got %s %q", r.Status, r.Summary)
	}
	if _, err := macLockFacts("sysadminctl: unknown", pm, -1); err == nil {
		t.Error("unexpected sysadminctl output should be an error")
	}
}

// Researched sample: `powercfg /q SCHEME_CURRENT SUB_SLEEP STANDBYIDLE` (English).
const winStandby = `Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)
  Subgroup GUID: 238c9fa8-0aad-41ed-83f4-97be242c8f20  (Sleep)
    GUID Alias: SUB_SLEEP
    Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)
      GUID Alias: STANDBYIDLE
      Minimum Possible Setting: 0x00000000
      Maximum Possible Setting: 0xffffffff
      Possible Settings increment: 0x00000001
      Possible Settings units: Seconds
    Current AC Power Setting Index: 0x00000708
    Current DC Power Setting Index: 0x00000180
`

// Researched sample: `powercfg /q SCHEME_CURRENT SUB_NONE CONSOLELOCK`.
const winConsoleLock = `Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)
  Subgroup GUID: fea3413e-7e05-4911-9a71-700331f1c294  (Settings belonging to no subgroup)
    GUID Alias: SUB_NONE
    Power Setting GUID: 0e796bdb-100d-47d6-a2d5-f7d2daa51f51  (Require a password on wakeup)
      GUID Alias: CONSOLELOCK
      Possible Setting Index: 000
      Possible Setting Friendly Name: No
      Possible Setting Index: 001
      Possible Setting Friendly Name: Yes
    Current AC Power Setting Index: 0x00000001
    Current DC Power Setting Index: 0x00000001
`

func TestWinLockFacts(t *testing.T) {
	if ac, dc, ok := parsePowercfg(winStandby); ac != 1800 || dc != 384 || !ok {
		t.Errorf("parsePowercfg: %d %d %v", ac, dc, ok)
	}
	opts := policy.Default().Checks.ScreenLock
	noSaver := kvLines("ScreenSaveActive=1\r\nScreenSaverIsSecure=0\r\nScreenSaveTimeOut=900\r\nSCRNSAVE.EXE=\r\nInactivityTimeoutSecs=\r\n")
	// Sleep after 30 minutes plugged in: too slow.
	r := evalScreenLock(winLockFacts(noSaver, winStandby, winConsoleLock), opts)
	if r.Status != check.Warn || !strings.Contains(r.Summary, "after 30 minutes idle") {
		t.Errorf("sleep only: got %s %q", r.Status, r.Summary)
	}
	// A machine inactivity limit of 5 minutes fixes it.
	limit := kvLines("ScreenSaveActive=1\nScreenSaverIsSecure=0\nInactivityTimeoutSecs=300\n")
	if r := evalScreenLock(winLockFacts(limit, winStandby, winConsoleLock), opts); r.Status != check.Pass || !strings.Contains(r.Summary, "5 minutes") {
		t.Errorf("inactivity limit: got %s %q", r.Status, r.Summary)
	}
	// No password on wake, no screen saver: never locks.
	noLock := strings.ReplaceAll(winConsoleLock, "0x00000001", "0x00000000")
	if r := evalScreenLock(winLockFacts(noSaver, winStandby, noLock), opts); r.Status != check.Fail || !strings.Contains(r.Summary, "No password") {
		t.Errorf("no consolelock: got %s %q", r.Status, r.Summary)
	}
	// A secure 10-minute screen saver, sleep never.
	saver := kvLines("ScreenSaveActive=1\nScreenSaverIsSecure=1\nScreenSaveTimeOut=600\nSCRNSAVE.EXE=C:\\Windows\\system32\\scrnsave.scr\n")
	neverSleep := strings.NewReplacer("0x00000708", "0x00000000", "0x00000180", "0x00000000").Replace(winStandby)
	if r := evalScreenLock(winLockFacts(saver, neverSleep, winConsoleLock), opts); r.Status != check.Pass || !strings.Contains(r.Summary, "10 minutes") {
		t.Errorf("screen saver: got %s %q", r.Status, r.Summary)
	}
	if r := evalScreenLock(winLockFacts(noSaver, neverSleep, winConsoleLock), opts); r.Status != check.Fail || !strings.Contains(r.Summary, "never locks") {
		t.Errorf("never: got %s %q", r.Status, r.Summary)
	}
	if r := evalScreenLock(winLockFacts(noSaver, "", ""), opts); r.Status != check.Error {
		t.Errorf("powercfg failed: got %s %q", r.Status, r.Summary)
	}
}

func TestLinuxLockFacts(t *testing.T) {
	// Researched sample: gsettings list-recursively org.gnome.desktop.screensaver on Ubuntu 24.04.
	ss := `org.gnome.desktop.screensaver color-shading-type 'solid'
org.gnome.desktop.screensaver idle-activation-enabled true
org.gnome.desktop.screensaver lock-delay uint32 0
org.gnome.desktop.screensaver lock-enabled true
org.gnome.desktop.screensaver logout-enabled false
org.gnome.desktop.screensaver picture-uri 'file:///usr/share/backgrounds/warty-final-ubuntu.png'
org.gnome.desktop.screensaver ubuntu-lock-on-suspend true
`
	opts := policy.Default().Checks.ScreenLock
	if r := evalScreenLock(gnomeLockFacts(ss, "uint32 300\n"), opts); r.Status != check.Pass || !strings.Contains(r.Summary, "5 minutes") {
		t.Errorf("gnome default: got %s %q", r.Status, r.Summary)
	}
	if r := evalScreenLock(gnomeLockFacts(ss, "uint32 0\n"), opts); r.Status != check.Fail || !strings.Contains(r.Summary, "never locks") {
		t.Errorf("gnome never blank: got %s %q", r.Status, r.Summary)
	}
	off := strings.Replace(ss, "lock-enabled true", "lock-enabled false", 1)
	if r := evalScreenLock(gnomeLockFacts(off, "uint32 300\n"), opts); r.Status != check.Fail {
		t.Errorf("gnome lock off: got %s %q", r.Status, r.Summary)
	}
	if f := gnomeLockFacts("No such schema “org.gnome.desktop.screensaver”", ""); f.Family != "" {
		t.Errorf("not gnome: %+v", f)
	}
	if r := evalScreenLock(kdeLockFacts(""), opts); r.Status != check.Pass || !strings.Contains(r.Summary, "5.1 minutes") {
		t.Errorf("kde defaults: got %s %q", r.Status, r.Summary)
	}
	rc := "[$Version]\nupdate_info=kscreenlocker.upd:0.1-autolock\n\n[Daemon]\nAutolock=false\nLockOnResume=false\n"
	if r := evalScreenLock(kdeLockFacts(rc), opts); r.Status != check.Fail || !strings.Contains(r.Summary, "No password") {
		t.Errorf("kde off: got %s %q", r.Status, r.Summary)
	}
	if r := evalScreenLock(kdeLockFacts("[Daemon]\nTimeout=30\n"), opts); r.Status != check.Warn {
		t.Errorf("kde slow: got %s %q", r.Status, r.Summary)
	}
}

// Captured (trimmed) `launchctl print-disabled system` and `netstat -an -p tcp`.
const macDisabled = `disabled services = {
		"com.apple.ftpd" => disabled
		"com.docker.socket" => enabled
		"com.apple.smbd" => disabled
		"com.apple.ftp-proxy" => enabled
	}
`

const macNetstat = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.20.58337     172.67.74.152.443      ESTABLISHED
tcp46      0      0  *.60340                *.*                    LISTEN
tcp6       0      0  *.5000                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.6924         *.*                    LISTEN
tcp4       0      0  100.64.0.7.8080        *.*                    LISTEN
tcp6       0      0  ::1.8021               *.*                    LISTEN
`

func TestMacRemoteServices(t *testing.T) {
	opts := policy.Default().Checks.RemoteAccess
	r := evalRemoteAccess(macRemoteServices(macDisabled, macNetstat, false, "true\n"), nil, opts.Allow) // captured: guest on
	if r.Status != check.Warn || r.Summary != "Guest user is on." {
		t.Errorf("captured: got %s %q", r.Status, r.Summary)
	}
	if r := evalRemoteAccess(macRemoteServices(macDisabled, macNetstat, false, "false"), nil, opts.Allow); r.Status != check.Pass {
		t.Errorf("all off: got %s %q", r.Status, r.Summary)
	}
	// Remote Login switched on in Sharing, Remote Management on (it serves 5900 itself).
	on := strings.Replace(macDisabled, `"com.apple.ftpd" => disabled`, `"com.openssh.sshd" => enabled`, 1)
	ns := macNetstat + "tcp4       0      0  *.22                   *.*                    LISTEN     \n" +
		"tcp6       0      0  *.5900                 *.*                    LISTEN     \n"
	r = evalRemoteAccess(macRemoteServices(on, ns, true, "false"), nil, nil)
	want := []string{"Remote Login (SSH): enabled in launchd, port 22 open", "Remote Management: turned on in Remote Management"}
	if r.Status != check.Fail || !slices.Equal(r.Evidence, want) || !strings.Contains(r.Fix, "turn off Remote Login") {
		t.Errorf("ssh + ard: got %s %q %q", r.Status, r.Evidence, r.Fix)
	}
	r = evalRemoteAccess(macRemoteServices(on, ns, true, "false"), nil, []string{"ssh", "remote-management"})
	if r.Status != check.Pass || !strings.Contains(r.Summary, "allowed by policy: Remote Login (SSH), Remote Management") {
		t.Errorf("allowed: got %s %q", r.Status, r.Summary)
	}
	// Screen sharing bound to localhost only (an SSH tunnel) is not a door.
	lo := macNetstat + "tcp4       0      0  127.0.0.1.5900         *.*                    LISTEN     \n"
	if r := evalRemoteAccess(macRemoteServices(macDisabled, lo, false, ""), nil, nil); r.Status != check.Pass {
		t.Errorf("loopback vnc: got %s %q", r.Status, r.Evidence)
	}
}

func TestWinRemoteServices(t *testing.T) {
	// Researched sample of winRemoteScript's output.
	out := "rdp_deny=1\r\nrdp_deny_policy=\r\nlisten=\r\nguest_disabled=True\r\n"
	if r := evalRemoteAccess(winRemoteServices(kvLines(out)), nil, nil); r.Status != check.Pass {
		t.Errorf("clean: got %s %q", r.Status, r.Evidence)
	}
	out = "rdp_deny=0\r\nrdp_deny_policy=\r\nsshd=Stopped/Automatic\r\nlisten=3389,5985\r\nguest_disabled=False\r\n"
	r := evalRemoteAccess(winRemoteServices(kvLines(out)), nil, []string{"winrm"})
	want := []string{"OpenSSH Server: service starts automatically", "Remote Desktop: allowed in settings, port 3389 open",
		"WinRM (PowerShell remoting): port 5985/5986 open (allowed by policy)", "Guest account: enabled"}
	if r.Status != check.Fail || !slices.Equal(r.Evidence, want) {
		t.Errorf("open: got %s %q", r.Status, r.Evidence)
	}
	// A policy that denies RDP wins over the setting.
	if r := evalRemoteAccess(winRemoteServices(kvLines("rdp_deny=0\nrdp_deny_policy=1\nguest_disabled=True\n")), nil, nil); r.Status != check.Pass {
		t.Errorf("policy deny: got %s %q", r.Status, r.Evidence)
	}
}

func TestLinuxRemoteServices(t *testing.T) {
	// Researched sample of /proc/net/tcp and /proc/net/tcp6: sshd on 0.0.0.0:22 and [::]:22,
	// a VNC server on 127.0.0.1:5901, systemd-resolved on 127.0.0.53:53.
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 21613 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 25331 1 0000000000000000 100 0 0 10 0
   2: 0100007F:170D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41771 1 0000000000000000 100 0 0 10 0
   3: 0B02A8C0:A3D2 5E7C1A68:01BB 01 00000000:00000000 02:000A1C47 00000000  1000        0 52114 2 0000000000000000 20 4 30 10 -1
`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 25333 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 30001 1 0000000000000000 100 0 0 10 0
`
	ls := append(procNetListen(tcp), procNetListen(tcp6)...)
	want := []listener{{"", "127.0.0.53", "53"}, {"", "0.0.0.0", "22"}, {"", "127.0.0.1", "5901"}, {"", "::", "22"}, {"", "::1", "631"}}
	if !slices.Equal(ls, want) {
		t.Fatalf("procNetListen: got %+v", ls)
	}
	active := map[string]string{"ssh.service": "inactive", "sshd.service": "inactive", "ssh.socket": "active", "sshd.socket": "inactive",
		"xrdp.service": "inactive", "gnome-remote-desktop.service": "inactive"}
	r := evalRemoteAccess(linuxRemoteServices(active, ls, false), nil, nil)
	if r.Status != check.Fail || !slices.Equal(r.Evidence, []string{"SSH server: ssh.socket active, port 22 open"}) {
		t.Errorf("ssh: got %s %q", r.Status, r.Evidence)
	}
	if r := evalRemoteAccess(linuxRemoteServices(nil, ls[2:3], false), nil, nil); r.Status != check.Pass {
		t.Errorf("loopback vnc: got %s %q", r.Status, r.Evidence)
	}
	conf := []string{"[Seat:*]\nuser-session=ubuntu\n", "[Seat:*]\nallow-guest=false\n"}
	if lightdmGuest(conf, true) || !lightdmGuest(conf[:1], true) || lightdmGuest(conf[:1], false) {
		t.Error("lightdmGuest")
	}
}

func TestPolicyDefaultsForNewChecks(t *testing.T) {
	c := policy.Default().Checks
	if !c.OSUpdates.IsEnabled() || !c.ScreenLock.IsEnabled() || !c.RemoteAccess.IsEnabled() {
		t.Error("new checks should be on by default")
	}
	ids := map[string]bool{}
	for _, ch := range All(policy.Default()) {
		ids[ch.ID] = true
	}
	for _, id := range []string{"os-updates", "screen-lock", "remote-access"} {
		if !ids[id] {
			t.Errorf("%s missing from All", id)
		}
	}
}
