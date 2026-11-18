package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func winGetenv(k string) string {
	return map[string]string{
		"SystemRoot": `C:\Windows`, "SystemDrive": "C:", "ProgramData": `C:\ProgramData`,
		"APPDATA": `C:\Users\me\AppData\Roaming`, "LOCALAPPDATA": `C:\Users\me\AppData\Local`,
		"TEMP": `C:\Users\me\AppData\Local\Temp`, "PUBLIC": `C:\Users\Public`,
	}[k]
}

func TestBroadExclusion(t *testing.T) {
	env := startupEnv{home: `C:\Users\me`, goos: "windows", tempDir: `C:\Users\me\AppData\Local\Temp`}
	for e, want := range map[string]string{
		`path C:\`:                             "a whole drive",
		`path C:`:                              "a whole drive",
		`path %APPDATA%`:                       "AppData",
		`path C:\Users\me\AppData\Local\Temp\`: "the temporary folder",
		`path C:\Users\me\AppData\Local\Temp\x7f2a`: "a temporary folder",
		`path C:\Users\me\Downloads`:                "the Downloads folder",
		`path C:\Users\me`:                          "your whole user folder",
		`path C:\ProgramData`:                       "ProgramData",
		`process powershell.exe`:                    "everything powershell.exe runs",
		`process C:\Users\me\Downloads\x.exe`:       "a program in the Downloads folder",
		`extension exe`:                             "every .exe file",
		`extension .PS1`:                            "every .ps1 file",
		`path C:\Users\me\src\myapp\node_modules`:   "",
		`path D:\builds`:                            "",
		`process devenv.exe`:                        "",
		`extension .log`:                            "",
	} {
		if got := broadExclusion(e, env, winGetenv); got != want {
			t.Errorf("%s: %q, want %q", e, got, want)
		}
	}
}

func TestHostsHijacks(t *testing.T) {
	hosts := "127.0.0.1 localhost\n" +
		"203.0.113.9 online.vietcombank.com.vn accounts.google.com\n" +
		"0.0.0.0 www.virustotal.com # malware\n" +
		"0.0.0.0 ads.example.com google-analytics.com\n" +
		"127.0.0.1 api.github.com\n" + // a developer pointing a name at their own machine
		"# 1.2.3.4 binance.com\n" +
		"10.0.0.5 intranet.example.com\n"
	r, b := hostsHijacks(hosts)
	if strings.Join(r, "|") != "accounts.google.com → 203.0.113.9|online.vietcombank.com.vn → 203.0.113.9" {
		t.Errorf("redirects: %q", r)
	}
	if strings.Join(b, "|") != "www.virustotal.com" {
		t.Errorf("blocks: %q", b)
	}
}

func TestParseHiddenScan(t *testing.T) {
	ex, read, run := parseHiddenScan("excl\tpath\tC:\\\r\nexcl\tprocess\tpowershell.exe\nproc\tC:\\Users\\me\\AppData\\Local\\Temp\\a.exe\n")
	if !read || strings.Join(ex, "|") != `path C:\|process powershell.exe` || len(run) != 1 {
		t.Errorf("%q %v %q", ex, read, run)
	}
	if _, read, _ := parseHiddenScan("excl\tna\n"); read {
		t.Error("N/A means not readable")
	}
}

func TestEvalStartupHidden(t *testing.T) {
	env := newStartupEnv(`C:\Users\me`, "windows", policy.Default().Checks.StartupItems)
	env.tempDir = `C:\Users\me\AppData\Local\Temp`
	x := hiddenFacts{ExclusionsRead: true, Exclusions: []string{`path C:\`, `path D:\work`}, Getenv: winGetenv,
		HostsPath: `C:\Windows\System32\drivers\etc\hosts`, Hosts: "198.51.100.7 login.microsoftonline.com\n",
		Running: []string{`C:\Users\me\Downloads\setup_crack.exe`}}
	r := evalStartupWith(nil, nil, env, startupFix("windows"), x)
	if r.Status != check.Fail || r.Severity != check.High || len(r.Compromise) != 2 {
		t.Fatalf("%s %s %+v", r.Status, r.Severity, r.Compromise)
	}
	for _, want := range []string{"1 Microsoft Defender exclusion", "sends 1 sign-in", "1 program not signed by a known developer", "0 items start"} {
		if !strings.Contains(r.Summary, want) {
			t.Errorf("summary lacks %q: %s", want, r.Summary)
		}
	}
	if !strings.Contains(r.Fix, "Exclusions") || !strings.Contains(r.Fix, `etc\hosts`) || strings.Contains(r.Fix, "Startup apps") {
		t.Errorf("fix: %s", r.Fix)
	}
	// Only an unsigned program running from Downloads: a warning, no sign of compromise.
	r = evalStartupWith(nil, nil, env, startupFix("windows"), hiddenFacts{Running: x.Running})
	if r.Status != check.Warn || r.Severity != check.Medium || r.Compromise != nil {
		t.Errorf("unsigned only: %s %s %+v", r.Status, r.Severity, r.Compromise)
	}
	if r := evalStartupWith(nil, nil, env, startupFix("windows"), hiddenFacts{Hosts: "0.0.0.0 doubleclick.net\n"}); r.Status != check.Pass {
		t.Errorf("an ad blocker's hosts file: %s %s", r.Status, r.Summary)
	}
}
