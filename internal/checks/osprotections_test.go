package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The csrutil and spctl "enabled" samples were captured on macOS 27; the rest
// are written from the documented output of each tool.

func TestParseCsrutilSpctl(t *testing.T) {
	for out, want := range map[string]string{
		"System Integrity Protection status: enabled.\n":                                                                    "enabled",
		"System Integrity Protection status: disabled.\n":                                                                   "disabled",
		"System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tKext Signing: disabled\n": "custom",
		"": "",
	} {
		if got := parseCsrutil(out); got != want {
			t.Errorf("%q: got %q", out, got)
		}
	}
	if g := parseSpctlStatus("assessments enabled\n"); g == nil || !*g {
		t.Error("enabled")
	}
	if g := parseSpctlStatus("assessments disabled\n"); g == nil || *g {
		t.Error("disabled")
	}
	if parseSpctlStatus("") != nil {
		t.Error("empty")
	}
}

func TestWinProtFacts(t *testing.T) {
	out := "defender=1\nrtp=False\nmode=Normal\ntamper=False\nsc=1\nav=397568|Windows Defender\n" +
		"smartscreen=Off\nsmartscreen_policy=\nsecureboot=0\nfirmware=UEFI\n"
	f := winProtFacts(out)
	if !f.DefenderKnown || f.DefenderRTP || len(f.OtherAV) != 0 || f.SmartScreen == nil || *f.SmartScreen ||
		f.SecureBoot == nil || *f.SecureBoot || f.Tamper == nil || *f.Tamper {
		t.Errorf("got %+v", f)
	}
	// Another antivirus on (0x061000), Defender passive, SmartScreen forced on by policy, legacy BIOS.
	f = winProtFacts("defender=1\nrtp=True\nmode=Passive Mode\nsc=1\nav=393472|Windows Defender\nav=397312|Acme AV\n" +
		"av=262144|Old AV\nsmartscreen=Off\nsmartscreen_policy=1\nsecureboot=\nfirmware=Legacy\n")
	if len(f.OtherAV) != 1 || f.OtherAV[0] != "Acme AV" || !*f.SmartScreen || !f.NoUEFI || f.SecureBoot != nil {
		t.Errorf("got %+v", f)
	}
	if !avProductOn("397568") || avProductOn("393472") || avProductOn("x") {
		t.Error("avProductOn")
	}
}

func TestLinuxProtParsers(t *testing.T) {
	if g := efiSecureBoot([]byte{6, 0, 0, 0, 1}); g == nil || !*g {
		t.Error("efi on")
	}
	if g := efiSecureBoot([]byte{6, 0, 0, 0, 0}); g == nil || *g {
		t.Error("efi off")
	}
	if efiSecureBoot([]byte{6}) != nil {
		t.Error("short")
	}
	if g := parseMokutilSB("SecureBoot disabled\n"); g == nil || *g {
		t.Error("mokutil")
	}
	if selinuxMode("1", true) != "enforcing" || selinuxMode("0", true) != "permissive" || selinuxMode("", false) != "" {
		t.Error("selinux")
	}
}

func TestEvalOSProtections(t *testing.T) {
	yes, no := true, false
	def := policy.Default().Checks.OSProtections
	cases := []struct {
		name string
		f    protFacts
		opts policy.OSProtections
		st   check.Status
		sev  check.Severity
		has  string
	}{
		{"mac ok", protFacts{Family: "macos", SIP: "enabled", Gatekeeper: &yes}, def, check.Pass, "", "System Integrity Protection, Gatekeeper"},
		{"sip off", protFacts{Family: "macos", SIP: "disabled", Gatekeeper: &yes}, def, check.Fail, check.High, "System Integrity Protection is off"},
		{"sip custom", protFacts{Family: "macos", SIP: "custom", Gatekeeper: &yes}, def, check.Warn, check.Medium, "partly"},
		{"gatekeeper off", protFacts{Family: "macos", SIP: "enabled", Gatekeeper: &no}, def, check.Fail, check.High, "Gatekeeper is off"},
		{"gatekeeper off allowed", protFacts{Family: "macos", SIP: "enabled", Gatekeeper: &no},
			policy.OSProtections{SIP: true}, check.Pass, "", "System Integrity Protection"},
		{"mac unknown", protFacts{Family: "macos"}, def, check.Error, "", "Could not tell"},
		{"win ok", protFacts{Family: "windows", DefenderKnown: true, DefenderRTP: true, DefenderMode: "Normal", Tamper: &yes,
			SmartScreen: &yes, SecureBoot: &yes}, def, check.Pass, "", "Microsoft Defender"},
		{"win no av", protFacts{Family: "windows", DefenderKnown: true, AVKnown: true, SmartScreen: &yes, SecureBoot: &yes},
			def, check.Fail, check.High, "no other antivirus"},
		{"win other av", protFacts{Family: "windows", DefenderKnown: true, DefenderMode: "Passive Mode", AVKnown: true,
			OtherAV: []string{"Acme AV"}, SmartScreen: &yes, SecureBoot: &yes}, def, check.Pass, "", "Acme AV"},
		{"win tamper smartscreen secureboot", protFacts{Family: "windows", DefenderKnown: true, DefenderRTP: true, Tamper: &no,
			SmartScreen: &no, SecureBoot: &no}, def, check.Warn, check.Medium, "Secure Boot is off"},
		{"linux ok", protFacts{Family: "linux", SecureBoot: &yes, AppArmor: true}, def, check.Pass, "", "AppArmor"},
		{"linux permissive", protFacts{Family: "linux", SecureBoot: &yes, SELinux: "permissive"}, def, check.Warn, check.Medium, "permissive"},
		{"linux nothing", protFacts{Family: "linux", NoUEFI: true}, def, check.Warn, check.Medium, "legacy BIOS"},
		{"wsl", protFacts{Family: "linux", WSL: true}, def, check.Skip, "", "Windows Subsystem"},
		{"all off", protFacts{Family: "linux"}, policy.OSProtections{}, check.Skip, "", "Nothing to check"},
	}
	for _, c := range cases {
		r := evalOSProtections(c.f, c.opts)
		if r.Status != c.st || r.Severity != c.sev || !strings.Contains(r.Summary, c.has) {
			t.Errorf("%s: got %s/%s %q", c.name, r.Status, r.Severity, r.Summary)
		}
	}
}
