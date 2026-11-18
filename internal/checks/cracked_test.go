package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Hosts files written from the entries crack guides tell people to add, and
// from ordinary hosts files that must pass.
func TestParseCrackHosts(t *testing.T) {
	hosts := `##
# Host Database
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
127.0.0.1 lmlicensing.adobe.com
0.0.0.0   practivate.adobe.com activate.adobe.com # crack
127.0.0.1 ic.adobe.io
0.0.0.0 prod.adobegenuine.com
0.0.0.0 cc-api-data.adobe.io
0.0.0.0 www.adobe.com
192.168.1.10 genuine.adobe.com
#127.0.0.1 genuine-software2.autodesk.com
::1 genuine-software2.autodesk.com
0.0.0.0 ads.example.com
`
	got := parseCrackHosts(hosts)
	want := map[string][]string{
		"Adobe":    {"lmlicensing.adobe.com", "practivate.adobe.com", "activate.adobe.com", "ic.adobe.io", "prod.adobegenuine.com"},
		"Autodesk": {"genuine-software2.autodesk.com"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for v, hs := range want {
		if strings.Join(got[v], ",") != strings.Join(hs, ",") {
			t.Errorf("%s: got %v, want %v", v, got[v], hs)
		}
	}
}

func TestKMSEmulated(t *testing.T) {
	for s, want := range map[string]bool{
		"127.0.0.2":           true,
		"127.0.0.2:1688":      true,
		"localhost":           true,
		"[::1]:1688":          true,
		"0.0.0.0":             true,
		"kms.corp.domain.com": false,
		"10.0.0.5:1688":       false,
		"":                    false,
	} {
		if got := kmsEmulated(s); got != want {
			t.Errorf("kmsEmulated(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestEvalCracked(t *testing.T) {
	opts := policy.Default().Checks.CrackedSoftware

	clean := crackFacts{HostsPath: "/etc/hosts", Hosts: "127.0.0.1 localhost\n",
		KMS: map[string]string{"Windows": "kms.corp.domain.com:1688"}}
	if r := evalCracked(clean, opts); r.Status != check.Pass {
		t.Errorf("clean machine: %+v", r)
	}

	r := evalCracked(crackFacts{HostsPath: "/etc/hosts", Hosts: "0.0.0.0 lmlicensing.adobe.com\n"}, opts)
	if r.Status != check.Warn || r.Severity != check.Medium || !strings.Contains(r.Summary, "Adobe") {
		t.Fatalf("Adobe crack, hosts only: %+v", r)
	}
	if !strings.Contains(r.Fix, "PhotoCraft") || strings.Contains(r.Fix, "WordCraft") {
		t.Errorf("fix should suggest Adobe alternatives only: %s", r.Fix)
	}

	r = evalCracked(crackFacts{KMS: map[string]string{"Microsoft Office": "127.0.0.2:1688"},
		Tools: []string{`KMSpico (C:\Program Files\KMSpico)`}}, opts)
	if r.Status != check.Fail || len(r.Evidence) != 2 || !strings.Contains(r.Fix, "WordCraft") {
		t.Errorf("Office crack: %+v", r)
	}

	// More vendors in the hosts file, firewall rules, scheduled tasks and Ohook.
	r = evalCracked(crackFacts{HostsPath: "/etc/hosts",
		Hosts:    "127.0.0.1 registeridm.com\n0.0.0.0 apps.corel.com\n0.0.0.0 activation.cloud.techsmith.com\n# 0.0.0.0 ssl.bandisoft.com\n",
		Hooks:    []string{`Ohook (C:\Program Files\Microsoft Office\root\vfs\System\sppc.dll)`},
		Firewall: []crackFirewall{{Vendor: "CorelDRAW", Program: `C:\Program Files\Corel\CorelDRAW\Programs64\CorelDRW.exe`, Rule: "block corel"}}}, opts)
	if r.Status != check.Warn || r.Compromise != nil ||
		!strings.Contains(r.Summary, "Microsoft Office, CorelDRAW, Internet Download Manager, TechSmith (Camtasia, Snagit)") ||
		strings.Contains(r.Summary, "Bandicam") || !strings.Contains(r.Fix, "wf.msc") {
		t.Errorf("traces only: %+v", r)
	}

	opts.SuggestAlternatives = false
	if r := evalCracked(crackFacts{Tools: []string{"KMSpico"}}, opts); strings.Contains(r.Fix, "ArtCraft") {
		t.Errorf("alternatives off, fix still names them: %s", r.Fix)
	}
}

func TestParseCrackScan(t *testing.T) {
	out := "fw\tBlock Photoshop\tC:\\Program Files\\Adobe\\Adobe Photoshop 2024\\Photoshop.exe\r\n" +
		"fw\tBlock game\tC:\\Games\\game.exe\n" +
		"fw\tIDM\tC:\\Program Files (x86)\\Internet Download Manager\\IDMan.exe\n" +
		"task\t\\AutoKMS\n" +
		"task\t\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\n" +
		"task\t\\KMSAutoNet\n" +
		"task\t\\Saact\n"
	rules, tasks := parseCrackScan(out)
	if len(rules) != 2 || rules[0].Vendor != "Adobe" || rules[1].Vendor != "Internet Download Manager" || rules[0].Rule != "Block Photoshop" {
		t.Errorf("rules: %+v", rules)
	}
	if strings.Join(tasks, "|") != `\AutoKMS|\KMSAutoNet` {
		t.Errorf("tasks: %q", tasks)
	}
}
