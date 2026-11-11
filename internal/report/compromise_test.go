package report

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
)

func compromisedResults() []check.Result {
	ind := func(key, detail string) []check.Indicator {
		return []check.Indicator{{What: msg.P(key), Detail: detail}}
	}
	return []check.Result{
		{ID: "startup-items", Title: "Startup", Status: check.Fail, Severity: check.High, Summary: "1 item downloads code.",
			Compromise: ind("compromise.startupDownloadRun", "LaunchAgent ~/Library/LaunchAgents/com.x.plist (com.x)")},
		{ID: "extensions", Title: "Extensions", Status: check.Waived, Severity: check.High, Summary: "blocked",
			Waived: &check.Waiver{Until: "2099-01-01", Reason: "lab"}, Compromise: ind("compromise.blockedExtension", "Chrome: Evil")},
		{ID: "cracked-software", Title: "Cracks", Status: check.Pass, Compromise: ind("compromise.crackTool", "KMSpico")},
		{ID: "firewall", Title: "Firewall", Status: check.Fail, Severity: check.High, Summary: "Off."},
	}
}

func TestReportCompromise(t *testing.T) {
	rep := New("v9", "test", compromisedResults())
	if !rep.Compromised || !slices.Equal(rep.CompromiseChecks, []string{"startup-items"}) {
		t.Fatalf("compromised %v %v", rep.Compromised, rep.CompromiseChecks)
	}
	// A waived (or passing) result never carries signs of compromise.
	if rep.Results[1].Compromise != nil || rep.Results[2].Compromise != nil {
		t.Errorf("waived or pass kept its signs: %+v", rep.Results)
	}
	if got := rep.CompromiseLines(); len(got) != 1 ||
		got[0] != "startup-items: A program set to start automatically downloads code from the internet and runs it. (LaunchAgent ~/Library/LaunchAgents/com.x.plist (com.x))" {
		t.Errorf("lines %q", got)
	}
	data, _ := json.Marshal(rep)
	if !strings.Contains(string(data), `"compromised":true,"compromise_checks":["startup-items"]`) ||
		!strings.Contains(string(data), `"compromise":[{"what":{"key":"compromise.startupDownloadRun"},"detail":"LaunchAgent`) {
		t.Errorf("json: %s", data)
	}

	var b strings.Builder
	rep.WriteText(&b, false)
	out := b.String()
	if i := strings.Index(out, "Signs that this computer may be compromised:"); i < 0 || i > strings.Index(out, "FAIL") ||
		!strings.Contains(out, "Stop using this computer for work and tell your IT team now. Do not just delete the item") {
		t.Errorf("text:\n%s", out)
	}

	rep.DropCompromise()
	data, _ = json.Marshal(rep)
	if rep.Compromised || strings.Contains(string(data), "compromis") || rep.Counts.Fail != 2 {
		t.Errorf("dropped: %s", data)
	}
	b.Reset()
	rep.WriteText(&b, false)
	if strings.Contains(b.String(), "compromised") {
		t.Errorf("text after drop:\n%s", b.String())
	}

	// No signs: nothing extra.
	clean := New("v9", "test", []check.Result{{ID: "firewall", Status: check.Fail, Severity: check.High}})
	data, _ = json.Marshal(clean)
	if clean.Compromised || strings.Contains(string(data), "compromis") {
		t.Errorf("clean: %s", data)
	}
}

func TestWriteFixCompromised(t *testing.T) {
	var b strings.Builder
	New("v9", "test", compromisedResults()).WriteFix(&b, "bordercheck", true)
	out := b.String()
	stop, rules, begin := strings.Index(out, "STOP FIRST"), strings.Index(out, "\nRules\n"), strings.Index(out, "BEGIN REPORT")
	if stop < 0 || stop > rules || !strings.Contains(out, "(checks: startup-items;") ||
		!strings.Contains(out, "Do not fix, remove, disable or clean up anything") ||
		!strings.Contains(out, "change their passwords and rotate their keys") {
		t.Fatalf("fix:\n%s", out)
	}
	// The signs, with their details from the machine, are inside the report markers.
	if i := strings.Index(out, "Signs of compromise:"); i < begin || !strings.Contains(out[begin:], "com.x.plist") || strings.Contains(out[:begin], "com.x.plist") {
		t.Errorf("signs outside the report:\n%s", out)
	}

	b.Reset()
	New("v9", "test", []check.Result{{ID: "firewall", Status: check.Fail, Severity: check.High}}).WriteFix(&b, "bordercheck", true)
	if strings.Contains(b.String(), "STOP FIRST") || strings.Contains(b.String(), "Signs of compromise") {
		t.Errorf("not compromised:\n%s", b.String())
	}
}
