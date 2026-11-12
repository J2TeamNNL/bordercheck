package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

func TestWaivedInReport(t *testing.T) {
	r := New("test", "Sample", []check.Result{
		{ID: "listeners", Title: "Nothing listens beyond localhost", Status: check.Waived, Severity: check.Medium,
			Summary: "1 port(s) can be reached", Fix: "Close it.", Waived: &check.Waiver{Until: "2026-11-15", Reason: "Postgres demo"}},
		{ID: "docker", Title: "Docker containers stay isolated", Status: check.Waived, Severity: check.High,
			Waived: &check.Waiver{Until: "2027-06-01", Reason: "lab machine"}},
		{ID: "firewall", Title: "Firewall is on", Status: check.Fail, Severity: check.High, WaiverEnded: "2026-11-01"},
		{ID: "secrets", Title: "No plain-text secrets", Status: check.Pass},
	})
	r.Time = time.Date(2026, 11, 10, 12, 0, 0, 0, time.Local)
	if c := r.Counts; c.Waived != 2 || c.Fail != 1 || c.Pass != 1 {
		t.Fatalf("counts %+v", c)
	}

	var js bytes.Buffer
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var back struct {
		Counts  map[string]int `json:"counts"`
		Results []map[string]any
	}
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	w, _ := back.Results[0]["waived"].(map[string]any)
	if back.Counts["waived"] != 2 || back.Results[0]["status"] != "waived" || w["until"] != "2026-11-15" ||
		w["reason"] != "Postgres demo" || back.Results[0]["fix"] != "Close it." || back.Results[2]["waived"] != nil {
		t.Errorf("json: %s", js.String())
	}

	var txt strings.Builder
	r.WriteText(&txt, false)
	out := txt.String()
	for _, want := range []string{
		"WAIV  Nothing listens beyond localhost [medium]",
		"Waived until 2026-11-15 (ends in 5 days): Postgres demo",
		"Waived until 2027-06-01: lab machine",
		"A waiver for this check ended on 2026-11-01",
		"1 fail · 1 pass · 2 waived",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	// Worst first: the fail, then the waived, then the pass.
	if !(strings.Index(out, "FAIL") < strings.Index(out, "WAIV") && strings.Index(out, "WAIV") < strings.Index(out, "PASS")) {
		t.Errorf("order:\n%s", out)
	}
}
