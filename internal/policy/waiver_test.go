package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

var today = time.Date(2026, 11, 10, 15, 0, 0, 0, time.Local)

func withClock(t *testing.T) {
	t.Helper()
	old := now
	now = func() time.Time { return today }
	t.Cleanup(func() { now = old })
}

func TestWaiveMatchesAndExpires(t *testing.T) {
	p := Default()
	p.Waivers = []Waiver{
		{Check: "listeners", Email: "An@Acme.com", Until: "2026-12-01", Reason: "Postgres for the migration"},
		{Check: "listeners", Email: "an@acme.com", Until: "2026-11-20", Reason: "shorter"},
		{Check: "docker", InstallID: "id1", Hostname: "ans-mbp", Until: "2026-11-10", Reason: "ends today"},
		{Check: "firewall", Email: "an@acme.com", Hostname: "ANS-MBP", Until: "2026-11-09", Reason: "ended yesterday"},
		{Check: "tailscale", Email: "an@acme.com", Hostname: "ans-mbp", Until: "2027-01-01", Reason: "narrowed by hostname"},
	}
	results := []check.Result{
		{ID: "listeners", Status: check.Warn, Severity: check.Medium, Summary: "1 port", Fix: "close it"},
		{ID: "docker", Status: check.Fail, Severity: check.High},
		{ID: "firewall", Status: check.Fail, Severity: check.High},
		{ID: "tailscale", Status: check.Pass},
		{ID: "secrets", Status: check.Fail, Severity: check.High},
	}
	installed := Identity{Email: "an@acme.com", InstallID: "id1", Hostname: "ans-mbp.local"}
	got := p.Waive(results, installed, today)

	l := got[0]
	if l.Status != check.Waived || l.Waived == nil || l.Waived.Until != "2026-12-01" || l.Waived.Reason != "Postgres for the migration" ||
		l.Severity != check.Medium || l.Summary != "1 port" || l.Fix != "close it" {
		t.Errorf("listeners: %+v %+v", l, l.Waived)
	}
	if got[1].Status != check.Waived {
		t.Errorf("docker: a waiver applies through its last day: %+v", got[1])
	}
	if got[2].Status != check.Fail || got[2].Waived != nil || got[2].WaiverEnded != "2026-11-09" {
		t.Errorf("firewall: an ended waiver has no effect but is noted: %+v", got[2])
	}
	if got[3].Status != check.Pass || got[3].Waived != nil {
		t.Errorf("tailscale: a pass stays a pass: %+v", got[3])
	}
	if got[4].Status != check.Fail {
		t.Errorf("secrets: no waiver: %+v", got[4])
	}
	if results[0].Status != check.Warn {
		t.Error("Waive must not change its input")
	}

	// Not installed: only the hostname is known, and no waiver rests on that alone.
	plain := p.Waive(results, Identity{Hostname: "ans-mbp"}, today)
	if plain[0].Status != check.Warn || plain[1].Status != check.Fail || plain[2].WaiverEnded != "" {
		t.Errorf("uninstalled: %+v", plain)
	}
	// Every identity field set must match.
	other := p.Waive(results, Identity{Email: "an@acme.com", InstallID: "id2", Hostname: "ans-mbp"}, today)
	if other[1].Status != check.Fail {
		t.Errorf("install_id mismatch still waived: %+v", other[1])
	}
	if p.Waive(results, Identity{Email: "bo@acme.com"}, today)[0].Status != check.Warn {
		t.Error("another person's waiver applied")
	}
}

func TestWaivedJSON(t *testing.T) {
	r := check.Result{ID: "listeners", Status: check.Waived, Waived: &check.Waiver{Until: "2026-12-01", Reason: "r"}, WaiverEnded: "x"}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"status":"waived"`) || !strings.Contains(string(b), `"waived":{"until":"2026-12-01","reason":"r"}`) ||
		strings.Contains(string(b), "WaiverEnded") {
		t.Errorf("got %s", b)
	}
}

func TestWaiverValidation(t *testing.T) {
	withClock(t)
	ok := `{"waivers": [{"check": "listeners", "email": "an@acme.com", "until": "2027-11-10", "reason": "r"},
		{"check": "secrets", "install_id": "id1", "hostname": "ans-mbp", "until": "2020-01-01", "reason": "ended long ago is fine"}]}`
	if p, err := load(t, ok); err != nil || len(p.Waivers) != 2 {
		t.Fatalf("valid waivers: %v", err)
	}
	for body, want := range map[string]string{
		`{"waivers": [{"check": "listeners", "email": "an@acme.com", "reason": "r"}]}`:                                "until",
		`{"waivers": [{"check": "listeners", "email": "an@acme.com", "until": "2028-01-01", "reason": "r"}]}`:         "days ahead",
		`{"waivers": [{"check": "listeners", "email": "an@acme.com", "until": "12/01/2026", "reason": "r"}]}`:         "date like",
		`{"waivers": [{"check": "listeners", "until": "2026-12-01", "reason": "r"}]}`:                                 "which machine",
		`{"waivers": [{"check": "listeners", "hostname": "ans-mbp", "until": "2026-12-01", "reason": "r"}]}`:          "which machine",
		`{"waivers": [{"check": "listener", "email": "an@acme.com", "until": "2026-12-01", "reason": "r"}]}`:          "check must be",
		`{"waivers": [{"check": "listeners", "email": "an@acme.com", "until": "2026-12-01"}]}`:                        "reason",
		`{"waivers": [{"check": "listeners", "email": "an", "until": "2026-12-01", "reason": "r"}]}`:                  "not an email",
		`{"waivers": [{"check": "listeners", "email": "an@acme.com", "until": "2026-12-01", "reason": "r", "x": 1}]}`: "unknown field",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}

func TestNotifyPolicy(t *testing.T) {
	p, err := load(t, `{"notify": {"statuses": ["fail", "warn"], "remind_every": "0"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Notify.Enabled || len(p.Notify.Statuses) != 2 || p.Notify.Remind() != 0 || len(p.Notify.Severities) != 2 {
		t.Errorf("got %+v", p.Notify)
	}
	if _, err := load(t, `{"notify": {"enabled": false, "statuses": []}}`); err != nil {
		t.Errorf("disabled with no statuses should be fine: %v", err)
	}
	for body, want := range map[string]string{
		`{"notify": {"statuses": ["error"]}}`:          "notify.statuses",
		`{"notify": {"statuses": ["waived"]}}`:         "notify.statuses",
		`{"notify": {"statuses": []}}`:                 "must not be empty",
		`{"notify": {"severities": ["critical"]}}`:     "notify.severities",
		`{"notify": {"remind_every": "10m"}}`:          "remind_every",
		`{"notify": {"remind_every": "daily"}}`:        "remind_every",
		`{"notify": {"enabled": true, "sound": true}}`: "unknown field",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}

// -print-policy output must list the new fields and parse back unchanged.
func TestDefaultRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(Default()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"notify":{"enabled":true,"statuses":["fail"],"severities":["high","medium"],"remind_every":"24h","open_report":true}`, `"waivers":[]`,
		`"include_ips":false,"include_location":false`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("default policy lacks %s:\n%s", want, buf.String())
		}
	}
	if _, err := Parse(buf.Bytes(), "default"); err != nil {
		t.Errorf("default does not parse back: %v", err)
	}
}

func TestCheckIDsFollowChecks(t *testing.T) {
	ids := checkIDs()
	for _, id := range []string{"firewall", "disk-encryption", "listeners", "tailscale", "docker", "secrets"} {
		if !ids[id] {
			t.Errorf("missing %s in %v", id, ids)
		}
	}
}

func TestActiveWaivers(t *testing.T) {
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.Local)
	p := Policy{Waivers: []Waiver{
		{Check: "listeners", Email: "an@acme.com", Until: "2026-12-01", Reason: "db"},
		{Check: "docker", Email: "an@acme.com", Until: "2026-11-01", Reason: "ended"},
		{Check: "firewall", Email: "binh@acme.com", Until: "2026-12-01", Reason: "other machine"},
	}}
	got := p.ActiveWaivers(Identity{Email: "AN@acme.com"}, at)
	if len(got) != 1 || got[0].Check != "listeners" {
		t.Errorf("got %+v", got)
	}
}
