package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/checks"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// compromiseRig is an installed bordercheck whose only check is a fake one
// that shows a sign of compromise while sign is set, posting to a server that
// records each report (or fails while failing is set).
type compromiseRig struct {
	env     Env
	out     *strings.Builder
	mu      sync.Mutex
	sign    string // the fake sign's item; "" = none
	failing bool
	got     []map[string]any
}

// A policy that reports daily and checks hourly, without notifications
// (nothing may pop up on the machine running the tests).
const compromisePolicy = `{"name": "Test", "report": {"url": %q, "interval": "24h", "check_interval": "1h",
 "include_evidence": %v %s}, "notify": {"enabled": false}}`

func newCompromiseRig(t *testing.T, evidence bool, extra string) *compromiseRig {
	t.Helper()
	rig := &compromiseRig{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		defer rig.mu.Unlock()
		if rig.failing {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var rep map[string]any
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rig.got = append(rig.got, rep)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, "config.json"), Config{Email: "an@domain.com", InstallID: "id1", UpdateRepo: "ptrinh/bordercheck"}); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(compromisePolicy, srv.URL+"/report", evidence, extra)
	if err := os.WriteFile(filepath.Join(dir, "policies.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.out = &strings.Builder{}
	rig.env = Env{Dir: dir, Version: "test", Client: srv.Client(), Out: rig.out}

	old := allChecks
	allChecks = func(policy.Policy, checks.Local) []check.Check {
		return []check.Check{{ID: "startup-items", Title: "Startup items", Run: func(context.Context) check.Result {
			rig.mu.Lock()
			defer rig.mu.Unlock()
			if rig.sign == "" {
				return check.Result{Status: check.Pass}.WithSummary(msg.Of("startup.pass", "n", 1))
			}
			return check.Result{Status: check.Fail, Severity: check.High, Evidence: []string{rig.sign + ": downloads code"},
				Compromise: []check.Indicator{{What: msg.P("compromise.startupDownloadRun"), Detail: rig.sign}}}.
				WithSummary(msg.Of("startup.downloadRun", "n", 1))
		}}}
	}
	t.Cleanup(func() { allChecks = old })
	return rig
}

func (rig *compromiseRig) set(sign string, failing bool) {
	rig.mu.Lock()
	rig.sign, rig.failing = sign, failing
	rig.mu.Unlock()
}

func (rig *compromiseRig) reports() []map[string]any {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	return append([]map[string]any(nil), rig.got...)
}

// hourLater moves the last check (and, with report, the last report) an hour
// back, so the next run's check is due but a report is not.
func (rig *compromiseRig) hourLater(t *testing.T) State {
	t.Helper()
	var st State
	path := filepath.Join(rig.env.Dir, "state.json")
	if err := readJSON(path, &st); err != nil {
		t.Fatal(err)
	}
	st.LastCheck = st.LastCheck.Add(-61 * time.Minute)
	st.LastSent = st.LastSent.Add(-61 * time.Minute)
	if err := writeJSON(path, st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCompromiseIsSentAtOnce(t *testing.T) {
	rig := newCompromiseRig(t, false, "")
	env := rig.env
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 1 || rig.reports()[0]["compromised"] != nil {
		t.Fatalf("first report: %v %v", err, rig.reports())
	}

	// An hour later the check finds a sign: the report goes now, not in 23 hours.
	rig.set("LaunchAgent com.x", false)
	rig.hourLater(t)
	if err := Send(t.Context(), env, false); err != nil {
		t.Fatal(err)
	}
	got := rig.reports()
	if len(got) != 2 || got[1]["compromised"] != true || fmt.Sprint(got[1]["compromise_checks"]) != "[startup-items]" {
		t.Fatalf("not sent at once: %d reports, last %v\n%s", len(got), got[len(got)-1], rig.out)
	}
	// Evidence is off: the sign says what it is, not which item.
	res := got[1]["results"].([]any)[0].(map[string]any)
	if b, _ := json.Marshal(res["compromise"]); string(b) != `[{"what":{"key":"compromise.startupDownloadRun"}}]` || res["evidence"] != nil {
		t.Errorf("without evidence: %s %v", b, res["evidence"])
	}
	if !strings.Contains(rig.out.String(), "signs of compromise found: sending a report now") {
		t.Errorf("log:\n%s", rig.out)
	}
	if s, err := Status(env); err != nil || !strings.HasPrefix(s, "Signs that this computer may be compromised") ||
		!strings.Contains(s, "· startup-items: A program set to start automatically downloads code from the internet and runs it. (LaunchAgent com.x)") ||
		!strings.Contains(s, "Your IT team has been sent a report saying so.") || !strings.Contains(s, "Stop using this computer for work") {
		t.Errorf("status: %v\n%s", err, s)
	}

	// Still there an hour later: not sent again.
	rig.hourLater(t)
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 2 {
		t.Fatalf("resent while unchanged: %v, %d reports", err, len(rig.reports()))
	}

	// Another item: the set changed, so it goes again.
	rig.set("LaunchAgent com.y", false)
	rig.hourLater(t)
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 3 || rig.reports()[2]["compromised"] != true {
		t.Fatalf("changed sign: %v, %d reports", err, len(rig.reports()))
	}

	// Cleared: a report without the mark goes at once.
	rig.set("", false)
	rig.hourLater(t)
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 4 || rig.reports()[3]["compromised"] != nil {
		t.Fatalf("cleared: %v, %d reports", err, len(rig.reports()))
	}
	if s, _ := Status(env); strings.Contains(s, "compromised") || !strings.Contains(s, "Compromise: looked for every hour, and reported as soon as a sign is found (the other checks run every 1h0m0s)") {
		t.Errorf("status after clearing:\n%s", s)
	}
}

// The checks that can show a compromise run on every wake, so a sign is
// reported within the hour even when neither a check nor a report is due.
func TestCompromiseIsWatchedBetweenChecks(t *testing.T) {
	rig := newCompromiseRig(t, false, "")
	env := rig.env
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 1 {
		t.Fatalf("first report: %v %v", err, rig.reports())
	}
	// Nothing due and no sign: nothing happens.
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 1 || !strings.Contains(rig.out.String(), "nothing due") {
		t.Fatalf("idle wake: %v, %d reports\n%s", err, len(rig.reports()), rig.out)
	}
	// A sign appears; the next wake reports it though no check is due.
	rig.set("LaunchAgent com.x", false)
	if err := Send(t.Context(), env, false); err != nil {
		t.Fatal(err)
	}
	if got := rig.reports(); len(got) != 2 || got[1]["compromised"] != true {
		t.Fatalf("not reported on the next wake: %d reports\n%s", len(got), rig.out)
	}
	// Unchanged on the wake after: not sent again.
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 2 {
		t.Fatalf("resent while unchanged: %v, %d reports", err, len(rig.reports()))
	}
	// Gone: reported at once too.
	rig.set("", false)
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 3 || rig.reports()[2]["compromised"] != nil {
		t.Fatalf("cleared: %v, %d reports", err, len(rig.reports()))
	}
}

func TestCompromiseRetriedHourlyWhenTheReportFails(t *testing.T) {
	rig := newCompromiseRig(t, true, "")
	env := rig.env
	if err := Send(t.Context(), env, false); err != nil {
		t.Fatal(err)
	}
	rig.set("LaunchAgent com.x", true)
	rig.hourLater(t)
	if err := Send(t.Context(), env, false); err == nil {
		t.Fatal("the portal is down; the send should fail")
	}
	if s, _ := Status(env); !strings.Contains(s, "Not reported to your IT team yet") {
		t.Errorf("status:\n%s", s)
	}
	// The next hourly run: no check is due, but the sign has not reached the portal.
	rig.set("LaunchAgent com.x", false)
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
	if time.Since(st.LastCheck) > time.Minute {
		t.Fatalf("the failed send should have checked just now: %v", st.LastCheck)
	}
	if err := Send(t.Context(), env, false); err != nil {
		t.Fatal(err)
	}
	got := rig.reports()
	if len(got) != 2 || got[1]["compromised"] != true || !strings.Contains(rig.out.String(), "signs of compromise not reported yet") {
		t.Fatalf("retry: %d reports\n%s", len(got), rig.out)
	}
	// With evidence on, the sign names its item.
	res := got[1]["results"].([]any)[0].(map[string]any)
	if b, _ := json.Marshal(res["compromise"]); !strings.Contains(string(b), `"detail":"LaunchAgent com.x"`) {
		t.Errorf("with evidence: %s", b)
	}
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 2 {
		t.Fatalf("sent again after it got through: %v %d", err, len(rig.reports()))
	}
}

func TestCompromiseAlertOff(t *testing.T) {
	rig := newCompromiseRig(t, true, `, "compromise_alert": false`)
	env := rig.env
	if err := Send(t.Context(), env, false); err != nil {
		t.Fatal(err)
	}
	rig.set("LaunchAgent com.x", false)
	rig.hourLater(t)
	if err := Send(t.Context(), env, false); err != nil || len(rig.reports()) != 1 {
		t.Fatalf("sent at once with compromise_alert off: %v %d", err, len(rig.reports()))
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	got := rig.reports()
	b, _ := json.Marshal(got[len(got)-1])
	if len(got) != 2 || strings.Contains(string(b), "compromis") || !strings.Contains(string(b), `"status":"fail"`) {
		t.Errorf("off: the fail goes as an ordinary one: %s", b)
	}
	if s, _ := Status(env); strings.Contains(s, "Signs that") || !strings.Contains(s, "Compromise: not flagged") {
		t.Errorf("status:\n%s", s)
	}
}
