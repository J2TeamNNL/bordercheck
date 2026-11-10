package agent

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// With report.check_interval the service checks more often than it reports:
// a check between reports sends nothing.
func TestChecksBetweenReports(t *testing.T) {
	reports := 0
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/policies.json":
			fmt.Fprintf(w, `{"name": "Weekly", "report": {"url": %q, "interval": "168h", "check_interval": "24h"}, %s}`,
				srv.URL+"/report", allChecksOff)
		case "/report":
			reports++
		}
	}))
	defer srv.Close()
	out := &strings.Builder{}
	env := Env{Dir: filepath.Join(t.TempDir(), "bc"), Version: "test", Client: srv.Client(), Out: out}
	if err := Install(t.Context(), env, InstallOptions{Policy: srv.URL + "/policies.json", Email: "an@example.com"}); err != nil {
		t.Fatal(err)
	}
	if reports != 1 || !strings.Contains(out.String(), "Checks this computer every 24h and reports every 168h") {
		t.Fatalf("install: %d reports\n%s", reports, out)
	}
	set := func(sinceCheck, sinceSent time.Duration) {
		st := readState(t, env)
		st.LastCheck, st.LastSent = time.Now().Add(-sinceCheck), time.Now().Add(-sinceSent)
		if err := writeJSON(filepath.Join(env.Dir, "state.json"), st); err != nil {
			t.Fatal(err)
		}
	}
	run := func() string {
		out.Reset()
		if err := Send(t.Context(), env, false); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	// An hour after the install: nothing is due.
	set(time.Hour, time.Hour)
	if log := run(); reports != 1 || !strings.Contains(log, "nothing due") {
		t.Errorf("hour later: %d reports\n%s", reports, log)
	}
	// A day later: checks, sends nothing.
	set(25*time.Hour, 25*time.Hour)
	if log := run(); reports != 1 || !strings.Contains(log, "checked (no report due") {
		t.Errorf("day later: %d reports\n%s", reports, log)
	}
	if st := readState(t, env); time.Since(st.LastCheck) > time.Minute || time.Since(st.LastSent) < 24*time.Hour {
		t.Errorf("state after a check: %+v", st)
	}
	// A week later: the report goes out, and counts as a check.
	set(25*time.Hour, 169*time.Hour)
	if log := run(); reports != 2 || !strings.Contains(log, "report sent") {
		t.Errorf("week later: %d reports\n%s", reports, log)
	}
	if st := readState(t, env); time.Since(st.LastCheck) > time.Minute {
		t.Errorf("a report is also a check: %+v", st)
	}
	if status, _ := Status(env); !strings.Contains(status, "Checks:     every 24h") {
		t.Errorf("status:\n%s", status)
	}
}
