package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/report"
)

// A policy with every check off, so tests don't depend on the machine they run on.
const policyFmt = `{"name": "Test", "report": {"url": %q, "headers": {"Authorization": "Bearer t0ken"},
 "interval": "24h", "email_domains": ["acme.com"]}, "update": {%s},
 "checks": {"firewall": {"enabled": false}, "disk-encryption": {"enabled": false},
  "listeners": {"enabled": false}, "tailscale": {"enabled": false}, "docker": {"enabled": false},
  "secrets": {"enabled": false}, "ssh-keys": {"enabled": false}, "ai-agents": {"enabled": false}}}`

func setup(t *testing.T, srv *httptest.Server) (Env, *strings.Builder) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{Email: "an@acme.com", InstallID: "id1", UpdateRepo: "ptrinh/bordercheck"}
	if err := writeJSON(filepath.Join(dir, "config.json"), cfg); err != nil {
		t.Fatal(err)
	}
	out := &strings.Builder{}
	env := Env{Dir: dir, Version: "test", Client: srv.Client(), Out: out}
	setPolicy(t, env, srv, "")
	return env, out
}

// setPolicy writes policies.json with the given fields in its "update" section.
func setPolicy(t *testing.T, env Env, srv *httptest.Server, update string, args ...any) {
	t.Helper()
	body := fmt.Sprintf(policyFmt, srv.URL+"/report", fmt.Sprintf(update, args...))
	if err := os.WriteFile(filepath.Join(env.Dir, "policies.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSendPostsJSONAndRespectsInterval(t *testing.T) {
	var got []report.Report
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/report" ||
			r.Header.Get("Authorization") != "Bearer t0ken" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var rep report.Report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, rep)
	}))
	defer srv.Close()
	env, out := setup(t, srv)

	if err := Send(t.Context(), env, false); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Email != "an@acme.com" || got[0].InstallID != "id1" || got[0].Policy != "Test" {
		t.Fatalf("got %+v", got)
	}
	if err := Send(t.Context(), env, false); err != nil || len(got) != 1 {
		t.Fatalf("second send within the interval should be skipped: err %v, %d reports", err, len(got))
	}
	if err := Send(t.Context(), env, true); err != nil || len(got) != 2 {
		t.Fatalf("forced send: err %v, %d reports", err, len(got))
	}
	if !strings.Contains(out.String(), "nothing due: next check") {
		t.Errorf("log: %s", out)
	}
}

func TestSendFailureIsRecordedWithoutHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	env, _ := setup(t, srv)

	err := Send(t.Context(), env, false)
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "t0ken") {
		t.Fatalf("got %v", err)
	}
	var st State
	if err := readJSON(filepath.Join(env.Dir, "state.json"), &st); err != nil {
		t.Fatal(err)
	}
	if !st.LastSent.IsZero() || st.LastError == "" || time.Since(st.LastTry) > time.Minute {
		t.Errorf("state %+v", st)
	}
}

func TestPolicyURLFallsBackToSavedCopy(t *testing.T) {
	reports := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/policies.json":
			http.Error(w, "down", http.StatusBadGateway)
		case "/report":
			reports++
		}
	}))
	defer srv.Close()
	env, out := setup(t, srv)
	setPolicy(t, env, srv, `"policy_url": %q`, srv.URL+"/policies.json")
	if err := Send(t.Context(), env, false); err != nil || reports != 1 {
		t.Fatalf("err %v, %d reports", err, reports)
	}
	if !strings.Contains(out.String(), "using the saved policy") {
		t.Errorf("log: %s", out)
	}
}

func TestCheckEmail(t *testing.T) {
	for in, want := range map[string]string{
		"  An@Acme.com ":          "an@acme.com",
		"An <an@acme.com>":        "an@acme.com",
		"an@gmail.com":            "error",
		"not an email":            "error",
		"an@sub.acme.com.evil.io": "error",
	} {
		got, err := checkEmail(in, []string{"acme.com"})
		if (err != nil) != (want == "error") || (err == nil && got != want) {
			t.Errorf("checkEmail(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := checkEmail("an@gmail.com", nil); err != nil {
		t.Errorf("no domain list should accept any domain: %v", err)
	}
}

func TestAskEmailRetries(t *testing.T) {
	out := &strings.Builder{}
	email, err := askEmail(strings.NewReader("an@gmail.com\nan@acme.com\n"), out, []string{"acme.com"})
	if err != nil || email != "an@acme.com" || strings.Count(out.String(), "Your work email") != 2 {
		t.Errorf("got %q %v; prompt %q", email, err, out)
	}
	if _, err := askEmail(strings.NewReader(""), io.Discard, nil); err == nil {
		t.Error("empty input should fail")
	}
}

func TestPolicyRefreshKeepsPinnedUpdateSource(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/policies.json" {
			// The fetched policy renames itself and tries to move updates to another repo and key.
			fmt.Fprintf(w, policyFmt, srv.URL+"/report", fmt.Sprintf(
				`"policy_url": %q, "repo": "evil/fork", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, srv.URL+"/policies.json"))
		}
	}))
	defer srv.Close()
	env, out := setup(t, srv)
	setPolicy(t, env, srv, `"policy_url": %q`, srv.URL+"/policies.json")

	cfg := Config{UpdateRepo: "ptrinh/bordercheck"}
	pol, err := currentPolicy(t.Context(), env, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pol.Update.Repo != "ptrinh/bordercheck" || pol.Update.PublicKey != "" {
		t.Errorf("update source not pinned: %+v", pol.Update)
	}
	if !strings.Contains(out.String(), "keeping the source pinned") {
		t.Errorf("log: %s", out)
	}
	saved, _ := os.ReadFile(filepath.Join(env.Dir, "policies.json"))
	if !strings.Contains(string(saved), "evil/fork") {
		t.Error("the fetched policy should still be saved as-is")
	}
}

func TestSendRunsUpdateOnlyWhenOnAndDue(t *testing.T) {
	var gets int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases/") {
			gets++
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	env, _ := setup(t, srv)
	env.GitHub = srv.URL
	env.Version = "v0.1.0"

	if err := Send(t.Context(), env, true); err != nil || gets != 0 {
		t.Fatalf("update off: err %v, %d release fetches", err, gets)
	}
	setPolicy(t, env, srv, `"binary": true`)
	cfg := Config{Email: "an@acme.com", InstallID: "id1", UpdateRepo: "o/r", UpdateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	if err := writeJSON(filepath.Join(env.Dir, "config.json"), cfg); err != nil {
		t.Fatal(err)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatalf("a failed update must not fail the report: %v", err)
	}
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
	if gets != 1 || st.UpdateError == "" || st.LastUpdateCheck.IsZero() {
		t.Fatalf("update on: %d fetches, state %+v", gets, st)
	}
	if err := Send(t.Context(), env, true); err != nil || gets != 1 {
		t.Fatalf("update not due yet: err %v, %d fetches", err, gets)
	}
}
