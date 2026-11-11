package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/checks"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func TestReportCarriesLikelySamplesOnlyWithConsent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for rel, body := range map[string]string{
		"app/.env":           "API_TOKEN=Zk3nW8sQe4yU\n",
		"demo-apps/web/.env": "SESSION_SECRET=Xq7rT2mVb9pL\n",
	} {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var raw []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep map[string]any
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw = append(raw, rep)
	}))
	defer srv.Close()
	env, _ := setup(t, srv)
	cs := map[string]any{}
	for _, c := range checks.All(policy.Default()) {
		cs[c.ID] = map[string]any{"enabled": false}
	}
	cs["secrets"] = map[string]any{"walk_depth": 3}
	pol, _ := json.Marshal(map[string]any{"name": "Test", "report": map[string]any{"url": srv.URL + "/report", "interval": "24h", "include_evidence": true},
		"notify": map[string]any{"enabled": false}, "checks": cs})
	if err := os.WriteFile(filepath.Join(env.Dir, "policies.json"), pol, 0o600); err != nil {
		t.Fatal(err)
	}
	privacyPath := filepath.Join(env.Dir, "privacy.json")
	if err := writeJSON(privacyPath, checks.Privacy{ProjectEnv: true}); err != nil {
		t.Fatal(err)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("%d reports", len(raw))
	}
	res := raw[0]["results"].([]any)[0].(map[string]any)
	if res["status"] != "warn" || res["likely_samples"] != nil || res["evidence"] != nil || res["summary"] != "" {
		t.Fatalf("report without local consent: %v", res)
	}
	if err := writeJSON(privacyPath, checks.Privacy{ProjectEnv: true, ReportDetails: true}); err != nil {
		t.Fatal(err)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 2 {
		t.Fatalf("%d reports", len(raw))
	}
	res = raw[1]["results"].([]any)[0].(map[string]any)
	ls, _ := res["likely_samples"].([]any)
	if res["id"] != "secrets" || res["status"] != "warn" || res["evidence"] == nil || len(ls) != 1 {
		t.Fatalf("result: %v", res)
	}
	got := ls[0].(map[string]any)
	if got["path"] != "~"+string(filepath.Separator)+filepath.Join("demo-apps", "web", ".env") || got["name"] != "SESSION_SECRET" ||
		got["rule"] != "sample-dir" || got["kind"] != "Secret-looking variable" {
		t.Errorf("likely_samples: %v", got)
	}
	data, _ := json.Marshal(raw[1])
	if strings.Contains(string(data), "Xq7rT2mVb9pL") || strings.Contains(string(data), "Zk3nW8sQe4yU") {
		t.Errorf("a value left the machine: %s", data)
	}
	if s, err := Status(env); err != nil || !strings.Contains(s, "evidence on") {
		t.Errorf("status: %v\n%s", err, s)
	}
}
