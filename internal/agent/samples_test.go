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

// Likely sample keys are in every report, also when evidence is not sent;
// the secrets check runs on a made-up home folder only.
func TestReportCarriesLikelySamplesWithoutEvidence(t *testing.T) {
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
	pol, _ := json.Marshal(map[string]any{"name": "Test", "report": map[string]any{"url": srv.URL + "/report", "interval": "24h"},
		"notify": map[string]any{"enabled": false}, "checks": cs})
	if err := os.WriteFile(filepath.Join(env.Dir, "policies.json"), pol, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("%d reports", len(raw))
	}
	res := raw[0]["results"].([]any)[0].(map[string]any)
	ls, _ := res["likely_samples"].([]any)
	if res["id"] != "secrets" || res["status"] != "warn" || res["evidence"] != nil || len(ls) != 1 {
		t.Fatalf("result: %v", res)
	}
	got := ls[0].(map[string]any)
	if got["path"] != "~"+string(filepath.Separator)+filepath.Join("demo-apps", "web", ".env") || got["name"] != "SESSION_SECRET" ||
		got["rule"] != "sample-dir" || got["kind"] != "Secret-looking variable" {
		t.Errorf("likely_samples: %v", got)
	}
	data, _ := json.Marshal(raw[0])
	if strings.Contains(string(data), "Xq7rT2mVb9pL") || strings.Contains(string(data), "Zk3nW8sQe4yU") {
		t.Errorf("a value left the machine: %s", data)
	}
	if s, err := Status(env); err != nil || !strings.Contains(s, "files set aside as likely sample keys") {
		t.Errorf("status: %v\n%s", err, s)
	}
}
