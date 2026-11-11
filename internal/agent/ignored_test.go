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
	"github.com/ptrinh/bordercheck/internal/ignore"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The list of ignored secrets is in every report, also when evidence is not
// sent; the secrets check runs on a made-up home folder only.
func TestReportCarriesUserIgnoredWithoutEvidence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "app", ".env"), []byte("POSTGRES_PASSWORD=Xq7rT2mVb9pL\nAPI_TOKEN=Zk3nW8sQe4yU\n"), 0o600); err != nil {
		t.Fatal(err)
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
	// Only the secrets check, include_evidence left at its default (false).
	cs := map[string]any{}
	for _, c := range checks.All(policy.Default()) {
		cs[c.ID] = map[string]any{"enabled": false}
	}
	cs["secrets"] = map[string]any{"walk_depth": 2}
	pol, _ := json.Marshal(map[string]any{"name": "Test", "report": map[string]any{"url": srv.URL + "/report", "interval": "24h"},
		"notify": map[string]any{"enabled": false}, "checks": cs})
	if err := os.WriteFile(filepath.Join(env.Dir, "policies.json"), pol, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ignore.Save(env.Dir, []ignore.Entry{{Check: "secrets", Path: "~/app/.env", Name: "POSTGRES_PASSWORD", Reason: "local docker db", Since: "2026-11-11"}}); err != nil {
		t.Fatal(err)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("%d reports", len(raw))
	}
	res := raw[0]["results"].([]any)[0].(map[string]any)
	ign, _ := res["user_ignored"].([]any)
	if res["id"] != "secrets" || res["status"] != "warn" || res["evidence"] != nil || len(ign) != 1 {
		t.Fatalf("result: %v", res)
	}
	got := ign[0].(map[string]any)
	if got["path"] != "~"+string(filepath.Separator)+filepath.Join("app", ".env") || got["name"] != "POSTGRES_PASSWORD" ||
		got["reason"] != "local docker db" || got["since"] != "2026-11-11" || got["kind"] != "Secret-looking variable" {
		t.Errorf("user_ignored: %v", got)
	}
	data, _ := json.Marshal(raw[0])
	if strings.Contains(string(data), "Xq7rT2mVb9pL") || strings.Contains(string(data), "Zk3nW8sQe4yU") {
		t.Errorf("a value left the machine: %s", data)
	}

	s, err := Status(env)
	if err != nil || !strings.Contains(s, "anything you ignored with your reason") || !strings.Contains(s, "Ignored:    1 entry you marked as not sensitive") {
		t.Errorf("status: %v\n%s", err, s)
	}
}
