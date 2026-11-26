package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWaiverRequestValidate(t *testing.T) {
	now := time.Date(2026, 11, 26, 9, 0, 0, 0, time.Local)
	ok := WaiverRequest{Check: "listeners", Until: "2026-12-31", Reason: "Postgres for billing", AcceptRisk: true}
	if err := ok.Validate(now); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	last := ok
	last.Until = "2027-11-26" // exactly a year ahead
	if err := last.Validate(now); err != nil {
		t.Errorf("a year ahead refused: %v", err)
	}
	for _, c := range []struct {
		mod  func(*WaiverRequest)
		want string
	}{
		{func(w *WaiverRequest) { w.Check = "nope" }, "not a check ID"},
		{func(w *WaiverRequest) { w.Check = "" }, "not a check ID"},
		{func(w *WaiverRequest) { w.Reason = "  " }, "-reason is required"},
		{func(w *WaiverRequest) { w.Reason = strings.Repeat("é", 301) }, "longer than 300"},
		{func(w *WaiverRequest) { w.Until = "" }, "last day of the waiver"},
		{func(w *WaiverRequest) { w.Until = "31/12/2026" }, "last day of the waiver"},
		{func(w *WaiverRequest) { w.Until = "2026-11-25" }, "in the past"},
		{func(w *WaiverRequest) { w.Until = "2027-11-27" }, "more than 365 days"},
		{func(w *WaiverRequest) { w.AcceptRisk = false }, "-accept-risk"},
	} {
		w := ok
		c.mod(&w)
		if err := w.Validate(now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", w, err, c.want)
		}
	}
}

// waiverPortal answers /waiver-requests like the receiver and records what it got.
func waiverPortal(t *testing.T, status int, answer string) (*portal, *[]*http.Request, *[]map[string]any) {
	t.Helper()
	p := newPortal(t)
	var reqs []*http.Request
	var bodies []map[string]any
	p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r)
		var b map[string]any
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &b)
		bodies = append(bodies, b)
		if r.URL.Path != "/waiver-requests" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		fmt.Fprint(w, answer)
	})
	return p, &reqs, &bodies
}

func TestRequestWaiverSendsWithToken(t *testing.T) {
	p, reqs, bodies := waiverPortal(t, http.StatusCreated, `{"request_id": 7, "check": "listeners", "status": "pending"}`)
	env, out := enrolledEnv(t, p)
	until := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	err := RequestWaiver(context.Background(), env, WaiverRequest{Check: "listeners", Until: until, Reason: " Postgres ", AcceptRisk: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(*reqs) != 1 {
		t.Fatalf("%d requests", len(*reqs))
	}
	r := (*reqs)[0]
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("User-Agent") != "bordercheck/v1.0.0" {
		t.Errorf("request %s %v", r.Method, r.Header)
	}
	want := map[string]any{"check": "listeners", "until": until, "reason": "Postgres", "accept_risk": true}
	if fmt.Sprint((*bodies)[0]) != fmt.Sprint(want) {
		t.Errorf("body %v, want %v", (*bodies)[0], want)
	}
	if !strings.Contains(out.String(), "request #7") || strings.Contains(out.String(), testToken) {
		t.Errorf("output: %s", out)
	}
}

func TestRequestWaiverRefusals(t *testing.T) {
	until := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	w := WaiverRequest{Check: "listeners", Until: until, Reason: "db", AcceptRisk: true}

	t.Run("invalid request sends nothing", func(t *testing.T) {
		p, reqs, _ := waiverPortal(t, http.StatusCreated, `{}`)
		env, _ := enrolledEnv(t, p)
		bad := w
		bad.AcceptRisk = false
		if err := RequestWaiver(context.Background(), env, bad); err == nil || len(*reqs) != 0 {
			t.Errorf("err %v, %d requests", err, len(*reqs))
		}
	})
	t.Run("portal message shown, cleaned", func(t *testing.T) {
		p, _, _ := waiverPortal(t, http.StatusConflict, `{"error": "already_requested", "message": "A waiver of listeners is already waiting\u0007 for IT's decision."}`)
		env, _ := enrolledEnv(t, p)
		err := RequestWaiver(context.Background(), env, w)
		if err == nil || !strings.Contains(err.Error(), "already waiting for IT's decision") || strings.ContainsRune(err.Error(), '\a') {
			t.Errorf("got %v", err)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		p, _, _ := waiverPortal(t, http.StatusUnauthorized, `{"error": "revoked"}`)
		env, _ := enrolledEnv(t, p)
		if err := RequestWaiver(context.Background(), env, w); !errors.Is(err, ErrRevoked) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("old portal", func(t *testing.T) {
		p, _, _ := waiverPortal(t, http.StatusNotFound, `{"error": "not found"}`)
		env, _ := enrolledEnv(t, p)
		if err := RequestWaiver(context.Background(), env, w); err == nil || !strings.Contains(err.Error(), "does not take waiver requests") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("not enrolled", func(t *testing.T) {
		env := Env{Dir: t.TempDir(), Version: "v1.0.0", Client: http.DefaultClient, Out: io.Discard}
		if err := writeJSON(filepath.Join(env.Dir, "config.json"), Config{Email: "an@example.com", InstallID: testInstallID}); err != nil {
			t.Fatal(err)
		}
		if err := RequestWaiver(context.Background(), env, w); err == nil || !strings.Contains(err.Error(), "policies.json") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("token only to its portal", func(t *testing.T) {
		var strayAuth []string
		stray := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			strayAuth = append(strayAuth, r.Header.Get("Authorization"))
		}))
		defer stray.Close()
		p, _, _ := waiverPortal(t, http.StatusCreated, `{}`)
		env, _ := enrolledEnv(t, p)
		cfg := readCfg(t, env)
		cfg.Enrollment.Portal = strings.Replace(stray.URL, "https://", "http://", 1)
		if err := writeJSON(filepath.Join(env.Dir, "config.json"), cfg); err != nil {
			t.Fatal(err)
		}
		if err := RequestWaiver(context.Background(), env, w); err == nil || !strings.Contains(err.Error(), "not sending this install's token") {
			t.Errorf("got %v", err)
		}
		if len(strayAuth) != 0 {
			t.Errorf("sent to %v", strayAuth)
		}
	})
}

func TestWaiverRequestsList(t *testing.T) {
	p, reqs, _ := waiverPortal(t, http.StatusOK, `{"data": [
 {"request_id": 2, "check": "docker", "until": "2026-12-31", "reason": "lab\u001b[31m box", "status": "rejected", "requested_at": "2026-11-20T10:00:00Z", "decision_note": "use the VM"},
 {"request_id": 1, "check": "listeners", "until": "2026-12-01", "reason": "db", "status": "pending", "requested_at": "2026-11-19T10:00:00Z", "decision_note": ""}]}`)
	env, _ := enrolledEnv(t, p)
	s, err := WaiverRequests(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if (*reqs)[0].Method != http.MethodGet || (*reqs)[0].Header.Get("Authorization") != "Bearer "+testToken {
		t.Errorf("request %s %v", (*reqs)[0].Method, (*reqs)[0].Header)
	}
	for _, want := range []string{"#2 docker until 2026-12-31: rejected (asked 2026-11-20)", "IT: use the VM", "#1 listeners until 2026-12-01: waiting for IT"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.ContainsRune(s, 0x1b) {
		t.Errorf("control character in output: %q", s)
	}
	_ = os.Remove(filepath.Join(env.Dir, TokenFile))
	if _, err := WaiverRequests(context.Background(), env); err == nil || !strings.Contains(err.Error(), "token is missing") {
		t.Errorf("without token: %v", err)
	}
}
