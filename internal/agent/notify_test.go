package agent

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/notifier"
	"github.com/ptrinh/bordercheck/internal/notify"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/update"
)

// Tests never put a notification on the desktop of the machine running them.
func TestMain(m *testing.M) {
	showNotification = func(context.Context, notify.Message) error { return errors.New("not in tests") }
	// Nor a browser, nor a real service.
	openURL = func(context.Context, string) error { return errors.New("not in tests") }
	services.check = func() error { return nil }
	services.register = func(string, string) error { return nil }
	services.unregister = func() error { return nil }
	services.status = func() string { return "fake service" }
	// Nor an entry in the app search of the machine running them.
	launcher.ensure = func(Env, Config) error { return nil }
	launcher.remove = func() error { return nil }
	// Nor the notification app: never launched, fetched or checked for real.
	ntfRun = func(context.Context, string, notifier.Mode, string, string) error { return errors.New("not in tests") }
	ntfVerify = func(context.Context, string, string) (string, error) { return "", errors.New("not in tests") }
	ntfFetch = func(context.Context, *http.Client, update.Source, string, string, int64) ([]byte, error) {
		return nil, errors.New("not in tests")
	}
	os.Exit(m.Run())
}

func TestNotifyUser(t *testing.T) {
	var shown []notify.Message
	fail := false
	showNotification = func(_ context.Context, m notify.Message) error {
		if fail {
			return errors.New("no desktop")
		}
		shown = append(shown, m)
		return nil
	}
	t.Cleanup(func() {
		showNotification = func(context.Context, notify.Message) error { return errors.New("not in tests") }
	})

	n := policy.Default().Notify
	results := []check.Result{
		{ID: "firewall", Status: check.Fail, Severity: check.High, Summary: "The macOS firewall is off."},
		{ID: "listeners", Status: check.Waived, Severity: check.High, Summary: "1 port"},
	}
	out := &strings.Builder{}
	env := Env{Out: out}
	var st State
	t0 := time.Now()

	// Forced (a person at a terminal): printed, not shown, and counted as announced.
	notifyUser(t.Context(), env, n, results, &st, t0, true, "")
	if len(shown) != 0 || !strings.Contains(out.String(), "firewall: The macOS firewall is off.") || st.Notified["firewall:fail"].IsZero() {
		t.Fatalf("forced: shown %v, out %q, state %v", shown, out, st.Notified)
	}
	if strings.Contains(out.String(), "listeners") {
		t.Error("a waived result was announced")
	}
	// The next scheduled run does not repeat it.
	notifyUser(t.Context(), env, n, results, &st, t0.Add(time.Hour), false, "")
	if len(shown) != 0 {
		t.Fatalf("repeated: %v", shown)
	}
	// A new problem, while the desktop is unavailable: logged, kept for next time.
	results = append(results, check.Result{ID: "secrets", Status: check.Fail, Severity: check.High, Summary: "2 secret(s)"})
	fail = true
	notifyUser(t.Context(), env, n, results, &st, t0.Add(2*time.Hour), false, "")
	if _, ok := st.Notified["secrets:fail"]; ok || !strings.Contains(out.String(), "notification not shown: no desktop") {
		t.Fatalf("failed show: state %v, out %q", st.Notified, out)
	}
	fail = false
	notifyUser(t.Context(), env, n, results, &st, t0.Add(3*time.Hour), false, "")
	if len(shown) != 1 || !strings.Contains(shown[0].Body, "secrets: 2 secret(s)") || strings.Contains(shown[0].Body, "firewall") {
		t.Fatalf("retry: %+v", shown)
	}
	// All fixed: silent, state cleared.
	notifyUser(t.Context(), env, n, nil, &st, t0.Add(4*time.Hour), false, "")
	if len(shown) != 1 || len(st.Notified) != 0 {
		t.Fatalf("fixed: %d shown, state %v", len(shown), st.Notified)
	}
}
