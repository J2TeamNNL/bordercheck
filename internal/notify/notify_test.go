package notify

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func res(id string, st check.Status, sev check.Severity) check.Result {
	return check.Result{ID: id, Title: id + " title", Status: st, Severity: sev, Summary: id + " is broken.",
		Evidence: []string{"~/.zshrc:3 OPENAI_API_KEY …abcd"}}
}

func ids(rs []check.Result) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func on() policy.Notify {
	return policy.Notify{Enabled: true, Statuses: []check.Status{check.Fail},
		Severities: []check.Severity{check.High, check.Medium}, RemindEvery: "24h"}
}

func TestPlanNewSeenAndReminders(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	fw, sec := res("firewall", check.Fail, check.High), res("secrets", check.Fail, check.High)

	due, seen := Plan([]check.Result{fw}, on(), nil, t0)
	if !slices.Equal(ids(due), []string{"firewall"}) {
		t.Fatalf("first run: due %v", ids(due))
	}
	// An hour later: firewall is old news, secrets is new.
	due, seen = Plan([]check.Result{fw, sec}, on(), seen, t0.Add(time.Hour))
	if !slices.Equal(ids(due), []string{"secrets"}) {
		t.Fatalf("second run: due %v", ids(due))
	}
	// A day after the first announcement firewall is reminded; secrets is not yet.
	due, seen = Plan([]check.Result{fw, sec}, on(), seen, t0.Add(24*time.Hour))
	if !slices.Equal(ids(due), []string{"firewall"}) {
		t.Fatalf("reminder: due %v", ids(due))
	}
	// Fixed, then back: new again.
	_, seen = Plan([]check.Result{sec}, on(), seen, t0.Add(25*time.Hour))
	if _, ok := seen[Key(fw)]; ok {
		t.Fatal("a fixed problem should be forgotten")
	}
	due, _ = Plan([]check.Result{fw, sec}, on(), seen, t0.Add(26*time.Hour))
	if !slices.Equal(ids(due), []string{"firewall"}) {
		t.Fatalf("came back: due %v", ids(due))
	}
	// Nothing failing: silent, and nothing remembered.
	if due, seen := Plan([]check.Result{res("docker", check.Pass, "")}, on(), seen, t0); len(due)+len(seen) != 0 {
		t.Fatalf("all passing: due %v seen %v", ids(due), seen)
	}
}

func TestPlanNeverRemindsWithZero(t *testing.T) {
	n := on()
	n.RemindEvery = "0"
	fw := res("firewall", check.Fail, check.High)
	_, seen := Plan([]check.Result{fw}, n, nil, time.Now())
	if due, _ := Plan([]check.Result{fw}, n, seen, time.Now().Add(1000*time.Hour)); len(due) != 0 {
		t.Fatalf("remind_every 0 reminded: %v", ids(due))
	}
}

func TestPlanFilters(t *testing.T) {
	results := []check.Result{
		res("a", check.Fail, check.High),
		res("b", check.Fail, check.Low),    // severity not wanted
		res("c", check.Warn, check.High),   // status not wanted
		res("d", check.Waived, check.High), // waived never notifies
		res("e", check.Error, ""),
		res("f", check.Fail, ""), // no severity counts as medium
	}
	due, _ := Plan(results, on(), nil, time.Now())
	if !slices.Equal(ids(due), []string{"a", "f"}) {
		t.Fatalf("due %v", ids(due))
	}
	n := on()
	n.Enabled = false
	if due, seen := Plan(results, n, nil, time.Now()); len(due)+len(seen) != 0 {
		t.Fatalf("disabled: due %v", ids(due))
	}
	n = on()
	n.Statuses = []check.Status{check.Fail, check.Warn}
	due, _ = Plan(results, n, nil, time.Now())
	if !slices.Equal(ids(due), []string{"a", "c", "f"}) {
		t.Fatalf("with warn: due %v", ids(due))
	}
}

func TestPlanEscalationIsNew(t *testing.T) {
	n := on()
	n.Statuses = []check.Status{check.Fail, check.Warn}
	_, seen := Plan([]check.Result{res("listeners", check.Warn, check.Medium)}, n, nil, time.Now())
	due, _ := Plan([]check.Result{res("listeners", check.Fail, check.Medium)}, n, seen, time.Now())
	if len(due) != 1 {
		t.Fatal("warn turning into fail should be announced")
	}
}

func TestComposeHasNoEvidence(t *testing.T) {
	due := []check.Result{
		res("firewall", check.Fail, check.High),
		{ID: "secrets", Status: check.Fail, Summary: "3 secret(s)\nin plain\x1b[31m text " + strings.Repeat("x", 300),
			Evidence: []string{"~/.env OPENAI_API_KEY …wxyz"}},
		res("docker", check.Fail, check.High),
		res("tailscale", check.Fail, check.High),
		res("listeners", check.Fail, check.High),
	}
	m := Compose(due)
	all := m.Title + "\n" + m.Body
	for _, bad := range []string{"OPENAI", "wxyz", "abcd", ".zshrc", ".env", "\x1b", "tailscale", "listeners"} {
		if strings.Contains(all, bad) {
			t.Errorf("notification contains %q:\n%s", bad, all)
		}
	}
	lines := strings.Split(m.Body, "\n")
	if !strings.Contains(m.Title, "5 problems") || len(lines) != 5 ||
		lines[0] != "firewall: firewall is broken." || !strings.HasPrefix(lines[1], "secrets: 3 secret(s) in plain[31m text x") ||
		len([]rune(lines[1])) > len("secrets: ")+maxSummary || lines[3] != "… and 2 more" ||
		!strings.Contains(lines[4], "Run bordercheck") {
		t.Errorf("got %q\n%s", m.Title, m.Body)
	}
	if one := Compose(due[:1]); !strings.Contains(one.Title, "1 problem on") {
		t.Errorf("one: %q", one.Title)
	}
}

func TestGVariantString(t *testing.T) {
	if got := gvariantString("it's a \\ test\nok"); got != `'it\'s a \\ test\nok'` {
		t.Errorf("got %s", got)
	}
}
