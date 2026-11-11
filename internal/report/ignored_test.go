package report

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
)

var ignoredResult = check.Result{ID: "secrets", Title: "No plain-text secrets", Status: check.Warn, Severity: check.Medium,
	Summary: "1 secret in plain text across 1 file(s). 2 more ignored by you.", Evidence: []string{"~/.zshrc:3  OpenAI API key (OPENAI_API_KEY)"},
	UserIgnored: []check.Ignored{
		{Path: "~/app/.env", Name: "POSTGRES_PASSWORD", Kind: "Secret-looking variable", Reason: "local docker db", Since: "2026-11-11"},
		{Path: "~/app/c.p12", Kind: "certificate bundle", Reason: "test cert"},
	}}

func TestWriteTextListsIgnored(t *testing.T) {
	var b strings.Builder
	New("v9", "test", []check.Result{ignoredResult}).WriteText(&b, false)
	out := b.String()
	for _, want := range []string{"Ignored by you: 2", "· ~/app/.env  Secret-looking variable (POSTGRES_PASSWORD): local docker db (since 2026-11-11)",
		"· ~/app/c.p12  certificate bundle: test cert"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestWriteFixCountsIgnored(t *testing.T) {
	var b strings.Builder
	New("v9", "test", []check.Result{ignoredResult}).WriteFix(&b, "bordercheck", false)
	out := b.String()
	if !strings.Contains(out, "Ignored by you: 2 (") || strings.Contains(out, "local docker db") || strings.Contains(out, "POSTGRES_PASSWORD") {
		t.Errorf("fix output should count ignored items, not list them:\n%s", out)
	}
	if strings.Index(out, "Ignored by you") > strings.Index(out, "\nBEGIN REPORT\n") {
		t.Errorf("the count belongs before the report:\n%s", out)
	}
	pass := ignoredResult
	pass.Status, pass.Severity, pass.Evidence = check.Pass, "", nil
	b.Reset()
	New("v9", "test", []check.Result{pass}).WriteFix(&b, "bordercheck", false)
	if out := b.String(); !strings.Contains(out, "Nothing to fix") || !strings.Contains(out, "Ignored by you: 2") {
		t.Errorf("nothing to fix:\n%s", out)
	}
}
