package report

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
)

var samplesResult = check.Result{ID: "secrets", Title: "No plain-text secrets", Status: check.Warn, Severity: check.Medium,
	Summary: "1 secret in plain text across 1 file(s). 3 more look like sample keys.", Evidence: []string{"~/.zshrc:3  OpenAI API key (OPENAI_API_KEY)"},
	LikelySamples: []check.LikelySample{
		{Path: "~/forks/app/config/default.pem", Kind: "Private key", Rule: "git-tracked"},
		{Path: "~/forks/app/.env.ci", Name: "API_SECRET", Kind: "Secret-looking variable", Rule: "git-tracked"},
		{Path: "~/demo-key/sign.pem", Kind: "Private key", Rule: "sample-dir"},
	}}

func TestWriteTextCountsSamples(t *testing.T) {
	var b strings.Builder
	New("v9", "test", []check.Result{samplesResult}).WriteText(&b, false)
	out := b.String()
	if !strings.Contains(out, "Look like sample keys: 3 (2 unchanged in a git repository, 1 in a demo or example folder; not counted, sent to IT; -json lists them)") {
		t.Errorf("missing the count line:\n%s", out)
	}
	if strings.Contains(out, "default.pem") || strings.Contains(out, "API_SECRET") {
		t.Errorf("the text report lists samples:\n%s", out)
	}
}

func TestWriteFixCountsSamples(t *testing.T) {
	var b strings.Builder
	New("v9", "test", []check.Result{samplesResult}).WriteFix(&b, "bordercheck", false)
	out := b.String()
	if !strings.Contains(out, "Look like sample keys: 3 (") || strings.Contains(out, "default.pem") || strings.Contains(out, "demo-key") {
		t.Errorf("fix output should count samples, not list them:\n%s", out)
	}
	if strings.Index(out, "Look like sample keys") > strings.Index(out, "\nBEGIN REPORT\n") {
		t.Errorf("the count belongs before the report:\n%s", out)
	}
	pass := samplesResult
	pass.Status, pass.Severity, pass.Evidence = check.Pass, "", nil
	b.Reset()
	New("v9", "test", []check.Result{pass}).WriteFix(&b, "bordercheck", false)
	if out := b.String(); !strings.Contains(out, "Nothing to fix") || !strings.Contains(out, "Look like sample keys: 3") {
		t.Errorf("nothing to fix:\n%s", out)
	}
}
