package checks

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// A token used as a JSON key or before a colon is caught where a variable's
// name would be; it must not be reported as the name.
func TestTokenIsNeverTheName(t *testing.T) {
	gh := "ghp_" + strings.Repeat("Ab1x", 9)
	for _, line := range []string{
		`{"` + gh + `": "github"}`,
		gh + `:x-oauth-basic`,
	} {
		home := isolatedHome(t)
		writeTestFile(t, filepath.Join(home, ".zshrc"), line+"\n")
		r := secrets(policy.Default().Checks.Secrets, Local{})(t.Context())
		ev := strings.Join(r.Evidence, "\n")
		if !strings.Contains(ev, "GitHub token") || strings.Contains(ev, gh[:20]) {
			t.Errorf("%s:\n%s", line, ev)
		}
	}
	for name, want := range map[string]string{
		"API_KEY": "API_KEY", "stripeSecret2": "stripeSecret2", "MYAPP_UPLOAD_STORE_PASSWORD": "MYAPP_UPLOAD_STORE_PASSWORD",
		gh: "", "aB3dE5fG7hJ9kL1mN3pQ": "", strings.Repeat("x", 41): "",
	} {
		if got := safeName(name); got != want {
			t.Errorf("safeName(%q) = %q, want %q", name, got, want)
		}
	}
}
