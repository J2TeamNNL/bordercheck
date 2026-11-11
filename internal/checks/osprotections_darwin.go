package checks

// OS gathering for os-protections on macOS: `csrutil status` and
// `spctl --status`, both readable without root and without a prompt.

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

func protFactsOS(ctx context.Context) (protFacts, error) {
	f := protFacts{Family: "macos"}
	if out, err := sysx.Run(ctx, "/usr/bin/csrutil", "status"); err == nil {
		f.SIP = parseCsrutil(out)
	}
	// spctl exits non-zero when assessments are disabled, so read it either way.
	out, _ := sysx.RunCombined(ctx, "/usr/sbin/spctl", "--status")
	f.Gatekeeper = parseSpctlStatus(out)
	return f, nil
}
