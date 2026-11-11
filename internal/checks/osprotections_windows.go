package checks

// OS gathering for os-protections on Windows: Get-MpComputerStatus, Security
// Center's antivirus list and the registry. A standard user can read all of it.

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

func protFactsOS(ctx context.Context) (protFacts, error) {
	out, err := sysx.PowerShellScript(ctx, winProtScript)
	if err != nil {
		return protFacts{}, err
	}
	return winProtFacts(out), nil
}
