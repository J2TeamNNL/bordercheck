package checks

// OS gathering for sharing on Windows: firewall rules, CIM shares and printers,
// and the user's Nearby sharing setting. A standard user can read all of it.

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

func shareServicesOS(ctx context.Context) ([]shareService, msg.Text, error) {
	out, err := sysx.PowerShellScript(ctx, winShareScript)
	if err != nil {
		return nil, nil, err
	}
	return winShareServices(kvLines(out)), nil, nil
}
