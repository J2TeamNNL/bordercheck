package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// listProcs reads the process table. CommandLine is empty for other users'
// processes without admin rights, which is fine: tunnels are the user's own.
func listProcs(ctx context.Context) ([]proc, error) {
	out, err := sysx.PowerShell(ctx, `Get-CimInstance Win32_Process | ForEach-Object { '{0}|{1}' -f $_.Name, $_.CommandLine }`)
	if err != nil {
		return nil, err
	}
	return parseWinProcs(out), nil
}
