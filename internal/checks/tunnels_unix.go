//go:build !windows

package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// listProcs reads the process table with ps. comm and args are read
// separately because an executable path may contain spaces.
func listProcs(ctx context.Context) ([]proc, error) {
	bin, ok := sysx.Find("ps", "/bin/ps", "/usr/bin/ps")
	if !ok {
		return nil, errUnsupported
	}
	comm, err := sysx.Run(ctx, bin, "-A", "-ww", "-o", "pid=,comm=")
	if err != nil {
		return nil, err
	}
	args, err := sysx.Run(ctx, bin, "-A", "-ww", "-o", "pid=,args=")
	if err != nil {
		return nil, err
	}
	return parsePs(comm, args), nil
}
