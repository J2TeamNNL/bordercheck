//go:build !darwin && !linux && !windows

package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/msg"
)

func gatherStartup(context.Context, string) ([]startupItem, msg.Text, error) {
	return nil, nil, errUnsupported
}
