//go:build !darwin && !windows && !linux

package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/msg"
)

func shareServicesOS(context.Context) ([]shareService, msg.Text, error) {
	return nil, nil, errUnsupported
}
