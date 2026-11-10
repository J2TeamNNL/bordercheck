//go:build !darwin && !windows && !linux

package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/msg"
)

func updateFactsOS(context.Context) (updateFacts, error) { return updateFacts{}, errUnsupported }

func browsersOS(context.Context) []browserInfo { return nil }

func screenLockOS(context.Context) (lockFacts, error) { return lockFacts{}, errUnsupported }

func remoteServicesOS(context.Context) ([]remoteService, msg.Text, error) {
	return nil, nil, errUnsupported
}
