//go:build !darwin && !windows && !linux

package checks

import "context"

func updateFactsOS(context.Context) (updateFacts, error) { return updateFacts{}, errUnsupported }

func browsersOS(context.Context) []browserInfo { return nil }

func screenLockOS(context.Context) (lockFacts, error) { return lockFacts{}, errUnsupported }

func remoteServicesOS(context.Context) ([]remoteService, []string, error) {
	return nil, nil, errUnsupported
}
