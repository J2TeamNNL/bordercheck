//go:build !darwin && !windows && !linux

package checks

import "context"

func adminFactsOS(context.Context) (adminFacts, error) { return adminFacts{}, errUnsupported }
