//go:build !darwin && !windows && !linux

package checks

import "context"

func protFactsOS(context.Context) (protFacts, error) { return protFacts{}, errUnsupported }
