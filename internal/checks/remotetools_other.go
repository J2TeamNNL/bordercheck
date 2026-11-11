//go:build !darwin && !linux && !windows

package checks

import "context"

func remoteToolsOS(context.Context) (rcRaw, error) { return rcRaw{}, errUnsupported }
