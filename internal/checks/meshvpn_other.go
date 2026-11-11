//go:build !darwin && !linux && !windows

package checks

import "context"

func meshToolsOS(context.Context) ([]meshTool, error) { return nil, errUnsupported }
