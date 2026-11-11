//go:build !darwin && !windows

package checks

import "context"

// Linux has no standard backup or device-finding service to read, so the
// check skips there.
func gatherBackup(context.Context) backupFacts { return backupFacts{} }
