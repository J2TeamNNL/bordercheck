package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// gatherBackup asks tmutil for the Time Machine destinations and reads Time
// Machine's preferences for encryption and dates. Without Full Disk Access
// either may fail; that is reported as "could not tell", never prompted for.
// Find My Mac is on when NVRAM holds its token: only the variable's name is
// looked at.
func gatherBackup(ctx context.Context) backupFacts {
	f := backupFacts{OS: "macos"}
	if info, err := sysx.Run(ctx, "/usr/bin/tmutil", "destinationinfo", "-X"); err == nil {
		prefs, _ := plistXML(ctx, "/Library/Preferences/com.apple.TimeMachine.plist")
		if dests, err := macBackupDests(info, prefs); err == nil {
			f.Dests, f.BackupKnown = dests, true
		}
	}
	if out, err := sysx.Run(ctx, "/usr/sbin/nvram", "-p"); err == nil {
		f.FindMy, f.FindMyKnown = nvramHasFindMy(out), true
	}
	return f
}
