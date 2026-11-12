package checks

import (
	"context"
	"strings"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// gatherBackup asks tmutil for the Time Machine destinations and reads Time
// Machine's preferences for encryption and dates. Without Full Disk Access
// either may fail; that is reported as "could not tell", never prompted for.
// Find My Mac is read from its preferences file, then from NVRAM, where only
// the token's name is looked at (see macFindMy).
func gatherBackup(ctx context.Context) backupFacts {
	f := backupFacts{OS: "macos"}
	if info, err := sysx.Run(ctx, "/usr/bin/tmutil", "destinationinfo", "-X"); err == nil {
		prefs, _ := plistXML(ctx, "/Library/Preferences/com.apple.TimeMachine.plist")
		if dests, err := macBackupDests(info, prefs); err == nil {
			f.Dests, f.BackupKnown = dests, true
		}
	}
	prefs, perr := plistXML(ctx, "/Library/Preferences/com.apple.FindMyMac.plist")
	nvram, nerr := sysx.Run(ctx, "/usr/sbin/nvram", "-p")
	if (perr == nil && prefs != "") || nerr == nil {
		f.FindMy, f.FindMyKnown = macFindMy(prefs, nvram), true
	}
	// A Mac without a battery (iMac, Mac mini, Mac Studio, Mac Pro) prints nothing here.
	if out, err := sysx.Run(ctx, "/usr/sbin/ioreg", "-r", "-c", "AppleSmartBattery", "-d", "1"); err == nil {
		f.Desktop = strings.TrimSpace(out) == ""
	}
	return f
}
