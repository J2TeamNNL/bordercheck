package checks

import (
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
)

// evalFileVault judges `fdesetup status`.
func evalFileVault(out string) check.Result {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return check.Result{Status: check.Pass, Summary: "FileVault is on."}
	case strings.Contains(out, "FileVault is Off"):
		return check.Result{Status: check.Fail, Severity: check.High,
			Summary: "FileVault is off: anyone who takes this Mac can read its disk.",
			Fix:     "System Settings → Privacy & Security → FileVault → Turn On."}
	}
	return check.Result{Status: check.Warn, Severity: check.Medium,
		Summary: "FileVault is not fully on: " + firstLine(out)}
}

// evalBitLocker judges the System.Volume.BitLockerProtection value of the system
// drive, which Windows reports without admin rights: 1 = on, 2 = off, other values
// mean in progress, suspended or locked.
func evalBitLocker(code string) check.Result {
	fix := "Settings → Privacy & security → Device encryption, or Control Panel → BitLocker Drive Encryption → turn on."
	switch code = strings.TrimSpace(code); code {
	case "1":
		return check.Result{Status: check.Pass, Summary: "BitLocker is on for the system drive."}
	case "2":
		return check.Result{Status: check.Fail, Severity: check.High,
			Summary: "BitLocker is off: anyone who takes this PC can read its disk.", Fix: fix}
	case "":
		return check.Skipped("Windows did not report BitLocker status for the system drive.")
	}
	return check.Result{Status: check.Warn, Severity: check.Medium,
		Summary: "BitLocker is not fully on for the system drive (status " + code + ").", Fix: fix}
}
