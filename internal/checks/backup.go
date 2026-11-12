package checks

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The backup check helps with a lost or stolen laptop: is there a backup to
// restore from, is it encrypted (a backup disk is a copy of the whole disk,
// so an unencrypted one undoes FileVault), and can the machine be located
// and locked remotely. Severities stay low except for an unencrypted backup.
// Many organisations back up some other way, so a missing backup is only
// reported when the policy requires one. Nothing here needs admin rights or
// prompts; what cannot be read is said in a note.

// backupDest is one backup destination.
type backupDest struct {
	Name      string    // the disk or share name the OS shows; never a URL
	Encrypted *bool     // nil when not known
	Last      time.Time // the last backup; zero when not known
}

type backupFacts struct {
	OS          string // "macos", "windows"; "" = not supported here
	BackupKnown bool   // Dests is the full list
	Dests       []backupDest
	FindMyKnown bool
	FindMy      bool
	Desktop     bool // no battery: not a machine that gets lost, so Find My is not asked of it
	Notes       msg.Text
}

func backup(p policy.Backup) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		f := gatherBackup(ctx)
		if f.OS == "" {
			return check.SkippedMsg(msg.Of("backup.unsupported", "os", runtime.GOOS))
		}
		return evalBackup(f, p, time.Now())
	}
}

func evalBackup(f backupFacts, p policy.Backup, now time.Time) check.Result {
	var ev []string
	var summary, fix msg.Text
	sev := check.Severity("")
	raise := func(s check.Severity) {
		if sev == "" || s == check.Medium {
			sev = s
		}
	}
	mac := f.OS == "macos"
	unenc, stale := 0, 0
	for _, d := range f.Dests {
		if p.RequireEncrypted && d.Encrypted != nil && !*d.Encrypted {
			unenc++
			ev = append(ev, fmt.Sprintf("Time Machine: %s  the backup is not encrypted", d.Name))
		}
		if p.MaxBackupAgeDays > 0 && !d.Last.IsZero() {
			if days := int(now.Sub(d.Last).Hours() / 24); days > p.MaxBackupAgeDays {
				stale++
				ev = append(ev, fmt.Sprintf("Time Machine: %s  last backup %s (%d days ago)", d.Name, d.Last.Format("2006-01-02"), days))
			}
		}
	}
	if unenc > 0 {
		summary = append(summary, msg.P("backup.unencrypted", "n", unenc))
		fix = append(fix, msg.P("backup.fix.mac.encrypt"))
		raise(check.Medium)
	}
	if stale > 0 {
		summary = append(summary, msg.P("backup.stale", "n", stale, "max", p.MaxBackupAgeDays))
		fix = append(fix, msg.P("backup.fix.mac.stale"))
		raise(check.Low)
	}
	if p.RequireBackup && f.BackupKnown && len(f.Dests) == 0 {
		summary = append(summary, msg.P("backup.none"))
		if mac {
			fix = append(fix, msg.P("backup.fix.mac.setup"))
		}
		ev = append(ev, "Time Machine: no backup disk is set up")
		raise(check.Low)
	}
	var desktop msg.Text
	if p.RequireFindMy && f.FindMyKnown && !f.FindMy && f.Desktop {
		desktop = msg.Text{msg.P("backup.findMyDesktop")}
	} else if p.RequireFindMy && f.FindMyKnown && !f.FindMy {
		if mac {
			summary = append(summary, msg.P("backup.findMyOff.mac"))
			fix = append(fix, msg.P("backup.fix.mac.findMy"))
			ev = append(ev, "Find My Mac: off (no Find My token in NVRAM)")
		} else {
			summary = append(summary, msg.P("backup.findMyOff.win"))
			fix = append(fix, msg.P("backup.fix.win.findMy"))
			ev = append(ev, "Find my device: off")
		}
		raise(check.Low)
	}
	notes := append(desktop, f.Notes...)
	if mac && !f.BackupKnown {
		notes = append(notes, msg.P("backup.unknown.mac"))
	}
	if !f.FindMyKnown {
		notes = append(notes, msg.P("backup.findMyUnknown"))
	}
	if sev != "" {
		return check.Result{Status: check.Warn, Severity: sev, Evidence: ev}.WithSummary(append(summary, notes...)).WithFix(fix)
	}
	var ok msg.Text
	if f.BackupKnown && len(f.Dests) > 0 {
		ok = append(ok, msg.P("backup.on", "n", len(f.Dests)))
	} else if f.BackupKnown {
		ok = append(ok, msg.P("backup.noneAllowed"))
	}
	if f.FindMyKnown && f.FindMy {
		ok = append(ok, msg.P(map[bool]string{true: "backup.findMyOn.mac", false: "backup.findMyOn.win"}[mac]))
	}
	return check.Result{Status: check.Pass}.WithSummary(append(ok, notes...))
}

// --- macOS parsing, portable so it is tested everywhere --------------------

// macBackupDests reads `tmutil destinationinfo -X` and Time Machine's
// preferences (/Library/Preferences/com.apple.TimeMachine.plist, as XML),
// whose Destinations hold LastKnownEncryptionState, DiskImageKeychainUUID (an
// encrypted network backup) and the snapshot dates. prefs may be "" when it
// could not be read; encryption and dates are then unknown.
func macBackupDests(info, prefs string) ([]backupDest, error) {
	d, err := plistDict(info)
	if err != nil {
		return nil, err
	}
	type pref struct {
		enc  *bool
		last time.Time
	}
	byID := map[string]pref{}
	if pd, err := plistDict(prefs); err == nil {
		list, _ := pd["Destinations"].([]any)
		for _, x := range list {
			m, ok := x.(map[string]any)
			if !ok {
				continue
			}
			id, _ := m["DestinationID"].(string)
			var pr pref
			state, _ := m["LastKnownEncryptionState"].(string)
			kc, _ := m["DiskImageKeychainUUID"].(string)
			switch {
			case state == "Encrypted" || kc != "":
				pr.enc = ptrBool(true)
			case state == "NotEncrypted":
				pr.enc = ptrBool(false)
			}
			if t, ok := m["ReferenceLocalSnapshotDate"].(time.Time); ok {
				pr.last = t
			}
			if dates, ok := m["SnapshotDates"].([]any); ok {
				for _, v := range dates {
					if t, ok := v.(time.Time); ok && t.After(pr.last) {
						pr.last = t
					}
				}
			}
			byID[strings.ToUpper(id)] = pr
		}
	}
	var out []backupDest
	list, _ := d["Destinations"].([]any)
	for _, x := range list {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["Name"].(string)
		if name == "" {
			name = "(unnamed)"
		}
		id, _ := m["ID"].(string)
		pr := byID[strings.ToUpper(id)]
		out = append(out, backupDest{Name: name, Encrypted: pr.enc, Last: pr.last})
	}
	return out, nil
}

func ptrBool(b bool) *bool { return &b }

// macFindMy says whether Find My Mac is on. FMMEnabled in
// /Library/Preferences/com.apple.FindMyMac.plist (prefs, as XML; "" when the
// file is absent) decides when it is there. Otherwise the NVRAM token does:
// on Apple silicon `nvram -p` does not show it to a normal user, so its
// absence alone never proved Find My was off.
func macFindMy(prefs, nvram string) bool {
	if d, err := plistDict(prefs); err == nil {
		if on, ok := d["FMMEnabled"].(bool); ok {
			return on
		}
	}
	return nvramHasFindMy(nvram)
}

// nvramHasFindMy reports whether `nvram -p` lists the variable Find My Mac
// stores its token in. Only the names are looked at; the value is never kept.
func nvramHasFindMy(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == "fmm-mobileme-token-FMM" {
			return true
		}
	}
	return false
}

// winFindMy reads the gatherer's key=value lines: policy (AllowFindMyDevice
// from Group Policy or MDM) and setting (LocationSyncEnabled, the Settings
// toggle). known is false when neither is set.
func winFindMy(kv map[string]string) (on, known bool) {
	if kv["policy"] == "0" {
		return false, true
	}
	switch kv["setting"] {
	case "1":
		return true, true
	case "0":
		return false, true
	}
	return false, false
}
