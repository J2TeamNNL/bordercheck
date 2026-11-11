package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Shapes of `tmutil destinationinfo -X` and com.apple.TimeMachine.plist
// (key names as osquery's time_machine tables and Pareto Security read them),
// with made-up names and IDs.
const sampleTMInfo = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Destinations</key><array>
<dict><key>ID</key><string>1111AAAA-0000-0000-0000-000000000001</string><key>Kind</key><string>Local</string><key>Name</key><string>Backup Disk</string></dict>
<dict><key>ID</key><string>2222BBBB-0000-0000-0000-000000000002</string><key>Kind</key><string>Network</string><key>Name</key><string>NAS</string></dict>
<dict><key>ID</key><string>3333CCCC-0000-0000-0000-000000000003</string><key>Kind</key><string>Local</string><key>Name</key><string>Old Disk</string></dict>
</array></dict></plist>`

const sampleTMPrefs = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>AutoBackup</key><true/><key>Destinations</key><array>
<dict><key>DestinationID</key><string>1111AAAA-0000-0000-0000-000000000001</string><key>LastKnownEncryptionState</key><string>NotEncrypted</string>
<key>SnapshotDates</key><array><date>2026-09-01T10:00:00Z</date><date>2026-10-01T10:00:00Z</date></array></dict>
<dict><key>DestinationID</key><string>2222BBBB-0000-0000-0000-000000000002</string><key>DiskImageKeychainUUID</key><string>X</string>
<key>ReferenceLocalSnapshotDate</key><date>2026-11-09T10:00:00Z</date></dict>
<dict><key>DestinationID</key><string>3333CCCC-0000-0000-0000-000000000003</string><key>LastKnownEncryptionState</key><string>Encrypted</string></dict>
</array></dict></plist>`

func TestMacBackupDests(t *testing.T) {
	d, err := macBackupDests(sampleTMInfo, sampleTMPrefs)
	if err != nil || len(d) != 3 {
		t.Fatalf("got %+v %v", d, err)
	}
	if d[0].Name != "Backup Disk" || d[0].Encrypted == nil || *d[0].Encrypted || d[0].Last.Format("2006-01-02") != "2026-10-01" {
		t.Errorf("local: %+v", d[0])
	}
	if !*d[1].Encrypted || d[1].Last.Day() != 9 || !*d[2].Encrypted || !d[2].Last.IsZero() {
		t.Errorf("network/old: %+v %+v", d[1], d[2])
	}
	// Preferences unreadable: encryption unknown.
	d, _ = macBackupDests(sampleTMInfo, "")
	if d[0].Encrypted != nil {
		t.Errorf("unknown: %+v", d[0])
	}
	// No destinations.
	d, err = macBackupDests(`<plist version="1.0"><dict/></plist>`, "")
	if err != nil || len(d) != 0 {
		t.Errorf("none: %+v %v", d, err)
	}
}

func TestNvramFindMy(t *testing.T) {
	if !nvramHasFindMy("SystemAudioVolume\t%80\nfmm-mobileme-token-FMM\tbplist00%d4...\n") ||
		nvramHasFindMy("fmm-computer-name\tMac\nprev-lang:kbd\ten:0\n") {
		t.Error("nvram")
	}
	for kv, want := range map[string][2]bool{
		"policy=\nsetting=1": {true, true}, "policy=0\nsetting=1": {false, true}, "policy=\nsetting=0": {false, true},
		"policy=\nsetting=": {false, false},
	} {
		if on, known := winFindMy(kvLines(kv)); on != want[0] || known != want[1] {
			t.Errorf("%q: got %v %v", kv, on, known)
		}
	}
}

func TestEvalBackup(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	def := policy.Default().Checks.Backup
	dests, _ := macBackupDests(sampleTMInfo, sampleTMPrefs)

	r := evalBackup(backupFacts{OS: "macos", BackupKnown: true, Dests: dests, FindMyKnown: true, FindMy: false}, def, now)
	ev := strings.Join(r.Evidence, "\n")
	if r.Status != check.Warn || r.Severity != check.Medium || len(r.Evidence) != 2 ||
		!strings.Contains(ev, "Backup Disk  the backup is not encrypted") || !strings.Contains(ev, "Find My Mac: off") ||
		!strings.Contains(r.Summary, "1 Time Machine backup is not encrypted") {
		t.Errorf("got %s %s %q\n%s", r.Status, r.Severity, r.Summary, ev)
	}

	p := def
	p.MaxBackupAgeDays, p.RequireFindMy = 30, false
	r = evalBackup(backupFacts{OS: "macos", BackupKnown: true, Dests: dests[1:], FindMyKnown: true}, p, now)
	if r.Status != check.Pass || r.Summary != "Backups go to 2 destinations." {
		t.Errorf("fresh: %s %q %v", r.Status, r.Summary, r.Evidence)
	}
	p.MaxBackupAgeDays = 7
	p.RequireEncrypted = false
	r = evalBackup(backupFacts{OS: "macos", BackupKnown: true, Dests: dests, FindMyKnown: true, FindMy: true}, p, now)
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Summary, "1 backup is older than 7 days") {
		t.Errorf("stale: %s %s %q %v", r.Status, r.Severity, r.Summary, r.Evidence)
	}

	// No backup: fine unless required.
	r = evalBackup(backupFacts{OS: "macos", BackupKnown: true, FindMyKnown: true, FindMy: true}, def, now)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "policy does not require one") || !strings.Contains(r.Summary, "Find My Mac is on") {
		t.Errorf("none allowed: %s %q", r.Status, r.Summary)
	}
	p = def
	p.RequireBackup = true
	r = evalBackup(backupFacts{OS: "macos", BackupKnown: true, FindMyKnown: true, FindMy: true}, p, now)
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Summary, "No backup is set up") {
		t.Errorf("none required: %s %q", r.Status, r.Summary)
	}

	// Could not tell: a note, never a warning.
	r = evalBackup(backupFacts{OS: "macos"}, p, now)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "Full Disk Access") || !strings.Contains(r.Summary, "located remotely") {
		t.Errorf("unknown: %s %q", r.Status, r.Summary)
	}

	// Windows: Find my device only.
	win := backupFacts{OS: "windows", FindMyKnown: true, FindMy: false}
	win.Notes = append(win.Notes, msg.P("backup.win.notRead"))
	r = evalBackup(win, def, now)
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Summary, "Find my device is off") ||
		!strings.Contains(r.Fix, "Privacy & security → Find my device") {
		t.Errorf("windows: %s %q %q", r.Status, r.Summary, r.Fix)
	}
}
