package checks

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The os-updates check never goes online. It judges what the OS already knows:
// its version against the policy's minimum, its own auto-update settings, when it
// last checked, which updates it has found and not installed, and how long ago
// each browser build landed on disk (Chrome, Edge, Firefox and Brave ship a new
// version at least every four weeks, so an old build is an unpatched one).

type pendingUpdate struct {
	Name  string
	Since time.Time // when the OS first offered it; zero if unknown
}

type updateFacts struct {
	Family         string   // "macos", "windows", "debian", "fedora", "arch" or "linux"; picks the fix text
	Name           string   // "macOS 27.2", for people
	Key            string   // key in min_os_versions
	Version        string   // compared with the minimum
	AutoUpdate     *bool    // nil: could not tell
	AutoUpdateOff  msg.Text // what is off, as the summary says it
	PausedUntil    time.Time
	LastCheck      time.Time // last successful check for updates; zero if unknown
	PendingKnown   bool      // the OS keeps a list of updates it found
	Pending        []pendingUpdate
	PendingCount   int       // updates found when only a count is known
	LastInstall    time.Time // last OS update installed; zero if unknown
	RebootRequired bool
	Notes          msg.Text // what could not be read
}

type browserInfo struct {
	ID, Name, Version string
	Modified          time.Time // when this build landed on disk
}

var browserNames = map[string]string{"chrome": "Google Chrome", "edge": "Microsoft Edge", "firefox": "Firefox", "brave": "Brave"}

func osUpdates(opts policy.OSUpdates) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		f, err := updateFactsOS(ctx)
		if errors.Is(err, errUnsupported) {
			return unsupported()
		}
		if err != nil {
			return check.Errored(err)
		}
		var bs []browserInfo
		if opts.CheckBrowsers == nil || *opts.CheckBrowsers {
			bs = browsersOS(ctx)
		}
		return evalOSUpdates(f, bs, opts, time.Now())
	}
}

func daysAgo(t, now time.Time) int { return int(now.Sub(t).Hours() / 24) }

func agoText(days int) string {
	switch days {
	case 0:
		return "today"
	case 1:
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

func evalOSUpdates(f updateFacts, bs []browserInfo, opts policy.OSUpdates, now time.Time) check.Result {
	var p issueList
	var notes msg.Text
	fix := func(kind string) msg.Part { return updateFix(kind, f.Family) }

	if min := opts.MinOSVersions[f.Key]; min != "" && f.Version != "" && versionLess(f.Version, min) {
		key := "updates.belowMin"
		if f.Key == "windows" {
			key = "updates.belowMinWin"
		}
		p.add(true, msg.Of(key, "os", f.Name, "min", min), fix("upgrade"))
	}
	if opts.RequireAutoUpdate == nil || *opts.RequireAutoUpdate {
		switch {
		case f.AutoUpdate == nil:
			notes = append(notes, msg.P("updates.autoUnknown"))
		case !*f.AutoUpdate:
			p.add(false, f.AutoUpdateOff, fix("auto"))
		}
	}
	if f.PausedUntil.After(now) {
		p.add(false, msg.Of("updates.paused", "until", f.PausedUntil.Format("2006-01-02")), fix("paused"))
	}
	if max := opts.MaxCheckAgeDays; max > 0 && !f.LastCheck.IsZero() {
		if d := daysAgo(f.LastCheck, now); d > max {
			p.add(false, msg.Of("updates.checkStale", "ago", d, "max", max), fix("check"))
		}
	}
	for _, u := range f.Pending {
		d := -1
		if !u.Since.IsZero() {
			d = daysAgo(u.Since, now)
		}
		if max := opts.MaxPendingDays; max > 0 && d > max {
			p.add(true, msg.Of("updates.waitingLong", "name", u.Name, "days", d, "max", max), fix("pending"))
		} else {
			if d >= 0 {
				notes = append(notes, msg.P("updates.ready", "name", u.Name, "ago", d))
			} else {
				notes = append(notes, msg.P("updates.readyUndated", "name", u.Name))
			}
		}
	}
	upToDate := f.PendingKnown && len(f.Pending) == 0 && f.PendingCount == 0
	if f.PendingCount > 0 {
		d := -1
		if !f.LastInstall.IsZero() {
			d = daysAgo(f.LastInstall, now)
		}
		if max := opts.MaxPendingDays; max > 0 && d > max {
			p.add(true, msg.Of("updates.countWaitingLong", "n", f.PendingCount, "days", d, "max", max), fix("pending"))
		} else {
			notes = append(notes, msg.P("updates.countReady", "n", f.PendingCount))
		}
	}
	if f.RebootRequired {
		p.add(false, msg.Of("updates.reboot"), fix("reboot"))
	}
	if max := opts.MaxDaysSinceUpdate; max > 0 && !f.LastInstall.IsZero() && !upToDate {
		if d := daysAgo(f.LastInstall, now); d > max && f.PendingCount == 0 {
			p.add(true, msg.Of("updates.noneInstalled", "days", d, "max", max), fix("pending"))
		}
	}

	auto := f.AutoUpdate != nil && *f.AutoUpdate
	state := f.Name
	if auto {
		state += ", automatic updates on"
	}
	var pass msg.Text
	switch {
	case !f.LastCheck.IsZero():
		d := daysAgo(f.LastCheck, now)
		state += ", last checked for updates " + agoText(d)
		if auto {
			pass = msg.Of("updates.stateAutoChecked", "os", f.Name, "ago", d)
		} else {
			pass = msg.Of("updates.stateChecked", "os", f.Name, "ago", d)
		}
	case auto:
		pass = msg.Of("updates.stateAuto", "os", f.Name)
	default:
		pass = msg.Of("updates.state", "os", f.Name)
	}
	evidence := []string{state}
	for _, b := range bs {
		line := b.Name
		if b.Version != "" {
			line += " " + b.Version
		}
		age := -1
		if !b.Modified.IsZero() {
			age = daysAgo(b.Modified, now)
			line += ", updated " + agoText(age)
		}
		evidence = append(evidence, line)
		if max := opts.MaxBrowserAgeDays; max > 0 && age > max {
			p.add(true, msg.Of("updates.browserStale", "browser", strings.TrimSpace(b.Name+" "+b.Version), "days", age, "max", max),
				updateFix("browser", ""))
		}
		if min := opts.MinBrowserVersions[b.ID]; min != "" && b.Version != "" && versionLess(b.Version, min) {
			p.add(true, msg.Of("updates.browserBelowMin", "browser", b.Name, "version", b.Version, "min", min),
				updateFix("browser", ""))
		}
	}

	if upToDate {
		pass = append(pass, msg.P("updates.noneWaiting"))
	}
	if len(bs) > 0 {
		pass = append(pass, msg.P("updates.browsersFresh", "n", len(bs)))
	}
	notes = append(notes, f.Notes...)
	return p.result(pass, notes, evidence)
}

// updateFix says how to fix one kind of update problem on one OS family.
func updateFix(kind, family string) msg.Part {
	if kind == "browser" {
		return msg.P("updates.fix.browser")
	}
	fixes := map[string]map[string]string{
		"macos": {
			"upgrade": "updates.fix.macos.upgrade",
			"auto":    "updates.fix.macos.auto",
			"pending": "updates.fix.macos.pending",
			"check":   "updates.fix.macos.check",
		},
		"windows": {
			"upgrade": "updates.fix.windows.upgrade",
			"auto":    "updates.fix.windows.auto",
			"paused":  "updates.fix.windows.paused",
			"pending": "updates.fix.windows.pending",
			"check":   "updates.fix.windows.check",
			"reboot":  "updates.fix.windows.reboot",
		},
		"debian": {
			"upgrade": "updates.fix.debian.upgrade",
			"auto":    "updates.fix.debian.auto",
			"pending": "updates.fix.debian.pending",
			"check":   "updates.fix.debian.check",
			"reboot":  "updates.fix.debian.reboot",
		},
		"fedora": {
			"upgrade": "updates.fix.fedora.upgrade",
			"auto":    "updates.fix.fedora.auto",
			"pending": "updates.fix.fedora.pending",
			"check":   "updates.fix.fedora.check",
		},
		"arch": {
			"pending": "updates.fix.arch.pending",
			"check":   "updates.fix.arch.pending",
		},
	}
	if k := fixes[family][kind]; k != "" {
		return msg.P(k)
	}
	return msg.P("updates.fix.generic")
}

// issueList collects what a check found and turns it into one result.
type issueList struct{ high, medium, fixes msg.Text }

// add records a problem; its fix, when it has one, is listed once.
func (p *issueList) add(high bool, text msg.Text, fix msg.Part) {
	if high {
		p.high = append(p.high, text...)
	} else {
		p.medium = append(p.medium, text...)
	}
	if fix.Key != "" && !slices.ContainsFunc(p.fixes, func(f msg.Part) bool { return reflect.DeepEqual(f, fix) }) {
		p.fixes = append(p.fixes, fix)
	}
}

func (p issueList) result(pass, notes msg.Text, evidence []string) check.Result {
	if len(p.high)+len(p.medium) == 0 {
		return check.Result{Status: check.Pass, Evidence: evidence}.WithSummary(slices.Concat(pass, notes))
	}
	r := check.Result{Status: check.Warn, Severity: check.Medium, Evidence: evidence}.
		WithSummary(slices.Concat(p.high, p.medium, notes)).WithFix(p.fixes)
	if len(p.high) > 0 {
		r.Status, r.Severity = check.Fail, check.High
	}
	return r
}

// versionLess compares dotted versions numerically; text after the digits of a
// part ("22.04.3 LTS", "156.0b1") is ignored.
func versionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := range max(len(pa), len(pb)) {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

var leadingDigits = regexp.MustCompile(`^\d+`)

func versionParts(v string) []int {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(v), ".") {
		d := leadingDigits.FindString(part)
		if d == "" {
			break
		}
		n, _ := strconv.Atoi(d)
		out = append(out, n)
	}
	return out
}

// ---- macOS ----

// macUpdateFacts reads `sw_vers -productVersion` and
// /Library/Preferences/com.apple.SoftwareUpdate.plist (world-readable), with a
// configuration profile's managed copy, if any, on top.
func macUpdateFacts(productVersion, suPlist, managedPlist string) (updateFacts, error) {
	v := strings.TrimSpace(productVersion)
	f := updateFacts{Family: "macos", Key: "macos", Version: v, Name: "macOS " + v, PendingKnown: true}
	su, err := plistDict(suPlist)
	if err != nil {
		return f, err
	}
	settings := maps.Clone(su)
	if managedPlist != "" {
		if m, err := plistDict(managedPlist); err == nil {
			maps.Copy(settings, m)
		}
	}
	var off []string
	for _, s := range []struct{ key, label string }{
		{"AutomaticCheckEnabled", "Check for updates"},
		{"AutomaticDownload", "Download new updates when available"},
		{"CriticalUpdateInstall", "Install Security Responses and system files"},
	} {
		if on, ok := settings[s.key].(bool); ok && !on { // missing means the default, on
			off = append(off, s.label)
		}
	}
	on := len(off) == 0
	f.AutoUpdate = &on
	if !on {
		f.AutoUpdateOff = msg.Of("updates.autoOff.mac", "settings", strings.Join(off, ", "))
	}
	for _, k := range []string{"LastSuccessfulDate", "LastFullSuccessfulDate"} {
		if t, ok := su[k].(time.Time); ok && t.After(f.LastCheck) {
			f.LastCheck = t
		}
	}
	offered, _ := su["FirstOfferDateDictionary"].(map[string]any)
	recs, _ := su["RecommendedUpdates"].([]any)
	for _, r := range recs {
		d, _ := r.(map[string]any)
		id, _ := d["Identifier"].(string)
		if id == "" {
			id, _ = d["Product Key"].(string)
		}
		if strings.HasSuffix(id, "_major") {
			continue // a new major version is the minimum-version rule's business
		}
		name, _ := d["Display Name"].(string)
		if name == "" {
			name = id
		}
		since, _ := offered[id].(time.Time)
		f.Pending = append(f.Pending, pendingUpdate{Name: name, Since: since})
	}
	return f, nil
}

// ---- Windows ----

// kvLines reads lines of "key=value".
func kvLines(out string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k != "" {
			kv[k] = strings.TrimSpace(v)
		}
	}
	return kv
}

// winUpdateScript prints what Windows knows about its updates, without admin
// rights and without going online.
const winUpdateScript = `$ErrorActionPreference = 'SilentlyContinue'
$inv = [Globalization.CultureInfo]::InvariantCulture
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"build=$($cv.CurrentBuild)"
"ubr=$($cv.UBR)"
"display_version=$($cv.DisplayVersion)"
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
"no_auto_update=$($au.NoAutoUpdate)"
"au_options=$($au.AUOptions)"
"wuauserv_start=$((Get-Service wuauserv).StartType)"
"pause_until=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings').PauseUpdatesExpiryTime)"
"reboot_required=$(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')"
$r = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
if ($r.LastSearchSuccessDate) { "last_search=" + $r.LastSearchSuccessDate.ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) }
$hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) { "last_hotfix=" + $hf.InstalledOn.ToString('yyyy-MM-dd', $inv) }`

func winUpdateFacts(kv map[string]string) updateFacts {
	build := kv["build"]
	f := updateFacts{Family: "windows", Key: "windows", Version: build}
	name := "Windows 10"
	if n, _ := strconv.Atoi(build); n >= 22000 {
		name = "Windows 11"
	}
	if dv := kv["display_version"]; dv != "" {
		name += " " + dv
	}
	f.Name = fmt.Sprintf("%s (build %s", name, build)
	if ubr := kv["ubr"]; ubr != "" {
		f.Name += "." + ubr
	}
	f.Name += ")"
	var why msg.Text
	if strings.EqualFold(kv["wuauserv_start"], "Disabled") {
		why = append(why, msg.P("updates.autoOff.winService"))
	}
	if kv["no_auto_update"] == "1" {
		why = append(why, msg.P("updates.autoOff.winPolicy"))
	}
	if o := kv["au_options"]; o == "1" || o == "2" {
		why = append(why, msg.P("updates.autoOff.winNotify"))
	}
	on := len(why) == 0
	f.AutoUpdate = &on
	if !on {
		f.AutoUpdateOff = append(msg.Of("updates.autoOff.win"), why...)
	}
	if t, err := time.Parse(time.RFC3339, kv["pause_until"]); err == nil {
		f.PausedUntil = t
	}
	if t, err := time.Parse(time.RFC3339, kv["last_search"]); err == nil && t.Year() > 2000 {
		f.LastCheck = t
	}
	if t, err := time.Parse("2006-01-02", kv["last_hotfix"]); err == nil {
		f.LastInstall = t
	} else {
		f.Notes = append(f.Notes, msg.P("updates.note.winLastInstall"))
	}
	f.RebootRequired = strings.EqualFold(kv["reboot_required"], "True")
	return f
}

// ---- Linux ----

// osReleaseFields reads /etc/os-release.
func osReleaseFields(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

// linuxFamily names the package-manager family of an os-release.
func linuxFamily(osr map[string]string) string {
	ids := " " + osr["ID"] + " " + osr["ID_LIKE"] + " "
	for _, fam := range []string{"debian", "ubuntu", "fedora", "rhel", "centos", "arch"} {
		if strings.Contains(ids, " "+fam+" ") {
			switch fam {
			case "ubuntu":
				return "debian"
			case "rhel", "centos":
				return "fedora"
			}
			return fam
		}
	}
	return "linux"
}

var (
	aptUnattendedRe = regexp.MustCompile(`(?m)^APT::Periodic::Unattended-Upgrade\s+"(\d+)";`)
	updatesNowRe    = regexp.MustCompile(`(\d+) updates? can be (?:applied|installed) immediately`)
)

// aptAutoUpgrade reads `apt-config dump`: unattended-upgrades runs when
// APT::Periodic::Unattended-Upgrade is not "0".
func aptAutoUpgrade(dump string) bool {
	m := aptUnattendedRe.FindStringSubmatch(dump)
	return m != nil && m[1] != "0"
}

// parseUpdatesAvailable reads Ubuntu's /var/lib/update-notifier/updates-available.
func parseUpdatesAvailable(s string) (int, bool) {
	if m := updatesNowRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n, true
	}
	if strings.TrimSpace(s) == "" || strings.Contains(s, "No updates") {
		return 0, true
	}
	return 0, false
}

// anyEnabled reads `systemctl is-enabled a b c`, one state per line.
func anyEnabled(out string) bool {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s == "enabled" || s == "enabled-runtime" {
			return true
		}
	}
	return false
}

func fileModTime(path string) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// ---- browsers ----

var versionDirRe = regexp.MustCompile(`^\d+(\.\d+){2,3}$`)

// chromiumVersion returns the newest version folder beside a Windows Chromium
// executable (Application\157.0.8103.39\).
func chromiumVersion(dir string) string {
	ents, _ := os.ReadDir(dir)
	best := ""
	for _, e := range ents {
		if e.IsDir() && versionDirRe.MatchString(e.Name()) && (best == "" || versionLess(best, e.Name())) {
			best = e.Name()
		}
	}
	return best
}

// iniVersion reads Version= from Firefox's application.ini.
func iniVersion(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Version="); ok {
			return v
		}
	}
	return ""
}

// browserAt describes the browser whose executable is exe, or reports false if
// it is not installed there.
func browserAt(id, exe, version string) (browserInfo, bool) {
	st, err := os.Stat(exe)
	if err != nil || st.IsDir() {
		return browserInfo{}, false
	}
	if version == "" && id == "firefox" {
		version = iniVersion(filepath.Join(filepath.Dir(exe), "application.ini"))
	}
	return browserInfo{ID: id, Name: browserNames[id], Version: version, Modified: st.ModTime()}, true
}
