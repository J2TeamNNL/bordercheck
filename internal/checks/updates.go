package checks

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
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
	Family         string // "macos", "windows", "debian", "fedora", "arch" or "linux"; picks the fix text
	Name           string // "macOS 27.2", for people
	Key            string // key in min_os_versions
	Version        string // compared with the minimum
	AutoUpdate     *bool  // nil: could not tell
	AutoUpdateOff  string // what is off, in the OS's own words
	PausedUntil    time.Time
	LastCheck      time.Time // last successful check for updates; zero if unknown
	PendingKnown   bool      // the OS keeps a list of updates it found
	Pending        []pendingUpdate
	PendingCount   int       // updates found when only a count is known
	LastInstall    time.Time // last OS update installed; zero if unknown
	RebootRequired bool
	Notes          []string // what could not be read
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
	var notes []string
	fix := func(kind string) string { return updateFix(kind, f.Family) }

	if min := opts.MinOSVersions[f.Key]; min != "" && f.Version != "" && versionLess(f.Version, min) {
		p.add(true, fmt.Sprintf("%s is older than the minimum version %s set by policy.", f.Name, minOSLabel(f.Key, min)), fix("upgrade"))
	}
	if opts.RequireAutoUpdate == nil || *opts.RequireAutoUpdate {
		switch {
		case f.AutoUpdate == nil:
			notes = append(notes, "Could not tell whether automatic updates are on.")
		case !*f.AutoUpdate:
			p.add(false, "Automatic updates are off ("+f.AutoUpdateOff+").", fix("auto"))
		}
	}
	if f.PausedUntil.After(now) {
		p.add(false, "Updates are paused until "+f.PausedUntil.Format("2 Jan 2006")+".", fix("paused"))
	}
	if max := opts.MaxCheckAgeDays; max > 0 && !f.LastCheck.IsZero() {
		if d := daysAgo(f.LastCheck, now); d > max {
			p.add(false, fmt.Sprintf("The OS last checked for updates %s (policy: every %d days).", agoText(d), max), fix("check"))
		}
	}
	for _, u := range f.Pending {
		d := -1
		if !u.Since.IsZero() {
			d = daysAgo(u.Since, now)
		}
		if max := opts.MaxPendingDays; max > 0 && d > max {
			p.add(true, fmt.Sprintf("%s has been waiting to be installed for %d days (policy: %d).", u.Name, d, max), fix("pending"))
		} else {
			if d >= 0 {
				notes = append(notes, fmt.Sprintf("%s is ready to install (found %s).", u.Name, agoText(d)))
			} else {
				notes = append(notes, u.Name+" is ready to install.")
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
			p.add(true, fmt.Sprintf("%d update(s) are waiting and nothing has been installed for %d days (policy: %d).", f.PendingCount, d, max), fix("pending"))
		} else {
			notes = append(notes, fmt.Sprintf("%d update(s) are ready to install.", f.PendingCount))
		}
	}
	if f.RebootRequired {
		p.add(false, "Updates are installed but need a restart to take effect.", fix("reboot"))
	}
	if max := opts.MaxDaysSinceUpdate; max > 0 && !f.LastInstall.IsZero() && !upToDate {
		if d := daysAgo(f.LastInstall, now); d > max && f.PendingCount == 0 {
			p.add(true, fmt.Sprintf("No OS update has been installed for %d days (policy: %d).", d, max), fix("pending"))
		}
	}

	state := f.Name
	if f.AutoUpdate != nil && *f.AutoUpdate {
		state += ", automatic updates on"
	}
	if !f.LastCheck.IsZero() {
		state += ", last checked for updates " + agoText(daysAgo(f.LastCheck, now))
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
			p.add(true, fmt.Sprintf("%s has not updated for %d days (policy: %d); browsers ship security fixes every few weeks.", strings.TrimSpace(b.Name+" "+b.Version), age, max), updateFix("browser", ""))
		}
		if min := opts.MinBrowserVersions[b.ID]; min != "" && b.Version != "" && versionLess(b.Version, min) {
			p.add(true, fmt.Sprintf("%s %s is older than the minimum %s set by policy.", b.Name, b.Version, min), updateFix("browser", ""))
		}
	}

	pass := state + "."
	if upToDate {
		pass += " No updates waiting."
	}
	if len(bs) > 0 {
		pass += fmt.Sprintf(" %d browser(s) recently updated.", len(bs))
	}
	notes = append(notes, f.Notes...)
	return p.result(pass, notes, evidence)
}

func minOSLabel(key, min string) string {
	if key == "windows" {
		return "build " + min
	}
	return min
}

// updateFix says how to fix one kind of update problem on one OS family.
func updateFix(kind, family string) string {
	switch kind {
	case "browser":
		return "Open each browser's About page (Chrome/Edge/Brave: Settings → About; Firefox: Help → About Firefox) " +
			"to update it, then relaunch it; uninstall browsers you don't use."
	}
	fixes := map[string]map[string]string{
		"macos": {
			"upgrade": "System Settings → General → Software Update → upgrade to a supported macOS.",
			"auto": "System Settings → General → Software Update → Automatic updates (i) → turn on Check for updates, " +
				"Download new updates when available and Install Security Responses and system files.",
			"pending": "System Settings → General → Software Update → Update Now.",
			"check":   "Connect to the internet and open System Settings → General → Software Update so macOS checks again.",
		},
		"windows": {
			"upgrade": "Settings → Windows Update → install the latest Windows 11 feature update.",
			"auto": "Windows Update must run automatically: the Windows Update service (wuauserv) must not be Disabled " +
				"and no policy may turn automatic updates off. If Settings → Windows Update says some settings are " +
				"managed by your organisation, ask IT.",
			"paused":  "Settings → Windows Update → Resume updates.",
			"pending": "Settings → Windows Update → Check for updates, install everything, then restart.",
			"check":   "Settings → Windows Update → Check for updates.",
			"reboot":  "Restart the PC to finish installing updates.",
		},
		"debian": {
			"upgrade": "Upgrade to a supported release (Ubuntu: sudo do-release-upgrade).",
			"auto":    "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
			"pending": "sudo apt update && sudo apt full-upgrade",
			"check":   "sudo apt update",
			"reboot":  "Restart to finish installing updates (/var/run/reboot-required is set).",
		},
		"fedora": {
			"upgrade": "Upgrade to a supported release: sudo dnf system-upgrade (see the Fedora upgrade guide).",
			"auto": "sudo dnf install dnf-automatic, set apply_updates = yes in /etc/dnf/automatic.conf, then " +
				"sudo systemctl enable --now dnf-automatic.timer (dnf5-automatic.timer on dnf5).",
			"pending": "sudo dnf upgrade --refresh",
			"check":   "sudo dnf check-update --refresh",
		},
		"arch": {
			"pending": "sudo pacman -Syu",
			"check":   "sudo pacman -Syu",
		},
	}
	if s := fixes[family][kind]; s != "" {
		return s
	}
	return "Install the latest updates with your distribution's package manager, and restart."
}

// issueList collects what a check found and turns it into one result.
type issueList struct{ high, medium, fixes []string }

func (p *issueList) add(high bool, text, fix string) {
	if high {
		p.high = append(p.high, text)
	} else {
		p.medium = append(p.medium, text)
	}
	if fix != "" && !slices.Contains(p.fixes, fix) {
		p.fixes = append(p.fixes, fix)
	}
}

func (p issueList) result(pass string, notes, evidence []string) check.Result {
	note := ""
	if len(notes) > 0 {
		note = " " + strings.Join(notes, " ")
	}
	if len(p.high)+len(p.medium) == 0 {
		return check.Result{Status: check.Pass, Summary: strings.TrimSpace(pass + note), Evidence: evidence}
	}
	r := check.Result{Status: check.Warn, Severity: check.Medium,
		Summary:  strings.Join(append(slices.Clone(p.high), p.medium...), " ") + note,
		Evidence: evidence, Fix: strings.Join(p.fixes, " ")}
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
	f.AutoUpdate, f.AutoUpdateOff = &on, strings.Join(off, ", ")
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
	var off []string
	if strings.EqualFold(kv["wuauserv_start"], "Disabled") {
		off = append(off, "the Windows Update service is disabled")
	}
	if kv["no_auto_update"] == "1" {
		off = append(off, "a policy turns automatic updates off")
	}
	if o := kv["au_options"]; o == "1" || o == "2" {
		off = append(off, "a policy only notifies about updates")
	}
	on := len(off) == 0
	f.AutoUpdate, f.AutoUpdateOff = &on, strings.Join(off, "; ")
	if t, err := time.Parse(time.RFC3339, kv["pause_until"]); err == nil {
		f.PausedUntil = t
	}
	if t, err := time.Parse(time.RFC3339, kv["last_search"]); err == nil && t.Year() > 2000 {
		f.LastCheck = t
	}
	if t, err := time.Parse("2006-01-02", kv["last_hotfix"]); err == nil {
		f.LastInstall = t
	} else {
		f.Notes = append(f.Notes, "Could not read when Windows last installed an update.")
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
