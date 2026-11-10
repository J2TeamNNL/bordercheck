package checks

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

type lockFacts struct {
	Family         string // "macos", "windows", "gnome" or "kde"; picks the fix text
	PasswordOnWake *bool  // nil: could not tell
	LockKnown      bool   // LockAfter or Never is known
	Never          bool   // nothing locks the screen when the machine is left alone
	LockAfter      time.Duration
	Details        []string // the settings read, for the evidence
}

func screenLock(opts policy.ScreenLock) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		f, err := screenLockOS(ctx)
		if errors.Is(err, errUnsupported) {
			return unsupported()
		}
		if err != nil {
			return check.Errored(err)
		}
		if f.Family == "" {
			return check.Skipped("No desktop whose screen lock bordercheck can read (GNOME and KDE Plasma are supported).")
		}
		return evalScreenLock(f, opts)
	}
}

func minutesText(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	m := d.Minutes()
	if m == float64(int(m)) {
		if m == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", int(m))
	}
	return fmt.Sprintf("%.1f minutes", m)
}

func evalScreenLock(f lockFacts, opts policy.ScreenLock) check.Result {
	if f.PasswordOnWake == nil && !f.LockKnown {
		return check.Result{Status: check.Error, Evidence: f.Details,
			Summary: "Could not tell whether a password is needed after sleep or when the screen locks."}
	}
	var p issueList
	var notes []string
	fixes := lockFixes[f.Family]
	noPassword := f.PasswordOnWake != nil && !*f.PasswordOnWake
	if opts.RequirePassword == nil || *opts.RequirePassword {
		switch {
		case f.PasswordOnWake == nil:
			notes = append(notes, "Could not tell whether a password is needed after sleep.")
		case noPassword:
			p.add(true, "No password is needed to get back in after sleep or the screen saver.", fixes[0])
		}
	}
	max := time.Duration(opts.MaxLockMinutes) * time.Minute
	if max > 0 && !noPassword { // without a password, nothing ever locks; reported above
		switch {
		case !f.LockKnown:
			notes = append(notes, "Could not tell when the screen locks by itself.")
		case f.Never:
			p.add(true, "The screen never locks by itself when the machine is left alone.", fixes[1])
		case f.LockAfter > max:
			p.add(false, fmt.Sprintf("The screen locks only after %s idle (policy: %s).", minutesText(f.LockAfter), minutesText(max)), fixes[1])
		}
	}
	var pass []string
	if f.PasswordOnWake != nil && *f.PasswordOnWake {
		pass = append(pass, "A password is needed after sleep")
	}
	if f.LockKnown && !f.Never {
		pass = append(pass, fmt.Sprintf("the screen locks after %s idle", minutesText(f.LockAfter)))
	}
	s := strings.Join(pass, " and ")
	if s != "" {
		s = strings.ToUpper(s[:1]) + s[1:] + "."
	}
	return p.result(s, notes, f.Details)
}

var lockFixes = map[string][2]string{
	"macos": {
		"System Settings → Lock Screen → \"Require password after screen saver begins or display is turned off\" → Immediately.",
		"System Settings → Lock Screen → set \"Turn display off on battery when inactive\" and \"…on power adapter when inactive\" " +
			"(and \"Start Screen Saver when inactive\", if used) to the policy's limit or less.",
	},
	"windows": {
		"Settings → Accounts → Sign-in options → \"If you've been away, when should Windows require you to sign in again?\" → When PC wakes up from sleep.",
		"Settings → System → Power & battery → Screen, sleep & hibernate timeouts → put the device to sleep within the policy's limit " +
			"(on battery and plugged in), or Settings → Personalization → Lock screen → Screen saver → a short wait with \"On resume, display logon screen\".",
	},
	"gnome": {
		"Settings → Privacy & Security → Screen Lock → turn on Automatic Screen Lock and Lock Screen on Suspend, Automatic Screen Lock Delay → Screen Turns Off.",
		"Settings → Power → Screen Blank → the policy's limit or less, and Settings → Privacy & Security → Screen Lock → Automatic Screen Lock on.",
	},
	"kde": {
		"System Settings → Screen Locking → turn on \"After waking from sleep\".",
		"System Settings → Screen Locking → \"Lock screen automatically\" after the policy's limit or less.",
	},
}

// ---- macOS ----

var (
	screenLockDelayRe = regexp.MustCompile(`screenLock delay is (\d+) seconds?`)
	pmsetLineRe       = regexp.MustCompile(`^\s*(displaysleep|sleep)\s+(\d+)`)
)

// parseSysadminctlLock reads `sysadminctl -screenLock status` (printed on
// stderr): whether a password is needed after sleep or the screen saver, and how
// long after it starts.
func parseSysadminctlLock(out string) (on bool, delay time.Duration, err error) {
	switch {
	case strings.Contains(out, "screenLock is off"):
		return false, 0, nil
	case strings.Contains(out, "screenLock delay is immediate"):
		return true, 0, nil
	}
	if m := screenLockDelayRe.FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		return true, time.Duration(n) * time.Second, nil
	}
	return false, 0, fmt.Errorf("unexpected output from sysadminctl -screenLock status: %q", firstLine(out))
}

// parsePmset reads `pmset -g custom`: minutes of display sleep and system sleep
// per power source, 0 meaning never.
func parsePmset(out string) map[string]map[string]int {
	m := map[string]map[string]int{}
	src := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), ":") && !strings.HasPrefix(line, " ") {
			src = strings.TrimSuffix(strings.TrimSpace(line), ":")
			m[src] = map[string]int{}
			continue
		}
		if g := pmsetLineRe.FindStringSubmatch(line); g != nil && src != "" {
			m[src][g[1]], _ = strconv.Atoi(g[2])
		}
	}
	return m
}

// macLockFacts combines sysadminctl, pmset and the screen saver's idle time in
// seconds (-1 if unset). The screen locks when the screen saver starts, the
// display sleeps or the Mac sleeps, whichever comes first, plus the delay.
func macLockFacts(sysadminctl, pmset string, screenSaverIdle int) (lockFacts, error) {
	f := lockFacts{Family: "macos"}
	on, delay, err := parseSysadminctlLock(sysadminctl)
	if err != nil {
		return f, err
	}
	f.PasswordOnWake = &on
	if on {
		if delay == 0 {
			f.Details = append(f.Details, "Password required: immediately")
		} else {
			f.Details = append(f.Details, "Password required: after "+minutesText(delay))
		}
	} else {
		f.Details = append(f.Details, "Password required: off")
	}
	if screenSaverIdle > 0 {
		f.Details = append(f.Details, "Screen saver: after "+minutesText(time.Duration(screenSaverIdle)*time.Second))
	} else if screenSaverIdle == 0 {
		f.Details = append(f.Details, "Screen saver: never")
	}
	sources := parsePmset(pmset)
	if len(sources) == 0 {
		return f, nil
	}
	f.LockKnown = true
	var worst time.Duration
	for _, src := range []string{"Battery Power", "AC Power", "UPS Power"} {
		vals, ok := sources[src]
		if !ok {
			continue
		}
		f.Details = append(f.Details, fmt.Sprintf("%s: display sleep %s, system sleep %s",
			src, pmsetText(vals["displaysleep"]), pmsetText(vals["sleep"])))
		idle := time.Duration(0)
		for _, d := range []time.Duration{time.Duration(vals["displaysleep"]) * time.Minute,
			time.Duration(vals["sleep"]) * time.Minute, time.Duration(max(screenSaverIdle, 0)) * time.Second} {
			if d > 0 && (idle == 0 || d < idle) {
				idle = d
			}
		}
		if idle == 0 {
			if screenSaverIdle < 0 {
				f.LockKnown = false // the screen saver may still start on its default timer
				continue
			}
			f.Never = true
			continue
		}
		worst = max(worst, idle)
	}
	f.LockAfter = worst + delay
	return f, nil
}

func pmsetText(min int) string {
	if min == 0 {
		return "never"
	}
	return minutesText(time.Duration(min) * time.Minute)
}

// ---- Windows ----

var hexValueRe = regexp.MustCompile(`:\s*0x([0-9a-fA-F]+)`)

// parsePowercfg reads `powercfg /q SCHEME_CURRENT <subgroup> <setting>`, whose
// last two hex values are the current AC and DC (battery) settings. The labels
// are translated, the layout is not.
func parsePowercfg(out string) (ac, dc int, ok bool) {
	ms := hexValueRe.FindAllStringSubmatch(out, -1)
	if len(ms) < 2 {
		return 0, 0, false
	}
	a, err1 := strconv.ParseUint(ms[len(ms)-2][1], 16, 32)
	d, err2 := strconv.ParseUint(ms[len(ms)-1][1], 16, 32)
	return int(a), int(d), err1 == nil && err2 == nil
}

// winLockScript reads the screen saver (with its policy override) and the
// machine inactivity limit; powercfg is run separately.
const winLockScript = `$ErrorActionPreference = 'SilentlyContinue'
$d = Get-ItemProperty 'HKCU:\Control Panel\Desktop'
$p = Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
foreach ($n in 'ScreenSaveActive','ScreenSaverIsSecure','ScreenSaveTimeOut','SCRNSAVE.EXE') {
  $v = $p.$n; if ($null -eq $v) { $v = $d.$n }
  "$n=$v"
}
"InactivityTimeoutSecs=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').InactivityTimeoutSecs)"`

// winLockFacts: Windows locks when a secure screen saver starts, when the
// machine inactivity limit passes, or on wake from sleep if a password is
// required on wakeup (CONSOLELOCK). Turning the display off does not lock.
func winLockFacts(kv map[string]string, sleepIdle, consoleLock string) lockFacts {
	f := lockFacts{Family: "windows"}
	var candidates []time.Duration
	ssSecs, _ := strconv.Atoi(kv["ScreenSaveTimeOut"])
	if kv["ScreenSaveActive"] == "1" && kv["ScreenSaverIsSecure"] == "1" && kv["SCRNSAVE.EXE"] != "" && ssSecs > 0 {
		candidates = append(candidates, time.Duration(ssSecs)*time.Second)
		f.Details = append(f.Details, "Screen saver with sign-in: after "+minutesText(time.Duration(ssSecs)*time.Second))
	} else {
		f.Details = append(f.Details, "Screen saver with sign-in: off")
	}
	if n, _ := strconv.Atoi(kv["InactivityTimeoutSecs"]); n > 0 {
		candidates = append(candidates, time.Duration(n)*time.Second)
		f.Details = append(f.Details, "Machine inactivity limit: "+minutesText(time.Duration(n)*time.Second))
	}
	lockAC, lockDC, lockOK := parsePowercfg(consoleLock)
	sleepAC, sleepDC, sleepOK := parsePowercfg(sleepIdle)
	if lockOK {
		on := lockAC != 0 && lockDC != 0
		f.PasswordOnWake = &on
		f.Details = append(f.Details, fmt.Sprintf("Sign-in on wake: %s plugged in, %s on battery", onOff(lockAC != 0), onOff(lockDC != 0)))
	}
	if sleepOK {
		f.Details = append(f.Details, fmt.Sprintf("Sleep: %s plugged in, %s on battery", secsText(sleepAC), secsText(sleepDC)))
	}
	if !lockOK || !sleepOK {
		if len(candidates) == 0 {
			return f // LockKnown stays false
		}
	}
	f.LockKnown = true
	var worst time.Duration
	for _, src := range []struct{ sleep, lock int }{{sleepAC, lockAC}, {sleepDC, lockDC}} {
		idle := time.Duration(0)
		cs := candidates
		if sleepOK && lockOK && src.sleep > 0 && src.lock != 0 {
			cs = append(cs[:len(cs):len(cs)], time.Duration(src.sleep)*time.Second)
		}
		for _, d := range cs {
			if idle == 0 || d < idle {
				idle = d
			}
		}
		if idle == 0 {
			f.Never = true
		}
		worst = max(worst, idle)
	}
	f.LockAfter = worst
	return f
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func secsText(s int) string {
	if s == 0 {
		return "never"
	}
	return minutesText(time.Duration(s) * time.Second)
}

// ---- Linux ----

// gnomeLockFacts reads `gsettings list-recursively org.gnome.desktop.screensaver`
// and `gsettings get org.gnome.desktop.session idle-delay`.
func gnomeLockFacts(screensaver, idleDelay string) lockFacts {
	f := lockFacts{Family: "gnome"}
	keys := map[string]string{}
	for _, line := range strings.Split(screensaver, "\n") {
		if fs := strings.Fields(line); len(fs) >= 3 && fs[0] == "org.gnome.desktop.screensaver" {
			keys[fs[1]] = fs[len(fs)-1]
		}
	}
	lockEnabled, ok := keys["lock-enabled"]
	if !ok {
		return lockFacts{} // not GNOME after all
	}
	on := lockEnabled == "true"
	f.Details = append(f.Details, "Automatic screen lock: "+onOff(on))
	wake := on
	if s, ok := keys["ubuntu-lock-on-suspend"]; ok {
		wake = s == "true"
		f.Details = append(f.Details, "Lock on suspend: "+onOff(wake))
	}
	f.PasswordOnWake = &wake
	fs := strings.Fields(idleDelay)
	if len(fs) == 0 {
		return f
	}
	idle, err := strconv.Atoi(fs[len(fs)-1])
	if err != nil {
		return f
	}
	delay, _ := strconv.Atoi(keys["lock-delay"])
	f.LockKnown = true
	f.Details = append(f.Details, "Screen blank: "+secsText(idle), "Lock delay: "+strconv.Itoa(delay)+" seconds")
	if !on || idle == 0 {
		f.Never = true
	}
	f.LockAfter = time.Duration(idle+delay) * time.Second
	return f
}

// kdeLockFacts reads ~/.config/kscreenlockerrc; missing keys keep Plasma's
// defaults (lock after 5 minutes, and on resume, with a 5 second grace).
func kdeLockFacts(rc string) lockFacts {
	f := lockFacts{Family: "kde"}
	vals := map[string]string{"Autolock": "true", "LockOnResume": "true", "Timeout": "5", "LockGrace": "5"}
	section := ""
	for _, line := range strings.Split(rc, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && section == "[Daemon]" {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	wake := vals["LockOnResume"] == "true"
	f.PasswordOnWake = &wake
	auto := vals["Autolock"] == "true"
	mins, _ := strconv.Atoi(vals["Timeout"])
	grace, _ := strconv.Atoi(vals["LockGrace"])
	f.LockKnown = true
	f.Never = !auto || mins == 0
	f.LockAfter = time.Duration(mins)*time.Minute + time.Duration(grace)*time.Second
	f.Details = append(f.Details, "Lock automatically: "+onOff(auto)+" after "+strconv.Itoa(mins)+" minutes",
		"Lock after waking: "+onOff(wake))
	return f
}
