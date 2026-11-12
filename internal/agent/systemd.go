package agent

import (
	"fmt"
	"strings"
)

// The Linux service is a systemd user timer, or a crontab line where there is
// no systemd user session. The text is built here, without a build tag, so it
// is unit-tested on every OS; service_linux.go installs it.

const (
	unitName     = "bordercheck"
	cronMarker   = "# bordercheck: hourly report (bordercheck uninstall removes this line)"
	cronSafePATH = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/snap/bin"
)

// systemdUnits returns the .service and .timer for a per-user hourly run of
// `bin send`. Like the launchd StartInterval, it runs while the user's session
// (systemd --user) is up; Persistent catches up on a run missed during sleep.
func systemdUnits(bin, dir string) (service, timer string) {
	service = fmt.Sprintf(`[Unit]
Description=BorderCheck: check this machine and report to IT
Documentation=https://github.com/ptrinh/bordercheck
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s send
WorkingDirectory=%s
Nice=10
IOSchedulingClass=idle
`, systemdQuote(bin), systemdEscape(dir))
	timer = `[Unit]
Description=Run BorderCheck every hour

[Timer]
OnCalendar=hourly
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
`
	return service, timer
}

// systemdEscape escapes systemd's specifier (%) and variable ($) characters.
func systemdEscape(s string) string {
	return strings.NewReplacer("%", "%%", "$", "$$").Replace(s)
}

// systemdQuote quotes one ExecStart word.
func systemdQuote(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
	return `"` + systemdEscape(s) + `"`
}

// cronLine is the crontab entry used when there is no systemd user session.
// Cron's PATH is minimal, so it sets one that finds ss, docker and tailscale;
// output goes to bordercheck.log already, so cron mails nothing.
func cronLine(bin string, minute int) string {
	q := "'" + strings.ReplaceAll(bin, "'", `'\''`) + "'"
	cmd := fmt.Sprintf("env PATH=%s %s send >/dev/null 2>&1", cronSafePATH, q)
	return fmt.Sprintf("%d * * * * %s %s", minute%60, strings.ReplaceAll(cmd, "%", `\%`), cronMarker)
}

// withCronLine returns crontab with bordercheck's line replaced by line, or
// removed when line is "". Every other line is kept as it was.
func withCronLine(crontab, line string) string {
	var keep []string
	for _, l := range strings.Split(crontab, "\n") {
		if !strings.HasSuffix(l, cronMarker) {
			keep = append(keep, l)
		}
	}
	out := strings.TrimRight(strings.Join(keep, "\n"), "\n")
	if line != "" {
		if out != "" {
			out += "\n"
		}
		out += line
	}
	if out == "" {
		return ""
	}
	return out + "\n"
}
