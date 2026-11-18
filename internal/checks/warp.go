package checks

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// The warp check looks at the Cloudflare One client (WARP), which Cloudflare
// Zero Trust needs on a device before it can judge the device's posture. It
// reads `warp-cli status`, `warp-cli registration show` and `warp-cli
// settings` as the person, changes nothing and never accepts the client's
// terms: a client never set up for this user answers with its terms prompt,
// which counts as not registered. Everything it finds is a warning: the
// device is not gated yet, but it will be once the organisation enforces.

// warpFacts is what the client says about itself.
type warpFacts struct {
	Installed  bool
	Running    bool   // the client's service answered
	Registered bool   // registered to some account
	Account    string // "Team", "Free", "Unlimited"…; "" when not said
	Org        string // the Zero Trust team it is registered to; "" when not said
	Connected  bool
	Status     string // the status as the client says it, for evidence
	Reason     string // why it is not connected, as the client says it
	Mode       string // the service mode as the client says it (PostureOnly, WarpWithDnsOverHttps…); "" when not said
}

func warp(p policy.Warp) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		return evalWarp(gatherWarp(ctx), p, runtime.GOOS)
	}
}

// warpCLIPaths are where the client installs warp-cli; it is also looked up in PATH.
func warpCLIPaths(goos string) []string {
	switch goos {
	case "darwin":
		return []string{
			"/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli",
			"/Applications/Cloudflare One Client.app/Contents/Resources/warp-cli",
			"/usr/local/bin/warp-cli",
		}
	case "windows":
		var out []string
		for _, pf := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramW6432")} {
			if pf != "" {
				out = append(out, filepath.Join(pf, `Cloudflare\Cloudflare WARP\warp-cli.exe`),
					filepath.Join(pf, `Cloudflare\Cloudflare One Client\warp-cli.exe`))
			}
		}
		return out
	default:
		return []string{"/usr/bin/warp-cli", "/bin/warp-cli", "/usr/local/bin/warp-cli"}
	}
}

func gatherWarp(ctx context.Context) warpFacts {
	cli, ok := sysx.Find("warp-cli", warpCLIPaths(runtime.GOOS)...)
	if !ok {
		return warpFacts{}
	}
	run := func(args ...string) string {
		out, err := sysx.RunFor(ctx, 10*time.Second, cli, args...)
		if err != nil {
			out += "\n" + err.Error()
		}
		return out
	}
	return parseWarp(run("status"), run("registration", "show"), run("settings"))
}

var (
	warpStatusRe  = regexp.MustCompile(`(?mi)^\s*Status update:\s*(.+?)\s*$`)
	warpReasonRe  = regexp.MustCompile(`(?mi)^\s*Reason:\s*(.+?)\s*$`)
	warpAccountRe = regexp.MustCompile(`(?mi)^\s*Account type:\s*(.+?)\s*$`)
	warpOrgRe     = regexp.MustCompile(`(?mi)^\s*(?:\([^)]*\)\s*)?Organization:\s*(.+?)\s*$`)
	warpModeRe    = regexp.MustCompile(`(?mi)^\s*(?:\([^)]*\)\s*)?Mode:\s*(\S+)`)
)

// parseWarp reads the three commands' output (with any error appended).
func parseWarp(status, registration, settings string) warpFacts {
	f := warpFacts{Installed: true}
	all := strings.ToLower(status + "\n" + registration)
	// The client's service is not running or not reachable.
	if strings.Contains(all, "daemon") && !warpStatusRe.MatchString(status) {
		return f
	}
	f.Running = true
	if m := warpStatusRe.FindStringSubmatch(status); m != nil {
		f.Status = m[1]
		f.Connected = strings.HasPrefix(strings.ToLower(m[1]), "connected")
	}
	if m := warpReasonRe.FindStringSubmatch(status); m != nil && !f.Connected {
		f.Reason = m[1]
	}
	if m := warpAccountRe.FindStringSubmatch(registration); m != nil {
		f.Account = m[1]
	}
	notRegistered := strings.Contains(all, "registration missing") || strings.Contains(all, "missing registration") ||
		strings.Contains(all, "terms of service") || strings.Contains(all, "not registered")
	f.Registered = f.Account != "" && !notRegistered
	if f.Registered {
		for _, out := range []string{registration, settings} {
			if m := warpOrgRe.FindStringSubmatch(out); m != nil && f.Org == "" {
				f.Org = m[1]
			}
		}
		if m := warpModeRe.FindStringSubmatch(settings); m != nil {
			f.Mode = m[1]
		}
	}
	return f
}

// warpFixes are the fix texts by OS and finding.
var warpFixes = map[string]map[string]string{
	"mac": {"install": "warp.fix.mac.install", "enroll": "warp.fix.mac.enroll",
		"start": "warp.fix.mac.start", "connect": "warp.fix.mac.connect"},
	"win": {"install": "warp.fix.win.install", "enroll": "warp.fix.win.enroll",
		"start": "warp.fix.win.start", "connect": "warp.fix.win.connect"},
	"linux": {"install": "warp.fix.linux.install", "enroll": "warp.fix.linux.enroll",
		"start": "warp.fix.linux.start", "connect": "warp.fix.linux.connect"},
}

// warpOS picks the fix texts: "mac", "win" or "linux".
func warpOS(goos string) string {
	switch goos {
	case "darwin":
		return "mac"
	case "windows":
		return "win"
	}
	return "linux"
}

func evalWarp(f warpFacts, p policy.Warp, goos string) check.Result {
	osKey := warpOS(goos)
	team := p.Team
	warn := func(sev check.Severity, summary msg.Part, fix msg.Text, ev ...string) check.Result {
		return check.Result{Status: check.Warn, Severity: sev, Evidence: ev}.WithSummary(msg.Text{summary}).WithFix(fix)
	}
	enroll := msg.P(warpFixes[osKey]["enroll"], "team", team)
	switch {
	case !f.Installed:
		return warn(check.Medium, msg.P("warp.missing"),
			msg.Text{msg.P(warpFixes[osKey]["install"]), enroll}, "warp-cli: not found")
	case !f.Running:
		return warn(check.Medium, msg.P("warp.notRunning"), msg.Text{msg.P(warpFixes[osKey]["start"])},
			"warp-cli: the client's service did not answer")
	case !f.Registered:
		return warn(check.Medium, msg.P("warp.notEnrolled", "team", team), msg.Text{enroll}, "registration: none")
	case !strings.EqualFold(f.Account, "Team"):
		return warn(check.Medium, msg.P("warp.consumer", "team", team), msg.Text{enroll}, "account type: "+f.Account)
	case f.Org != "" && !strings.EqualFold(f.Org, team):
		return warn(check.Medium, msg.P("warp.otherTeam", "org", f.Org, "team", team),
			msg.Text{msg.P("warp.fix.logout"), enroll}, "organization: "+f.Org)
	case !f.Connected && (f.Status == "" || strings.HasPrefix(strings.ToLower(f.Status), "disconnected")):
		return warn(check.Low, msg.P("warp.disconnected"), msg.Text{msg.P(warpFixes[osKey]["connect"])},
			"status: "+orUnknown(f.Status))
	case !f.Connected:
		// Switched on but not connected: "Connecting", or "Unable" with the client's reason.
		return warn(check.Low, msg.P("warp.cannotConnect", "status", f.Status, "reason", orUnknown(f.Reason)),
			msg.Text{msg.P("warp.fix.cannotConnect")}, "status: "+f.Status, "reason: "+orUnknown(f.Reason))
	case p.PostureOnly && f.Mode != "" && !strings.EqualFold(f.Mode, "PostureOnly"):
		return warn(check.Low, msg.P("warp.notPostureOnly", "mode", f.Mode), msg.Text{msg.P("warp.fix.mode")},
			"mode: "+f.Mode)
	}
	ok := msg.Text{msg.P("warp.ok", "team", team)}
	if f.Org == "" {
		ok = append(ok, msg.P("warp.teamUnknown"))
	}
	if p.PostureOnly && f.Mode == "" {
		ok = append(ok, msg.P("warp.modeUnknown"))
	}
	ev := []string{"status: " + f.Status, "account type: " + f.Account}
	if f.Org != "" {
		ev = append(ev, "organization: "+f.Org)
	}
	if f.Mode != "" {
		ev = append(ev, "mode: "+f.Mode)
	}
	return check.Result{Status: check.Pass, Evidence: ev}.WithSummary(ok)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
