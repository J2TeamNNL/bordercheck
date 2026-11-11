// Package checks holds every check bordercheck runs. Each check gathers raw
// output from the OS in a per-OS file (_darwin.go, _windows.go) and judges it in
// a portable eval function, so the judging is unit-tested on every platform.
package checks

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/ignore"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Local is what the person at this computer has set for the checks, kept in
// the install folder rather than the policy.
type Local struct {
	Ignored   []ignore.Entry // secrets marked as not sensitive (bordercheck ignore)
	IgnoreErr error          // the list of ignored secrets could not be read
}

// CompromiseCheckIDs are the checks whose findings can be a sign of compromise
// (check.Result.Compromise). The installed service runs just these on every
// wake, so they must stay quick.
var CompromiseCheckIDs = []string{"startup-items", "extensions", "cracked-software"}

// All returns every check the policy enables, in report order, without
// anything set locally.
func All(p policy.Policy) []check.Check { return AllWith(p, Local{}) }

// AllWith is All with what the person at the computer has set.
func AllWith(p policy.Policy, local Local) []check.Check {
	c := p.Checks
	all := []struct {
		check.Check
		policy.Common
	}{
		{check.Check{ID: "firewall", Title: "Firewall is on",
			Run: func(ctx context.Context) check.Result {
				r := firewall(ctx, *c.Firewall.RequireStealth)
				if c.Firewall.SuggestOutbound && (r.Status == check.Pass || r.Status == check.Warn) {
					if found, adv, ok := outboundFirewalls(ctx); ok {
						r = withOutbound(r, found, adv)
					}
				}
				return r
			}}, c.Firewall.Common},
		{check.Check{ID: "disk-encryption", Title: "Disk is encrypted", Run: diskEncryption}, c.DiskEncryption},
		{check.Check{ID: "listeners", Title: "Nothing listens beyond localhost",
			Run: func(ctx context.Context) check.Result { return listeners(ctx, c.Listeners.Allow) }}, c.Listeners.Common},
		{check.Check{ID: "tailscale", Title: "Tailscale blocks incoming connections", Run: tailscale}, c.Tailscale},
		{check.Check{ID: "docker", Title: "Docker containers stay isolated",
			Run: func(ctx context.Context) check.Result { return docker(ctx, c.Docker) }}, c.Docker.Common},
		{check.Check{ID: "secrets", Title: "No plain-text secrets", Run: secrets(c.Secrets, local)}, c.Secrets.Common},
		{check.Check{ID: "os-updates", Title: "OS and browsers are up to date", Run: osUpdates(c.OSUpdates)}, c.OSUpdates.Common},
		{check.Check{ID: "screen-lock", Title: "Screen locks with a password", Run: screenLock(c.ScreenLock)}, c.ScreenLock.Common},
		{check.Check{ID: "remote-access", Title: "Remote login and sharing are off", Run: remoteAccess(c.RemoteAccess)}, c.RemoteAccess.Common},
		{check.Check{ID: "ssh-keys", Title: "SSH keys are protected", Run: sshKeys(c.SSHKeys, local)}, c.SSHKeys.Common},
		{check.Check{ID: "tunnels", Title: "Nothing is tunnelled to the internet", Run: tunnels(c.Tunnels)}, c.Tunnels.Common},
		{check.Check{ID: "ai-agents", Title: "AI agents keep their guardrails", Run: aiAgents(c.AIAgents, c.Secrets, local)}, c.AIAgents.Common},
		{check.Check{ID: "cracked-software", Title: "No cracked software", Run: crackedSoftware(c.CrackedSoftware)}, c.CrackedSoftware.Common},
		{check.Check{ID: "admin-rights", Title: "Daily account has limited rights", Run: adminRights(c.AdminRights)}, c.AdminRights.Common},
		{check.Check{ID: "os-protections", Title: "Built-in OS protections are on", Run: osProtections(c.OSProtections)}, c.OSProtections.Common},
		{check.Check{ID: "sharing", Title: "Nothing is shared with nearby devices", Run: sharing(c.Sharing)}, c.Sharing.Common},
		{check.Check{ID: "extensions", Title: "Browser and editor extensions are trusted", Run: extensions(c.Extensions)}, c.Extensions.Common},
		{check.Check{ID: "browser-passwords", Title: "Passwords are not saved in the browser", Run: browserPasswords(c.BrowserPasswords)}, c.BrowserPasswords.Common},
		{check.Check{ID: "trust-store", Title: "No unexpected root certificates or proxies", Run: trustStore(c.TrustStore)}, c.TrustStore.Common},
		{check.Check{ID: "package-managers", Title: "Package managers guard against bad packages", Run: packageManagers(c.PackageManagers)}, c.PackageManagers.Common},
		{check.Check{ID: "startup-items", Title: "Nothing unexpected starts at login", Run: startupItems(c.StartupItems)}, c.StartupItems.Common},
		{check.Check{ID: "backup", Title: "A lost laptop can be found and restored", Run: backup(c.Backup)}, c.Backup.Common},
	}
	var out []check.Check
	for _, a := range all {
		if a.IsEnabled() {
			out = append(out, withOnProblem(a.Check, a.OnProblem))
		}
	}
	return out
}

// withOnProblem makes every problem the check finds report as status on.
func withOnProblem(c check.Check, on check.Status) check.Check {
	if on == "" {
		return c
	}
	run := c.Run
	c.Run = func(ctx context.Context) check.Result {
		r := run(ctx)
		if r.Status == check.Fail || r.Status == check.Warn {
			r.Status = on
		}
		return r
	}
	return c
}

// expandHome turns a leading ~ into the home folder.
func expandHome(p, home string) string {
	if rest, ok := strings.CutPrefix(p, "~"); ok {
		return filepath.Join(home, filepath.FromSlash(rest))
	}
	return p
}

var errUnsupported = errors.New("not supported on " + runtime.GOOS + " yet")

func unsupported() check.Result {
	return check.SkippedMsg(msg.Of("check.unsupported", "os", runtime.GOOS))
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}

func uniqSorted(ss []string) []string {
	sort.Strings(ss)
	out := ss[:0]
	for i, s := range ss {
		if i == 0 || s != ss[i-1] {
			out = append(out, s)
		}
	}
	return out
}
