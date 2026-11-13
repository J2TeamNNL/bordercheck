// Package agent installs bordercheck as a per-user service that runs every
// hour. Each run refreshes policies.json from update.policy_url, POSTs a report
// to report.url whenever report.interval has passed since the last report that
// got through, and, with update.binary, installs a newer signed release once
// every update.interval.
//
// The install folder holds the binary, policies.json beside it, and:
//
//	config.json     the user's email and this install's ID; for an install
//	                from an invite link, the portal, role and policy URL
//	token           an enrolled install's bearer token, this user only (enroll.go)
//	state.json      when the last report was sent, the last error, which
//	                problems the person at the machine was last notified of,
//	                and the link to this machine's report page
//	bordercheck.log what each scheduled run did
//	ignored.json    secrets the person marked as not sensitive (bordercheck
//	                ignore; package ignore); a plain run reads it too
//	Bordercheck.app macOS only: the app bordercheck's notifications come from
//	                (notifier.go)
package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/checks"
	"github.com/ptrinh/bordercheck/internal/hostinfo"
	"github.com/ptrinh/bordercheck/internal/ignore"
	"github.com/ptrinh/bordercheck/internal/notifier"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/report"
	"github.com/ptrinh/bordercheck/internal/update"
)

// Env is what the agent needs from outside, so tests can swap it.
type Env struct {
	Dir     string // install folder
	Version string
	Client  *http.Client
	Out     io.Writer
	Term    io.Writer // the terminal only, never the log; nil = none
	GitHub  string    // release host for updates; "" = https://github.com
}

// Dir is the install folder: ~/Library/Application Support/bordercheck on macOS,
// %LOCALAPPDATA%\bordercheck on Windows, $XDG_DATA_HOME/bordercheck (by default
// ~/.local/share/bordercheck) on Linux: it holds a program and its state, not
// just settings, so it belongs in the data folder rather than ~/.config.
func Dir() (string, error) {
	if runtime.GOOS == "windows" && os.Getenv("LOCALAPPDATA") != "" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "bordercheck"), nil
	}
	if runtime.GOOS == "linux" {
		if d := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(d) {
			return filepath.Join(d, "bordercheck"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share", "bordercheck"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "bordercheck"), nil
}

func binName() string {
	if runtime.GOOS == "windows" {
		return "bordercheck.exe"
	}
	return "bordercheck"
}

type Config struct {
	Email     string `json:"email"`
	InstallID string `json:"install_id"`
	// Pinned at install from the policy: where updates come from and the key
	// they must be signed with. A refreshed policy cannot change them.
	UpdateRepo string `json:"update_repo"`
	UpdateKey  string `json:"update_public_key,omitempty"`
	// Set for an install made from an invite link; nil for a policies.json one.
	Enrollment *Enrollment `json:"enrollment,omitempty"`
	// macOS: the notification app's Team ID, pinned when it was first
	// installed, and the digest of the bundle as installed (notifier.go).
	NotifierTeam   string `json:"notifier_team_id,omitempty"`
	NotifierDigest string `json:"notifier_sha256,omitempty"`
}

type State struct {
	LastSent        time.Time `json:"last_sent,omitzero"`
	LastCheck       time.Time `json:"last_check,omitzero"` // when the checks last ran, with or without a report
	LastTry         time.Time `json:"last_try,omitzero"`
	LastError       string    `json:"last_error,omitempty"`
	LastUpdateCheck time.Time `json:"last_update_check,omitzero"`
	UpdateError     string    `json:"update_error,omitempty"`
	// Notified maps each problem announced on the desktop (notify.Key) and
	// still present at the last check to when it was last announced.
	Notified map[string]time.Time `json:"notified,omitempty"`
	// ReportPage is the link the receiver gave to this machine's report page;
	// anyone who has it can see this machine's results.
	ReportPage string `json:"report_page,omitempty"`
	// An enrolled install the portal revoked: since when, when it last asked
	// the portal again, and whether the person at the machine has been told.
	Revoked         time.Time `json:"revoked,omitzero"`
	RevokedChecked  time.Time `json:"revoked_checked,omitzero"`
	RevokedNotified bool      `json:"revoked_notified,omitempty"`
	// macOS: what the notification app last said about bordercheck's own
	// notifications (authorized, denied, not_determined, or error), and when.
	Notifications      string    `json:"notifications,omitempty"`
	NotificationsError string    `json:"notifications_error,omitempty"`
	NotificationsAt    time.Time `json:"notifications_at,omitzero"`
	// Signs of compromise ("check-id: what (item)", report.CompromiseLines)
	// that the last check found, and those in the last report that got
	// through. While they differ, the service sends a report at once,
	// whatever report.interval says: a new sign, a changed one, or the signs
	// clearing. Empty when the policy turns report.compromise_alert off.
	CompromiseFound []string `json:"compromise_found,omitempty"`
	CompromiseSent  []string `json:"compromise_sent,omitempty"`
}

// compromiseChanged reports whether the signs of compromise the last check
// found have not reached the portal yet.
func (st State) compromiseChanged() bool { return !slices.Equal(st.CompromiseFound, st.CompromiseSent) }

// newReport is the report for results under pol.
func newReport(env Env, pol policy.Policy, results []check.Result) report.Report {
	rep := report.New(env.Version, pol.Name, results)
	if !pol.Report.CompromiseAlert {
		rep.DropCompromise()
	}
	return rep
}

// compromiseWatch runs only the checks that can show a sign of compromise
// (checks.CompromiseCheckIDs: a second or less together) and reports whether
// the signs differ from those the last full check found. The service calls it
// on every wake when nothing else is due, so a compromise is noticed within
// the hour whatever report.check_interval says.
func compromiseWatch(ctx context.Context, env Env, cfg Config, pol policy.Policy, st State, now time.Time) bool {
	var watch []check.Check
	for _, c := range allChecks(pol, Local(env.Dir)) {
		if slices.Contains(checks.CompromiseCheckIDs, c.ID) {
			watch = append(watch, c)
		}
	}
	if len(watch) == 0 {
		return false
	}
	rep := newReport(env, pol, pol.Waive(check.RunAll(ctx, watch), identity(cfg), now))
	return !slices.Equal(rep.CompromiseLines(), st.CompromiseFound)
}

// allChecks is checks.ForReport; tests replace it so a run does not depend on
// the machine it runs on.
var allChecks = checks.ForReport

// Local is what the person at this computer has set in the install folder
// dir: the secrets they marked as not sensitive. A list that cannot be read
// counts as empty, and the secrets check says so.
func Local(dir string) checks.Local {
	entries, err := ignore.Load(dir)
	return checks.Local{Ignored: entries, IgnoreErr: err}
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// writeFile replaces path atomically, readable by this user only.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(data, '\n'), 0o600)
}

// InstallOptions are the answers install needs; Email is asked for when empty.
type InstallOptions struct {
	// Policy is the https URL (or path) of policies.json, or an invite link
	// https://<host>/i/<code>. "" = finish or redo an install made from an
	// invite, else the policies.json beside this binary.
	Policy string
	Email  string    // policies.json installs only
	In     io.Reader // where to read the email from when Email is empty
	Ask    bool      // In is a terminal, so asking is possible
	// Invite installs only: the update source, instead of the built-in default.
	UpdateRepo, UpdateKey string
	// macOS: install the notification app from this zip instead of downloading
	// this version's from the release (for testing a build).
	NotifierZip string
}

// Install copies bordercheck and its policy into env.Dir, records the user's
// email, registers the hourly service and sends a first report right away, so
// the person installing sees at once whether reports get through. With an
// invite link, it enrolls instead: see installEnrolled.
func Install(ctx context.Context, env Env, o InstallOptions) error {
	var saved Config
	hadConfig := readJSON(filepath.Join(env.Dir, "config.json"), &saved) == nil
	if portal, code, ok := ParseInvite(o.Policy); ok {
		return installEnrolled(ctx, env, o, saved, hadConfig, portal, code)
	}
	if saved.Enrollment != nil {
		if o.Policy == "" {
			return installEnrolled(ctx, env, o, saved, hadConfig, "", "")
		}
		return fmt.Errorf("this machine is enrolled with %s; to install from a policies.json instead, run bordercheck uninstall first",
			hostOf(saved.Enrollment.Portal))
	}
	if o.UpdateRepo != "" || o.UpdateKey != "" {
		return errors.New("-update-repo and -update-key are for invite links; a policies.json install takes update.repo and update.public_key from the policy")
	}
	source := o.Policy
	if source == "" {
		if source = policy.NextToBinary(); source == "" {
			return fmt.Errorf("no %s beside this binary; get it from your IT team or pass -policy", policy.FileName)
		}
	}
	data, pol, err := readPolicy(ctx, env.Client, source, nil)
	if err != nil {
		return err
	}
	if pol.Report.URL == "" {
		return errors.New("the policy has no report.url, so there is nowhere to send reports")
	}

	email := o.Email
	if email == "" {
		if !o.Ask {
			return errors.New("-email is required when not run in a terminal")
		}
		if email, err = askEmail(o.In, env.Out, pol.Report.EmailDomains); err != nil {
			return err
		}
	} else if email, err = checkEmail(email, pol.Report.EmailDomains); err != nil {
		return err
	}

	if err := os.MkdirAll(env.Dir, 0o700); err != nil {
		return err
	}
	var cfg Config
	_ = readJSON(filepath.Join(env.Dir, "config.json"), &cfg) // a reinstall keeps its install ID
	if cfg.InstallID == "" {
		cfg.InstallID = newID()
	}
	cfg.Email, cfg.UpdateRepo, cfg.UpdateKey = email, pol.Update.Repo, pol.Update.PublicKey

	bin := filepath.Join(env.Dir, binName())
	if err := copySelf(bin); err != nil {
		return fmt.Errorf("copying BorderCheck to %s: %w", env.Dir, err)
	}
	if err := writeFile(filepath.Join(env.Dir, policy.FileName), data, 0o600); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(env.Dir, "config.json"), cfg); err != nil {
		return err
	}
	if err := services.register(bin, env.Dir); err != nil {
		return fmt.Errorf("registering the hourly service: %w", err)
	}
	fmt.Fprintf(env.Out, "Installed in %s for %s.\n%s\n", env.Dir, email, schedule(pol.Report))
	if pol.Update.PolicyURL != "" {
		fmt.Fprintf(env.Out, "Policy refreshed from %s.\n", pol.Update.PolicyURL)
	} else if isURL(source) {
		fmt.Fprintf(env.Out, "The policy has no update.policy_url, so it stays as installed; set it to %s to refresh it hourly.\n", source)
	}
	if pol.Update.Binary {
		fmt.Fprintf(env.Out, "Updates itself from github.com/%s releases.\n", pol.Update.Repo)
	}
	printSends(env.Out, pol)
	setUpNotifications(ctx, env, &cfg, pol, o.NotifierZip)
	fmt.Fprintf(env.Out, "\nNow checking this computer for the first time. It usually takes under a minute, %s at most.\n", check.Timeout)
	if err := Send(ctx, env, true); err != nil {
		fmt.Fprintf(env.Out, "\nBorderCheck is installed and will check every hour, but the first report did not get through (%v). It tries again on its own; \"%s\" send -force tries now.\n",
			err, filepath.Join(env.Dir, binName()))
		return err
	}
	fmt.Fprintf(env.Out, "Done: BorderCheck is installed and the first report is sent. Nothing else to do; it checks again on its own.\nTo see the details and how to fix anything it found, run: \"%s\"\n", filepath.Join(env.Dir, binName()))
	fmt.Fprintf(env.Out, "\nBorderCheck %s · %s\n", env.Version, report.Credit)
	return nil
}

// schedule says, at install, how often bordercheck does what. The service
// wakes every hour, but only to see whether anything is due (and to refresh
// the policy): the checks themselves run every CheckEvery.
func schedule(r policy.Report) string {
	every := func(d time.Duration) string { return strings.TrimSuffix(strings.TrimSuffix(d.String(), "0s"), "0m") }
	s := fmt.Sprintf("Checks this computer every %s and reports every %s to %s.", every(r.CheckEvery()), every(r.Every()), hostOf(r.URL))
	if r.CheckEvery() == r.Every() {
		s = fmt.Sprintf("Checks this computer and reports every %s to %s.", every(r.Every()), hostOf(r.URL))
	}
	return s + " (It wakes hourly for a moment to see if either is due.)"
}

// printSends says, at install, when the report carries more than results.
func printSends(w io.Writer, pol policy.Policy) {
	if pol.Report.IncludeIPs || pol.Report.IncludeLocation {
		fmt.Fprintf(w, "Your organisation's policy also sends: %s.\n", sends(pol.Report))
	}
}

// sends lists what a report carries besides the results.
func sends(r policy.Report) string {
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	loc := onOff(r.IncludeLocation)
	if r.IncludeLocation {
		if _, err := hostinfo.Location(context.Background()); err != nil {
			loc += " (" + hostinfo.LocationSupport() + ")"
		}
	}
	return fmt.Sprintf("evidence %s, IP addresses %s, location %s", onOff(r.IncludeEvidence), onOff(r.IncludeIPs), loc)
}

// Uninstall removes the service and the install folder, the token with it.
// The portal is not told: a revoked or forgotten install is IT's to clean up.
func Uninstall(env Env) error {
	err := errors.Join(services.unregister(), notifier.Remove(env.Dir))
	for _, name := range []string{"config.json", "state.json", "bordercheck.log", policy.FileName, TokenFile, ignore.FileName, binName()} {
		if e := os.Remove(filepath.Join(env.Dir, name)); e != nil && !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e) // Windows cannot remove a running binary; it goes on the next uninstall
		}
	}
	_ = os.Remove(env.Dir)
	return err
}

// Send is what the service runs every hour. It sends a report when the policy's
// interval has passed since the last one that got through, or right away with force.
func Send(ctx context.Context, env Env, force bool) error {
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		return fmt.Errorf("BorderCheck is not installed (%w); run: bordercheck install", err)
	}
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
	tok, err := credentials(env, cfg)
	if err != nil {
		return err
	}
	statePath := filepath.Join(env.Dir, "state.json")
	now := time.Now()
	// A revoked install asks the portal again once a day, not every hour.
	if tok != nil && !st.Revoked.IsZero() && !force && now.Sub(st.RevokedChecked) < revokedRetry {
		fmt.Fprintf(env.Out, "%s revoked by IT since %s; asking %s again after %s\n", now.Format(time.RFC3339),
			st.Revoked.Format(time.RFC3339), hostOf(tok.portal), st.RevokedChecked.Add(revokedRetry).Format(time.RFC3339))
		notifyRevoked(ctx, env, &st, now, force)
		return errors.Join(ErrRevoked, writeJSON(statePath, st))
	}

	pol, err := currentPolicy(ctx, env, cfg, tok)
	if errors.Is(err, ErrRevoked) {
		revoked(ctx, env, &st, now, force)
		return errors.Join(err, writeJSON(statePath, st))
	}
	if err != nil {
		return err
	}
	if pol.Report.URL == "" {
		return errors.New("the policy has no report.url")
	}
	switch {
	case force || now.Sub(st.LastSent) >= pol.Report.Every():
		err = sendReport(ctx, env, cfg, pol, &st, now, force, tok, nil)
	case pol.Report.CompromiseAlert && st.compromiseChanged():
		// The last check found the signs of compromise changed, but that
		// report did not get through: try again every hour, not every
		// check_interval.
		fmt.Fprintf(env.Out, "%s signs of compromise not reported yet: sending a report now\n", now.Format(time.RFC3339))
		err = sendReport(ctx, env, cfg, pol, &st, now, false, tok, nil)
	case now.Sub(st.LastCheck) >= pol.Report.CheckEvery():
		// Between reports: check, and tell the person at the machine about
		// anything new. Nothing is sent, unless the signs of compromise changed.
		err = checkOnly(ctx, env, cfg, pol, &st, now, tok)
	case pol.Report.CompromiseAlert && compromiseWatch(ctx, env, cfg, pol, st, now):
		// Nothing is due, but the few checks that can show a compromise run
		// on every wake, and what they found differs from the last check:
		// run everything now, which sends the report at once.
		fmt.Fprintf(env.Out, "%s signs of compromise changed since the last check: checking now\n", now.Format(time.RFC3339))
		err = checkOnly(ctx, env, cfg, pol, &st, now, tok)
	default:
		fmt.Fprintf(env.Out, "%s nothing due: next check %s, next report %s\n", now.Format(time.RFC3339),
			st.LastCheck.Add(pol.Report.CheckEvery()).Format(time.RFC3339), st.LastSent.Add(pol.Report.Every()).Format(time.RFC3339))
	}
	if errors.Is(err, ErrRevoked) {
		revoked(ctx, env, &st, now, force)
	}
	// After the report, so a broken update never costs a report. Its error is
	// in state.json and the log; the report's error is what Send returns.
	if pol.Update.Binary && now.Sub(st.LastUpdateCheck) >= pol.Update.Every() {
		_ = updateBinary(ctx, env, cfg, &st, now)
	}
	return errors.Join(err, writeJSON(filepath.Join(env.Dir, "state.json"), st))
}

// checkOnly runs the checks without reporting: what the service does when
// report.check_interval has passed but a report is not due yet. When the signs
// of compromise differ from those last reported, it sends these results at
// once instead.
func checkOnly(ctx context.Context, env Env, cfg Config, pol policy.Policy, st *State, now time.Time, tok *bearer) error {
	results := pol.Waive(check.RunAll(ctx, allChecks(pol, Local(env.Dir))), identity(cfg), now)
	st.LastCheck = now
	rep := newReport(env, pol, results)
	st.CompromiseFound = rep.CompromiseLines()
	if pol.Report.CompromiseAlert && st.compromiseChanged() {
		what := "found"
		if len(st.CompromiseFound) == 0 {
			what = "cleared"
		}
		fmt.Fprintf(env.Out, "%s signs of compromise %s: sending a report now\n", now.Format(time.RFC3339), what)
		return sendReport(ctx, env, cfg, pol, st, now, false, tok, results)
	}
	c := rep.Counts
	fmt.Fprintf(env.Out, "%s checked (no report due until %s): %d fail, %d warn, %d pass, %d waived\n", now.Format(time.RFC3339),
		st.LastSent.Add(pol.Report.Every()).Format(time.RFC3339), c.Fail, c.Warn, c.Pass, c.Waived)
	notifyUser(ctx, env, pol.Notify, results, st, now, false, pol.Report.URL)
	return nil
}

// sendReport runs the checks, or takes results a check just made, and posts the report.
func sendReport(ctx context.Context, env Env, cfg Config, pol policy.Policy, st *State, now time.Time, force bool, tok *bearer, results []check.Result) error {
	if results == nil {
		st.LastCheck = now
		var progress check.Progress
		if force && env.Term != nil { // someone is watching: show how far the checks are
			progress = report.Progress(env.Term)
		}
		results = check.RunAllProgress(ctx, allChecks(pol, Local(env.Dir)), progress)
		results = pol.Waive(results, identity(cfg), now)
	}
	rep := newReport(env, pol, results)
	found := rep.CompromiseLines() // before evidence is left out: the details tell one sign from another
	st.CompromiseFound = found
	rep.Email, rep.InstallID = cfg.Email, cfg.InstallID
	if pol.Report.IncludeIPs {
		rep.Host.IPs = hostinfo.IPs()
	}
	if pol.Report.IncludeLocation {
		if loc, err := hostinfo.Location(ctx); err == nil {
			rep.Location = loc
		}
	}
	// After the report is posted, whether or not it got through; a notification
	// never holds up or fails a report.
	defer notifyUser(ctx, env, pol.Notify, results, st, now, force, pol.Report.URL)
	if !pol.Report.IncludeEvidence {
		for i := range rep.Results {
			rep.Results[i].Evidence = nil
			// The flag, the check IDs and what each sign is still go; which
			// item it is (a name or path) is evidence.
			if c := rep.Results[i].Compromise; c != nil {
				bare := make([]check.Indicator, len(c))
				for j, ind := range c {
					bare[j] = check.Indicator{What: ind.What}
				}
				rep.Results[i].Compromise = bare
			}
		}
	}
	st.LastTry = now
	page, err := post(ctx, env, pol.Report, rep, tok)
	if err != nil {
		st.LastError = err.Error()
		fmt.Fprintf(env.Out, "%s report failed: %v\n", now.Format(time.RFC3339), err)
		return err
	}
	if page != "" {
		st.ReportPage = page
	}
	if tok != nil {
		st.Revoked, st.RevokedChecked, st.RevokedNotified = time.Time{}, time.Time{}, false
	}
	st.LastSent, st.LastError, st.CompromiseSent = now, "", found
	c := rep.Counts
	marked := ""
	if rep.Compromised {
		marked = " · marked compromised (" + strings.Join(rep.CompromiseChecks, ", ") + ")"
	}
	fmt.Fprintf(env.Out, "%s report sent to %s: %d fail, %d warn, %d pass, %d waived%s\n",
		now.Format(time.RFC3339), hostOf(pol.Report.URL), c.Fail, c.Warn, c.Pass, c.Waived, marked)
	return nil
}

// Update refreshes the policy and installs a newer signed release now, whether
// or not the policy turns automatic updates on.
func Update(ctx context.Context, env Env) error {
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		return fmt.Errorf("BorderCheck is not installed (%w); run: bordercheck install", err)
	}
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
	tok, err := credentials(env, cfg)
	if err != nil {
		return err
	}
	if _, err := currentPolicy(ctx, env, cfg, tok); err != nil {
		return err
	}
	err = updateBinary(ctx, env, cfg, &st, time.Now())
	return errors.Join(err, writeJSON(filepath.Join(env.Dir, "state.json"), st))
}

func updateBinary(ctx context.Context, env Env, cfg Config, st *State, now time.Time) error {
	gh := env.GitHub
	if gh == "" {
		gh = "https://github.com"
	}
	src := update.Source{GitHub: gh, Repo: cfg.UpdateRepo, PublicKey: cfg.UpdateKey}
	res, err := update.Run(ctx, env.Client, src, env.Version, filepath.Join(env.Dir, binName()))
	st.LastUpdateCheck, st.UpdateError = now, ""
	switch {
	case err != nil:
		st.UpdateError = err.Error()
		fmt.Fprintf(env.Out, "%s update failed: %v\n", now.Format(time.RFC3339), err)
	case res.Updated:
		fmt.Fprintf(env.Out, "%s updated %s → %s; the next run uses it\n", now.Format(time.RFC3339), res.Current, res.Latest)
		refreshNotifier(ctx, env, res.Latest, now)
	default:
		fmt.Fprintf(env.Out, "%s up to date (%s)\n", now.Format(time.RFC3339), res.Current)
	}
	return err
}

// Status describes the install for `bordercheck status`.
func Status(env Env) (string, error) {
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		return "", fmt.Errorf("BorderCheck is not installed: %w", err)
	}
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
	var b strings.Builder
	if len(st.CompromiseFound) > 0 {
		fmt.Fprintf(&b, "Signs that this computer may be compromised (found by the check on %s):\n", st.LastCheck.Format(time.RFC1123))
		for _, l := range st.CompromiseFound {
			fmt.Fprintf(&b, "  · %s\n", l)
		}
		if slices.Equal(st.CompromiseFound, st.CompromiseSent) {
			b.WriteString("Your IT team has been sent a report saying so.\n")
		} else {
			b.WriteString("Not reported to your IT team yet; BorderCheck keeps trying every hour.\n")
		}
		b.WriteString(report.CompromiseAdvice + "\n\n")
	}
	fmt.Fprintf(&b, "Installed:  %s (%s)\nEmail:      %s\nInstall ID: %s\n", env.Dir, env.Version, cfg.Email, cfg.InstallID)
	refreshedFrom := ""
	if e := cfg.Enrollment; e != nil {
		fmt.Fprintf(&b, "Enrolled:   with %s", hostOf(e.Portal))
		if e.Role != "" {
			fmt.Fprintf(&b, ", role %s", e.Role)
		}
		b.WriteString("\n")
		if e.Pending {
			fmt.Fprintf(&b, "Unfinished: the install stopped after enrolling; run: %s install\n", filepath.Join(env.Dir, binName()))
			return b.String(), nil
		}
		refreshedFrom = e.PolicyURL
	}
	if !st.Revoked.IsZero() {
		fmt.Fprintf(&b, "Revoked:    by IT on %s; no reports are sent. Ask IT for a new invite, or run bordercheck uninstall\n",
			st.Revoked.Format(time.RFC1123))
	}
	pol, err := policy.Load(filepath.Join(env.Dir, policy.FileName))
	if err != nil {
		return "", err
	}
	if refreshedFrom == "" {
		refreshedFrom = pol.Update.PolicyURL
	}
	fmt.Fprintf(&b, "Policy:     %s", pol.Name)
	if refreshedFrom != "" {
		fmt.Fprintf(&b, " (refreshed from %s)", refreshedFrom)
	}
	fmt.Fprintf(&b, "\nChecks:     every %s\nReports:    every %s to %s\nSends:      results, anything you ignored with your reason, and files set aside as likely sample keys; %s\nService:    %s\n",
		pol.Report.CheckEvery(), pol.Report.Interval, hostOf(pol.Report.URL), sends(pol.Report), services.status())
	if pol.Report.CompromiseAlert {
		fmt.Fprintf(&b, "Compromise: looked for every hour, and reported as soon as a sign is found (the other checks run every %s)\n", pol.Report.CheckEvery())
	} else {
		b.WriteString("Compromise: not flagged (the policy turns report.compromise_alert off)\n")
	}
	if entries, err := ignore.Load(env.Dir); err != nil {
		fmt.Fprintf(&b, "Ignored:    your list cannot be read (%v), so nothing is ignored\n", err)
	} else if len(entries) > 0 {
		allowed := map[string]bool{"secrets": pol.Checks.Secrets.UserIgnore, "ai-agents": pol.Checks.AIAgents.UserIgnore,
			"ssh-keys": pol.Checks.SSHKeys.UserIgnore}
		off := 0
		for _, e := range entries {
			if !allowed[e.Check] {
				off++
			}
		}
		fmt.Fprintf(&b, "Ignored:    %d entr%s you marked as not sensitive, sent with your reasons in every report (bordercheck ignore -list)",
			len(entries), plural(len(entries), "y", "ies"))
		if off > 0 {
			fmt.Fprintf(&b, "; %d not applied: the policy does not allow it for that check", off)
		}
		b.WriteString("\n")
	}
	if !st.LastSent.IsZero() {
		fmt.Fprintf(&b, "Last sent:  %s\n", st.LastSent.Format(time.RFC1123))
	}
	if st.LastError != "" {
		fmt.Fprintf(&b, "Last error: %s (%s)\n", st.LastError, st.LastTry.Format(time.RFC1123))
	}
	if link := reportPage(st.ReportPage, pol.Report.URL); link != "" {
		fmt.Fprintf(&b, "Report page: %s (anyone with this link can see this machine's results)\n", link)
	}
	if n := pol.Notify; n.Enabled {
		fmt.Fprintf(&b, "Notify:     new %s (%s)", joinWords(n.Statuses), joinWords(n.Severities))
		if n.Remind() > 0 {
			fmt.Fprintf(&b, ", again every %s", n.RemindEvery)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("Notify:     off\n")
	}
	if macNotifier {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		fmt.Fprintf(&b, "Notifications: %s\n", notificationsNote(ctx, env, cfg))
		cancel()
	}
	for _, w := range pol.ActiveWaivers(identity(cfg), time.Now()) {
		fmt.Fprintf(&b, "Waiver:     %s until %s (%s)\n", w.Check, w.Until, w.Reason)
	}
	if pol.Update.Binary {
		fmt.Fprintf(&b, "Updates:    every %s from github.com/%s\n", pol.Update.Interval, cfg.UpdateRepo)
	} else {
		fmt.Fprintf(&b, "Updates:    off\n")
	}
	if !st.LastUpdateCheck.IsZero() {
		fmt.Fprintf(&b, "Last check: %s\n", st.LastUpdateCheck.Format(time.RFC1123))
	}
	if st.UpdateError != "" {
		fmt.Fprintf(&b, "Update err: %s\n", st.UpdateError)
	}
	return b.String(), nil
}

func plural(n int, one, other string) string {
	if n == 1 {
		return one
	}
	return other
}

// joinWords joins string-like values with ", ".
func joinWords[T ~string](vs []T) string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return strings.Join(out, ", ")
}

// currentPolicy refreshes policies.json from its update.policy_url, keeping the
// last good copy if the fetch or the new policy fails, and applies the update
// source pinned at install. An enrolled install (tok != nil) refreshes from the
// policy URL it was enrolled with, with its token, refuses a policy that points
// reports or its refresh at another host, and returns ErrRevoked when the
// portal says so.
func currentPolicy(ctx context.Context, env Env, cfg Config, tok *bearer) (policy.Policy, error) {
	path := filepath.Join(env.Dir, policy.FileName)
	pol, err := policy.Load(path)
	if err != nil {
		return pol, err
	}
	u := pol.Update.PolicyURL
	if tok != nil {
		u = cfg.Enrollment.PolicyURL
	}
	if u != "" {
		data, fresh, err := readPolicy(ctx, env.Client, u, tok)
		if errors.Is(err, ErrRevoked) {
			return pol, err
		}
		if err == nil && tok != nil {
			err = checkEnrolledPolicy(fresh, tok.portal)
		}
		if err == nil {
			err = writeFile(path, data, 0o600)
		}
		if err != nil {
			fmt.Fprintf(env.Out, "%s using the saved policy: %v\n", time.Now().Format(time.RFC3339), err)
		} else {
			pol = fresh
		}
	}
	if cfg.UpdateRepo != "" && (pol.Update.Repo != cfg.UpdateRepo || pol.Update.PublicKey != cfg.UpdateKey) {
		fmt.Fprintf(env.Out, "%s policy asks for updates from %s with another key; keeping the source pinned at install (%s)\n",
			time.Now().Format(time.RFC3339), pol.Update.Repo, cfg.UpdateRepo)
	}
	pol.Update.Repo, pol.Update.PublicKey = cfg.UpdateRepo, cfg.UpdateKey
	return pol, nil
}

func isURL(s string) bool { return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") }

// readPolicy reads a policy from a file or an https URL; with tok, from the
// portal that issued the token only, sending it and following no redirects.
func readPolicy(ctx context.Context, client *http.Client, source string, tok *bearer) ([]byte, policy.Policy, error) {
	var data []byte
	if !isURL(source) {
		var err error
		if data, err = os.ReadFile(source); err != nil {
			return nil, policy.Policy{}, err
		}
	} else {
		if !strings.HasPrefix(source, "https://") {
			return nil, policy.Policy{}, fmt.Errorf("policy URL must be https: %s", source)
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, policy.Policy{}, err
		}
		if tok != nil {
			if err := tok.allows(source); err != nil {
				return nil, policy.Policy{}, err
			}
			req.Header.Set("Authorization", "Bearer "+tok.token)
			client = noRedirects(client)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, policy.Policy{}, err
		}
		defer resp.Body.Close()
		if tok != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, policy.Policy{}, fmt.Errorf("fetching policy: %w", authError(resp, hostOf(source)))
		}
		if resp.StatusCode != http.StatusOK {
			return nil, policy.Policy{}, fmt.Errorf("fetching policy: %s", resp.Status)
		}
		if data, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20)); err != nil {
			return nil, policy.Policy{}, err
		}
	}
	pol, err := policy.Parse(data, source)
	return data, pol, err
}

// post sends the report and returns the link to this machine's report page if
// the receiver gave a usable one (see reportPage). Errors name the host only,
// never the headers, which may hold a token. An enrolled install's token (tok)
// goes only to the portal that issued it.
func post(ctx context.Context, env Env, r policy.Report, rep report.Report, tok *bearer) (string, error) {
	body, err := json.Marshal(rep)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bordercheck/"+env.Version)
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	client := env.Client
	if tok != nil {
		if err := tok.allows(r.URL); err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+tok.token)
		client = noRedirects(client)
	}
	resp, err := client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return "", fmt.Errorf("posting to %s: %w", hostOf(r.URL), err)
	}
	defer resp.Body.Close()
	if tok != nil && resp.StatusCode == http.StatusUnauthorized {
		return "", authError(resp, hostOf(r.URL))
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("%s answered %s", hostOf(r.URL), resp.Status)
	}
	var answer struct {
		ReportURL string `json:"report_url"`
	}
	_ = json.Unmarshal(data, &answer) // other receivers answer with nothing, or something else
	return reportPage(answer.ReportURL, r.URL), nil
}

func askEmail(in io.Reader, out io.Writer, domains []string) (string, error) {
	sc := bufio.NewScanner(in)
	for range 3 {
		fmt.Fprint(out, "Your work email: ")
		if !sc.Scan() {
			break
		}
		email, err := checkEmail(sc.Text(), domains)
		if err == nil {
			return email, nil
		}
		fmt.Fprintln(out, err)
	}
	return "", errors.New("no valid email given")
}

func checkEmail(s string, domains []string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil || !strings.Contains(addr.Address, "@") {
		return "", fmt.Errorf("%q is not an email address", strings.TrimSpace(s))
	}
	email := strings.ToLower(addr.Address)
	if len(domains) > 0 {
		_, domain, _ := strings.Cut(email, "@")
		if !slices.ContainsFunc(domains, func(d string) bool { return strings.EqualFold(d, domain) }) {
			return "", fmt.Errorf("use your work email (@%s)", strings.Join(domains, ", @"))
		}
	}
	return email, nil
}

// copySelf copies the running binary to dst unless it already is dst.
func copySelf(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if a, err := filepath.EvalSymlinks(src); err == nil {
		src = a
	}
	if b, err := filepath.EvalSymlinks(dst); err == nil && b == src {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFile(dst, data, 0o755)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return u
}
