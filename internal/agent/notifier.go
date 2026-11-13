package agent

// bordercheck's own notifications on macOS, through Bordercheck.app (see
// internal/notifier): its own name and icon, its own switch in System
// Settings → Notifications, and a click opens the machine's report page.
//
// macOS asks the person once whether "bordercheck" may send notifications,
// and only while they are at the terminal: during `bordercheck install`
// (after install has said what the notifications are for and that macOS is
// about to ask) or when they run `bordercheck notifications`. The hourly run
// never asks: it posts only if the person already allowed it.
//
//   - Allowed: notifications come from bordercheck. One that carries the
//     report page opens it when clicked, and the page no longer opens by
//     itself (see notifyUser).
//   - Declined, or turned off later in System Settings: nothing is shown, not
//     even through Script Editor (they said no). Reports go on; `bordercheck
//     status` says notifications are off.
//   - Not asked yet (an install with no terminal, an install upgraded from a
//     version without the app, or the question left unanswered) or the app
//     missing, refused or failing: notifications come through osascript, as
//     before, and `bordercheck status` says how to switch.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/notifier"
	"github.com/ptrinh/bordercheck/internal/notify"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/update"
)

// The notification app and how it is fetched, checked and run; tests replace them.
var (
	macNotifier                   = runtime.GOOS == "darwin"
	ntfRun      notifier.Runner   = notifier.Open
	ntfVerify   notifier.Verifier = notifier.Codesign
	ntfFetch                      = update.FetchAsset
)

// Values of State.Notifications besides notifier.Status.
const ntfError = "error"

// errNotificationsOff means the person turned bordercheck's notifications off:
// nothing is shown, and nothing else is tried.
var errNotificationsOff = errors.New("notifications are turned off for BorderCheck in System Settings")

func notifierFor(env Env, cfg Config) notifier.Helper {
	return notifier.Helper{Dir: env.Dir, TeamID: cfg.NotifierTeam, Digest: cfg.NotifierDigest, Run: ntfRun, Verify: ntfVerify}
}

func notificationsCommand(env Env) string {
	return fmt.Sprintf("%q notifications", filepath.Join(env.Dir, binName()))
}

func recordNotifications(st *State, s notifier.Status, err error, now time.Time) {
	st.NotificationsAt, st.NotificationsError = now, ""
	switch {
	case err != nil:
		st.Notifications, st.NotificationsError = ntfError, err.Error()
	case s == notifier.Posted:
		st.Notifications = string(notifier.Authorized)
	default:
		st.Notifications = string(s)
	}
}

// ownNotification posts m through bordercheck's notification app, with link
// (already checked by the caller; "" for none) to open when it is clicked.
// It never asks for permission. It returns:
//
//	true, nil                   shown
//	false, errNotificationsOff  the person turned them off: show nothing
//	false, nil                  not set up here (not macOS, no app, not allowed
//	                            yet): show it the old way
//	false, err                  the app failed: show it the old way, and log err
//
// The link goes to the app in a file, never in an argument or the log.
func ownNotification(ctx context.Context, env Env, st *State, m notify.Message, link, host string, now time.Time) (bool, error) {
	if !macNotifier {
		return false, nil
	}
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		return false, nil
	}
	h := notifierFor(env, cfg)
	if !h.Ready() {
		return false, nil
	}
	// The banner already says "BorderCheck" above the title.
	title := strings.TrimPrefix(m.Title, "BorderCheck: ")
	req, err := notifier.NewRequest(title, m.Body, link, host)
	if err != nil {
		return false, err
	}
	s, err := h.Post(ctx, req)
	recordNotifications(st, s, err, now)
	switch {
	case err != nil:
		return false, err
	case s == notifier.Posted:
		return true, nil
	case s == notifier.Denied:
		return false, errNotificationsOff
	}
	return false, nil // not allowed yet: the person was never asked, or did not answer
}

// showMessage shows m on the desktop: through bordercheck's own notifications
// when they are set up, else as before. errNotificationsOff when the person
// turned them off.
func showMessage(ctx context.Context, env Env, st *State, m notify.Message, now time.Time) error {
	posted, err := ownNotification(ctx, env, st, m, "", "", now)
	switch {
	case posted:
		return nil
	case errors.Is(err, errNotificationsOff):
		return err
	case err != nil:
		fmt.Fprintf(env.Out, "%s BorderCheck's notification app failed, using Script Editor: %v\n", now.Format(time.RFC3339), err)
	}
	return showNotification(ctx, m)
}

// ensureNotifier installs the notification app if it is not there, or not as
// installed: from zipPath when given (a build being tested), else this
// version's release asset from the pinned update source, checked like a
// binary update. It records the Team ID (pinned the first time) and the
// bundle digest in cfg and config.json.
func ensureNotifier(ctx context.Context, env Env, cfg *Config, zipPath string) error {
	if zipPath == "" && notifierFor(env, *cfg).Ready() {
		if d, err := notifier.Digest(notifier.Path(env.Dir)); err == nil && d == cfg.NotifierDigest {
			return nil
		}
	}
	var data []byte
	var err error
	if zipPath != "" {
		data, err = notifier.ReadCapped(zipPath, notifier.MaxZip)
	} else {
		data, err = fetchNotifier(ctx, env, *cfg, env.Version)
	}
	if err != nil {
		return err
	}
	return installNotifier(ctx, env, cfg, data)
}

func installNotifier(ctx context.Context, env Env, cfg *Config, data []byte) error {
	team, digest, err := notifier.InstallZip(ctx, env.Dir, data, ntfVerify, cfg.NotifierTeam)
	if err != nil {
		return err
	}
	cfg.NotifierTeam, cfg.NotifierDigest = team, digest
	return writeJSON(filepath.Join(env.Dir, "config.json"), *cfg)
}

func fetchNotifier(ctx context.Context, env Env, cfg Config, version string) ([]byte, error) {
	if !isRelease(version) {
		return nil, fmt.Errorf("this is a %q build, which cannot download the notification app; pass -notifier-zip <zip>", version)
	}
	gh := env.GitHub
	if gh == "" {
		gh = "https://github.com"
	}
	repo := cfg.UpdateRepo
	if repo == "" {
		repo = policy.Default().Update.Repo
	}
	src := update.Source{GitHub: gh, Repo: repo, PublicKey: cfg.UpdateKey}
	return ntfFetch(ctx, env.Client, src, version, notifier.AssetName(version), notifier.MaxZip)
}

// isRelease reports whether v looks like a release version, vX.Y.Z[-pre].
func isRelease(v string) bool {
	core, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), "-")
	return strings.HasPrefix(v, "v") && strings.Count(core, ".") == 2 && strings.Trim(core, "0123456789.") == ""
}

// askNotifications lets macOS ask the person, who is at the terminal, whether
// bordercheck may send notifications, if it never has. It says first what
// they are for, prints what happened and records it in st.
func askNotifications(ctx context.Context, env Env, cfg Config, st *State) {
	now := time.Now()
	h := notifierFor(env, cfg)
	s, err := h.Status(ctx)
	if err == nil && s == notifier.NotDetermined {
		fmt.Fprintln(env.Out, "\nBorderCheck shows a notification when it finds a new problem on this computer; clicking it opens your report page.\n"+
			`macOS will now ask whether "BorderCheck" may send notifications. Choose Allow to get them.`)
		s, err = h.Authorize(ctx)
	}
	recordNotifications(st, s, err, now)
	switch {
	case err != nil:
		fmt.Fprintf(env.Out, "Notifications: BorderCheck's own are not working (%v); notifications come through Script Editor instead.\n", err)
	case s == notifier.Authorized:
		fmt.Fprintln(env.Out, "Notifications: allowed. To change that: System Settings → Notifications → BorderCheck.")
	case s == notifier.Denied:
		fmt.Fprintln(env.Out, "Notifications: turned off for BorderCheck, so it shows none; it still reports to IT. To turn them on: System Settings → Notifications → BorderCheck.")
	default:
		fmt.Fprintf(env.Out, "Notifications: no answer yet; macOS keeps the question in Notification Center. Until you allow them, notifications come through Script Editor. To be asked again, run:\n  %s\n", notificationsCommand(env))
	}
}

// setUpNotifications is install's part on a Mac: install the notification
// app, then, with a person at the terminal (env.Term), let macOS ask them.
// Without a terminal nothing is asked: notifications come through Script
// Editor until the person runs `bordercheck notifications`.
func setUpNotifications(ctx context.Context, env Env, cfg *Config, pol policy.Policy, zipPath string) {
	if !macNotifier {
		return
	}
	if err := ensureNotifier(ctx, env, cfg, zipPath); err != nil {
		fmt.Fprintf(env.Out, "\nNotifications come through Script Editor: BorderCheck's own notification app is not available (%v).\n", err)
		// The first run, a moment from now, need not try again (adoptNotifier).
		var st State
		_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
		st.NotifierTried = time.Now()
		_ = writeJSON(filepath.Join(env.Dir, "state.json"), st)
		return
	}
	if !pol.Notify.Enabled {
		return // nothing to ask about; `bordercheck notifications` asks if the policy turns them on later
	}
	statePath := filepath.Join(env.Dir, "state.json")
	var st State
	_ = readJSON(statePath, &st)
	if env.Term == nil {
		recordNotifications(&st, notifier.NotDetermined, nil, time.Now())
		fmt.Fprintf(env.Out, "\nBorderCheck shows a notification when it finds a new problem. There is no terminal, so macOS was not asked whether \"BorderCheck\" may send them; until it is, they come through Script Editor. To be asked, run:\n  %s\n",
			notificationsCommand(env))
	} else {
		askNotifications(ctx, env, *cfg, &st)
	}
	if err := writeJSON(statePath, st); err != nil {
		fmt.Fprintf(env.Out, "saving %s: %v\n", statePath, err)
	}
}

// Notifications is `bordercheck notifications`: run by the person at the Mac
// to (re)install bordercheck's notification app and let macOS ask them.
func Notifications(ctx context.Context, env Env, zipPath string) error {
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		return fmt.Errorf("BorderCheck is not installed (%w); run: bordercheck install", err)
	}
	if !macNotifier {
		fmt.Fprintln(env.Out, "Notifications need no setting up on this system; BorderCheck shows them with what the system provides.")
		return nil
	}
	if env.Term == nil {
		return errors.New("run bordercheck notifications in a terminal: macOS asks the person at the Mac")
	}
	if err := ensureNotifier(ctx, env, &cfg, zipPath); err != nil {
		return fmt.Errorf("BorderCheck's notification app could not be installed (%w); notifications come through Script Editor", err)
	}
	statePath := filepath.Join(env.Dir, "state.json")
	var st State
	_ = readJSON(statePath, &st)
	askNotifications(ctx, env, cfg, &st)
	return writeJSON(statePath, st)
}

// refreshNotifier installs the notification app of version after a binary
// update, when one is installed. Failure keeps the old one, which still works.
func refreshNotifier(ctx context.Context, env Env, version string, now time.Time) {
	if !macNotifier || !notifier.Installed(env.Dir) {
		return
	}
	var cfg Config
	err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg)
	if err == nil {
		var data []byte
		if data, err = fetchNotifier(ctx, env, cfg, version); err == nil {
			err = installNotifier(ctx, env, &cfg, data)
		}
	}
	if err != nil {
		fmt.Fprintf(env.Out, "%s notification app not updated (keeping the current one): %v\n", now.Format(time.RFC3339), err)
		return
	}
	fmt.Fprintf(env.Out, "%s notification app updated to %s\n", now.Format(time.RFC3339), version)
}

// adoptNotifier gives a Mac installed without BorderCheck's app (before the
// app existed, or when it could not be downloaded) the app of this version,
// so the person finds BorderCheck in Spotlight (see launcher). It tries once a
// day, never asks macOS or the person anything, and changes nothing about how
// notifications are shown until they run `bordercheck notifications`.
func adoptNotifier(ctx context.Context, env Env, cfg *Config, st *State, now time.Time) {
	if !macNotifier || !isRelease(env.Version) || notifier.Installed(env.Dir) || now.Sub(st.NotifierTried) < 24*time.Hour {
		return
	}
	st.NotifierTried = now
	if err := ensureNotifier(ctx, env, cfg, ""); err != nil {
		fmt.Fprintf(env.Out, "%s BorderCheck's app not installed (trying again tomorrow): %v\n", now.Format(time.RFC3339), err)
		return
	}
	fmt.Fprintf(env.Out, "%s installed BorderCheck's app %s\n", now.Format(time.RFC3339), env.Version)
}

// notificationsNote says, for status, how notifications reach the person on a
// Mac. It asks the app (which never asks the person) for the current answer,
// so a switch flipped in System Settings shows at once.
func notificationsNote(ctx context.Context, env Env, cfg Config) string {
	scriptEditor := "through Script Editor (osascript); for BorderCheck's own, run: bordercheck notifications"
	h := notifierFor(env, cfg)
	if !h.Ready() {
		return scriptEditor
	}
	s, err := h.Status(ctx)
	if err != nil {
		return "through Script Editor (osascript); BorderCheck's own are not working: " + err.Error()
	}
	switch s {
	case notifier.Authorized:
		return "BorderCheck's own (allowed in System Settings); clicking one opens your report page"
	case notifier.Denied:
		return "turned off for BorderCheck in System Settings; none are shown (System Settings → Notifications → BorderCheck to turn them on)"
	}
	return "through Script Editor (osascript) until you allow BorderCheck's own; run: bordercheck notifications"
}
