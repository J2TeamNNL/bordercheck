package agent

// Enrollment: `bordercheck install https://<portal>/i/<code>` spends a one-time
// invite IT created for one person, and gets back this install's own ID, the
// person's email as IT set it, their role and a bearer token. The token is the
// only secret bordercheck keeps. It lives in the file "token" in the install
// folder, readable by this user only, and is sent only to the portal that
// issued it, over https, with redirects refused. It never goes in config.json,
// state.json, bordercheck.log, a report body or `bordercheck status`.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/ptrinh/bordercheck/internal/notify"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/report"
)

// services is how the hourly service is registered; tests replace it so they
// never touch launchd, systemd, cron or Task Scheduler.
var services = struct {
	check      func() error
	register   func(bin, dir string) error
	unregister func() error
	status     func() string
}{canRegisterService, registerService, unregisterService, serviceStatus}

// Enrollment is what config.json records about an install made from an invite.
type Enrollment struct {
	Portal    string `json:"portal"`               // https://host that issued the token; the only place it is sent
	Role      string `json:"role,omitempty"`       // as IT set it; picks the policy
	PolicyURL string `json:"policy_url"`           // where the policy is fetched with the token
	Invite    string `json:"invite_sha256"`        // hash of the spent code: the same link again resumes, not re-enrolls
	Pending   bool   `json:"pending,omitempty"`    // credentials saved, install not finished
	Enrolled  string `json:"enrolled_at,omitzero"` // RFC 3339
}

// TokenFile holds this install's bearer token, and nothing else.
const TokenFile = "token"

// ErrRevoked is what the portal's 401 {"error": "revoked"} means.
var ErrRevoked = errors.New("IT has revoked bordercheck on this machine; ask IT for a new invite, or run bordercheck uninstall")

// revokedRetry is how often a revoked install asks the portal again.
const revokedRetry = 24 * time.Hour

var inviteRe = regexp.MustCompile(`^/i/([A-Za-z0-9._~-]{1,256})/?$`)

// ParseInvite reports whether s is an invite link, https://<host>/i/<code>, and
// returns the portal's origin (scheme and host) and the code. An http link is
// recognised too, so that install can refuse it with a clear message.
func ParseInvite(s string) (portal, code string, ok bool) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", "", false
	}
	m := inviteRe.FindStringSubmatch(u.EscapedPath())
	if m == nil {
		return "", "", false
	}
	return origin(u), m[1], true
}

// origin is scheme://host of u, lower case, without a default port.
func origin(u *url.URL) string {
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if (scheme == "https" && strings.HasSuffix(host, ":443")) || (scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndexByte(host, ':')]
	}
	return scheme + "://" + host
}

func originOf(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	return origin(u)
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// bearer is the token and the only origin it may be sent to.
type bearer struct {
	token, portal string
}

// allows reports whether the token may go to target: the portal itself, over https.
func (b *bearer) allows(target string) error {
	if !strings.HasPrefix(b.portal, "https://") || originOf(target) != b.portal {
		return fmt.Errorf("not sending this install's token to %s: it was issued by %s", hostOf(target), hostOf(b.portal))
	}
	return nil
}

// noRedirects is client, refusing to follow redirects, for requests that carry
// the token or spend an invite.
func noRedirects(client *http.Client) *http.Client {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("the portal redirected; bordercheck does not follow redirects with its token")
	}
	return &c
}

// authError reads a 401 from the portal: revoked, or an ordinary error.
func authError(resp *http.Response, host string) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&e)
	if e.Error == "revoked" {
		return ErrRevoked
	}
	return fmt.Errorf("%s answered %s", host, resp.Status)
}

func readToken(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, TokenFile))
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(data))
	if t == "" {
		return "", errors.New("the token file is empty")
	}
	return t, nil
}

// writeToken saves the token readable and writable by this user only. On
// Windows the mode bits mean nothing: the file takes the ACL of
// %LOCALAPPDATA%, which grants the user, SYSTEM and Administrators.
func writeToken(dir, token string) error {
	path := filepath.Join(dir, TokenFile)
	_ = os.Remove(path + ".tmp") // a leftover would keep its old mode
	if err := writeFile(path, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Chmod(path, 0o600)
	}
	return nil
}

// credentials is the token of an enrolled install, nil for a policies.json one.
func credentials(env Env, cfg Config) (*bearer, error) {
	e := cfg.Enrollment
	if e == nil {
		return nil, nil
	}
	if e.Pending {
		return nil, fmt.Errorf("the install did not finish; run: %s install", filepath.Join(env.Dir, binName()))
	}
	t, err := readToken(env.Dir)
	if err != nil {
		return nil, fmt.Errorf("this install's token is missing (%v); ask IT for a new invite and run bordercheck install with it", err)
	}
	return &bearer{token: t, portal: e.Portal}, nil
}

// checkEnrolledPolicy refuses a policy that would send reports, or point its
// own refresh, anywhere but the portal that issued the token. Refusing (and so
// keeping the last good policy) rather than sending without the token keeps
// reports going to IT and makes the mistake visible in bordercheck status,
// instead of quietly handing a stranger every report.
func checkEnrolledPolicy(pol policy.Policy, portal string) error {
	if pol.Report.URL == "" {
		return errors.New("the portal's policy has no report.url")
	}
	if originOf(pol.Report.URL) != portal {
		return fmt.Errorf("the policy sends reports to %s, not to %s, which issued this install's token; refusing it",
			pol.Report.URL, portal)
	}
	if u := pol.Update.PolicyURL; u != "" && originOf(u) != portal {
		return fmt.Errorf("the policy's update.policy_url is on %s, not on %s, which issued this install's token; refusing it",
			hostOf(u), hostOf(portal))
	}
	return nil
}

type enrollResponse struct {
	InstallID string `json:"install_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Token     string `json:"token"`
	PolicyURL string `json:"policy_url"`
	ReportURL string `json:"report_url"`
}

var installIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// enroll spends the invite code. It never retries: a code works once.
func enroll(ctx context.Context, env Env, portal, code string) (enrollResponse, error) {
	var enr enrollResponse
	hostname, _ := os.Hostname()
	body, err := json.Marshal(map[string]any{
		"code":    code,
		"host":    report.Host{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: hostname},
		"version": env.Version,
	})
	if err != nil {
		return enr, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, portal+"/enroll", bytes.NewReader(body))
	if err != nil {
		return enr, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bordercheck/"+env.Version)
	host := hostOf(portal)
	resp, err := noRedirects(env.Client).Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return enr, fmt.Errorf("could not reach %s to enroll: %v\nRun the same command again. If it then says the invite was already used, ask IT for a new one", host, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return enr, fmt.Errorf("reading the answer from %s: %v", host, err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error, Message string }
		_ = json.Unmarshal(data, &e)
		return enr, enrollError(host, resp.Status, resp.StatusCode, e.Error, e.Message)
	}
	// The answer holds the token: never put it, or any of it, in an error.
	if err := json.Unmarshal(data, &enr); err != nil {
		return enr, fmt.Errorf("%s answered the enrollment with something bordercheck cannot read; your invite may have been used, so tell IT", host)
	}
	if err := enr.validate(portal); err != nil {
		return enrollResponse{}, fmt.Errorf("%s enrolled this machine but its answer is unusable (%v); your invite has been used, so tell IT and ask for a new one", host, err)
	}
	enr.Email = strings.ToLower(strings.TrimSpace(enr.Email))
	return enr, nil
}

func (e enrollResponse) validate(portal string) error {
	switch {
	case !installIDRe.MatchString(e.InstallID):
		return errors.New("install_id is not 32 hex characters")
	case len(e.Token) < 16 || len(e.Token) > 4096 || strings.IndexFunc(e.Token, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0:
		return errors.New("the token is missing or not plain text")
	case len([]rune(e.Role)) > 100 || strings.IndexFunc(e.Role, unicode.IsControl) >= 0:
		return errors.New("the role is not a short line of text")
	case !strings.HasPrefix(e.PolicyURL, "https://") || originOf(e.PolicyURL) != portal:
		return fmt.Errorf("policy_url %q is not https on %s", e.PolicyURL, hostOf(portal))
	case originOf(e.ReportURL) != portal:
		return fmt.Errorf("report_url %q is not on %s", e.ReportURL, hostOf(portal))
	}
	if _, err := checkEmail(e.Email, nil); err != nil {
		return err
	}
	return nil
}

// enrollError turns the portal's refusal into what the person should do.
func enrollError(host, status string, code int, kind, message string) error {
	var msg string
	switch {
	case kind == "invalid_code":
		msg = "This invite link is not valid. Check that you copied the whole link; if you did, ask IT for a new invite."
	case kind == "expired":
		msg = "This invite has expired. Ask IT for a new invite."
	case kind == "used":
		msg = "This invite has already been used; each invite works once. Ask IT for a new one, and if you did not use it yourself, tell IT."
	case kind == "revoked":
		msg = "IT has cancelled this invite. Ask IT for a new one."
	case kind == "bad_request":
		msg = "The portal could not read this enrollment request. Make sure you have the latest bordercheck, or tell IT."
	case code == http.StatusTooManyRequests:
		msg = "Too many attempts. Wait a few minutes and run the same command again."
	default:
		msg = fmt.Sprintf("%s answered %s. Try again later, or tell IT.", host, status)
	}
	if m := notify.Clean(message); m != "" && kind != "" {
		msg += fmt.Sprintf(" (%s says: %s)", host, notify.Clip(m, 200))
	}
	return errors.New(msg)
}

// prepareDir creates the install folder for this user only and checks it can be written.
func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return probeWrite(dir)
}

// probeWrite checks that dir accepts a new file.
func probeWrite(dir string) error {
	f, err := os.CreateTemp(dir, ".bordercheck-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// updatePins decides the update source of an enrolled install. The portal's
// policy never chooses it: it is the built-in default (the official repo and
// release key) unless the person installing names another on the command line.
// Re-running install without flags keeps what an earlier run pinned.
func updatePins(o InstallOptions, cfg Config, keepSaved bool) (repo, key string, err error) {
	repo, key = policy.Default().Update.Repo, ""
	if keepSaved && cfg.UpdateRepo != "" {
		repo, key = cfg.UpdateRepo, cfg.UpdateKey
	}
	if o.UpdateRepo != "" {
		if !policy.ValidRepo(o.UpdateRepo) {
			return "", "", fmt.Errorf("-update-repo must look like owner/name, not %q", o.UpdateRepo)
		}
		repo = o.UpdateRepo
	}
	if o.UpdateKey != "" {
		if raw, err := base64.StdEncoding.DecodeString(o.UpdateKey); err != nil || len(raw) != 32 {
			return "", "", errors.New("-update-key must be a base64 ed25519 public key")
		}
		key = o.UpdateKey
	}
	return repo, key, nil
}

// installEnrolled installs from an invite link (code != ""), or finishes or
// redoes an enrolled install from the saved credentials (code == "").
//
// Order matters, because the code works once: everything that can fail on
// this machine (the folder, copying the binary, whether the service can be
// registered) happens before the code is spent; once it is spent the
// credentials are saved at once, so if a later step fails, running
// `bordercheck install` again finishes the job without a new invite.
func installEnrolled(ctx context.Context, env Env, o InstallOptions, cfg Config, hadConfig bool, portal, code string) error {
	if o.Email != "" {
		return errors.New("-email cannot be used with an invite link: IT set your email when they created the invite")
	}
	if code != "" && !strings.HasPrefix(portal, "https://") {
		return errors.New("an invite link must start with https://")
	}
	resume := code == "" || (cfg.Enrollment != nil && cfg.Enrollment.Invite == hashCode(code))
	repo, key, err := updatePins(o, cfg, resume)
	if err != nil {
		return err
	}
	bin := filepath.Join(env.Dir, binName())
	unspent := func(err error) error {
		if resume {
			return err
		}
		if !hadConfig { // leave nothing behind on a machine that had no install
			_ = os.Remove(bin)
			_ = os.Remove(env.Dir)
		}
		return fmt.Errorf("%w\nNothing was installed and your invite is still unused", err)
	}
	if err := prepareDir(env.Dir); err != nil {
		return unspent(fmt.Errorf("cannot write to %s: %w", env.Dir, err))
	}
	if err := services.check(); err != nil {
		return unspent(fmt.Errorf("this machine cannot run bordercheck's hourly service: %w", err))
	}
	if err := copySelf(bin); err != nil {
		return unspent(fmt.Errorf("copying bordercheck to %s: %w", env.Dir, err))
	}

	var token string
	if resume {
		if token, err = readToken(env.Dir); err != nil {
			return fmt.Errorf("this install's saved token is missing (%v); ask IT for a new invite and run bordercheck install with it", err)
		}
		portal = cfg.Enrollment.Portal
		cfg.UpdateRepo, cfg.UpdateKey = repo, key
		fmt.Fprintf(env.Out, "Using this machine's saved enrollment with %s.\n", hostOf(portal))
	} else {
		switch {
		case cfg.Enrollment != nil:
			fmt.Fprintf(env.Out, "This machine is enrolled as %s with %s; the new invite replaces that enrollment.\n",
				cfg.Email, hostOf(cfg.Enrollment.Portal))
		case hadConfig:
			fmt.Fprintf(env.Out, "This machine reports for %s from a policies.json; the invite replaces that install.\n", cfg.Email)
		}
		fmt.Fprintf(env.Out, "Enrolling with %s ...\n", hostOf(portal))
		enr, err := enroll(ctx, env, portal, code)
		if err != nil {
			if !hadConfig {
				_ = os.Remove(bin)
				_ = os.Remove(env.Dir)
			}
			return err
		}
		// The code is spent: save what it bought before anything else can fail.
		token = enr.Token
		if err := writeToken(env.Dir, token); err != nil {
			return fmt.Errorf("saving this install's token in %s: %w\nYour invite has been used; ask IT for a new one", env.Dir, err)
		}
		cfg = Config{Email: enr.Email, InstallID: enr.InstallID, UpdateRepo: repo, UpdateKey: key,
			Enrollment: &Enrollment{Portal: portal, Role: enr.Role, PolicyURL: enr.PolicyURL, Invite: hashCode(code),
				Pending: true, Enrolled: time.Now().UTC().Format(time.RFC3339)}}
		if err := writeJSON(filepath.Join(env.Dir, "config.json"), cfg); err != nil {
			return fmt.Errorf("saving %s: %w\nYour invite has been used; ask IT for a new one", filepath.Join(env.Dir, "config.json"), err)
		}
	}
	spent := func(err error) error {
		return fmt.Errorf("%w\nYour invite has been used and this machine's enrollment is saved in %s. Once that is fixed, finish with:\n  %s install",
			err, env.Dir, bin)
	}

	tok := &bearer{token: token, portal: portal}
	data, pol, err := readPolicy(ctx, env.Client, cfg.Enrollment.PolicyURL, tok)
	if errors.Is(err, ErrRevoked) {
		return err
	}
	if err == nil {
		err = checkEnrolledPolicy(pol, portal)
	}
	if err != nil {
		return spent(fmt.Errorf("fetching this machine's policy from %s: %w", hostOf(portal), err))
	}
	if err := writeFile(filepath.Join(env.Dir, policy.FileName), data, 0o600); err != nil {
		return spent(err)
	}
	if err := services.register(bin, env.Dir); err != nil {
		return spent(fmt.Errorf("registering the hourly service: %w", err))
	}
	cfg.Enrollment.Pending = false
	if err := writeJSON(filepath.Join(env.Dir, "config.json"), cfg); err != nil {
		return spent(err)
	}

	role := ""
	if cfg.Enrollment.Role != "" {
		role = ", role " + cfg.Enrollment.Role
	}
	fmt.Fprintf(env.Out, "Installed in %s for %s%s, enrolled with %s.\nChecking every hour; reporting every %s to %s.\n",
		env.Dir, cfg.Email, role, hostOf(portal), pol.Report.Interval, hostOf(pol.Report.URL))
	if pol.Update.Binary {
		fmt.Fprintf(env.Out, "Updates itself from github.com/%s releases.\n", cfg.UpdateRepo)
	}
	printSends(env.Out, pol)
	fmt.Fprintln(env.Out)
	return Send(ctx, env, true)
}

// revoked records that the portal revoked this install and tells the person.
func revoked(ctx context.Context, env Env, st *State, now time.Time, force bool) {
	if st.Revoked.IsZero() {
		st.Revoked = now
	}
	st.RevokedChecked = now
	fmt.Fprintf(env.Out, "%s %v\n", now.Format(time.RFC3339), ErrRevoked)
	notifyRevoked(ctx, env, st, now, force)
}

// notifyRevoked tells the person at the machine, once, that IT revoked this
// install; a notification that cannot be shown is tried at the next run.
func notifyRevoked(ctx context.Context, env Env, st *State, now time.Time, force bool) {
	if st.RevokedNotified {
		return
	}
	msg := notify.Message{Title: "bordercheck: IT has revoked this install",
		Body: "This computer no longer reports to IT. Ask IT for a new invite, or run bordercheck uninstall."}
	if force {
		fmt.Fprintf(env.Out, "\n%s\n%s\n\n", msg.Title, indent(msg.Body))
		st.RevokedNotified = true
		return
	}
	if err := showNotification(ctx, msg); err != nil {
		fmt.Fprintf(env.Out, "%s notification not shown: %v\n", now.Format(time.RFC3339), err)
		return
	}
	st.RevokedNotified = true
	fmt.Fprintf(env.Out, "%s notified: install revoked\n", now.Format(time.RFC3339))
}
