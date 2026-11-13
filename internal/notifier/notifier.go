// Package notifier posts bordercheck's macOS notifications through
// Bordercheck.app, a small signed helper app installed beside bordercheck, so
// they carry bordercheck's own name and icon, can be turned off on their own
// in System Settings → Notifications, and open the machine's report page when
// clicked. The app's source is in macos/notifier.
//
// A copy of the app in ~/Applications (internal/agent, launcher) is what a
// person finds in Spotlight: opened that way, with no mode, the app runs the
// installed `bordercheck open`. This package never launches that copy.
//
// macOS lets an app post notifications only once the person has allowed it,
// and records that against the app's bundle ID. bordercheck launches the app
// through LaunchServices (/usr/bin/open), so the app, not bordercheck,
// Terminal or Script Editor, is the one macOS asks about and remembers.
//
// The app takes one argument, a mode fixed in this package (never anything
// from a policy or a check):
//
//	status     the authorization status; never asks
//	authorize  ask macOS whether "bordercheck" may send notifications, if it
//	           never has; only while a person is at the terminal
//	post       post one notification if, and only if, already allowed; never asks
//
// The notification's text and link go in a Request, written to a file in the
// install folder readable by this user only and handed to the app as its
// stdin (open --stdin), never on a command line; the file is removed when the
// app has quit. The app answers with one JSON line on stdout (see Parse).
//
// Before running the app, bordercheck checks it is the bundle it installed (a
// digest of every file, recorded at install) and that its code signature is
// valid, Developer ID, with the bundle ID below and the Team ID pinned when it
// was first installed.
package notifier

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	// AppName is the helper's folder in the install folder.
	AppName = "Bordercheck.app"
	// BundleID is the helper's CFBundleIdentifier and code signing identifier.
	BundleID = "io.github.ptrinh.bordercheck.notifier"

	// MaxAnswer caps what the helper may write; a real answer is ~40 bytes.
	MaxAnswer = 4 << 10
	// MaxZip caps the downloaded helper archive; a real one is ~1.5 MB.
	MaxZip      = 32 << 20
	maxFiles    = 200
	maxUnpacked = 64 << 20

	// Limits on what goes into a notification; the app applies them again.
	MaxTitle     = 120
	MaxBodyLine  = 240
	MaxBodyLines = 8
	MaxLink      = 2048
)

// AssetName is the helper's archive in a release, listed in SHA256SUMS.
func AssetName(version string) string {
	return "bordercheck-notifier-" + version + "-darwin-universal.zip"
}

// Mode is what the helper is asked to do.
type Mode string

const (
	ModeStatus    Mode = "status"
	ModeAuthorize Mode = "authorize"
	ModePost      Mode = "post"
)

// Timeout is how long bordercheck waits for the helper. The helper stops
// itself sooner (15 s; 120 s for the person to answer macOS's question).
func Timeout(m Mode) time.Duration {
	if m == ModeAuthorize {
		return 150 * time.Second
	}
	return 30 * time.Second
}

// Status is what the helper found.
type Status string

const (
	Posted        Status = "posted"         // post: shown (or in Notification Center, as the person set it)
	Authorized    Status = "authorized"     // the person allowed bordercheck's notifications
	Denied        Status = "denied"         // they said no, or turned them off later
	NotDetermined Status = "not_determined" // never asked, or the question went unanswered
)

// ErrNotInstalled means there is no helper, or none recorded at install.
var ErrNotInstalled = errors.New("BorderCheck's notification app is not installed")

// Path is where the helper lives in the install folder dir.
func Path(dir string) string { return filepath.Join(dir, AppName) }

// Installed reports whether a helper bundle is in dir.
func Installed(dir string) bool {
	_, err := os.Lstat(Path(dir))
	return err == nil
}

// Remove deletes the helper and anything an interrupted install or run left.
func Remove(dir string) error {
	var errs []error
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".notifier-*"))
	for _, p := range append([]string{Path(dir)}, leftovers...) {
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Request is one notification, as the helper reads it on stdin.
type Request struct {
	V           int    `json:"v"`
	Title       string `json:"title"`
	Body        string `json:"body,omitempty"`
	Link        string `json:"link,omitempty"`         // opened when the notification is clicked; never shown
	AllowedHost string `json:"allowed_host,omitempty"` // the only host Link may be on
}

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$`)

// NewRequest makes the request for a notification with title and body,
// plain text from check results: control and format characters are dropped
// and it is capped. link, if not "", must be https on exactly allowedHost
// (host, or host:port) with no user info; otherwise it is an error and
// nothing is sent.
func NewRequest(title, body, link, allowedHost string) (Request, error) {
	r := Request{V: 1, Title: plain(title, MaxTitle)}
	if r.Title == "" {
		return Request{}, errors.New("a notification needs a title")
	}
	var lines []string
	for _, l := range strings.Split(body, "\n") {
		if l = plain(l, MaxBodyLine); l != "" && len(lines) < MaxBodyLines {
			lines = append(lines, l)
		}
	}
	r.Body = strings.Join(lines, "\n")
	if link != "" {
		if err := CheckLink(link, allowedHost); err != nil {
			return Request{}, err
		}
		r.Link, r.AllowedHost = link, strings.ToLower(allowedHost)
	}
	return r, nil
}

// CheckLink is the rule the helper applies before opening a link: printable
// ASCII, at most MaxLink bytes, https, no user info, and on exactly host.
// Errors never include the link, which is a secret.
func CheckLink(link, host string) error {
	if len(host) > 260 || !hostRe.MatchString(strings.ToLower(host)) {
		return errors.New("the report page's host is not a host name")
	}
	if len(link) > MaxLink || strings.IndexFunc(link, func(r rune) bool { return r <= ' ' || r >= 0x7f }) >= 0 {
		return errors.New("the report page link is not a plain https link")
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Opaque != "" {
		return errors.New("the report page link is not a plain https link")
	}
	if !strings.EqualFold(u.Host, host) {
		return errors.New("the report page link is not on the host reports go to")
	}
	return nil
}

// plain puts s on one line without control or format characters (bidi
// overrides, zero-width characters) and clips it to n characters.
func plain(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Co, r),
			r == ' ', r == ' ', r == unicode.ReplacementChar:
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}

// answer is the helper's JSON, version 1:
//
//	{"v":1,"status":"posted"}
//	{"v":1,"status":"denied"}
//	{"error":"timed out","status":"error","v":1}
type answer struct {
	V      int    `json:"v"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Parse reads the helper's answer to mode. Anything but a status that mode
// can give is an error, so a broken or tampered helper is treated as missing.
func Parse(mode Mode, data []byte) (Status, error) {
	if len(data) > MaxAnswer {
		return "", fmt.Errorf("BorderCheck's notification app wrote more than %d bytes", MaxAnswer)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return "", errors.New("BorderCheck's notification app gave no answer")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var a answer
	if err := dec.Decode(&a); err != nil {
		return "", errors.New("BorderCheck's notification app's answer is not valid JSON")
	}
	if dec.More() {
		return "", errors.New("BorderCheck's notification app wrote more than one answer")
	}
	if a.V != 1 {
		return "", fmt.Errorf("BorderCheck's notification app answered in format %d; this BorderCheck reads 1", a.V)
	}
	switch s := Status(a.Status); {
	case s == Denied || s == NotDetermined:
		return s, nil
	case s == Authorized && mode != ModePost, s == Posted && mode == ModePost:
		return s, nil
	case a.Status == "error" || a.Status == "invalid":
		return "", fmt.Errorf("BorderCheck's notification app: %s (%s)", a.Status, plain(a.Error, 200))
	}
	return "", fmt.Errorf("BorderCheck's notification app answered %.32q to %s", plain(a.Status, 32), mode)
}

// Runner launches the helper app in mode, with stdin read from the file in
// and stdout going to the file out, and returns once it has quit.
type Runner func(ctx context.Context, app string, mode Mode, in, out string) error

// Open launches the helper through LaunchServices as a fresh instance (-n)
// and waits for it to quit (-W). Only authorize may come to the front, as
// macOS shows its question for an app in front; the rest run hidden in the
// background (-g -j). The arguments are fixed: the mode and the paths of two
// files in the install folder. The environment is cut down to what it needs.
func Open(ctx context.Context, app string, mode Mode, in, out string) error {
	args := []string{"-W", "-n"}
	if mode != ModeAuthorize {
		args = append(args, "-g", "-j")
	}
	args = append(args, "--stdin", in, "--stdout", out, "--stderr", "/dev/null", "-a", app, "--args", string(mode))
	cmd := exec.CommandContext(ctx, "/usr/bin/open", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + os.Getenv("HOME")}
	if b, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("open: %v: %s", err, plain(string(b), 200))
	}
	return nil
}

// Verifier checks the helper's code signature: valid, Developer ID, with
// BundleID and, when teamID is not "", that Team ID. It returns the Team ID.
type Verifier func(ctx context.Context, app, teamID string) (string, error)

var teamRe = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// Requirement is the code requirement the helper must satisfy: signed by a
// Developer ID Application certificate issued by Apple, with our bundle ID,
// and, once pinned, our Team ID (see Apple's TN3127, Inside Code Signing:
// Requirements).
func Requirement(teamID string) string {
	r := `anchor apple generic and identifier "` + BundleID + `"` +
		` and certificate 1[field.1.2.840.113635.100.6.2.6] exists` + // Developer ID CA
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` // Developer ID Application
	if teamID != "" {
		r += ` and certificate leaf[subject.OU] = "` + teamID + `"`
	}
	return r
}

// Codesign verifies with /usr/bin/codesign.
func Codesign(ctx context.Context, app, teamID string) (string, error) {
	if teamID != "" && !teamRe.MatchString(teamID) {
		return "", fmt.Errorf("pinned Team ID %q is not valid", teamID)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "--deep",
		"--test-requirement", "="+Requirement(teamID), app).CombinedOutput(); err != nil {
		return "", fmt.Errorf("BorderCheck's notification app is not signed by BorderCheck's Developer ID: %s", firstLine(out))
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--display", "--verbose=2", app).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("reading the notification app's signature: %s", firstLine(out))
	}
	return TeamFromDisplay(out, teamID)
}

// TeamFromDisplay reads the Team ID and identifier from `codesign -dv` output.
func TeamFromDisplay(out []byte, want string) (string, error) {
	var team, ident string
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "TeamIdentifier="); ok {
			team = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Identifier="); ok {
			ident = strings.TrimSpace(v)
		}
	}
	if ident != BundleID {
		return "", fmt.Errorf("the notification app is signed as %.64q, not %s", ident, BundleID)
	}
	if !teamRe.MatchString(team) {
		return "", errors.New("the notification app is not signed with a Developer ID Team ID")
	}
	if want != "" && team != want {
		return "", fmt.Errorf("the notification app is signed by Team ID %s, not %s pinned at install", team, want)
	}
	return team, nil
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return plain(s, 200)
}

// Digest hashes every file of the bundle at app (paths, modes and contents),
// so bordercheck can tell it is the bundle it installed. Links and other
// special files are refused.
func Digest(app string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(app, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(app, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			fmt.Fprintf(h, "d %s\n", filepath.ToSlash(rel))
			return nil
		case !info.Mode().IsRegular():
			return fmt.Errorf("%s in the notification app is not a regular file", rel)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		fh := sha256.New()
		if _, err := io.Copy(fh, f); err != nil {
			return err
		}
		fmt.Fprintf(h, "f %s %o %x\n", filepath.ToSlash(rel), info.Mode().Perm()&0o111, fh.Sum(nil))
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// InstallZip unpacks the helper archive into dir, replacing the helper there,
// once its signature passes verify (with pinned Team ID teamID, if not "").
// It returns the Team ID and the bundle's Digest. Entries outside
// "Bordercheck.app/", links, absolute or ".." paths, and archives over the
// size limits are refused; nothing is replaced unless all is well.
func InstallZip(ctx context.Context, dir string, data []byte, verify Verifier, teamID string) (team, digest string, err error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", "", errors.New("the notification app archive is not a zip file")
	}
	if len(zr.File) > maxFiles {
		return "", "", errors.New("the notification app archive has too many files")
	}
	staging := filepath.Join(dir, ".notifier-new")
	if err := os.RemoveAll(staging); err != nil {
		return "", "", err
	}
	defer os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return "", "", err
	}
	var total int64
	for _, f := range zr.File {
		name := f.Name
		if strings.Contains(name, `\`) || path.IsAbs(name) || slices.Contains(strings.Split(name, "/"), "..") {
			return "", "", fmt.Errorf("the notification app archive has a bad path %.80q", name)
		}
		clean := path.Clean(name)
		if clean != AppName && !strings.HasPrefix(clean, AppName+"/") {
			return "", "", fmt.Errorf("the notification app archive has %.80q outside %s", name, AppName)
		}
		mode := f.Mode()
		dst := filepath.Join(staging, filepath.FromSlash(clean))
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return "", "", err
			}
			continue
		case !mode.IsRegular():
			return "", "", fmt.Errorf("the notification app archive has a link or special file %.80q", name)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return "", "", err
		}
		perm := os.FileMode(0o644)
		if mode.Perm()&0o111 != 0 {
			perm = 0o755
		}
		rc, err := f.Open()
		if err != nil {
			return "", "", err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			rc.Close()
			return "", "", err
		}
		n, err := io.Copy(out, io.LimitReader(rc, maxUnpacked-total+1))
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return "", "", err
		}
		if total += n; total > maxUnpacked {
			return "", "", errors.New("the notification app archive unpacks too large")
		}
	}
	app := filepath.Join(staging, AppName)
	if st, err := os.Stat(filepath.Join(app, "Contents", "Info.plist")); err != nil || !st.Mode().IsRegular() {
		return "", "", errors.New("the notification app archive has no " + AppName)
	}
	if team, err = verify(ctx, app, teamID); err != nil {
		return "", "", err
	}
	if teamID != "" && team != teamID {
		return "", "", fmt.Errorf("the notification app is signed by Team ID %s, not %s pinned at install", team, teamID)
	}
	if digest, err = Digest(app); err != nil {
		return "", "", err
	}
	old := filepath.Join(dir, ".notifier-old")
	_ = os.RemoveAll(old)
	if err := os.Rename(Path(dir), old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", "", err
	}
	if err := os.Rename(app, Path(dir)); err != nil {
		_ = os.Rename(old, Path(dir))
		return "", "", err
	}
	_ = os.RemoveAll(old)
	return team, digest, nil
}

// Helper is an installed helper and how to run it.
type Helper struct {
	Dir    string // install folder
	TeamID string // pinned when it was first installed
	Digest string // recorded when it was installed
	Run    Runner
	Verify Verifier
}

// Ready reports whether a helper was installed and recorded, without checking it.
func (h Helper) Ready() bool { return h.TeamID != "" && h.Digest != "" && Installed(h.Dir) }

// Status asks the helper whether bordercheck's notifications are allowed. It never asks the person.
func (h Helper) Status(ctx context.Context) (Status, error) { return h.run(ctx, ModeStatus, nil) }

// Authorize lets macOS ask the person, if it never has, and returns their
// answer. Only for a person at the terminal.
func (h Helper) Authorize(ctx context.Context) (Status, error) { return h.run(ctx, ModeAuthorize, nil) }

// Post shows r if bordercheck's notifications are allowed: Posted, else
// Denied or NotDetermined and nothing is shown. It never asks the person.
func (h Helper) Post(ctx context.Context, r Request) (Status, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return h.run(ctx, ModePost, data)
}

// run checks the bundle is the one installed (Digest) and its signature,
// then runs it in mode with request (if any) as its stdin.
func (h Helper) run(ctx context.Context, mode Mode, request []byte) (Status, error) {
	if mode != ModeStatus && mode != ModeAuthorize && mode != ModePost {
		return "", fmt.Errorf("unknown notification app mode %q", mode)
	}
	app := Path(h.Dir)
	st, err := os.Lstat(app)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && (h.TeamID == "" || h.Digest == "")) {
		return "", ErrNotInstalled
	}
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a folder", app)
	}
	if d, err := Digest(app); err != nil || d != h.Digest {
		return "", errors.New("BorderCheck's notification app has changed since BorderCheck installed it; not running it (run bordercheck notifications to reinstall it)")
	}
	if _, err := h.Verify(ctx, app, h.TeamID); err != nil {
		return "", err
	}
	in := os.DevNull
	if request != nil {
		// Readable by this user only, in the install folder (itself 0700),
		// and gone once the app has quit.
		f, err := os.CreateTemp(h.Dir, ".notifier-in-*")
		if err != nil {
			return "", err
		}
		in = f.Name()
		defer os.Remove(in)
		_, err = f.Write(request)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return "", err
		}
	}
	f, err := os.CreateTemp(h.Dir, ".notifier-out-*")
	if err != nil {
		return "", err
	}
	out := f.Name()
	f.Close()
	defer os.Remove(out)
	rctx, cancel := context.WithTimeout(ctx, Timeout(mode))
	defer cancel()
	if err := h.Run(rctx, app, mode, in, out); err != nil {
		if rctx.Err() != nil {
			return "", fmt.Errorf("BorderCheck's notification app did not answer within %s", Timeout(mode))
		}
		return "", err
	}
	data, err := readLimited(out, MaxAnswer+1)
	if err != nil {
		return "", err
	}
	return Parse(mode, data)
}

func readLimited(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// ReadCapped reads the file p, refusing one over limit bytes.
func ReadCapped(p string, limit int64) ([]byte, error) {
	data, err := readLimited(p, limit+1)
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("%s is larger than %d bytes", p, limit)
	}
	return data, err
}
