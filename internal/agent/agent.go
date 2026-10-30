// Package agent installs bordercheck as a per-user service that checks the
// machine every hour and POSTs a report to the policy's report.url whenever
// report.interval has passed since the last report that got through.
//
// The install folder holds the binary, policies.json beside it, and:
//
//	config.json     the user's email and this install's ID
//	state.json      when the last report was sent, and the last error
//	bordercheck.log what each scheduled run did
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
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/report"
)

// Env is what the agent needs from outside, so tests can swap it.
type Env struct {
	Dir     string // install folder
	Version string
	Client  *http.Client
	Out     io.Writer
}

// Dir is the install folder: ~/Library/Application Support/bordercheck on macOS,
// %LOCALAPPDATA%\bordercheck on Windows.
func Dir() (string, error) {
	if runtime.GOOS == "windows" && os.Getenv("LOCALAPPDATA") != "" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "bordercheck"), nil
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
	// PolicyURL, when set, is fetched before each report so IT can change the
	// policy centrally; the last good copy stays in policies.json.
	PolicyURL string `json:"policy_url,omitempty"`
}

type State struct {
	LastSent  time.Time `json:"last_sent,omitzero"`
	LastTry   time.Time `json:"last_try,omitzero"`
	LastError string    `json:"last_error,omitempty"`
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
	Policy string    // policies.json path or https URL; "" = the one beside this binary
	Email  string    //
	In     io.Reader // where to read the email from when Email is empty
	Ask    bool      // In is a terminal, so asking is possible
}

// Install copies bordercheck and its policy into env.Dir, records the user's
// email, registers the hourly service and sends a first report right away, so
// the person installing sees at once whether reports get through.
func Install(ctx context.Context, env Env, o InstallOptions) error {
	source := o.Policy
	if source == "" {
		if source = policy.NextToBinary(); source == "" {
			return fmt.Errorf("no %s beside this binary; get it from your IT team or pass -policy", policy.FileName)
		}
	}
	data, pol, err := readPolicy(ctx, env.Client, source)
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
	cfg.Email, cfg.PolicyURL = email, ""
	if isURL(source) {
		cfg.PolicyURL = source
	}

	bin := filepath.Join(env.Dir, binName())
	if err := copySelf(bin); err != nil {
		return fmt.Errorf("copying bordercheck to %s: %w", env.Dir, err)
	}
	if err := writeFile(filepath.Join(env.Dir, policy.FileName), data, 0o600); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(env.Dir, "config.json"), cfg); err != nil {
		return err
	}
	if err := registerService(bin, env.Dir); err != nil {
		return fmt.Errorf("registering the hourly service: %w", err)
	}
	fmt.Fprintf(env.Out, "Installed in %s for %s.\nChecking every hour; reporting every %s to %s.\n\n",
		env.Dir, email, pol.Report.Interval, hostOf(pol.Report.URL))
	return Send(ctx, env, true)
}

// Uninstall removes the service and the install folder.
func Uninstall(env Env) error {
	err := unregisterService()
	for _, name := range []string{"config.json", "state.json", "bordercheck.log", policy.FileName, binName()} {
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
		return fmt.Errorf("bordercheck is not installed (%w); run: bordercheck install", err)
	}
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)

	pol, err := currentPolicy(ctx, env, cfg)
	if err != nil {
		return err
	}
	if pol.Report.URL == "" {
		return errors.New("the policy has no report.url")
	}
	now := time.Now()
	if !force && now.Sub(st.LastSent) < pol.Report.Every() {
		fmt.Fprintf(env.Out, "%s next report due %s\n", now.Format(time.RFC3339),
			st.LastSent.Add(pol.Report.Every()).Format(time.RFC3339))
		return nil
	}

	rep := report.New(env.Version, pol.Name, check.RunAll(ctx, checks.All(pol)))
	rep.Email, rep.InstallID = cfg.Email, cfg.InstallID
	if !pol.Report.IncludeEvidence {
		for i := range rep.Results {
			rep.Results[i].Evidence = nil
		}
	}
	st.LastTry = now
	err = post(ctx, env, pol.Report, rep)
	if err != nil {
		st.LastError = err.Error()
		fmt.Fprintf(env.Out, "%s report failed: %v\n", now.Format(time.RFC3339), err)
	} else {
		st.LastSent, st.LastError = now, ""
		c := rep.Counts
		fmt.Fprintf(env.Out, "%s report sent to %s: %d fail, %d warn, %d pass\n",
			now.Format(time.RFC3339), hostOf(pol.Report.URL), c.Fail, c.Warn, c.Pass)
	}
	return errors.Join(err, writeJSON(filepath.Join(env.Dir, "state.json"), st))
}

// Status describes the install for `bordercheck status`.
func Status(env Env) (string, error) {
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		return "", fmt.Errorf("bordercheck is not installed: %w", err)
	}
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
	pol, err := policy.Load(filepath.Join(env.Dir, policy.FileName))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Installed:  %s\nEmail:      %s\nPolicy:     %s", env.Dir, cfg.Email, pol.Name)
	if cfg.PolicyURL != "" {
		fmt.Fprintf(&b, " (from %s)", cfg.PolicyURL)
	}
	fmt.Fprintf(&b, "\nReports:    every %s to %s\nService:    %s\n", pol.Report.Interval, hostOf(pol.Report.URL), serviceStatus())
	if !st.LastSent.IsZero() {
		fmt.Fprintf(&b, "Last sent:  %s\n", st.LastSent.Format(time.RFC1123))
	}
	if st.LastError != "" {
		fmt.Fprintf(&b, "Last error: %s (%s)\n", st.LastError, st.LastTry.Format(time.RFC1123))
	}
	return b.String(), nil
}

// currentPolicy refreshes policies.json from PolicyURL when there is one, and
// falls back to the last good copy if the fetch fails.
func currentPolicy(ctx context.Context, env Env, cfg Config) (policy.Policy, error) {
	path := filepath.Join(env.Dir, policy.FileName)
	if cfg.PolicyURL != "" {
		data, pol, err := readPolicy(ctx, env.Client, cfg.PolicyURL)
		if err == nil {
			return pol, writeFile(path, data, 0o600)
		}
		fmt.Fprintf(env.Out, "%s using the saved policy: %v\n", time.Now().Format(time.RFC3339), err)
	}
	return policy.Load(path)
}

func isURL(s string) bool { return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") }

// readPolicy reads a policy from a file or an https URL.
func readPolicy(ctx context.Context, client *http.Client, source string) ([]byte, policy.Policy, error) {
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
		resp, err := client.Do(req)
		if err != nil {
			return nil, policy.Policy{}, err
		}
		defer resp.Body.Close()
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

// post sends the report. Errors name the host only, never the headers, which
// may hold a token.
func post(ctx context.Context, env Env, r policy.Report, rep report.Report) error {
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bordercheck/"+env.Version)
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	resp, err := env.Client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("posting to %s: %w", hostOf(r.URL), err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %s", hostOf(r.URL), resp.Status)
	}
	return nil
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
