// Package policy holds an organisation's rules for bordercheck. A policy file
// only needs the fields it changes; everything else keeps the built-in default.
// Lists in a policy file replace the default list rather than adding to it.
package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

type Policy struct {
	Name   string `json:"name"`
	Report Report `json:"report"`
	Update Update `json:"update"`
	Notify Notify `json:"notify"` // desktop notifications, see notify.go

	// Waivers exempt one machine from one check until a date; see waiver.go.
	Waivers []Waiver `json:"waivers"`

	Checks Checks `json:"checks"`
}

// Update keeps an installed bordercheck and its policy current.
type Update struct {
	Binary    bool   `json:"binary"`     // install newer releases whose SHA256SUMS is signed by the trusted key
	PolicyURL string `json:"policy_url"` // HTTPS URL this policies.json is refreshed from before each report
	Interval  string `json:"interval"`   // how often to look for a newer binary, e.g. "24h"
	// Repo and PublicKey decide what code may run, so an installed bordercheck
	// keeps the values it was installed with; a policy fetched from PolicyURL
	// cannot change them.
	Repo      string `json:"repo"`       // GitHub owner/name
	PublicKey string `json:"public_key"` // base64 ed25519 key that signs SHA256SUMS; "" = the official key
}

// Every returns the interval between binary update checks.
func (u Update) Every() time.Duration {
	d, _ := time.ParseDuration(u.Interval)
	return d
}

// Report says where an installed bordercheck sends its reports.
type Report struct {
	URL      string            `json:"url"`      // HTTPS endpoint that receives a POST of the JSON report
	Headers  map[string]string `json:"headers"`  // e.g. a token that can only submit reports
	Interval string            `json:"interval"` // Go duration between reports, e.g. "24h"
	// CheckInterval makes the service check the machine more often than it
	// reports, e.g. "24h" with a weekly report: the person at the machine hears
	// about a new problem within a day, IT gets one report a week. "" = check
	// only when a report is due.
	CheckInterval   string   `json:"check_interval"`
	IncludeEvidence bool     `json:"include_evidence"` // send file paths, ports, etc., not just pass/fail
	EmailDomains    []string `json:"email_domains"`    // if set, the user's email must be in one of these
	// IncludeIPs adds the machine's own interface addresses (host.ips) to the
	// installed service's report; IncludeLocation adds a device position
	// (location) where the OS can give one without a prompt. Both off by default.
	IncludeIPs      bool `json:"include_ips"`
	IncludeLocation bool `json:"include_location"`
}

// Every returns the interval between reports.
func (r Report) Every() time.Duration {
	d, _ := time.ParseDuration(r.Interval)
	return d
}

// CheckEvery returns the interval between checks: CheckInterval, or the
// report interval when it is not set.
func (r Report) CheckEvery() time.Duration {
	if d, err := time.ParseDuration(r.CheckInterval); err == nil && r.CheckInterval != "" {
		return d
	}
	return r.Every()
}

type Checks struct {
	Firewall       Firewall  `json:"firewall"`
	DiskEncryption Common    `json:"disk-encryption"`
	Listeners      Listeners `json:"listeners"`
	Tailscale      Common    `json:"tailscale"`
	Docker         Docker    `json:"docker"`
	Secrets        Secrets   `json:"secrets"`
	SSHKeys        SSHKeys   `json:"ssh-keys"`
	Tunnels        Tunnels   `json:"tunnels"`
	AIAgents       AIAgents  `json:"ai-agents"`

	CrackedSoftware CrackedSoftware `json:"cracked-software"`

	OSUpdates    OSUpdates    `json:"os-updates"`
	ScreenLock   ScreenLock   `json:"screen-lock"`
	RemoteAccess RemoteAccess `json:"remote-access"`
}

// Common is what every check accepts.
type Common struct {
	Enabled *bool `json:"enabled,omitempty"`
	// OnProblem, when set to "fail" or "warn", replaces the status of any problem
	// the check finds, e.g. "fail" to make open ports block compliance.
	OnProblem check.Status `json:"on_problem,omitempty"`
}

func (c Common) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

type Firewall struct {
	Common
	RequireStealth *bool `json:"require_stealth,omitempty"` // macOS stealth mode
	// SuggestOutbound warns (low) on macOS or Windows when nothing controls
	// which apps connect out, and suggests a free outbound firewall (LuLu,
	// simplewall).
	SuggestOutbound bool `json:"suggest_outbound"`
}

type Listeners struct {
	Common
	Allow []ListenerRule `json:"allow"`
}

// ListenerRule allows a process to listen beyond localhost, on one port or, with
// Port empty, on any.
type ListenerRule struct {
	Process string `json:"process"`
	Port    string `json:"port,omitempty"`
}

// UnmarshalJSON starts from an empty rule. Without it, decoding a policy's list
// over the default list reuses the default elements, so a rule missing
// "process" would inherit the default's.
func (r *ListenerRule) UnmarshalJSON(b []byte) error {
	type plain ListenerRule
	var v plain
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	*r = ListenerRule(v)
	return nil
}

type Docker struct {
	Common
	AllowContainers []string `json:"allow_containers"` // names exempt from every Docker rule
	AllowMounts     []string `json:"allow_mounts"`     // host paths that may be mounted, ~ allowed
}

type Secrets struct {
	Common
	ExtraFiles         []string        `json:"extra_files"`  // more files to scan, ~ allowed
	IgnorePaths        []string        `json:"ignore_paths"` // globs on the shown path: * one level, ** any depth
	ProductionKeywords []string        `json:"production_keywords"`
	ShowTail           *bool           `json:"show_tail,omitempty"` // last 4 characters of provider tokens
	WalkDepth          int             `json:"walk_depth"`          // folders below home searched for .env and key files
	ExtraPatterns      []SecretPattern `json:"extra_patterns"`      // the org's own token formats
	Locations          SecretLocations `json:"locations"`           // credential stores read with format-aware rules
}

// SecretLocations switches each well-known credential store on or off.
type SecretLocations struct {
	Docker         bool `json:"docker"`          // ~/.docker/config.json inline auths (credsStore/credHelpers are fine)
	Kube           bool `json:"kube"`            // ~/.kube/config inline tokens, passwords, client-key-data
	Netrc          bool `json:"netrc"`           // ~/.netrc, ~/_netrc
	GitCredentials bool `json:"git_credentials"` // ~/.git-credentials and credential.helper=store
	GCloud         bool `json:"gcloud"`          // application default credentials, credential DBs
	Azure          bool `json:"azure"`           // Azure CLI plain-text token caches
	PyPI           bool `json:"pypirc"`          // ~/.pypirc passwords
	GitHubCLI      bool `json:"gh"`              // gh hosts.yml token (absent when gh uses the OS keychain)
	Terraform      bool `json:"terraform"`       // ~/.terraform.d/credentials.tfrc.json
	PgPass         bool `json:"pgpass"`          // ~/.pgpass
	MySQL          bool `json:"mysql"`           // ~/.my.cnf
}

// SSHKeys judges the SSH keys in ~/.ssh and those named by ~/.ssh/config.
type SSHKeys struct {
	Common
	NoPassphrase     bool     `json:"no_passphrase"`     // private keys stored without a passphrase
	LoosePermissions bool     `json:"loose_permissions"` // private keys other users can read (macOS, Linux)
	AuthorizedKeys   bool     `json:"authorized_keys"`   // keys that can log in to this machine
	AllowKeys        []string `json:"allow_keys"`        // globs on the shown path (~/.ssh/deploy_key) exempt from every rule
}

// TunnelTools are the names tunnels.allow and tunnels.lower_severity accept.
var TunnelTools = []string{"tailscale-funnel", "tailscale-serve", "ngrok", "cloudflared", "localtunnel", "bore",
	"frp", "zrok", "vscode-tunnel", "devtunnel", "ssh"}

// Tunnels judges software that publishes this machine by dialling out.
type Tunnels struct {
	Common
	Processes       bool     `json:"processes"`        // running tunnel clients: ngrok, cloudflared, ssh -R…
	TailscaleFunnel bool     `json:"tailscale_funnel"` // tailscale funnel: public internet
	TailscaleServe  bool     `json:"tailscale_serve"`  // tailscale serve: the tailnet
	Allow           []string `json:"allow"`            // tool names (TunnelTools) that may run
	LowerSeverity   []string `json:"lower_severity"`   // tools the org recommends: low severity, medium if open to anyone
}

// AIAgents judges AI coding-agent and MCP config files.
type AIAgents struct {
	Common
	Tokens      bool     `json:"tokens"`       // plain-text tokens and API keys in MCP / agent configs
	Guardrails  bool     `json:"guardrails"`   // agents set to skip approvals or run unsandboxed
	ExtraPaths  []string `json:"extra_paths"`  // more config files to scan for tokens, ~ allowed
	IgnorePaths []string `json:"ignore_paths"` // globs on the shown path
}

// CrackedSoftware looks for traces of cracked paid software (Adobe, Autodesk,
// Windows and Microsoft Office activation).
type CrackedSoftware struct {
	Common
	SuggestAlternatives bool `json:"suggest_alternatives"` // the fix names free, open-source replacements
}

type SecretPattern struct {
	Kind     string `json:"kind"`
	Regex    string `json:"regex"`
	High     bool   `json:"high,omitempty"`      // a match fails the check
	ShowTail bool   `json:"show_tail,omitempty"` // safe only for long random tokens
}

// OSUpdates judges the OS and browsers from what the machine already knows, with
// no network: day limits of 0 turn that rule off.
type OSUpdates struct {
	Common
	// MinOSVersions maps "macos", "windows" (a build number such as "26100") or a
	// Linux os-release ID ("ubuntu", "debian", "fedora"…) to the oldest version
	// allowed. Keys merge with the defaults; "" removes a minimum.
	MinOSVersions      map[string]string `json:"min_os_versions"`
	RequireAutoUpdate  *bool             `json:"require_auto_update,omitempty"` // the OS checks for and installs security updates by itself
	MaxCheckAgeDays    int               `json:"max_check_age_days"`            // days since the OS last checked for updates
	MaxPendingDays     int               `json:"max_pending_days"`              // days an update the OS has found may wait to be installed
	MaxDaysSinceUpdate int               `json:"max_days_since_update"`         // Windows and Linux: days since an OS update was last installed
	CheckBrowsers      *bool             `json:"check_browsers,omitempty"`      // Chrome, Edge, Firefox, Brave
	MaxBrowserAgeDays  int               `json:"max_browser_age_days"`          // days since the installed browser build landed on disk
	MinBrowserVersions map[string]string `json:"min_browser_versions"`          // "chrome", "edge", "firefox", "brave" → oldest version allowed
}

type ScreenLock struct {
	Common
	RequirePassword *bool `json:"require_password,omitempty"` // a password is needed after sleep or the screen saver
	MaxLockMinutes  int   `json:"max_lock_minutes"`           // the screen must lock after at most this many idle minutes; 0 = don't check
}

// RemoteAccessServices are the names RemoteAccess.Allow accepts.
var RemoteAccessServices = []string{"ssh", "screen-sharing", "remote-management", "remote-apple-events", "rdp", "winrm", "guest"}

type RemoteAccess struct {
	Common
	Allow []string `json:"allow"` // services from RemoteAccessServices that may be on
}

func ptr[T any](v T) *T { return &v }

// Default is the built-in policy.
func Default() Policy {
	return Policy{
		Name:   "built-in",
		Report: Report{Headers: map[string]string{}, Interval: "24h", EmailDomains: []string{}, IncludeIPs: false, IncludeLocation: false},
		Update: Update{Interval: "24h", Repo: "ptrinh/bordercheck"},
		Notify: defaultNotify(),

		Waivers: []Waiver{},

		Checks: Checks{
			Firewall: Firewall{RequireStealth: ptr(true), SuggestOutbound: true},
			Listeners: Listeners{Allow: []ListenerRule{
				{Process: "rapportd"}, // Apple Handoff/Continuity
			}},
			Docker: Docker{AllowContainers: []string{}, AllowMounts: []string{}},
			Secrets: Secrets{
				ExtraFiles:         []string{},
				IgnorePaths:        []string{},
				ExtraPatterns:      []SecretPattern{},
				ProductionKeywords: []string{"prod", "production", "live"},
				ShowTail:           ptr(true),
				WalkDepth:          5,
				Locations: SecretLocations{Docker: true, Kube: true, Netrc: true, GitCredentials: true, GCloud: true,
					Azure: true, PyPI: true, GitHubCLI: true, Terraform: true, PgPass: true, MySQL: true},
			},
			OSUpdates: OSUpdates{
				MinOSVersions:     map[string]string{"macos": "15", "windows": "26100", "ubuntu": "22.04", "debian": "12", "fedora": "43"},
				RequireAutoUpdate: ptr(true), MaxCheckAgeDays: 14, MaxPendingDays: 14, MaxDaysSinceUpdate: 45,
				CheckBrowsers: ptr(true), MaxBrowserAgeDays: 60, MinBrowserVersions: map[string]string{},
			},
			ScreenLock: ScreenLock{RequirePassword: ptr(true), MaxLockMinutes: 10},
			// A guest account is accepted unless a policy says otherwise: on macOS it
			// is a sandboxed, throw-away session.
			RemoteAccess: RemoteAccess{Allow: []string{"guest"}},
			SSHKeys:      SSHKeys{NoPassphrase: true, LoosePermissions: true, AuthorizedKeys: true, AllowKeys: []string{}},
			Tunnels: Tunnels{Processes: true, TailscaleFunnel: true, TailscaleServe: true, Allow: []string{},
				LowerSeverity: []string{"cloudflared"}},
			AIAgents:        AIAgents{Tokens: true, Guardrails: true, ExtraPaths: []string{}, IgnorePaths: []string{}},
			CrackedSoftware: CrackedSoftware{SuggestAlternatives: true},
		},
	}
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// ValidRepo reports whether s looks like a GitHub owner/name.
func ValidRepo(s string) bool { return repoRe.MatchString(s) }

// FileName is the policy file bordercheck looks for next to its binary.
const FileName = "policies.json"

// NextToBinary returns the policies.json beside the running binary, also
// checking beside the symlink's target (Homebrew), or "" if there is none.
func NextToBinary() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dirs := []string{filepath.Dir(exe)}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		dirs = append(dirs, filepath.Dir(real))
	}
	for _, d := range dirs {
		if p := filepath.Join(d, FileName); fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// Load reads a policy file; see Parse.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	return Parse(data, path)
}

// Parse reads a policy on top of Default. Unknown fields are errors, so a typo
// cannot silently turn a rule off. source names the policy in errors, and in
// reports when the policy has no name.
func Parse(data []byte, source string) (Policy, error) {
	p := Default()
	p.Name = ""
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", source, err)
	}
	if p.Name == "" {
		p.Name = source
	}
	if err := p.validate(); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", source, err)
	}
	return p, nil
}

func (p Policy) validate() error {
	if u := p.Report.URL; u != "" {
		parsed, err := url.Parse(u)
		local := err == nil && parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")
		if err != nil || (parsed.Scheme != "https" && !local) || parsed.Host == "" {
			return fmt.Errorf("report.url must be an https:// URL, not %q", u)
		}
	}
	if d, err := time.ParseDuration(p.Report.Interval); err != nil || d < 15*time.Minute {
		return fmt.Errorf("report.interval must be a duration of at least 15m, like \"24h\", not %q", p.Report.Interval)
	}
	if ci := p.Report.CheckInterval; ci != "" {
		d, err := time.ParseDuration(ci)
		if err != nil || d < 15*time.Minute {
			return fmt.Errorf("report.check_interval must be a duration of at least 15m, like \"24h\", or \"\", not %q", ci)
		}
		if d > p.Report.Every() {
			return fmt.Errorf("report.check_interval (%s) must not be longer than report.interval (%s)", ci, p.Report.Interval)
		}
	}
	u := p.Update
	if u.PolicyURL != "" && !strings.HasPrefix(u.PolicyURL, "https://") {
		return fmt.Errorf("update.policy_url must be an https:// URL, not %q", u.PolicyURL)
	}
	if d, err := time.ParseDuration(u.Interval); err != nil || d < time.Hour {
		return fmt.Errorf("update.interval must be a duration of at least 1h, like \"24h\", not %q", u.Interval)
	}
	if !repoRe.MatchString(u.Repo) {
		return fmt.Errorf("update.repo must look like owner/name, not %q", u.Repo)
	}
	if u.PublicKey != "" {
		if raw, err := base64.StdEncoding.DecodeString(u.PublicKey); err != nil || len(raw) != 32 {
			return errors.New("update.public_key must be a base64 ed25519 public key")
		}
	}
	if err := p.Notify.validate(); err != nil {
		return err
	}
	if err := validateWaivers(p.Waivers, now()); err != nil {
		return err
	}
	c := p.Checks
	for id, on := range map[string]check.Status{
		"firewall": c.Firewall.OnProblem, "disk-encryption": c.DiskEncryption.OnProblem,
		"listeners": c.Listeners.OnProblem, "tailscale": c.Tailscale.OnProblem,
		"docker": c.Docker.OnProblem, "secrets": c.Secrets.OnProblem,
		"os-updates": c.OSUpdates.OnProblem, "screen-lock": c.ScreenLock.OnProblem, "remote-access": c.RemoteAccess.OnProblem,
		"ssh-keys": c.SSHKeys.OnProblem, "tunnels": c.Tunnels.OnProblem, "ai-agents": c.AIAgents.OnProblem,
		"cracked-software": c.CrackedSoftware.OnProblem,
	} {
		if on != "" && on != check.Fail && on != check.Warn {
			return fmt.Errorf("checks.%s.on_problem must be \"fail\" or \"warn\", not %q", id, on)
		}
	}
	for _, r := range c.Listeners.Allow {
		if r.Process == "" {
			return errors.New("checks.listeners.allow: every rule needs a process")
		}
	}
	s := c.Secrets
	if len(s.ProductionKeywords) == 0 {
		return errors.New("checks.secrets.production_keywords must not be empty")
	}
	if s.WalkDepth < 0 || s.WalkDepth > 20 {
		return errors.New("checks.secrets.walk_depth must be between 0 and 20")
	}
	for _, g := range s.IgnorePaths {
		if _, err := Glob(g); err != nil {
			return fmt.Errorf("checks.secrets.ignore_paths %q: %w", g, err)
		}
	}
	for _, sp := range s.ExtraPatterns {
		if sp.Kind == "" {
			return errors.New("checks.secrets.extra_patterns: every pattern needs a kind")
		}
		if _, err := regexp.Compile(sp.Regex); err != nil {
			return fmt.Errorf("checks.secrets.extra_patterns %q: %w", sp.Kind, err)
		}
	}
	if err := c.OSUpdates.validate(); err != nil {
		return err
	}
	if m := c.ScreenLock.MaxLockMinutes; m < 0 || m > 240 {
		return errors.New("checks.screen-lock.max_lock_minutes must be between 0 and 240")
	}
	for _, s := range c.RemoteAccess.Allow {
		if !slices.Contains(RemoteAccessServices, s) {
			return fmt.Errorf("checks.remote-access.allow: unknown service %q (known: %s)", s, strings.Join(RemoteAccessServices, ", "))
		}
	}
	return c.validateNew()
}

var versionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

func (o OSUpdates) validate() error {
	for name, days := range map[string]int{"max_check_age_days": o.MaxCheckAgeDays, "max_pending_days": o.MaxPendingDays,
		"max_days_since_update": o.MaxDaysSinceUpdate, "max_browser_age_days": o.MaxBrowserAgeDays} {
		if days < 0 || days > 3650 {
			return fmt.Errorf("checks.os-updates.%s must be between 0 and 3650", name)
		}
	}
	for field, m := range map[string]map[string]string{"min_os_versions": o.MinOSVersions, "min_browser_versions": o.MinBrowserVersions} {
		for k, v := range m {
			if v != "" && !versionRe.MatchString(v) {
				return fmt.Errorf("checks.os-updates.%s %q: %q is not a version like \"15\" or \"22.04\"", field, k, v)
			}
		}
	}
	for k := range o.MinBrowserVersions {
		if !slices.Contains([]string{"chrome", "edge", "firefox", "brave"}, k) {
			return fmt.Errorf("checks.os-updates.min_browser_versions: unknown browser %q (known: chrome, edge, firefox, brave)", k)
		}
	}
	return nil
}

func (c Checks) validateNew() error {
	for field, globs := range map[string][]string{
		"ssh-keys.allow_keys": c.SSHKeys.AllowKeys, "ai-agents.ignore_paths": c.AIAgents.IgnorePaths,
	} {
		for _, g := range globs {
			if _, err := Glob(g); err != nil {
				return fmt.Errorf("checks.%s %q: %w", field, g, err)
			}
		}
	}
	for field, tools := range map[string][]string{
		"tunnels.allow": c.Tunnels.Allow, "tunnels.lower_severity": c.Tunnels.LowerSeverity,
	} {
		for _, t := range tools {
			if !slices.Contains(TunnelTools, t) {
				return fmt.Errorf("checks.%s: unknown tool %q, expected one of %s", field, t, strings.Join(TunnelTools, ", "))
			}
		}
	}
	for _, p := range c.AIAgents.ExtraPaths {
		if strings.TrimSpace(p) == "" {
			return errors.New("checks.ai-agents.extra_paths: empty path")
		}
	}
	return nil
}

func (p Policy) WriteJSON(w *os.File) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(p)
}

// Glob compiles a path glob, matched against slash-separated paths: ** matches
// any number of folders, * and ? stay within one.
func Glob(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
