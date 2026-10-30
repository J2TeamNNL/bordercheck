// Package policy holds an organisation's rules for bordercheck. A policy file
// only needs the fields it changes; everything else keeps the built-in default.
// Lists in a policy file replace the default list rather than adding to it.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

type Policy struct {
	Name   string `json:"name"`
	Report Report `json:"report"`
	Checks Checks `json:"checks"`
}

// Report says where an installed bordercheck sends its reports.
type Report struct {
	URL             string            `json:"url"`              // HTTPS endpoint that receives a POST of the JSON report
	Headers         map[string]string `json:"headers"`          // e.g. a token that can only submit reports
	Interval        string            `json:"interval"`         // Go duration between reports, e.g. "24h"
	IncludeEvidence bool              `json:"include_evidence"` // send file paths, ports, etc., not just pass/fail
	EmailDomains    []string          `json:"email_domains"`    // if set, the user's email must be in one of these
}

// Every returns the interval between reports.
func (r Report) Every() time.Duration {
	d, _ := time.ParseDuration(r.Interval)
	return d
}

type Checks struct {
	Firewall       Firewall  `json:"firewall"`
	DiskEncryption Common    `json:"disk-encryption"`
	Listeners      Listeners `json:"listeners"`
	Tailscale      Common    `json:"tailscale"`
	Docker         Docker    `json:"docker"`
	Secrets        Secrets   `json:"secrets"`
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
}

type SecretPattern struct {
	Kind     string `json:"kind"`
	Regex    string `json:"regex"`
	High     bool   `json:"high,omitempty"`      // a match fails the check
	ShowTail bool   `json:"show_tail,omitempty"` // safe only for long random tokens
}

func ptr[T any](v T) *T { return &v }

// Default is the built-in policy.
func Default() Policy {
	return Policy{
		Name:   "built-in",
		Report: Report{Headers: map[string]string{}, Interval: "24h", EmailDomains: []string{}},
		Checks: Checks{
			Firewall: Firewall{RequireStealth: ptr(true)},
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
			},
		},
	}
}

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
	c := p.Checks
	for id, on := range map[string]check.Status{
		"firewall": c.Firewall.OnProblem, "disk-encryption": c.DiskEncryption.OnProblem,
		"listeners": c.Listeners.OnProblem, "tailscale": c.Tailscale.OnProblem,
		"docker": c.Docker.OnProblem, "secrets": c.Secrets.OnProblem,
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
