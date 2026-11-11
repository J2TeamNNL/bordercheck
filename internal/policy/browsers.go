package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
)

// BrowserIDs are the browsers the extensions and browser-passwords checks know.
var BrowserIDs = []string{"chrome", "edge", "brave", "chromium", "vivaldi", "arc", "firefox"}

// Extensions judges browser and code-editor extensions.
type Extensions struct {
	Common
	Browsers bool `json:"browsers"` // Chrome, Edge, Brave, Chromium, Vivaldi, Arc, Firefox
	Editors  bool `json:"editors"`  // VS Code, VS Code Insiders, Cursor, Windsurf, VSCodium
	// Block fails on these extensions: browser extension IDs, or publisher.name
	// for editors. * matches any run of characters.
	Block []string `json:"block"`
	// Allow, when not empty, warns on every extension not on it (allowlist mode).
	Allow []string `json:"allow"`
	// WarnAllSites warns on browser extensions that can read and change every
	// site; otherwise they are only counted.
	WarnAllSites bool `json:"warn_all_sites"`
	// AllowUnpacked are extensions that may come from outside a store.
	AllowUnpacked []string `json:"allow_unpacked"`
}

// BrowserPasswords judges the browsers' own password saving.
type BrowserPasswords struct {
	Common
	// AllowBrowsers are browsers (BrowserIDs) whose password manager the
	// organisation uses on purpose.
	AllowBrowsers []string `json:"allow_browsers"`
}

// TrustStore judges added root certificates and the system proxy.
type TrustStore struct {
	Common
	CAs     bool `json:"cas"`     // root certificates added by the user or an admin
	Proxies bool `json:"proxies"` // a system proxy, PAC file or proxy environment variable
	// AllowCAs are certificates that may be trusted: a SHA-256 fingerprint
	// (hex, colons optional) or a glob on the subject common name.
	AllowCAs []string `json:"allow_cas"`
	// AllowProxies are globs on the proxy host (or PAC URL host).
	AllowProxies []string `json:"allow_proxies"`
	// CASeverity is the severity of an added root certificate.
	CASeverity check.Severity `json:"ca_severity"`
}

func (c Checks) validateBrowserChecks() error {
	for field, list := range map[string][]string{
		"extensions.block": c.Extensions.Block, "extensions.allow": c.Extensions.Allow,
		"extensions.allow_unpacked": c.Extensions.AllowUnpacked,
		"trust-store.allow_cas":     c.TrustStore.AllowCAs, "trust-store.allow_proxies": c.TrustStore.AllowProxies,
	} {
		for _, s := range list {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("checks.%s: empty entry", field)
			}
			if _, err := Glob(s); err != nil {
				return fmt.Errorf("checks.%s %q: %w", field, s, err)
			}
		}
	}
	for _, b := range c.BrowserPasswords.AllowBrowsers {
		if !slices.Contains(BrowserIDs, b) {
			return fmt.Errorf("checks.browser-passwords.allow_browsers: unknown browser %q (known: %s)", b, strings.Join(BrowserIDs, ", "))
		}
	}
	switch c.TrustStore.CASeverity {
	case check.Low, check.Medium, check.High:
	default:
		return errors.New(`checks.trust-store.ca_severity must be "low", "medium" or "high"`)
	}
	return nil
}
