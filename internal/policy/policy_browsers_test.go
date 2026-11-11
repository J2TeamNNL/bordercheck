package policy

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
)

func TestBrowserChecksPolicy(t *testing.T) {
	d := Default().Checks
	if !d.Extensions.Browsers || !d.Extensions.Editors || d.Extensions.WarnAllSites || len(d.Extensions.Block) != 0 ||
		len(d.BrowserPasswords.AllowBrowsers) != 0 || !d.TrustStore.CAs || !d.TrustStore.Proxies || d.TrustStore.CASeverity != check.Medium {
		t.Errorf("defaults: %+v %+v %+v", d.Extensions, d.BrowserPasswords, d.TrustStore)
	}
	p, err := load(t, `{"checks": {
	  "extensions": {"editors": false, "block": ["evil.*", "abcdefghijklmnopabcdefghijklmnop"], "warn_all_sites": true},
	  "browser-passwords": {"allow_browsers": ["edge"], "on_problem": "fail"},
	  "trust-store": {"proxies": false, "allow_cas": ["Acme Corp *"], "ca_severity": "high"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Checks
	if c.Extensions.Editors || !c.Extensions.Browsers || len(c.Extensions.Block) != 2 || !c.Extensions.WarnAllSites ||
		c.BrowserPasswords.AllowBrowsers[0] != "edge" || c.BrowserPasswords.OnProblem != check.Fail ||
		c.TrustStore.Proxies || !c.TrustStore.CAs || c.TrustStore.CASeverity != check.High {
		t.Errorf("got %+v %+v %+v", c.Extensions, c.BrowserPasswords, c.TrustStore)
	}
}

func TestBrowserChecksPolicyRejects(t *testing.T) {
	for body, want := range map[string]string{
		`{"checks": {"extensions": {"block": [""]}}}`:                   "empty entry",
		`{"checks": {"extensions": {"allow_unpacked": [" "]}}}`:         "empty entry",
		`{"checks": {"extensions": {"warn_all": true}}}`:                "unknown field",
		`{"checks": {"extensions": {"on_problem": "skip"}}}`:            "on_problem",
		`{"checks": {"browser-passwords": {"allow_browsers": ["ie"]}}}`: "unknown browser",
		`{"checks": {"trust-store": {"ca_severity": "critical"}}}`:      "ca_severity",
		`{"checks": {"trust-store": {"allow_proxies": [""]}}}`:          "empty entry",
		`{"checks": {"trust-store": {"on_problem": "error"}}}`:          "on_problem",
		`{"checks": {"browser-passwords": {"allow": ["chrome"]}}}`:      "unknown field",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}
