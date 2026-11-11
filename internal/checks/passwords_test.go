package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func TestChromiumPasswordFacts(t *testing.T) {
	p := browserProfile{ID: "chrome", Name: "Chrome", Profile: "Default"}
	for _, tc := range []struct {
		prefs          string
		sizes          map[string]int64
		saving, stored bool
	}{
		{`{}`, map[string]int64{"Login Data": 40960, "Login Data For Account": 40960}, true, false},
		{`{"credentials_enable_service": false}`, map[string]int64{"Login Data": 40960}, false, false},
		{`{"credentials_enable_service": true}`, map[string]int64{"Login Data": 98304}, true, true},
		{`{"credentials_enable_service": false}`, map[string]int64{"Login Data For Account": 49152}, false, true},
		{`not json`, nil, true, false},
	} {
		r := chromiumPasswordFacts(p, []byte(tc.prefs), tc.sizes)
		if r.Saving != tc.saving || r.Stored != tc.stored || r.Label != "Chrome (Default)" {
			t.Errorf("%s %v: got %+v", tc.prefs, tc.sizes, r)
		}
	}
}

func TestFirefoxPasswords(t *testing.T) {
	// Field names as in a real logins.json; the values are made up and must
	// never reach the result.
	logins := `{"nextId": 3, "logins": [
	  {"id": 1, "hostname": "https://secret-intranet.example.com", "encryptedUsername": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECA==",
	   "encryptedPassword": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECB==", "usernameField": "alice.smith"},
	  {"id": 2, "hostname": "https://bank.example.net", "encryptedUsername": "x", "encryptedPassword": "y"}
	], "potentiallyVulnerablePasswords": [], "version": 3}`
	if n := countFirefoxLogins(strings.NewReader(logins)); n != 2 {
		t.Fatalf("count = %d", n)
	}
	if n := countFirefoxLogins(strings.NewReader(`{"logins": []}`)); n != 0 {
		t.Errorf("empty: %d", n)
	}
	p := browserProfile{ID: "firefox", Name: "Firefox", Profile: "ab12.default-release", Firefox: true}
	off := "user_pref(\"browser.startup.page\", 3);\nuser_pref(\"signon.rememberSignons\", false);\n"
	if r := firefoxPasswordFacts(p, []byte(off), 0); r.Saving || r.Stored {
		t.Errorf("off: %+v", r)
	}
	if r := firefoxPasswordFacts(p, []byte("user_pref(\"signon.rememberSignons\", true);\n"), 2); !r.Saving || !r.Stored ||
		r.Details != "2 saved logins in logins.json; Ask to save passwords is on" {
		t.Errorf("on: %+v", r)
	}
	if r := firefoxPasswordFacts(p, nil, 0); !r.Saving {
		t.Errorf("default must be on: %+v", r)
	}

	res := evalBrowserPasswords([]pwProfile{firefoxPasswordFacts(p, nil, countFirefoxLogins(strings.NewReader(logins)))},
		policy.Default().Checks.BrowserPasswords)
	for _, bad := range []string{"secret-intranet", "bank.example", "alice", "MDoE"} {
		if strings.Contains(strings.Join(append(res.Evidence, res.Summary, res.Fix), "\n"), bad) {
			t.Errorf("result shows %q", bad)
		}
	}
}

func TestEvalBrowserPasswords(t *testing.T) {
	def := policy.Default().Checks.BrowserPasswords
	if r := evalBrowserPasswords(nil, def); r.Status != check.Skip {
		t.Errorf("none: %+v", r)
	}
	chromeOff := pwProfile{ID: "chrome", Name: "Chrome", Label: "Chrome (Default)", Details: "x"}
	chromeOn := pwProfile{ID: "chrome", Name: "Chrome", Label: "Chrome (Profile 1)", Saving: true, Details: "x"}
	edgeStored := pwProfile{ID: "edge", Name: "Edge", Label: "Edge (Default)", Saving: true, Stored: true, Details: "x"}
	ffStored := pwProfile{ID: "firefox", Name: "Firefox", Label: "Firefox (p)", Stored: true, Details: "x"}
	vivStored := pwProfile{ID: "vivaldi", Name: "Vivaldi", Label: "Vivaldi (Default)", Stored: true, Details: "x"}

	if r := evalBrowserPasswords([]pwProfile{chromeOff}, def); r.Status != check.Pass || r.Summary !=
		"No passwords are saved in the browsers, and they do not offer to save them." {
		t.Errorf("off: %+v", r)
	}
	if r := evalBrowserPasswords([]pwProfile{chromeOff, chromeOn}, def); r.Status != check.Pass ||
		!strings.Contains(r.Summary, "but Chrome still offers") || len(r.Evidence) != 1 {
		t.Errorf("saving on: %+v", r)
	}
	r := evalBrowserPasswords([]pwProfile{chromeOn, edgeStored, ffStored, vivStored}, def)
	if r.Status != check.Warn || r.Severity != check.Medium || !strings.Contains(r.Summary, "saved in Edge, Firefox, Vivaldi.") ||
		!strings.Contains(r.Fix, "Edge: Settings") || !strings.Contains(r.Fix, "Firefox: Settings") ||
		!strings.Contains(r.Fix, "Other browsers") || strings.Contains(r.Fix, "Chrome:") {
		t.Errorf("stored: %+v", r)
	}
	p := def
	p.AllowBrowsers = []string{"edge", "firefox", "vivaldi"}
	r = evalBrowserPasswords([]pwProfile{chromeOff, edgeStored, ffStored, vivStored}, p)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "Allowed by policy: Edge, Firefox, Vivaldi.") {
		t.Errorf("allowed: %+v", r)
	}
}
