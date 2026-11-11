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

// When the logins can be counted, the count decides, whatever the file's size.
func TestChromiumPasswordFactsCounted(t *testing.T) {
	p := browserProfile{ID: "chrome", Name: "Chrome", Profile: "Default"}
	big := map[string]int64{"Login Data": 40960, "Login Data For Account": 49152}
	// Deleted logins leave a large file with nothing in it.
	if r := chromiumPasswordFactsCounted(p, []byte(`{}`), big, map[string]int{"Login Data": 0, "Login Data For Account": 0}); r.Stored {
		t.Errorf("emptied databases: %+v", r)
	}
	// A few logins fit in a file of the empty size.
	r := chromiumPasswordFactsCounted(p, []byte(`{}`), big, map[string]int{"Login Data": 3, "Login Data For Account": 0})
	if !r.Stored || !strings.Contains(r.Details, "Login Data holds 3 saved login(s)") || strings.Contains(r.Details, "For Account") {
		t.Errorf("three logins: %+v", r)
	}
	// One that could not be counted falls back to its size.
	r = chromiumPasswordFactsCounted(p, []byte(`{}`), big, map[string]int{"Login Data": 0})
	if !r.Stored || !strings.Contains(r.Details, "Login Data For Account is 48 KB") {
		t.Errorf("uncounted: %+v", r)
	}
}

// Fewer than pass_below per profile is no finding; up to medium_above is low; more is medium.
func TestBrowserPasswordsByCount(t *testing.T) {
	def := policy.Default().Checks.BrowserPasswords
	prof := func(id, name string, n int) pwProfile {
		return pwProfile{ID: id, Name: name, Label: name + " (Default)", Saving: true, Stored: true, Logins: n, Details: "x"}
	}
	unknown := pwProfile{ID: "brave", Name: "Brave", Label: "Brave (Default)", Stored: true, Details: "by size"}
	for _, tc := range []struct {
		name string
		ps   []pwProfile
		st   check.Status
		sev  check.Severity
		has  string
	}{
		{"3 and 9", []pwProfile{prof("chrome", "Chrome", 3), prof("edge", "Edge", 9)}, check.Pass, "", "Chrome, Edge holds fewer than 10"},
		{"10", []pwProfile{prof("chrome", "Chrome", 10)}, check.Warn, check.Low, "No profile holds more than 20"},
		{"20 and 3", []pwProfile{prof("chrome", "Chrome", 20), prof("edge", "Edge", 3)}, check.Warn, check.Low, "Edge holds fewer than 10"},
		{"21", []pwProfile{prof("chrome", "Chrome", 21)}, check.Warn, check.Medium, "Passwords are saved in Chrome."},
		{"12 and uncounted", []pwProfile{prof("chrome", "Chrome", 12), unknown}, check.Warn, check.Medium, "Chrome, Brave"},
	} {
		r := evalBrowserPasswords(tc.ps, def)
		if r.Status != tc.st || r.Severity != tc.sev || !strings.Contains(r.Summary, tc.has) {
			t.Errorf("%s: %s %s %q", tc.name, r.Status, r.Severity, r.Summary)
		}
		// A pass has no fix, but still lists what it found.
		if tc.st == check.Pass && (r.Fix != "" || len(r.Evidence) != 2) {
			t.Errorf("%s: a pass with fix %q and evidence %q", tc.name, r.Fix, r.Evidence)
		}
	}
	// pass_below 0: any saved login counts; medium_above 0: no low tier.
	strict := def
	strict.PassBelow, strict.MediumAbove = 0, 0
	if r := evalBrowserPasswords([]pwProfile{prof("chrome", "Chrome", 1)}, strict); r.Status != check.Warn || r.Severity != check.Medium {
		t.Errorf("strict: %s %s", r.Status, r.Severity)
	}
}
