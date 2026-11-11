package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The browser-passwords check looks at whether the browsers' own password
// saving is on and whether logins are stored there: information stealers
// take a browser's saved logins first. It never opens, parses or copies a
// Chromium login database (Login Data is only measured with stat), and from
// Firefox's logins.json it keeps only the number of entries: no site, user
// name or ciphertext is ever kept or shown.

// chromeEmptyLoginData is the size of an empty Chromium login database (ten
// 4 KB SQLite pages: its tables and indexes, measured on a current Chrome). A
// larger file almost always holds saved logins. A handful of logins can still
// fit in those pages, and deleted ones leave the file large, so this is a
// strong hint rather than a count.
const chromeEmptyLoginData = 40960

// pwProfile is what one browser profile says about saved passwords.
type pwProfile struct {
	ID      string // "chrome", "firefox"…
	Name    string // "Chrome"
	Label   string // "Chrome (Default)"
	Saving  bool   // the browser offers to save passwords
	Stored  bool   // logins are (very probably) stored
	Logins  int    // how many, when they could be counted; 0 = not known
	Details string // evidence: sizes or a count, never contents
}

func evalBrowserPasswords(ps []pwProfile, opts policy.BrowserPasswords) check.Result {
	return evalBrowserPasswordsOn("", ps, opts)
}

// evalBrowserPasswordsOn is evalBrowserPasswords for one OS: on macOS the fix
// names Apple's Passwords app, which is built in and fills in Chrome and Edge.
func evalBrowserPasswordsOn(goos string, ps []pwProfile, opts policy.BrowserPasswords) check.Result {
	if len(ps) == 0 {
		return check.SkippedMsg(msg.Of("passwords.notFound"))
	}
	var stored, saving, allowed []string
	few := true // every profile with saved logins holds fewer than opts.LowBelow
	var storedIDs []string
	var ev []string
	add := func(list []string, name string) []string {
		if !slices.Contains(list, name) {
			list = append(list, name)
		}
		return list
	}
	for _, p := range ps {
		if slices.Contains(opts.AllowBrowsers, p.ID) {
			allowed = add(allowed, p.Name)
			continue
		}
		switch {
		case p.Stored:
			if opts.LowBelow <= 0 || p.Logins <= 0 || p.Logins >= opts.LowBelow {
				few = false
			}
			stored = add(stored, p.Name)
			storedIDs = add(storedIDs, p.ID)
		case p.Saving:
			saving = add(saving, p.Name)
		default:
			continue
		}
		ev = append(ev, p.Label+": "+p.Details)
	}
	var note msg.Text
	if len(allowed) > 0 {
		note = msg.Of("passwords.allowed", "browsers", strings.Join(allowed, ", "))
	}
	if len(stored) == 0 {
		summary := msg.Of("passwords.pass")
		if len(saving) > 0 {
			summary = msg.Of("passwords.passSavingOn", "browsers", strings.Join(saving, ", "))
		}
		return check.Result{Status: check.Pass, Evidence: ev}.WithSummary(append(summary, note...))
	}
	fix := msg.Of("passwords.fix")
	if goos == "darwin" {
		fix = append(fix, msg.P("passwords.fix.mac"))
	}
	other := false
	for _, id := range storedIDs {
		if k, ok := passwordFixes[id]; ok {
			fix = append(fix, msg.P(k))
		} else {
			other = true
		}
	}
	if other {
		fix = append(fix, msg.P("passwords.fix.other"))
	}
	// A handful of saved logins per profile are rarely someone's main passwords.
	if few {
		return check.Result{Status: check.Warn, Severity: check.Low, Evidence: ev}.
			WithSummary(slices.Concat(msg.Of("passwords.stored", "browsers", strings.Join(stored, ", ")),
				msg.Of("passwords.few", "n", opts.LowBelow), note)).
			WithFix(fix)
	}
	return check.Result{Status: check.Warn, Severity: check.Medium, Evidence: ev}.
		WithSummary(append(msg.Of("passwords.stored", "browsers", strings.Join(stored, ", ")), note...)).
		WithFix(fix)
}

// passwordFixes says how to turn saving off, per browser.
var passwordFixes = map[string]string{"chrome": "passwords.fix.chrome", "edge": "passwords.fix.edge",
	"brave": "passwords.fix.brave", "firefox": "passwords.fix.firefox"}

// ---- gathering (portable: only files in the user's profile) ----

func browserPasswords(opts policy.BrowserPasswords) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		home, err := os.UserHomeDir()
		if err != nil {
			return check.Errored(err)
		}
		var ps []pwProfile
		for _, p := range browserProfiles(home, runtime.GOOS) {
			if ctx.Err() != nil {
				break
			}
			if p.Firefox {
				ps = append(ps, firefoxPasswords(p))
			} else {
				ps = append(ps, chromiumPasswords(p))
			}
		}
		return evalBrowserPasswordsOn(runtime.GOOS, ps, opts)
	}
}

func fileSize(path string) (int64, bool) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return 0, false
	}
	return st.Size(), true
}

func chromiumPasswords(p browserProfile) pwProfile {
	prefs, _ := os.ReadFile(filepath.Join(p.Dir, "Preferences"))
	sizes := map[string]int64{}
	for _, n := range []string{"Login Data", "Login Data For Account"} {
		if sz, ok := fileSize(filepath.Join(p.Dir, n)); ok {
			sizes[n] = sz
		}
	}
	// The number of rows in the logins table, where the file can be read that
	// way: its size alone cannot tell, since a file keeps its size after the
	// passwords in it are deleted.
	counts := map[string]int{}
	for n := range sizes {
		if c, err := sqliteTableRows(filepath.Join(p.Dir, n), "logins"); err == nil {
			counts[n] = c
		}
	}
	return chromiumPasswordFactsCounted(p, prefs, sizes, counts)
}

// chromiumPasswordFacts judges a Chromium profile from its Preferences
// (credentials_enable_service: "Offer to save passwords", on unless set to
// false) and the sizes of its login databases: Login Data on this device,
// Login Data For Account for passwords kept in the browser account.
func chromiumPasswordFacts(p browserProfile, prefs []byte, sizes map[string]int64) pwProfile {
	return chromiumPasswordFactsCounted(p, prefs, sizes, nil)
}

// chromiumPasswordFactsCounted is chromiumPasswordFacts with the number of
// saved logins in each database that could be counted (counts); for the rest
// the size has to do.
func chromiumPasswordFactsCounted(p browserProfile, prefs []byte, sizes map[string]int64, counts map[string]int) pwProfile {
	var doc struct {
		Save *bool `json:"credentials_enable_service"`
	}
	_ = json.Unmarshal(prefs, &doc)
	r := pwProfile{ID: p.ID, Name: p.Name, Label: p.Label(), Saving: doc.Save == nil || *doc.Save}
	var parts []string
	logins, uncounted := 0, false
	for _, n := range []string{"Login Data", "Login Data For Account"} {
		sz, ok := sizes[n]
		if !ok {
			continue
		}
		if c, counted := counts[n]; counted {
			if c > 0 {
				logins += c
				r.Stored = true
				parts = append(parts, fmt.Sprintf("%s holds %d saved login(s)", n, c))
			}
			continue
		}
		if sz > chromeEmptyLoginData {
			uncounted = true
			r.Stored = true
			parts = append(parts, fmt.Sprintf("%s is %d KB, larger than an empty one (%d KB)", n, sz/1024, chromeEmptyLoginData/1024))
		}
	}
	if !uncounted {
		r.Logins = logins
	}
	if !r.Stored {
		parts = append(parts, "no saved logins found")
	}
	if r.Saving {
		parts = append(parts, "Offer to save passwords is on")
	} else {
		parts = append(parts, "Offer to save passwords is off")
	}
	r.Details = strings.Join(parts, "; ")
	return r
}

func firefoxPasswords(p browserProfile) pwProfile {
	prefs, _ := os.ReadFile(filepath.Join(p.Dir, "prefs.js"))
	n := 0
	if f, err := os.Open(filepath.Join(p.Dir, "logins.json")); err == nil {
		n = countFirefoxLogins(f)
		f.Close()
	}
	return firefoxPasswordFacts(p, prefs, n)
}

// countFirefoxLogins counts the entries of logins.json without keeping any
// of their fields.
func countFirefoxLogins(r io.Reader) int {
	var doc struct {
		Logins []struct{} `json:"logins"`
	}
	if json.NewDecoder(r).Decode(&doc) != nil {
		return 0
	}
	return len(doc.Logins)
}

// firefoxPasswordFacts judges a Firefox profile from prefs.js
// (signon.rememberSignons: "Ask to save passwords", on unless false) and the
// number of saved logins.
func firefoxPasswordFacts(p browserProfile, prefsJS []byte, logins int) pwProfile {
	saving := true
	sc := bufio.NewScanner(bytes.NewReader(prefsJS))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.ReplaceAll(strings.TrimSpace(sc.Text()), " ", "")
		if strings.HasPrefix(line, `user_pref("signon.rememberSignons",`) {
			saving = !strings.HasPrefix(line, `user_pref("signon.rememberSignons",false)`)
		}
	}
	r := pwProfile{ID: p.ID, Name: p.Name, Label: p.Label(), Saving: saving, Stored: logins > 0, Logins: logins}
	parts := []string{"no saved logins"}
	if logins > 0 {
		parts = []string{fmt.Sprintf("%d saved logins in logins.json", logins)}
	}
	if saving {
		parts = append(parts, "Ask to save passwords is on")
	} else {
		parts = append(parts, "Ask to save passwords is off")
	}
	r.Details = strings.Join(parts, "; ")
	return r
}
