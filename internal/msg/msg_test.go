package msg

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the receiver's English catalogue from the Go table")

const catalogJSON = "../../receiver/src/i18n/checks.en.json"

// catalogFile is the table as the receiver reads it: key → template, or
// {one, other} for a plural.
func catalogFile() []byte {
	m := map[string]any{}
	for k, e := range Catalog {
		if e.One != "" {
			m[k] = e
		} else {
			m[k] = e.Other
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// TestCatalogJSON fails when receiver/src/i18n/checks.en.json is not the Go
// table. Regenerate it with: go generate ./internal/msg
func TestCatalogJSON(t *testing.T) {
	want := catalogFile()
	if *update {
		if err := os.WriteFile(catalogJSON, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(catalogJSON)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date with internal/msg/catalog.go; run: go generate ./internal/msg", catalogJSON)
	}
}

var (
	braceRe  = regexp.MustCompile(`\{[^{}]*\}`)
	keyRe    = regexp.MustCompile(`^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)+$`)
	markupOK = regexp.MustCompile(`\[(/?)(b|code|kbd)\]`)
)

func TestCatalogTemplates(t *testing.T) {
	for k, e := range Catalog {
		if !keyRe.MatchString(k) {
			t.Errorf("%s: keys are dotted lowerCamel words", k)
		}
		if e.Other == "" {
			t.Errorf("%s: no text", k)
		}
		forms := []string{e.Other}
		if e.One != "" {
			forms = append(forms, e.One)
			if !slices.Contains(Placeholders(e.Other), "n") {
				t.Errorf("%s: a plural's other form must use {n}", k)
			}
		}
		for _, f := range forms {
			// Every {…} that looks like a placeholder must be a valid one.
			// ${env:NAME} is literal text (an agent config's syntax).
			for _, ix := range braceRe.FindAllStringIndex(f, -1) {
				b := f[ix[0]:ix[1]]
				if ix[0] > 0 && f[ix[0]-1] == '$' {
					continue
				}
				if regexp.MustCompile(`^\{\w+(:\w+)?\}$`).MatchString(b) && !placeholderRe.MatchString(b) {
					t.Errorf("%s: unknown placeholder type in %s", k, b)
				}
			}
			for _, p := range Placeholders(f) {
				if name, typ, _ := strings.Cut(p, ":"); name == "n" && typ != "" {
					t.Errorf("%s: {n} is the plural count and has no type", k)
				}
			}
			// Markup must nest and close.
			var open []string
			for _, m := range markupOK.FindAllStringSubmatch(f, -1) {
				if m[1] == "" {
					if len(open) > 0 {
						t.Errorf("%s: nested markup", k)
					}
					open = append(open, m[2])
				} else if len(open) == 0 || open[len(open)-1] != m[2] {
					t.Errorf("%s: unbalanced [/%s]", k, m[2])
				} else {
					open = open[:len(open)-1]
				}
			}
			if len(open) > 0 {
				t.Errorf("%s: unclosed markup", k)
			}
			if strings.ContainsAny(f, "<>") && !strings.Contains(f, "<key>") {
				t.Errorf("%s: angle brackets other than <key> (they are shown as text)", k)
			}
		}
	}
}

func TestRender(t *testing.T) {
	cases := []struct {
		p    Part
		want string
	}{
		{P("listeners.exposed", "n", 1), "1 port can be reached from other machines (LAN, Wi-Fi, Tailscale)."},
		{P("listeners.exposed", "n", 3), "3 ports can be reached from other machines (LAN, Wi-Fi, Tailscale)."},
		{P("screenlock.tooLate", "after", 900, "max", 300), "The screen locks only after 15 minutes idle (policy: 5 minutes)."},
		{P("screenlock.passIdle", "after", 90), "The screen locks after 1.5 minutes idle."},
		{P("screenlock.passIdle", "after", 30), "The screen locks after 30 seconds idle."},
		{P("updates.paused", "until", "2026-12-01"), "Updates are paused until 1 Dec 2026."},
		{P("updates.checkStale", "ago", 0, "max", 14), "The OS last checked for updates today (policy: every 14 days)."},
		{P("updates.checkStale", "ago", 1, "max", 14), "The OS last checked for updates 1 day ago (policy: every 14 days)."},
		{P("firewall.mac.off.fix"), "System Settings → Network → Firewall → turn it on. Or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"},
		{P("no.such.key"), "no.such.key"},
	}
	for _, c := range cases {
		if got := c.p.English(); got != c.want {
			t.Errorf("%s: got %q, want %q", c.p.Key, got, c.want)
		}
	}
	if got := (Text{P("check.moreAllowed", "n", 2), P("listeners.note.mac")}).English(); got !=
		"2 more allowed by policy. Only your own processes are visible; run with sudo to include system services." {
		t.Errorf("joined: %q", got)
	}
	if e := Err("tailscale.badPrefs"); e.Error() != "unexpected output from `tailscale debug prefs`" {
		t.Errorf("Err: %q", e.Error())
	}
}

func TestParamTypes(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a float parameter should panic")
		}
	}()
	P("listeners.exposed", "n", 1.5)
}

// The keys a check names in Go source, as literals: msg.P("…"), msg.Of("…"),
// msg.Err("…"), and key strings in tables (e.g. updateFix's map).
var sourceKeyRe = regexp.MustCompile(`"([a-z][A-Za-z0-9]*(?:\.[a-z][A-Za-z0-9]*)+)"`)
var callKeyRe = regexp.MustCompile(`msg\.(?:P|Of|Err)\("([^"]+)"`)

// TestKeysUsed: every key a check uses is in the table, and every key in the
// table is used somewhere (no dead translations).
func TestKeysUsed(t *testing.T) {
	seen := map[string]bool{}
	for _, dir := range []string{"../check", "../checks"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range callKeyRe.FindAllStringSubmatch(string(b), -1) {
				if _, ok := Catalog[m[1]]; !ok {
					t.Errorf("%s uses %q, which is not in the catalogue", f, m[1])
				}
			}
			for _, m := range sourceKeyRe.FindAllStringSubmatch(string(b), -1) {
				if _, ok := Catalog[m[1]]; ok {
					seen[m[1]] = true
				}
			}
		}
	}
	for k := range Catalog {
		if !seen[k] {
			t.Errorf("%s is in the catalogue but no check uses it", k)
		}
	}
}
