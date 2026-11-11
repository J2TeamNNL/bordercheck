package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The extensions check reads which extensions the browsers (Chromium-based
// and Firefox) and the VS Code family of editors have installed, from the
// files those apps keep in the user's profile. A malicious or hijacked
// extension sees everything the person does in the browser or the editor,
// so it fails on the organisation's block list and warns on extensions
// loaded from outside a store. It reads nothing outside the browsers' and
// editors' own folders (an unpacked extension's folder may be in a place
// macOS guards with a privacy prompt), opens no credential file, and never
// goes online. Safari is not covered: its data is in a protected container.

// extItem is one installed extension.
type extItem struct {
	App      string // "Chrome", "VS Code": what the summary counts by
	Where    string // "Chrome (Default)", "VS Code"
	Editor   bool
	ID       string // browser extension ID, or publisher.name for editors
	Name     string
	Version  string
	Enabled  bool
	Outside  string // why it is from outside a store, "" if it is not
	AllSites bool   // can read and change every website
}

func (e extItem) String() string {
	s := e.Where + ": " + e.Name
	if e.Version != "" {
		s += " " + e.Version
	}
	if e.Name != e.ID {
		s += " (" + e.ID + ")"
	}
	if !e.Enabled {
		s += ", disabled"
	}
	return s
}

// extFacts is what gathering found: every extension and, in order, every
// browser or editor that has a profile (so one with no extensions still counts).
type extFacts struct {
	Apps  []string
	Items []extItem
}

func (f *extFacts) addApp(app string) {
	if !slices.Contains(f.Apps, app) {
		f.Apps = append(f.Apps, app)
	}
}

// globList compiles policy globs (validated when the policy loaded), matched
// case-insensitively.
func globList(pats []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range pats {
		if re, err := policy.Glob(strings.ToLower(p)); err == nil {
			out = append(out, re)
		}
	}
	return out
}

func matchAny(res []*regexp.Regexp, s string) bool {
	s = strings.ToLower(s)
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// shortList names up to five things, with "…" when there are more.
func shortList(names []string) string {
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + ", …"
	}
	return strings.Join(names, ", ")
}

func evalExtensions(f extFacts, opts policy.Extensions) check.Result {
	if len(f.Apps) == 0 {
		return check.SkippedMsg(msg.Of("extensions.notFound"))
	}
	block, allow, unpacked := globList(opts.Block), globList(opts.Allow), globList(opts.AllowUnpacked)
	count := map[string]int{}
	var blocked, outside, notAllowed, allSites []extItem
	for _, e := range f.Items {
		count[e.App]++
		switch {
		case matchAny(block, e.ID):
			blocked = append(blocked, e) // even when disabled: it can be turned back on
		case !e.Enabled:
		case len(allow) > 0 && !matchAny(allow, e.ID):
			notAllowed = append(notAllowed, e)
		case e.Outside != "" && !matchAny(unpacked, e.ID):
			outside = append(outside, e)
		}
		if e.Enabled && e.AllSites && !matchAny(block, e.ID) {
			allSites = append(allSites, e)
		}
	}
	var counts []string
	for _, a := range f.Apps {
		counts = append(counts, fmt.Sprintf("%s %d", a, count[a]))
	}
	names := func(es []extItem) string {
		var ns []string
		for _, e := range es {
			if !slices.Contains(ns, e.Name) {
				ns = append(ns, e.Name)
			}
		}
		return shortList(ns)
	}
	summary := msg.Of("extensions.found", "counts", strings.Join(counts, ", "))
	var fix msg.Text
	var ev []string
	var compromise []check.Indicator
	status, sev := check.Pass, check.Severity("")
	raise := func(st check.Status, sv check.Severity) {
		if st == check.Fail || status == check.Pass {
			status = st
		}
		if sev == "" || sv == check.High {
			sev = sv
		}
	}
	if len(blocked) > 0 {
		raise(check.Fail, check.High)
		summary = append(summary, msg.P("extensions.blocked", "n", len(blocked), "names", names(blocked)))
		fix = append(fix, msg.P("extensions.fix.blocked"))
		for _, e := range blocked {
			ev = append(ev, "on the block list: "+e.String())
			// A sign of compromise: IT has declared this extension malicious
			// or forbidden, and it is installed (even disabled, it can be
			// turned back on).
			compromise = append(compromise, check.Indicator{What: msg.P("compromise.blockedExtension"), Detail: e.String()})
		}
	}
	if len(outside) > 0 {
		raise(check.Warn, check.Medium)
		summary = append(summary, msg.P("extensions.outside", "n", len(outside), "names", names(outside)))
		fix = append(fix, msg.P("extensions.fix.outside"))
		for _, e := range outside {
			ev = append(ev, e.Outside+": "+e.String())
		}
	}
	if len(notAllowed) > 0 {
		raise(check.Warn, check.Medium)
		summary = append(summary, msg.P("extensions.notAllowed", "n", len(notAllowed), "names", names(notAllowed)))
		fix = append(fix, msg.P("extensions.fix.notAllowed"))
		for _, e := range notAllowed {
			ev = append(ev, "not on the allowed list: "+e.String())
		}
	}
	if len(allSites) > 0 {
		if opts.WarnAllSites {
			raise(check.Warn, check.Medium)
			summary = append(summary, msg.P("extensions.allSitesWarn", "n", len(allSites), "names", names(allSites)))
			fix = append(fix, msg.P("extensions.fix.allSites"))
		} else {
			summary = append(summary, msg.P("extensions.allSites", "n", len(allSites)))
		}
		for i, e := range allSites {
			if i == 20 {
				ev = append(ev, fmt.Sprintf("can read and change every website: %d more", len(allSites)-20))
				break
			}
			ev = append(ev, "can read and change every website: "+e.String())
		}
	}
	if status == check.Pass {
		summary = append(summary, msg.P("extensions.pass"))
	}
	r := check.Result{Status: status, Severity: sev, Evidence: ev, Compromise: compromise}.WithSummary(summary)
	if len(fix) > 0 {
		r = r.WithFix(fix)
	}
	return r
}

// ---- gathering (portable: only files in the user's profile) ----

func extensions(opts policy.Extensions) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		home, err := os.UserHomeDir()
		if err != nil {
			return check.Errored(err)
		}
		return evalExtensions(gatherExtensions(ctx, home, runtime.GOOS, opts), opts)
	}
}

func gatherExtensions(ctx context.Context, home, goos string, opts policy.Extensions) extFacts {
	var f extFacts
	if opts.Browsers {
		for _, p := range browserProfiles(home, goos) {
			if ctx.Err() != nil {
				break
			}
			var items []extItem
			var ok bool
			if p.Firefox {
				items, ok = firefoxExtensions(p)
			} else {
				items, ok = chromiumExtensions(p, home)
			}
			if ok {
				f.addApp(p.Name)
				f.Items = append(f.Items, items...)
			}
		}
	}
	if opts.Editors {
		for _, ed := range editorDirs {
			data, err := os.ReadFile(filepath.Join(home, ed.dir, "extensions", "extensions.json"))
			if err != nil {
				continue
			}
			items, ok := parseEditorExtensions(data, ed.name)
			if ok {
				f.addApp(ed.name)
				f.Items = append(f.Items, items...)
			}
		}
	}
	return f
}

// editorDirs are the VS Code family's per-user folders (the same under the
// home folder on every OS); each keeps extensions/extensions.json.
var editorDirs = []struct{ name, dir string }{
	{"VS Code", ".vscode"}, {"VS Code Insiders", ".vscode-insiders"}, {"Cursor", ".cursor"},
	{"Windsurf", ".windsurf"}, {"VSCodium", ".vscode-oss"},
}

// parseEditorExtensions reads a VS Code-style extensions.json. Its metadata
// records how each extension was installed: source "gallery" (marketplace),
// "vsix" (from a file) or "resource".
func parseEditorExtensions(data []byte, editor string) ([]extItem, bool) {
	var list []struct {
		Identifier struct {
			ID string `json:"id"`
		} `json:"identifier"`
		Version  string `json:"version"`
		Metadata *struct {
			Source string `json:"source"`
		} `json:"metadata"`
	}
	if json.Unmarshal(data, &list) != nil {
		return nil, false
	}
	var out []extItem
	for _, e := range list {
		if e.Identifier.ID == "" {
			continue
		}
		id := strings.ToLower(e.Identifier.ID)
		it := extItem{App: editor, Where: editor, Editor: true, ID: id, Name: id, Version: e.Version, Enabled: true}
		if e.Metadata != nil && e.Metadata.Source == "vsix" {
			it.Outside = "installed from a VSIX file"
		}
		out = append(out, it)
	}
	return out, true
}

// ---- Chromium ----

// Chromium's extension install locations (extensions/common/mojom/manifest.mojom).
const (
	chromeInternal          = 1 // from a .crx: the store, or a file
	chromeExternalPref      = 2 // put there by another program
	chromeExternalRegistry  = 3
	chromeUnpacked          = 4 // "Load unpacked" in developer mode
	chromeComponent         = 5 // part of the browser
	chromeExternalPrefDL    = 6
	chromePolicyDownload    = 7 // forced by the organisation's browser policy
	chromeCommandLine       = 8 // --load-extension
	chromePolicy            = 9
	chromeExternalComponent = 10
)

// chromeStoreUpdateURLs are the update URLs of the Chrome Web Store and of
// Microsoft Edge Add-ons; an extension updating from elsewhere is self-hosted.
var chromeStoreUpdateURLs = []string{
	"https://clients2.google.com/service/update2/crx",
	"https://edge.microsoft.com/extensionwebstorebase/v1/crx",
}

type chromeExtSetting struct {
	Location       int             `json:"location"`
	FromWebstore   *bool           `json:"from_webstore"`
	DisableReasons json.RawMessage `json:"disable_reasons"` // a bit mask in older versions, a list in newer
	State          *int            `json:"state"`           // older versions: 0 = disabled
	Path           string          `json:"path"`
	Manifest       json.RawMessage `json:"manifest"`
	ByDefault      bool            `json:"was_installed_by_default"`
}

func (s chromeExtSetting) enabled() bool {
	if s.State != nil && *s.State == 0 {
		return false
	}
	r := strings.TrimSpace(string(s.DisableReasons))
	return r == "" || r == "0" || r == "[]" || r == "null"
}

// chromeExtSettings merges extensions.settings from Preferences and Secure
// Preferences (where newer versions keep them on macOS and Windows).
func chromeExtSettings(files ...[]byte) (map[string]*chromeExtSetting, bool) {
	out := map[string]*chromeExtSetting{}
	ok := false
	for _, data := range files {
		var doc struct {
			Extensions struct {
				Settings map[string]json.RawMessage `json:"settings"`
			} `json:"extensions"`
		}
		if len(data) == 0 || json.Unmarshal(data, &doc) != nil {
			continue
		}
		ok = true
		for id, raw := range doc.Extensions.Settings {
			s := out[id]
			if s == nil {
				s = &chromeExtSetting{}
				out[id] = s
			}
			_ = json.Unmarshal(raw, s) // fields present here override the earlier file's
		}
	}
	return out, ok
}

type chromeManifest struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	DefaultLocale  string `json:"default_locale"`
	UpdateURL      string `json:"update_url"`
	Theme          any    `json:"theme"`
	Permissions    []any  `json:"permissions"`
	Hosts          []any  `json:"host_permissions"`
	ContentScripts []struct {
		Matches []string `json:"matches"`
	} `json:"content_scripts"`
}

// allSitesPattern reports whether a match pattern covers every website.
func allSitesPattern(p string) bool {
	if p == "<all_urls>" {
		return true
	}
	_, rest, ok := strings.Cut(p, "://")
	if !ok {
		return false
	}
	host, _, _ := strings.Cut(rest, "/")
	return host == "*"
}

func (m chromeManifest) allSites() bool {
	pats := []string{}
	for _, v := range append(slices.Clone(m.Permissions), m.Hosts...) {
		if s, ok := v.(string); ok {
			pats = append(pats, s)
		}
	}
	for _, cs := range m.ContentScripts {
		pats = append(pats, cs.Matches...)
	}
	return slices.ContainsFunc(pats, allSitesPattern)
}

// localizedName resolves a "__MSG_name__" manifest name from the extension's
// _locales folder.
func localizedName(name, extDir, locale string) string {
	key, ok := strings.CutPrefix(name, "__MSG_")
	if !ok || extDir == "" {
		return name
	}
	key = strings.ToLower(strings.TrimSuffix(key, "__"))
	for _, loc := range []string{locale, "en", "en_US"} {
		if loc == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(extDir, "_locales", loc, "messages.json"))
		if err != nil {
			continue
		}
		var msgs map[string]struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &msgs) != nil {
			continue
		}
		for k, v := range msgs {
			if strings.ToLower(k) == key && v.Message != "" {
				return v.Message
			}
		}
	}
	return name
}

func chromiumExtensions(p browserProfile, home string) ([]extItem, bool) {
	prefs, _ := os.ReadFile(filepath.Join(p.Dir, "Preferences"))
	secure, _ := os.ReadFile(filepath.Join(p.Dir, "Secure Preferences"))
	settings, ok := chromeExtSettings(prefs, secure)
	if !ok {
		return nil, false
	}
	readManifest := func(id string, s *chromeExtSetting) (chromeManifest, string) {
		var m chromeManifest
		if s.Path != "" && !filepath.IsAbs(s.Path) {
			// Inside the profile's Extensions folder. An unpacked extension's
			// own folder (an absolute path) is left alone.
			dir := filepath.Join(p.Dir, "Extensions", filepath.FromSlash(s.Path))
			if data, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil && json.Unmarshal(data, &m) == nil {
				return m, dir
			}
		}
		if len(s.Manifest) > 0 {
			_ = json.Unmarshal(s.Manifest, &m)
		}
		return m, ""
	}
	return chromiumItems(p, home, settings, readManifest), true
}

// chromiumItems judges the merged settings; readManifest finds each
// extension's manifest and folder.
func chromiumItems(p browserProfile, home string, settings map[string]*chromeExtSetting,
	readManifest func(string, *chromeExtSetting) (chromeManifest, string)) []extItem {
	ids := make([]string, 0, len(settings))
	for id := range settings {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []extItem
	for _, id := range ids {
		s := settings[id]
		switch s.Location {
		case 0, chromeComponent, chromeExternalComponent, chromePolicyDownload, chromePolicy:
			continue // built in, managed by the organisation, or a stale entry
		}
		m, dir := readManifest(id, s)
		if m.Theme != nil {
			continue
		}
		it := extItem{App: p.Name, Where: p.Label(), ID: id, Version: m.Version, Enabled: s.enabled(), AllSites: m.allSites()}
		it.Name = localizedName(m.Name, dir, m.DefaultLocale)
		if it.Name == "" || strings.HasPrefix(it.Name, "__MSG_") {
			it.Name = id
		}
		store := m.UpdateURL != "" && slices.ContainsFunc(chromeStoreUpdateURLs, func(u string) bool {
			return strings.HasPrefix(m.UpdateURL, u)
		})
		switch s.Location {
		case chromeUnpacked:
			it.Outside = "loaded unpacked"
			if s.Path != "" {
				it.Outside += " from " + tildePath(home, s.Path)
			}
		case chromeCommandLine:
			it.Outside = "loaded with --load-extension"
		case chromeExternalPref, chromeExternalRegistry, chromeExternalPrefDL:
			if !store {
				it.Outside = "installed by another program, not from a store"
			}
		case chromeInternal:
			if s.FromWebstore != nil && !*s.FromWebstore && !store && !s.ByDefault {
				it.Outside = "installed from a file, not from a store"
			}
		}
		out = append(out, it)
	}
	return out
}

// ---- Firefox ----

// firefoxBuiltIn are extensions.json locations of add-ons that ship with
// Firefox; firefoxSideload those of add-ons other programs put in place.
var (
	firefoxBuiltIn  = []string{"app-builtin", "app-builtin-addons", "app-system-defaults", "app-system-addons"}
	firefoxSideload = []string{"app-system-share", "app-system-local", "app-system-user", "app-global",
		"winreg-app-user", "winreg-app-global"}
)

func firefoxExtensions(p browserProfile) ([]extItem, bool) {
	data, err := os.ReadFile(filepath.Join(p.Dir, "extensions.json"))
	if err != nil {
		// A profile that never installed an add-on may have no extensions.json.
		_, statErr := os.Stat(filepath.Join(p.Dir, "prefs.js"))
		return nil, statErr == nil
	}
	return parseFirefoxExtensions(data, p)
}

// parseFirefoxExtensions reads a Firefox profile's extensions.json. Signed
// states (AddonManager): -2 broken, -1 unknown, 0 missing, 1 preliminary,
// 2 signed, 3 system, 4 privileged.
func parseFirefoxExtensions(data []byte, p browserProfile) ([]extItem, bool) {
	var doc struct {
		Addons []struct {
			ID             string  `json:"id"`
			Type           string  `json:"type"`
			Location       string  `json:"location"`
			Version        string  `json:"version"`
			Active         bool    `json:"active"`
			Hidden         bool    `json:"hidden"`
			SignedState    *int    `json:"signedState"`
			ForeignInstall bool    `json:"foreignInstall"`
			SourceURI      *string `json:"sourceURI"`
			DefaultLocale  struct {
				Name string `json:"name"`
			} `json:"defaultLocale"`
			UserPermissions *struct {
				Origins []string `json:"origins"`
			} `json:"userPermissions"`
			InstallTelemetryInfo *struct {
				Source string `json:"source"`
			} `json:"installTelemetryInfo"`
		} `json:"addons"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil, false
	}
	var out []extItem
	for _, a := range doc.Addons {
		if a.Type != "extension" || a.Hidden || slices.Contains(firefoxBuiltIn, a.Location) {
			continue
		}
		it := extItem{App: p.Name, Where: p.Label(), ID: a.ID, Name: a.DefaultLocale.Name, Version: a.Version, Enabled: a.Active}
		if it.Name == "" {
			it.Name = a.ID
		}
		if a.UserPermissions != nil {
			it.AllSites = slices.ContainsFunc(a.UserPermissions.Origins, allSitesPattern)
		}
		fromFile := a.SourceURI != nil && strings.HasPrefix(*a.SourceURI, "file:") ||
			a.InstallTelemetryInfo != nil && a.InstallTelemetryInfo.Source == "file-url"
		switch {
		case a.Location == "app-temporary":
			it.Outside = "loaded temporarily from about:debugging"
		case a.SignedState != nil && *a.SignedState <= 0:
			it.Outside = "not signed by Mozilla"
		case a.ForeignInstall || slices.Contains(firefoxSideload, a.Location):
			it.Outside = "installed by another program, not from a store"
		case fromFile:
			it.Outside = "installed from a file, not from a store"
		}
		out = append(out, it)
	}
	return out, true
}
