package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Synthetic profiles in a temporary home, written in the shapes Chrome,
// Firefox and VS Code use (fields trimmed to what the check reads).

func putFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const (
	extStoreID    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	extUnpackedID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	extExternalID = "cccccccccccccccccccccccccccccccc"
	extFileID     = "dddddddddddddddddddddddddddddddd"
	extDisabledID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	extPolicyID   = "ffffffffffffffffffffffffffffffff"
	extThemeID    = "gggggggggggggggggggggggggggggggg"
)

// chromeFixture writes a Chrome profile. Preferences holds part of the
// settings and Secure Preferences the rest, as on macOS and Windows.
func chromeFixture(t *testing.T, profile string) {
	t.Helper()
	putFile(t, filepath.Join(profile, "Preferences"), `{"credentials_enable_service": false, "extensions": {"settings": {
	  "`+extStoreID+`": {"location": 1, "path": "`+extStoreID+`/1.2.3_0"},
	  "`+extPolicyID+`": {"location": 7, "path": "`+extPolicyID+`/1.0_0"}
	}}}`)
	putFile(t, filepath.Join(profile, "Secure Preferences"), `{"extensions": {"settings": {
	  "`+extStoreID+`": {"from_webstore": true, "disable_reasons": []},
	  "`+extUnpackedID+`": {"location": 4, "path": "/home/demo/dev/my-ext", "manifest": {"name": "My Dev Ext", "version": "0.1",
	      "content_scripts": [{"matches": ["<all_urls>"]}]}},
	  "`+extExternalID+`": {"location": 6, "path": "`+extExternalID+`/2.0_0", "from_webstore": false},
	  "`+extFileID+`": {"location": 1, "path": "`+extFileID+`/1.0_0", "from_webstore": false},
	  "`+extDisabledID+`": {"location": 4, "path": "/home/demo/old", "disable_reasons": [1], "manifest": {"name": "Old", "version": "1"}},
	  "`+extThemeID+`": {"location": 1, "path": "`+extThemeID+`/1_0", "from_webstore": true},
	  "mhjfbmdgcfjbbpaeojofohoefgiehjai": {"location": 5, "manifest": {"name": "Chrome PDF Viewer"}}
	}}}`)
	ext := filepath.Join(profile, "Extensions")
	putFile(t, filepath.Join(ext, extStoreID, "1.2.3_0", "manifest.json"), `{"name": "__MSG_appName__", "version": "1.2.3",
	  "default_locale": "en", "update_url": "https://clients2.google.com/service/update2/crx", "host_permissions": ["*://*/*"]}`)
	putFile(t, filepath.Join(ext, extStoreID, "1.2.3_0", "_locales", "en", "messages.json"), `{"appName": {"message": "Store Helper"}}`)
	putFile(t, filepath.Join(ext, extExternalID, "2.0_0", "manifest.json"), `{"name": "Bundled Toolbar", "version": "2.0",
	  "update_url": "https://updates.example.com/crx", "permissions": ["tabs", "https://*/*"]}`)
	putFile(t, filepath.Join(ext, extFileID, "1.0_0", "manifest.json"), `{"name": "Coupon Finder", "version": "1.0",
	  "permissions": ["https://shop.example.com/*"]}`)
	putFile(t, filepath.Join(ext, extThemeID, "1_0", "manifest.json"), `{"name": "Dark", "version": "1", "theme": {}}`)
}

func firefoxFixture(t *testing.T, profile string) {
	t.Helper()
	putFile(t, filepath.Join(profile, "prefs.js"), "// Mozilla User Preferences\nuser_pref(\"signon.rememberSignons\", false);\n")
	putFile(t, filepath.Join(profile, "extensions.json"), `{"schemaVersion": 36, "addons": [
	  {"id": "ublock@example.org", "type": "extension", "location": "app-profile", "version": "1.60", "active": true,
	   "signedState": 2, "sourceURI": "https://addons.mozilla.org/firefox/downloads/file/1/x.xpi",
	   "defaultLocale": {"name": "Blocker"}, "userPermissions": {"permissions": ["tabs"], "origins": ["<all_urls>"]},
	   "installTelemetryInfo": {"source": "amo"}},
	  {"id": "dev@example.org", "type": "extension", "location": "app-temporary", "version": "0.0.1", "active": true,
	   "defaultLocale": {"name": "Temp Dev"}},
	  {"id": "unsigned@example.org", "type": "extension", "location": "app-profile", "version": "1", "active": true,
	   "signedState": 0, "defaultLocale": {"name": "Unsigned"}},
	  {"id": "sideload@vendor.example", "type": "extension", "location": "app-system-share", "version": "3", "active": true,
	   "signedState": 2, "foreignInstall": true, "defaultLocale": {"name": "Vendor Helper"}},
	  {"id": "fromfile@example.org", "type": "extension", "location": "app-profile", "version": "1", "active": true,
	   "signedState": 2, "sourceURI": "file:///home/demo/x.xpi", "defaultLocale": {"name": "From File"}},
	  {"id": "formautofill@mozilla.org", "type": "extension", "location": "app-builtin", "active": true, "hidden": true},
	  {"id": "default-theme@mozilla.org", "type": "theme", "location": "app-builtin", "active": true}
	]}`)
}

func TestGatherExtensions(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			home := t.TempDir()
			var chrome, ff string
			switch goos {
			case "darwin":
				chrome = filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default")
				ff = filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles", "ab12.default-release")
			case "linux":
				chrome = filepath.Join(home, ".config", "google-chrome", "Default")
				ff = filepath.Join(home, ".mozilla", "firefox", "ab12.default-release")
			case "windows":
				chrome = filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default")
				ff = filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "ab12.default-release")
			}
			chromeFixture(t, chrome)
			firefoxFixture(t, ff)
			// The internal System Profile is ignored.
			putFile(t, filepath.Join(filepath.Dir(chrome), "System Profile", "Preferences"), `{}`)
			putFile(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), `[
			  {"identifier": {"id": "ms-python.python", "uuid": "u1"}, "version": "2026.1.0",
			   "metadata": {"id": "u1", "publisherDisplayName": "Microsoft", "source": "gallery"}},
			  {"identifier": {"id": "Sample.Internal-Tools"}, "version": "0.3.0", "metadata": {"source": "vsix"}},
			  {"identifier": {"id": "old.ext"}, "version": "1.0.0"}
			]`)
			putFile(t, filepath.Join(home, ".cursor", "extensions", "extensions.json"), `[]`)

			f := gatherExtensions(context.Background(), home, goos, policy.Default().Checks.Extensions)
			if strings.Join(f.Apps, ",") != "Chrome,Firefox,VS Code,Cursor" {
				t.Fatalf("apps = %v", f.Apps)
			}
			got := map[string]extItem{}
			for _, e := range f.Items {
				got[e.ID] = e
			}
			want := map[string]struct {
				name, outside string
				enabled, all  bool
			}{
				extStoreID:                {"Store Helper", "", true, true},
				extUnpackedID:             {"My Dev Ext", "loaded unpacked from /home/demo/dev/my-ext", true, true},
				extExternalID:             {"Bundled Toolbar", "installed by another program, not from a store", true, true},
				extFileID:                 {"Coupon Finder", "installed from a file, not from a store", true, false},
				extDisabledID:             {"Old", "loaded unpacked from /home/demo/old", false, false},
				"ublock@example.org":      {"Blocker", "", true, true},
				"dev@example.org":         {"Temp Dev", "loaded temporarily from about:debugging", true, false},
				"unsigned@example.org":    {"Unsigned", "not signed by Mozilla", true, false},
				"sideload@vendor.example": {"Vendor Helper", "installed by another program, not from a store", true, false},
				"fromfile@example.org":    {"From File", "installed from a file, not from a store", true, false},
				"ms-python.python":        {"ms-python.python", "", true, false},
				"sample.internal-tools":   {"sample.internal-tools", "installed from a VSIX file", true, false},
				"old.ext":                 {"old.ext", "", true, false},
			}
			if len(got) != len(want) {
				t.Errorf("got %d extensions, want %d: %v", len(got), len(want), got)
			}
			for id, w := range want {
				e, ok := got[id]
				if !ok {
					t.Errorf("%s missing", id)
					continue
				}
				if e.Name != w.name || e.Outside != w.outside || e.Enabled != w.enabled || e.AllSites != w.all {
					t.Errorf("%s = %+v, want %+v", id, e, w)
				}
			}
		})
	}
}

func TestGatherExtensionsSwitches(t *testing.T) {
	home := t.TempDir()
	chromeFixture(t, filepath.Join(home, ".config", "chromium", "Default"))
	putFile(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), `[]`)
	p := policy.Default().Checks.Extensions
	p.Browsers = false
	if f := gatherExtensions(context.Background(), home, "linux", p); strings.Join(f.Apps, ",") != "VS Code" {
		t.Errorf("browsers off: %v", f.Apps)
	}
	p.Browsers, p.Editors = true, false
	if f := gatherExtensions(context.Background(), home, "linux", p); strings.Join(f.Apps, ",") != "Chromium" {
		t.Errorf("editors off: %v", f.Apps)
	}
	if r := evalExtensions(gatherExtensions(context.Background(), t.TempDir(), "linux", p), p); r.Status != check.Skip {
		t.Errorf("nothing installed: %+v", r)
	}
}

func sampleExtItems() []extItem {
	return []extItem{
		{App: "Chrome", Where: "Chrome (Default)", ID: extStoreID, Name: "Store Helper", Version: "1.2.3", Enabled: true, AllSites: true},
		{App: "Chrome", Where: "Chrome (Default)", ID: extUnpackedID, Name: "My Dev Ext", Enabled: true, Outside: "loaded unpacked from ~/dev/my-ext"},
		{App: "Firefox", Where: "Firefox (ab12.default-release)", ID: "ublock@example.org", Name: "Blocker", Enabled: true, AllSites: true},
		{App: "VS Code", Where: "VS Code", Editor: true, ID: "evil.miner", Name: "evil.miner", Version: "0.0.1", Enabled: true},
		{App: "VS Code", Where: "VS Code", Editor: true, ID: "ms-python.python", Name: "ms-python.python", Enabled: true},
	}
}

func TestEvalExtensions(t *testing.T) {
	apps := []string{"Chrome", "Firefox", "VS Code"}
	def := policy.Default().Checks.Extensions

	r := evalExtensions(extFacts{Apps: apps, Items: sampleExtItems()[2:3]}, def)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "Chrome 0, Firefox 1, VS Code 0") ||
		!strings.Contains(r.Summary, "1 of them can read and change every website") {
		t.Errorf("pass: %+v", r)
	}

	r = evalExtensions(extFacts{Apps: apps, Items: sampleExtItems()}, def)
	if r.Status != check.Warn || r.Severity != check.Medium || !strings.Contains(r.Summary, "1 extension was installed from outside a store") ||
		!strings.Contains(r.Summary, "My Dev Ext") || r.Fix == "" {
		t.Errorf("outside store: %+v", r)
	}

	p := def
	p.Block = []string{"EVIL.*"}
	p.AllowUnpacked = []string{extUnpackedID}
	r = evalExtensions(extFacts{Apps: apps, Items: sampleExtItems()}, p)
	if r.Status != check.Fail || r.Severity != check.High || !strings.Contains(r.Summary, "block list: evil.miner") ||
		strings.Contains(r.Summary, "outside a store") {
		t.Errorf("blocked: %+v", r)
	}

	p = def
	p.Allow = []string{"ms-python.*", extStoreID, "ublock@example.org"}
	r = evalExtensions(extFacts{Apps: apps, Items: sampleExtItems()}, p)
	if r.Status != check.Warn || !strings.Contains(r.Summary, "2 extensions are not on the organisation's allowed list: My Dev Ext, evil.miner") {
		t.Errorf("allowlist: %+v", r)
	}

	p = def
	p.WarnAllSites, p.AllowUnpacked = true, []string{extUnpackedID}
	r = evalExtensions(extFacts{Apps: apps, Items: sampleExtItems()}, p)
	if r.Status != check.Warn || !strings.Contains(r.Summary, "2 extensions can read and change every website you visit") {
		t.Errorf("warn_all_sites: %+v", r)
	}

	// A disabled extension on the block list still fails; a disabled unpacked one is fine.
	items := []extItem{{App: "Chrome", Where: "Chrome (Default)", ID: extUnpackedID, Name: "Old", Outside: "loaded unpacked"},
		{App: "Chrome", Where: "Chrome (Default)", ID: extFileID, Name: "Bad"}}
	p = def
	p.Block = []string{extFileID}
	r = evalExtensions(extFacts{Apps: []string{"Chrome"}, Items: items}, p)
	if r.Status != check.Fail || len(r.Evidence) != 1 || !strings.Contains(r.Evidence[0], "disabled") {
		t.Errorf("disabled: %+v", r)
	}
}

func TestAllSitesPattern(t *testing.T) {
	for p, want := range map[string]bool{
		"<all_urls>": true, "*://*/*": true, "https://*/*": true, "http://*/": true,
		"https://*.example.com/*": false, "https://example.com/*": false, "tabs": false, "file:///*": false,
	} {
		if allSitesPattern(p) != want {
			t.Errorf("allSitesPattern(%q) != %v", p, want)
		}
	}
}
