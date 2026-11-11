package checks

// Where browsers keep their per-user profiles, shared by the extensions and
// browser-passwords checks. The install locations of the browsers themselves
// are in browsersOS (os-updates); these are the user-data folders, at the
// paths each vendor uses. Safari is left out: its data sits in a container
// that macOS guards with a privacy prompt.

import (
	"os"
	"path/filepath"
	"sort"
)

// browserProfileNames names each browser ID (policy.BrowserIDs) in evidence.
var browserProfileNames = map[string]string{
	"chrome": "Chrome", "edge": "Edge", "brave": "Brave", "chromium": "Chromium", "vivaldi": "Vivaldi",
	"arc": "Arc", "firefox": "Firefox",
}

// browserProfile is one profile folder of one browser.
type browserProfile struct {
	ID      string // "chrome", "firefox"…
	Name    string // "Chrome"
	Profile string // the profile folder's name: "Default", "Profile 1", "abcd1234.default-release"
	Dir     string
	Firefox bool // a Firefox profile; otherwise Chromium
}

// Label is how evidence names the profile: "Chrome (Default)".
func (p browserProfile) Label() string { return p.Name + " (" + p.Profile + ")" }

type browserRoot struct {
	id      string
	dir     string
	firefox bool
}

func localAppData(home string) string { return filepath.Join(home, "AppData", "Local") }

// browserRoots lists the user-data folders of the browsers on goos.
func browserRoots(home, goos string) []browserRoot {
	switch goos {
	case "darwin":
		as := filepath.Join(home, "Library", "Application Support")
		return []browserRoot{
			{id: "chrome", dir: filepath.Join(as, "Google", "Chrome")},
			{id: "edge", dir: filepath.Join(as, "Microsoft Edge")},
			{id: "brave", dir: filepath.Join(as, "BraveSoftware", "Brave-Browser")},
			{id: "chromium", dir: filepath.Join(as, "Chromium")},
			{id: "vivaldi", dir: filepath.Join(as, "Vivaldi")},
			{id: "arc", dir: filepath.Join(as, "Arc", "User Data")},
			{id: "firefox", dir: filepath.Join(as, "Firefox", "Profiles"), firefox: true},
		}
	case "windows":
		local := localAppData(home)
		return []browserRoot{
			{id: "chrome", dir: filepath.Join(local, "Google", "Chrome", "User Data")},
			{id: "edge", dir: filepath.Join(local, "Microsoft", "Edge", "User Data")},
			{id: "brave", dir: filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data")},
			{id: "chromium", dir: filepath.Join(local, "Chromium", "User Data")},
			{id: "vivaldi", dir: filepath.Join(local, "Vivaldi", "User Data")},
			{id: "firefox", dir: filepath.Join(appData(home), "Mozilla", "Firefox", "Profiles"), firefox: true},
		}
	}
	cfg := filepath.Join(home, ".config")
	return []browserRoot{
		{id: "chrome", dir: filepath.Join(cfg, "google-chrome")},
		{id: "chrome", dir: filepath.Join(home, ".var", "app", "com.google.Chrome", "config", "google-chrome")},
		{id: "edge", dir: filepath.Join(cfg, "microsoft-edge")},
		{id: "brave", dir: filepath.Join(cfg, "BraveSoftware", "Brave-Browser")},
		{id: "brave", dir: filepath.Join(home, ".var", "app", "com.brave.Browser", "config", "BraveSoftware", "Brave-Browser")},
		{id: "chromium", dir: filepath.Join(cfg, "chromium")},
		{id: "chromium", dir: filepath.Join(home, "snap", "chromium", "common", "chromium")},
		{id: "vivaldi", dir: filepath.Join(cfg, "vivaldi")},
		{id: "firefox", dir: filepath.Join(home, ".mozilla", "firefox"), firefox: true},
		{id: "firefox", dir: filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"), firefox: true},
		{id: "firefox", dir: filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"), firefox: true},
	}
}

// browserProfiles finds every profile folder: for Chromium browsers the
// folders holding a Preferences file (not the internal Guest and System
// profiles), for Firefox those holding prefs.js.
func browserProfiles(home, goos string) []browserProfile {
	var out []browserProfile
	for _, r := range browserRoots(home, goos) {
		entries, err := os.ReadDir(r.dir)
		if err != nil {
			continue
		}
		marker := "Preferences"
		if r.firefox {
			marker = "prefs.js"
		}
		var names []string
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "System Profile" || e.Name() == "Guest Profile" {
				continue
			}
			if st, err := os.Stat(filepath.Join(r.dir, e.Name(), marker)); err == nil && st.Mode().IsRegular() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, browserProfile{ID: r.id, Name: browserProfileNames[r.id], Profile: n,
				Dir: filepath.Join(r.dir, n), Firefox: r.firefox})
		}
	}
	return out
}
