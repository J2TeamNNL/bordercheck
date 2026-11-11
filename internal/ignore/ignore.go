// Package ignore keeps the findings the person at the machine has marked as
// not sensitive (`bordercheck ignore`), in ignored.json in the install folder.
// It covers the checks in Checks: plain-text secrets, tokens in AI agent
// configs, and SSH keys without a passphrase. Ignored findings stop counting
// toward their check, but every one is listed in the report with its reason,
// whatever report.include_evidence says: the list is what lets IT look at it.
//
// The file:
//
//	{"version": 1, "entries": [
//	  {"check": "secrets", "path": "~/proj/.env", "name": "POSTGRES_PASSWORD",
//	   "reason": "local Docker database", "since": "2026-11-11"}]}
//
// path is the file as the report shows it (~ for the home folder); name, when
// set, narrows the entry to findings with that name (a variable, an AI config
// setting) or kind. Lines are never part of an entry: they move when the file
// is edited.
package ignore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FileName is the list's file in the install folder.
const FileName = "ignored.json"

// Checks are the checks whose findings the person at the machine may ignore.
var Checks = []string{"secrets", "ai-agents", "ssh-keys"}

const (
	fileVersion = 1
	// MaxEntries is how many entries the file may hold; MaxReason how long a
	// reason may be, in characters.
	MaxEntries = 200
	MaxReason  = 200
	maxPath    = 1024
	maxName    = 128
)

// Entry is one thing the person marked as not sensitive.
type Entry struct {
	Check  string `json:"check"` // one of Checks
	Path   string `json:"path"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason"`
	Since  string `json:"since"` // YYYY-MM-DD, local date it was added
}

type file struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Load reads the list in dir. A missing file is an empty list; a file that
// cannot be read or understood returns an error, and callers treat it as
// empty. Entries without a path or a reason are dropped, and fields are cut
// to their limits.
func Load(dir string) ([]Entry, error) {
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s is not valid: %w", FileName, err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("%s has version %d; this bordercheck reads version %d", FileName, f.Version, fileVersion)
	}
	var out []Entry
	for _, e := range f.Entries {
		e = e.clipped()
		if e.Check == "" {
			e.Check = "secrets"
		}
		if e.Path == "" || e.Reason == "" || !slices.Contains(Checks, e.Check) {
			continue
		}
		if out = append(out, e); len(out) == MaxEntries {
			break
		}
	}
	return out, nil
}

// Save writes the list to dir, readable by this user only, creating dir if needed.
func Save(dir string, entries []Entry) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if entries == nil {
		entries = []Entry{}
	}
	data, err := json.MarshalIndent(file{Version: fileVersion, Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, FileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (e Entry) clipped() Entry {
	e.Check = strings.TrimSpace(e.Check)
	e.Path = Clip(strings.TrimSpace(e.Path), maxPath)
	e.Name = Clip(strings.TrimSpace(e.Name), maxName)
	e.Reason = Clip(OneLine(e.Reason), MaxReason)
	e.Since = Clip(strings.TrimSpace(e.Since), 32)
	return e
}

// Clip cuts s to at most n characters.
func Clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// OneLine turns control characters (newlines, tabs, escapes) into spaces and
// trims the result.
func OneLine(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
}

// CheckReason says what is wrong with a reason the person typed, or nil.
func CheckReason(reason string) error {
	reason = OneLine(reason)
	switch {
	case reason == "":
		return errors.New(`a reason is required: -reason "why this is not sensitive" (IT sees it in the report)`)
	case utf8.RuneCountInString(reason) > MaxReason:
		return fmt.Errorf("the reason is too long: at most %d characters", MaxReason)
	}
	return nil
}

// Shown writes path p the way the report shows it: ~ for the home folder, and
// absolute otherwise. A relative path is taken from the current folder.
func Shown(p, home string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("no path given")
	}
	abs := expand(p, home)
	if !filepath.IsAbs(abs) {
		var err error
		if abs, err = filepath.Abs(abs); err != nil {
			return "", err
		}
	}
	abs = filepath.Clean(abs)
	if home != "" {
		h := filepath.Clean(home)
		if abs == h {
			return "~", nil
		}
		if rest, ok := strings.CutPrefix(abs, h+string(filepath.Separator)); ok {
			return "~" + string(filepath.Separator) + rest, nil
		}
	}
	return abs, nil
}

// expand turns a leading ~ (alone, or followed by / or \) into home.
func expand(p, home string) string {
	if p == "~" {
		return home
	}
	if len(p) > 1 && p[0] == '~' && (p[1] == '/' || p[1] == '\\') {
		return filepath.Join(home, filepath.FromSlash(strings.ReplaceAll(p[2:], `\`, "/")))
	}
	return p
}

// key is a path in a form two spellings of the same file share: ~ expanded,
// cleaned, forward slashes, and without case where the file system usually
// ignores it (Windows, macOS).
func key(p, home string) string {
	k := filepath.ToSlash(filepath.Clean(expand(strings.TrimSpace(p), home)))
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		k = strings.ToLower(k)
	}
	return k
}

// SamePath reports whether a and b, each as typed or as the report shows it, name the same file.
func SamePath(a, b, home string) bool { return key(a, home) == key(b, home) }

// Covers reports whether e covers a finding of check in path, with those
// names (a variable name, an AI config setting) and that kind. An entry
// without a name covers every finding of its check in the file; with one, a
// finding with exactly that name, or with that kind without regard to case.
func (e Entry) Covers(check, path string, names []string, kind, home string) bool {
	if e.Check != check || !SamePath(e.Path, path, home) {
		return false
	}
	return e.Name == "" || slices.Contains(names, e.Name) || strings.EqualFold(e.Name, kind)
}
