package checks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// rawStore is a tool that keeps chats (or a clipboard) in a database: its
// file is searched as bytes for the token formats, with no lines or message
// context. Text in SQLite is stored as it is, so a token written to one is
// found; one the database compressed or encrypted is not. Nothing inside
// another app's container (~/Library/Containers, Group Containers) is read:
// macOS would ask the person whether BorderCheck may.
type rawStore struct {
	app   string
	paths func(home, goos string) []string
}

var rawStores = []rawStore{
	// Cursor's editor keeps its chats (composerData, bubbleId entries) in state.vscdb.
	{app: "Cursor (editor)", paths: func(home, goos string) []string {
		u := vscodeUserDirs(home, goos)[3] // Cursor
		out := []string{filepath.Join(u, "globalStorage", "state.vscdb")}
		ws, _ := filepath.Glob(filepath.Join(u, "workspaceStorage", "*", "state.vscdb"))
		return append(out, ws...)
	}},
	{app: "opencode", paths: func(home, _ string) []string {
		if p := os.Getenv("OPENCODE_DB"); filepath.IsAbs(p) {
			return []string{p}
		}
		base := os.Getenv("XDG_DATA_HOME")
		if !filepath.IsAbs(base) {
			base = filepath.Join(home, ".local", "share")
		}
		dbs, _ := filepath.Glob(filepath.Join(base, "opencode", "opencode*.db"))
		return dbs
	}},
	{app: "Goose", paths: func(home, _ string) []string {
		if r := os.Getenv("GOOSE_PATH_ROOT"); filepath.IsAbs(r) {
			return []string{filepath.Join(r, "data", "sessions", "sessions.db")}
		}
		return []string{
			filepath.Join(home, ".local", "share", "goose", "sessions", "sessions.db"),
			filepath.Join(home, "Library", "Application Support", "Block", "goose", "sessions", "sessions.db"),
		}
	}},
	// Alfred's clipboard history (Raycast's is encrypted; Maccy and Paste live in containers).
	{app: "Alfred clipboard", paths: func(home, goos string) []string {
		if goos != "darwin" {
			return nil
		}
		return []string{filepath.Join(home, "Library", "Application Support", "Alfred", "Databases", "clipboard.alfdb")}
	}},
}

// logRoots are where programs leave logs that may hold a token they printed
// (curl -v, a failed request, set -x): read by `bordercheck full-scan` only.
func logRoots(home, goos string) []string {
	roots := []string{os.TempDir(), "/tmp"}
	switch goos {
	case "darwin":
		roots = append(roots, filepath.Join(home, "Library", "Logs"))
	case "linux":
		roots = append(roots, filepath.Join(home, ".local", "state"))
	case "windows":
		roots = []string{os.TempDir()}
	}
	return roots
}

// logDepth bounds the walk below a log folder.
const logDepth = 3

// findLogs lists the .log files under logRoots, up to secretMaxFileSize each.
func findLogs(ctx context.Context, home, goos string) []chatFile {
	var out []chatFile
	seen := map[string]bool{}
	for _, root := range logRoots(home, goos) {
		real, err := filepath.EvalSymlinks(root)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		_ = filepath.WalkDir(real, func(p string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				if ctx.Err() != nil {
					return filepath.SkipAll
				}
				return nil
			}
			if d.IsDir() {
				if rel, _ := filepath.Rel(real, p); strings.Count(rel, string(filepath.Separator)) >= logDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.EqualFold(filepath.Ext(p), ".log") || !d.Type().IsRegular() {
				return nil
			}
			if info, err := d.Info(); err == nil && info.Size() <= secretMaxFileSize && info.Size() > 0 {
				out = append(out, chatFile{app: "Log file", path: p, mod: info.ModTime(), size: info.Size(), raw: true})
			}
			return nil
		})
	}
	return out
}
