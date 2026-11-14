package checks

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/ptrinh/bordercheck/internal/policy"
)

func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, v := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "COPILOT_HOME", "CLINE_DATA_DIR", "CLINE_DIR",
		"XDG_CONFIG_HOME", "XDG_DATA_HOME", "OPENCODE_DB", "GOOSE_PATH_ROOT", "AIDER_CHAT_HISTORY_FILE", "AIDER_INPUT_HISTORY_FILE"} {
		t.Setenv(v, "")
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=An", "GIT_AUTHOR_EMAIL=an@example.com",
		"GIT_COMMITTER_NAME=An", "GIT_COMMITTER_EMAIL=an@example.com", "GIT_AUTHOR_DATE=2026-03-02T10:00:00Z", "GIT_COMMITTER_DATE=2026-03-02T10:00:00Z")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestGitHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	home := isolatedHome(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	repo := filepath.Join(home, "code", "api")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, t.TempDir(), "init", "-q", "--bare", remote)
	git(t, repo, "init", "-q", "-b", "main")
	gone := "gh" + "p_" + strings.Repeat("Q7x9", 9)          // committed, then removed, pushed
	kept := "sk-" + "ant-api03-" + strings.Repeat("Zq9X", 6) // still in the files, not pushed
	stashed := "AKIA" + "Z7Q2" + "W8E4R5T6Y1U3"              // only in the stash
	writeTestFile(t, filepath.Join(repo, ".env"), "GH_TOKEN="+gone+"\n")
	git(t, repo, "add", ".env")
	git(t, repo, "commit", "-q", "-m", "add env")
	first := git(t, repo, "rev-parse", "--short=8", "HEAD")
	writeTestFile(t, filepath.Join(repo, ".env"), "# moved to touchenv\n")
	git(t, repo, "commit", "-q", "-am", "remove token")
	git(t, repo, "remote", "add", "origin", remote)
	git(t, repo, "push", "-q", "origin", "main")
	writeTestFile(t, filepath.Join(repo, "config.yml"), "anthropic: "+kept+"\n")
	git(t, repo, "add", "config.yml")
	git(t, repo, "commit", "-q", "-m", "config")
	writeTestFile(t, filepath.Join(repo, "config.yml"), "anthropic: "+kept+"\naws: "+stashed+"\n")
	git(t, repo, "stash", "-q")

	found, repos, partial, err := ScanGitHistory(t.Context(), policy.Default().Checks.Secrets)
	if err != nil || repos != 1 || len(partial) != 0 {
		t.Fatalf("%v repos %d partial %v", err, repos, partial)
	}
	byKind := map[string]GitFinding{}
	for _, f := range found {
		byKind[f.Kind] = f
	}
	gh, ant, aws := byKind["GitHub token"], byKind["Anthropic API key"], byKind["AWS access key"]
	if gh.Commit != first || gh.File != ".env" || !gh.Pushed || gh.Current || filepath.ToSlash(gh.Repo) != "~/code/api" || gh.Date != "2026-03-02" {
		t.Errorf("removed token: %+v", gh)
	}
	if ant.File != "config.yml" || ant.Pushed || !ant.Current || ant.Stash {
		t.Errorf("kept token: %+v", ant)
	}
	if !aws.Stash || aws.File != "config.yml" {
		t.Errorf("stashed key: %+v", aws)
	}
	if len(found) != 3 {
		t.Errorf("%d found: %+v", len(found), found)
	}
	for _, f := range found {
		line := f.Item() + f.Where() + f.State()
		if strings.Contains(line, gone) || strings.Contains(line, kept) || strings.Contains(line, stashed) {
			t.Errorf("a value is shown: %s", line)
		}
	}
	if !strings.Contains(gh.State(), "pushed to a remote") || !strings.Contains(ant.State(), "still in the current files") {
		t.Errorf("states: %q / %q", gh.State(), ant.State())
	}
}

func TestRawStoresAndLogs(t *testing.T) {
	home := isolatedHome(t)
	tok := "sk_" + "live_" + strings.Repeat("a1B2", 8)
	writeTestFile(t, filepath.Join(home, ".local", "share", "goose", "sessions", "sessions.db"), "SQLite format 3\x00\x00binary "+tok+" \x00more")
	writeTestFile(t, filepath.Join(home, ".local", "share", "opencode", "opencode.db-wal"), "x") // a -wal without its db is not read
	logDir := filepath.Join(t.TempDir(), "logs")
	t.Setenv("TMPDIR", logDir) // the temporary folder: TMPDIR on macOS and Linux, TEMP / TMP on Windows
	t.Setenv("TEMP", logDir)
	t.Setenv("TMP", logDir)
	writeTestFile(t, filepath.Join(logDir, "app", "run.log"), "> Authorization: Bearer x\nnpm token npm_"+strings.Repeat("Ab1", 12)+"\n")
	writeTestFile(t, filepath.Join(logDir, "notes.txt"), tok)

	chats, err := ScanChatsAndLogs(t.Context(), policy.Default().Checks.Secrets, time.Time{}, true)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range chats {
		got = append(got, f.App()+": "+f.Kind)
	}
	if strings.Join(got, "; ") != "Goose: Stripe live key; Log file: npm token" {
		t.Errorf("found %v", got)
	}
	// Without logs (the AI chats only), the log is not read.
	if chats, _ := ScanAIChats(t.Context(), policy.Default().Checks.Secrets, time.Time{}); len(chats) != 1 {
		t.Errorf("without logs: %v", chats)
	}
}

func TestRecycledName(t *testing.T) {
	dir := t.TempDir()
	name := `C:\Users\An\proj\.env.local`
	u := utf16.Encode([]rune(name))
	v2 := make([]byte, 28+2*len(u))
	binary.LittleEndian.PutUint64(v2[0:], 2)
	binary.LittleEndian.PutUint32(v2[24:], uint32(len(u)))
	for i, c := range u {
		binary.LittleEndian.PutUint16(v2[28+2*i:], c)
	}
	writeTestFile(t, filepath.Join(dir, "$IABC123.local"), string(v2))
	if got := recycledName(filepath.Join(dir, "$IABC123.local")); got != ".env.local" {
		t.Errorf("version 2: %q", got)
	}
	v1 := make([]byte, 24+520)
	binary.LittleEndian.PutUint64(v1[0:], 1)
	for i, c := range utf16.Encode([]rune(`D:\keys\id_rsa`)) {
		binary.LittleEndian.PutUint16(v1[24+2*i:], c)
	}
	writeTestFile(t, filepath.Join(dir, "$IXYZ"), string(v1))
	if got := recycledName(filepath.Join(dir, "$IXYZ")); got != "id_rsa" {
		t.Errorf("version 1: %q", got)
	}
	if recycledName(filepath.Join(dir, "missing")) != "" {
		t.Error("missing file")
	}
}

func TestSyncedBy(t *testing.T) {
	home := t.TempDir()
	for p, want := range map[string]string{
		filepath.Join(home, "Library", "CloudStorage", "GoogleDrive-an@example.com", "My Drive", "x.env"): "GoogleDrive",
		filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", "x.env"):                "iCloud Drive",
		filepath.Join(home, "Dropbox", "proj", ".env"):                                                    "Dropbox",
		filepath.Join(home, "code", ".env"):                                                               "",
	} {
		if got := syncedBy(home, p); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
	// A folder that is a link into a synced one counts as synced.
	target := filepath.Join(home, "Dropbox", "work")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, "work")); err == nil {
		writeTestFile(t, filepath.Join(target, ".env"), "x")
		if got := syncedBy(home, filepath.Join(home, "work", ".env")); got != "Dropbox" {
			t.Errorf("through a link: %q", got)
		}
	}
}

func TestGitHistoryOwnCommitsOnly(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	home := isolatedHome(t)
	repo := filepath.Join(home, "src", "upstream")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "init", "-q", "-b", "main")
	git(t, repo, "config", "user.email", "me@example.org") // not the commits' author (an@example.com)
	writeTestFile(t, filepath.Join(repo, "app.env"), "TOKEN=gh"+"p_"+strings.Repeat("Q7x9", 9)+"\n")
	writeTestFile(t, filepath.Join(repo, "node_modules", "x", "README.md"), "use sk-"+"ant-api03-"+strings.Repeat("Zq9X", 6)+"\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "upstream")
	found, repos, _, _ := ScanGitHistory(t.Context(), policy.Default().Checks.Secrets)
	if repos != 1 || len(found) != 0 {
		t.Errorf("someone else's commit: %d repos, %+v", repos, found)
	}
	git(t, repo, "config", "user.email", "An@Example.com") // the same address, another case
	if found, _, _, _ := ScanGitHistory(t.Context(), policy.Default().Checks.Secrets); len(found) != 1 || found[0].Kind != "GitHub token" {
		t.Errorf("own commit, node_modules left out: %+v", found)
	}
	for p, want := range map[string]bool{"api/.env.example": true, "src/db_test.go": true, "app/src/test/java/X.kt": true, "README.md": true,
		"deploy/prod.env": false, "src/config.ts": false} {
		if sampleFile(p) != want {
			t.Errorf("sampleFile(%s) = %v", p, !want)
		}
	}
	if !toolCache("~/.claude/plugins/cache/x") || toolCache("~/ClaudeCode/x") || !generatedPath("web/dist/app.js") || generatedPath("src/app.ts") {
		t.Error("toolCache / generatedPath")
	}
}
