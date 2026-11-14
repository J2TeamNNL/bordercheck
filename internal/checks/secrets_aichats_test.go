package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// Tokens built at run time, so no secret-shaped string sits in this file.
var (
	chatGH  = "gh" + "p_" + strings.Repeat("a1B2", 9)
	chatAnt = "sk-" + "ant-api03-" + strings.Repeat("Zq9X", 6)
	chatURL = "postgres://app:" + "s3cretPw9@db.internal:5432/app"
)

func TestScanChatFindsEachSecretOncePerConversation(t *testing.T) {
	s := testScanner(t, policy.Default().Checks.Secrets)
	data := strings.Join([]string{
		`{"type":"user","message":{"content":"here is my token ` + chatGH + `"}}`,
		`{"type":"assistant","message":{"content":"Got it: ` + chatGH + ` (same one again)"}}`,
		`{"type":"tool_result","content":"ANTHROPIC_API_KEY=` + chatAnt + `\nDATABASE_URL=` + chatURL + `"}`,
		// Not secrets: examples, words that merely start like a token, a key's name, code.
		`{"content":"AKIAIOSFODNN7EXAMPLE and ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx and sk-learn-is-a-library-name"}`,
		`{"content":"task-disk-encryption ask-me risk-free API_KEY = os.environ[\"API_KEY\"] https://example.com/x"}`,
		`{"content":"postgres://user:${PASSWORD}@host/db and https://user:password@host"}`,
		// Passwords, in a .env pasted as text and in JSON quoted inside JSON.
		`{"content":"DB_PASSWORD=Tr0ub4dor-x9 and {\"admin_password\": \"n7Kq2pLw8\"}"}`,
		// A pasted key, and code that only names one.
		`{"content":"-----BEGIN OPENSSH PRIVATE KEY-----\n` + strings.Repeat("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUA\\n", 5) + `-----END OPENSSH PRIVATE KEY-----"}`,
		`{"content":"if strings.HasPrefix(pem, \"-----BEGIN PRIVATE KEY-----\") { return nil }"}`,
		// The name after a JSON line break; a hash is not a password.
		`{"content":"line one\nPassword=Xk29dLq7w and password_hash=9f8e7d6c5b4a3f2e"}`,
		// Code that only names a password.
		`{"content":"password = os.environ[\"DB_PASSWORD\"]; set_password(new_password_value); password: str"}`,
	}, "\n")
	got := s.scanChat([]byte(data), "~/.claude/projects/p/s.jsonl", true, nil)
	var lines []string
	for _, f := range got {
		if !f.chat {
			t.Errorf("%v not marked as a chat finding", f)
		}
		lines = append(lines, f.String())
	}
	want := []string{
		"~/.claude/projects/p/s.jsonl:1  GitHub token …" + chatGH[len(chatGH)-4:],
		"~/.claude/projects/p/s.jsonl:3  Anthropic API key …" + chatAnt[len(chatAnt)-4:],
		"~/.claude/projects/p/s.jsonl:3  Password in URL",
		"~/.claude/projects/p/s.jsonl:7  Password (DB_PASSWORD)",
		"~/.claude/projects/p/s.jsonl:7  Password (admin_password)",
		"~/.claude/projects/p/s.jsonl:8  Private key",
		"~/.claude/projects/p/s.jsonl:10  Password (Password)",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range lines {
		if strings.Contains(l, chatGH) || strings.Contains(l, chatAnt) || strings.Contains(l, "s3cretPw9") ||
			strings.Contains(l, "Tr0ub4dor") || strings.Contains(l, "n7Kq2pLw8") || strings.Contains(l, "Xk29dLq7w") {
			t.Errorf("a secret is in the finding: %s", l)
		}
	}
	// Read from the end of a file, offsets are not line numbers.
	if got := s.scanChat([]byte(data), "~/x.jsonl", false, nil); len(got) != len(want) || got[0].line != 0 {
		t.Errorf("without lines: %v", got)
	}
}

func writeChat(t *testing.T, p, body string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestScanChatsReadsRecentConversationsWithinBudget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	day := 24 * time.Hour
	// Older messages first, the token in the newest: a file read from its end keeps it.
	line := `{"older":"` + strings.Repeat("words ", 40) + `","content":"` + chatGH + `"}` + "\n"
	writeChat(t, filepath.Join(home, ".claude", "projects", "-Users-an-app", "s1.jsonl"), line, day)
	writeChat(t, filepath.Join(home, ".claude", "projects", "-Users-an-app", "s1", "subagents", "agent-1.jsonl"), line, day)
	writeChat(t, filepath.Join(home, ".codex", "sessions", "2026", "11", "13", "rollout-1.jsonl"), `{"older":"`+strings.Repeat("words ", 40)+`","x":"`+chatAnt+`"}`+"\n", 2*day)
	writeChat(t, filepath.Join(home, ".claude", "projects", "-Users-an-old", "old.jsonl"), line, 40*day) // too old
	writeChat(t, filepath.Join(home, ".claude", "projects", "-Users-an-app", "notes.txt"), line, day)    // not a conversation
	s := testScanner(t, policy.Default().Checks.Secrets)
	none := func(string) bool { return false }
	monthAgo := time.Now().AddDate(0, 0, -30)

	got, partial := s.scanChats(t.Context(), home, monthAgo, 1<<20, none)
	if len(got) != 3 || partial {
		t.Fatalf("partial %v, found %v", partial, got)
	}
	// Ignored paths are left out; a budget of 0 reads nothing.
	ign := func(p string) bool { return strings.Contains(filepath.ToSlash(p), "/.codex/") }
	if got, _ := s.scanChats(t.Context(), home, monthAgo, 1<<20, ign); len(got) != 2 {
		t.Errorf("with .codex ignored: %v", got)
	}
	if got, _ := s.scanChats(t.Context(), home, monthAgo, 0, none); got != nil {
		t.Errorf("days 0: %v", got)
	}
	// A budget smaller than the files: the newest is read from its end, and the scan says it stopped.
	got, partial = s.scanChats(t.Context(), home, monthAgo, 10, none)
	if !partial || len(got) != 0 {
		t.Errorf("small budget: partial %v, %v", partial, got)
	}
	// Two files' worth: each may take a quarter of it, half of each file, read from
	// the end, which still holds its token; the scan says it left some unread.
	got, partial = s.scanChats(t.Context(), home, monthAgo, int64(2*len(line)), none)
	if !partial || len(got) != 3 || got[0].line != 0 {
		t.Errorf("two files' worth: partial %v, %v", partial, got)
	}

	// CLAUDE_CONFIG_DIR moves Claude Code's folder.
	other := t.TempDir()
	writeChat(t, filepath.Join(other, "projects", "p", "s.jsonl"), line, day)
	t.Setenv("CLAUDE_CONFIG_DIR", other)
	if got, _ := s.scanChats(t.Context(), t.TempDir(), monthAgo, 1<<20, none); len(got) != 1 || !strings.HasPrefix(got[0].path, other) {
		t.Errorf("CLAUDE_CONFIG_DIR: %v", got)
	}
}

func TestChatFindingsAreInformation(t *testing.T) {
	fix := secretFix()
	chat := secretFinding{path: "~/.claude/projects/p/s.jsonl", line: 4, kind: "Stripe live key", severe: true, chat: true}
	env := secretFinding{path: "~/app/.env", line: 1, kind: "GitHub token"}

	// Only in chats, even a high-severity kind: the check passes and says so.
	r := evalSecrets([]secretFinding{chat}, nil, false, fix)
	if r.Status != "pass" || !strings.Contains(r.Summary, "bordercheck full-scan") || !strings.Contains(r.Summary, "For information: 1 secret") ||
		strings.Contains(r.Summary, "No plain-text secrets in shell files, shell history, credential files, .env files or recent") {
		t.Errorf("chat only: %s %q", r.Status, r.Summary)
	}
	if len(r.Evidence) != 1 || !strings.HasSuffix(r.Evidence[0], "[AI chat, information]") {
		t.Errorf("evidence %q", r.Evidence)
	}
	// With another finding: judged by that one alone, the chat named as well.
	r = evalSecrets([]secretFinding{env, chat}, nil, false, fix)
	if r.Status != "warn" || r.Severity != "medium" || !strings.Contains(r.Summary, "1 secret in plain text across 1 file") ||
		!strings.Contains(r.Summary, "For information") || len(r.Evidence) != 2 {
		t.Errorf("with another: %s %s %q %q", r.Status, r.Severity, r.Summary, r.Evidence)
	}
	// Nothing anywhere.
	if r := evalSecrets(nil, nil, false, fix); r.Status != "pass" || strings.Contains(r.Summary, "For information") {
		t.Errorf("none: %q", r.Summary)
	}
}

func TestChatContext(t *testing.T) {
	s := testScanner(t, policy.Default().Checks.Secrets)
	pw := "Zq7" + "pLw9mKx2Tr"
	lines := strings.Join([]string{
		`{"display":"connect with postgres://app:` + pw + `@db.internal:5432/app please","timestamp":1762160100000,"project":"/Users/an/api"}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","content":"DB_PASSWORD=` + pw + `x"}]}}`,
		`{"timestamp":"2026-11-02T10:00:00Z","type":"response_item","payload":{"role":"assistant","content":"short PASSWORD=a1b2c3d4"}}`,
	}, "\n")
	got := s.scanChat([]byte(lines), "~/.codex/history.jsonl", true, nil)
	if len(got) != 3 {
		t.Fatalf("found %v", got)
	}
	url, tool, asst := got[0].ctx, got[1].ctx, got[2].ctx
	if url.source != "prompt" || url.host != "db.internal:5432" || url.project != "/Users/an/api" || url.when.Format("2006-01-02") != "2025-11-03" || url.tail != "x2Tr" {
		t.Errorf("url: %+v", url)
	}
	if tool.source != "tool" || tool.tail != "2Trx" {
		t.Errorf("tool: %+v", tool)
	}
	// A password under 12 characters: no tail.
	if asst.source != "assistant" || asst.tail != "" || asst.when.Format("2006-01-02") != "2026-11-02" {
		t.Errorf("assistant: %+v", asst)
	}
	// None of it reaches a report.
	for _, f := range got {
		if strings.Contains(f.String(), "x2Tr") || strings.Contains(f.String(), "db.internal") {
			t.Errorf("report line has chat details: %s", f)
		}
	}
}

func TestScanAIChatsReadsAllOfIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	cwd, _ := json.Marshal(filepath.Join(home, "app")) // as the assistant writes it: C:\\Users\\… on Windows
	line := `{"type":"user","cwd":` + string(cwd) + `,"timestamp":"2026-11-03T09:15:00.000Z","message":{"content":"` + chatGH + `"}}` + "\n"
	writeChat(t, filepath.Join(home, ".claude", "projects", "p", "new.jsonl"), line, time.Hour)
	writeChat(t, filepath.Join(home, ".claude", "projects", "p", "old.jsonl"), line, 400*24*time.Hour)
	p := policy.Default().Checks.Secrets
	all, err := ScanAIChats(t.Context(), p, time.Time{})
	if err != nil || len(all) != 2 {
		t.Fatalf("all: %v %v", err, all)
	}
	f := all[0]
	if f.Item() != "GitHub token …"+chatGH[len(chatGH)-4:] || filepath.ToSlash(f.Where()) != "~/.claude/projects/p/new.jsonl, line 1" {
		t.Errorf("first: %q %q", f.Item(), f.Where())
	}
	if got, want := filepath.ToSlash(f.Explain(home)), "Claude Code, in ~/app, 3 Nov 2026, in a message you sent. Access to GitHub as you: your repositories, and possibly your organisation's."; got != want {
		t.Errorf("explain:\n got %s\nwant %s", got, want)
	}
	// new.jsonl changed an hour ago, but its message says 3 Nov 2026: not in the last 48 hours of 2030.
	if recent, _ := ScanAIChats(t.Context(), p, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); len(recent) != 0 {
		t.Errorf("message older than since: %v", recent)
	}
	if recent, _ := ScanAIChats(t.Context(), p, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)); len(recent) != 1 {
		t.Errorf("since 1 Nov: %v", recent)
	}
	if !strings.Contains(ChatFix(), "~/.claude/projects") || strings.Contains(ChatFix(), "[code]") {
		t.Errorf("fix: %s", ChatFix())
	}
}

func TestChatInfoSuggestsTheGuard(t *testing.T) {
	chat := secretFinding{path: "~/.claude/projects/p/s.jsonl", line: 4, kind: "GitHub token", chat: true}
	r := evalSecretsSamples([]secretFinding{chat}, nil, false, chatState{unguarded: true}, secretFix(), nil, nil)
	if !strings.Contains(r.Summary, "bordercheck guard install") {
		t.Errorf("unguarded: %q", r.Summary)
	}
	r = evalSecretsSamples([]secretFinding{chat}, nil, false, chatState{}, secretFix(), nil, nil)
	if strings.Contains(r.Summary, "guard") {
		t.Errorf("guarded: %q", r.Summary)
	}
	// Nothing found anywhere, Claude Code used without the guard: suggested all the same.
	r = evalSecretsSamples(nil, nil, false, chatState{unguarded: true}, secretFix(), nil, nil)
	if r.Status != "pass" || !strings.Contains(r.Summary, "bordercheck guard install") {
		t.Errorf("clean machine: %s %q", r.Status, r.Summary)
	}
}

func TestEveryPromptCountsButOnlyRecentConversation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	old := `"timestamp":"2025-01-02T03:04:05Z"`
	// A prompt typed long ago, in a history file last written months ago too.
	writeChat(t, filepath.Join(home, ".claude", "history.jsonl"),
		`{"display":"token `+chatGH+`","timestamp":1735787045000}`+"\n", 90*24*time.Hour)
	// A conversation written to today, whose message with the key is old.
	writeChat(t, filepath.Join(home, ".claude", "projects", "p", "s.jsonl"),
		`{"type":"user",`+old+`,"message":{"content":"`+chatAnt+`"}}`+"\n"+`{"type":"assistant","message":{"content":"ok"}}`+"\n", time.Hour)
	s := testScanner(t, policy.Default().Checks.Secrets)
	got, _ := s.scanChats(t.Context(), home, time.Now().Add(-48*time.Hour), 1<<20, func(string) bool { return false })
	if len(got) != 1 || filepath.ToSlash(got[0].path) != "~/.claude/history.jsonl" || got[0].kind != "GitHub token" {
		t.Errorf("48 hours: %v", got)
	}
	// A budget smaller than the prompt history still reads all of it.
	if got, _ := s.scanChats(t.Context(), home, time.Now().Add(-48*time.Hour), 8, func(string) bool { return false }); len(got) != 1 {
		t.Errorf("small budget: %v", got)
	}
}

func TestEncodedStringsAreSkipped(t *testing.T) {
	img := strings.Repeat("iVBORw0KGgoAAAANSUhEUg+/", 100) // 2,400 base64 characters
	sig := strings.Repeat("EpYBCkYIBRgCKkB_-", 80)
	short := "eyJhbGciOiJI"
	// A token-shaped string inside an image's base64 is not a token.
	inImg := img[:1200] + chatGH + img[1200:]
	data := []byte(`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + inImg + `"}}` + "\n" +
		`{"type":"thinking","signature":"` + sig + `"}` + "\n" +
		`{"content":"![x](data:image/png;base64,` + img + `) and {\"data\":\"` + short + `\"} ` + chatAnt + `"}` + "\n")
	segs, text := textSegments(data)
	if want := len(data) - len(inImg) - len(sig) - len(img); text != want || len(segs) != 4 {
		t.Fatalf("text %d, want %d; segments %v", text, want, segs)
	}
	s := testScanner(t, policy.Default().Checks.Secrets)
	got := s.scanChatIn(data, segs, "~/x.jsonl", true, nil)
	if len(got) != 1 || got[0].line != 3 || got[0].kind != "Anthropic API key" {
		t.Errorf("found %v", got)
	}
	// A short "data" string, or text that is not base64, is searched.
	if _, text := textSegments([]byte(`{"data":"` + strings.Repeat("hello world ", 200) + `"}`)); text == 0 {
		t.Error("prose taken for an encoded string")
	}
}

func TestAiderHistories(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	proj := filepath.Join(home, "code", "api")
	writeChat(t, filepath.Join(proj, aiderChat), "\n# aider chat started at 2026-11-03 09:15:00\n\n#### deploy with "+chatGH+"\n\nSure.\n\n> Run shell command? DB_PASSWORD=Tr0ub4dor-x9\n", time.Hour)
	writeChat(t, filepath.Join(proj, aiderInput), "\n# 2024-05-06 07:08:09.123456\n+use "+chatAnt+"\n", 300*24*time.Hour)
	all, err := ScanAIChats(t.Context(), policy.Default().Checks.Secrets, time.Time{})
	if err != nil || len(all) != 3 {
		t.Fatalf("%v %+v", err, all)
	}
	byKind := map[string]ChatFinding{}
	for _, f := range all {
		byKind[f.Kind] = f
	}
	gh, pw, ant := byKind["GitHub token"], byKind["Password"], byKind["Anthropic API key"]
	if gh.App() != "Aider" || gh.Source != "user" || gh.When.Format("2006-01-02 15:04") != "2026-11-03 09:15" || filepath.ToSlash(gh.Project) != "~/code/api" {
		t.Errorf("chat: %+v", gh)
	}
	if pw.Source != "tool" || ant.Source != "prompt" || ant.When.Year() != 2024 || ant.App() != "Aider" {
		t.Errorf("tool %+v / typed %+v", pw, ant)
	}
	if got := filepath.ToSlash(gh.Explain(home)); !strings.HasPrefix(got, "Aider, in ~/code/api, 3 Nov 2026, in a message you sent.") {
		t.Errorf("explain: %s", got)
	}
}

func TestOtherAssistants(t *testing.T) {
	home := t.TempDir()
	for _, v := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "COPILOT_HOME", "CLINE_DATA_DIR", "CLINE_DIR",
		"XDG_CONFIG_HOME", "AIDER_CHAT_HISTORY_FILE", "AIDER_INPUT_HISTORY_FILE"} {
		t.Setenv(v, "")
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	tok := func(i int) string { return "gh" + "p_" + strings.Repeat("a1B"+string(rune('A'+i)), 9) }
	code := vscodeUserDirs(home, runtime.GOOS)[0] // VS Code's own
	cursorEd := vscodeUserDirs(home, runtime.GOOS)[3]
	want := map[string]string{ // file → assistant; each holds its own token
		filepath.Join(home, ".gemini", "tmp", "api", "chats", "session-2026-11-03T09-15-ab12cd34.jsonl"):       "Gemini CLI",
		filepath.Join(home, ".gemini", "tmp", "api", "logs.json"):                                              "Gemini CLI",
		filepath.Join(home, ".gemini", "tmp", "api", "checkpoint-before.json"):                                 "Gemini CLI",
		filepath.Join(home, ".codex", "archived_sessions", "rollout-1.jsonl"):                                  "Codex",
		filepath.Join(home, ".copilot", "session-state", "0b1c", "events.jsonl"):                               "Copilot CLI",
		filepath.Join(home, ".cursor", "projects", "api", "agent-transcripts", "t1.jsonl"):                     "Cursor",
		filepath.Join(home, ".cursor", "prompt_history.json"):                                                  "Cursor",
		filepath.Join(code, "workspaceStorage", "9f3e", "chatSessions", "s1.jsonl"):                            "VS Code chat",
		filepath.Join(cursorEd, "globalStorage", "emptyWindowChatSessions", "s2.json"):                         "VS Code chat",
		filepath.Join(home, ".cline", "data", "tasks", "171", "api_conversation_history.json"):                 "Cline",
		filepath.Join(code, "globalStorage", "rooveterinaryinc.roo-cline", "tasks", "172", "ui_messages.json"): "Cline",
		filepath.Join(home, ".cline", "data", "sessions", "s9", "s9.messages.json"):                            "Cline",
	}
	notChats := []string{ // same folders, not conversations
		filepath.Join(home, ".cursor", "projects", "api", "settings.jsonl"),
		filepath.Join(code, "workspaceStorage", "9f3e", "workspace.json"),
		filepath.Join(home, ".cline", "data", "tasks", "171", "task_metadata.json"),
	}
	i := 0
	for p := range want {
		writeChat(t, p, `{"type":"user","content":"`+tok(i)+`"}`+"\n", time.Hour)
		i++
	}
	for _, p := range notChats {
		writeChat(t, p, `{"content":"`+tok(20)+`"}`+"\n", time.Hour)
	}
	all, err := ScanAIChats(t.Context(), policy.Default().Checks.Secrets, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range all {
		got[f.Path] = f.App()
	}
	for p, app := range want {
		if shown := tildePath(home, p); got[shown] != app {
			t.Errorf("%s: %q, want %q", shown, got[shown], app)
		}
	}
	if len(all) != len(want) {
		t.Errorf("%d found, want %d: %v", len(all), len(want), got)
	}
}

func TestCredentialStoresGetTheirOwnFix(t *testing.T) {
	general := secretFix()
	azure := secretFinding{path: "~/.azure/msal_token_cache.json", kind: "Azure CLI token cache (plain text)"}
	gh := secretFinding{path: "~/.config/gh/hosts.yml", kind: "GitHub CLI token"}
	env := secretFinding{path: "~/app/.env", line: 1, kind: "GitHub token"}

	r := evalSecrets([]secretFinding{azure}, nil, false, general)
	if !strings.Contains(r.Fix, "az logout") || strings.Contains(r.Fix, "touchenv set NAME, then") || !strings.Contains(r.Fix, "Rotate a key only") {
		t.Errorf("azure only: %s", r.Fix)
	}
	r = evalSecrets([]secretFinding{azure, gh, env}, nil, false, general)
	for _, want := range []string{"az logout", "gh auth login", "then delete the line or file", "Rotate a key only"} {
		if !strings.Contains(r.Fix, want) {
			t.Errorf("mixed: no %q in %s", want, r.Fix)
		}
	}
	if r := evalSecrets([]secretFinding{env}, nil, false, general); strings.Contains(r.Fix, "az logout") {
		t.Errorf("plain: %s", r.Fix)
	}
}

func TestChatFalsePositives(t *testing.T) {
	s := testScanner(t, policy.Default().Checks.Secrets)
	data := strings.Join([]string{
		// Passwords in code: a field, another variable, a query string.
		`{"content":"password: process.env.E2E_DB_URL2, password = settings.db.pass9, PASSWORD=DATABASE_PASSWORD2, password=x1&sslmode=require"}`,
		// A pattern, prose and examples, not URLs with logins.
		"{\"content\":\"re := `^postgres://[^:]+:([^@]+)@.*|` and `smtp://user:pa55word@host:587` and https://u:pw123456@db.example.com/x\"}",
		// Real ones still found.
		`{"content":"DB_URL=postgres://app:Zq7pLw9mKx2@db.prod-eu.internal.corp:5432/app and password: Tr0ub4dor-x9"}`,
	}, "\n")
	var got []string
	for _, f := range s.scanChat([]byte(data), "~/x.jsonl", true, nil) {
		got = append(got, f.String())
	}
	want := []string{"~/x.jsonl:3  Password in URL", "~/x.jsonl:3  Password (password)"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s", strings.Join(got, "\n"))
	}
}

func TestRepeatedSecretListsEveryLine(t *testing.T) {
	s := testScanner(t, policy.Default().Checks.Secrets)
	data := "a " + chatGH + "\nb\nc " + chatGH + " and again " + chatGH + "\nd " + chatGH + "\n"
	got := s.scanChat([]byte(data), "~/x.jsonl", true, nil)
	if len(got) != 1 || got[0].line != 1 || got[0].ctx.rep.times != 4 || fmt.Sprint(got[0].ctx.rep.lines) != "[1 3 4]" {
		t.Fatalf("%+v", got)
	}
	f := ChatFinding{Path: "~/x.jsonl", Line: 1, Times: 4, Lines: []int{1, 3, 4}}
	if f.Where() != "~/x.jsonl, lines 1, 3, 4" {
		t.Errorf("where: %s", f.Where())
	}
	if w := (ChatFinding{Path: "~/x.jsonl", Line: 7, Times: 2, Lines: []int{7}}).Where(); w != "~/x.jsonl, line 7 (2 times on it)" {
		t.Errorf("one line: %s", w)
	}
	if w := (ChatFinding{Path: "~/x.jsonl", Times: 3}).Where(); w != "~/x.jsonl (3 times)" {
		t.Errorf("no lines: %s", w)
	}
}

func TestCloudSignInsAreInformation(t *testing.T) {
	azure := secretFinding{path: "~/.azure/msal_token_cache.json", kind: "Azure CLI token cache (plain text)", signIn: true}
	env := secretFinding{path: "~/app/.env", line: 1, kind: "GitHub token"}

	r := evalSecrets([]secretFinding{azure}, nil, false, secretFix())
	if r.Status != "pass" || !strings.Contains(r.Summary, "For information: 1 cloud CLI sign-in") || !strings.Contains(r.Summary, "az logout") ||
		!strings.HasPrefix(r.Summary, "No plain-text secrets that count") {
		t.Errorf("sign-in only: %s %q", r.Status, r.Summary)
	}
	if len(r.Evidence) != 1 || !strings.HasSuffix(r.Evidence[0], "[sign-in, information]") {
		t.Errorf("evidence %q", r.Evidence)
	}
	r = evalSecrets([]secretFinding{azure, env}, nil, false, secretFix())
	if r.Status != "warn" || !strings.Contains(r.Summary, "1 secret in plain text across 1 file") || strings.Contains(r.Fix, "az logout") {
		t.Errorf("with another: %s %q %q", r.Status, r.Summary, r.Fix)
	}
	// Without the policy's cli_sign_ins_info the scan does not mark it: a warning, as before.
	azure.signIn = false
	if r := evalSecrets([]secretFinding{azure}, nil, false, secretFix()); r.Status != "warn" {
		t.Errorf("policy off: %s", r.Status)
	}
}

func TestFullScanSuggestedUntilRun(t *testing.T) {
	if r := evalSecretsSamples(nil, nil, false, chatState{fullScanNever: true}, secretFix(), nil, nil); r.Status != "pass" ||
		!strings.Contains(r.Summary, "run bordercheck full-scan once") {
		t.Errorf("never run: %q", r.Summary)
	}
	if r := evalSecretsSamples(nil, nil, false, chatState{}, secretFix(), nil, nil); strings.Contains(r.Summary, "full-scan") {
		t.Errorf("run before: %q", r.Summary)
	}
}
