package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/checks"
)

// Made-up findings: nothing on this machine is scanned.
var testChats = []checks.ChatFinding{
	{Path: "~/.claude/projects/p/s.jsonl", Line: 12, Kind: "GitHub token", Tail: "a1B2", Source: "prompt",
		Project: "/home/an/app", When: time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)},
	{Path: "~/.codex/sessions/2026/11/03/r.jsonl", Kind: "Password", Name: "DB_PASSWORD", Source: "tool"},
}

func TestWriteChatsText(t *testing.T) {
	var b strings.Builder
	if code := writeChats(&b, testChats, 0, "all of the AI chat history", "/home/an", false); code != 1 {
		t.Errorf("exit %d", code)
	}
	for _, want := range []string{
		"2 secret(s) in 2 conversation(s), in all of the AI chat history, newest first. Values are not shown.",
		"  1. GitHub token …a1B2\n     Where: ~/.claude/projects/p/s.jsonl, line 12\n     What:  Claude Code, in ~/app, 3 Nov 2026, typed or pasted into the prompt. Access to GitHub",
		"  2. Password (DB_PASSWORD)\n     Where: ~/.codex/sessions/2026/11/03/r.jsonl\n     What:  Codex, in the output of a command or tool the assistant ran. A password, assigned to DB_PASSWORD.",
		"delete that conversation",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
	b.Reset()
	if code := writeChats(&b, nil, 48, "AI chat history from the last 48 hours", "/home/an", false); code != 0 || b.String() != "No secrets found in AI chat history from the last 48 hours.\n" {
		t.Errorf("none: %d %q", code, b.String())
	}
}

func TestWriteChatsJSON(t *testing.T) {
	var b strings.Builder
	if code := writeChats(&b, testChats, 0, "", "/home/an", true); code != 1 {
		t.Errorf("exit %d", code)
	}
	var out struct {
		Hours    int `json:"hours"`
		Findings []struct {
			Path, Kind, Name, Tail, Source, Project, App, Explain string
			Line                                                  int
			When                                                  *time.Time
		} `json:"findings"`
		Fix string `json:"fix"`
	}
	if err := json.Unmarshal([]byte(b.String()), &out); err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	f := out.Findings
	if len(f) != 2 || f[0].Tail != "a1B2" || f[0].Line != 12 || f[0].App != "Claude Code" || f[0].When == nil ||
		f[1].App != "Codex" || f[1].When != nil || f[1].Name != "DB_PASSWORD" || out.Fix == "" {
		t.Errorf("%+v", out)
	}
	b.Reset()
	if code := writeChats(&b, nil, 48, "", "/home/an", true); code != 0 || !strings.Contains(b.String(), `"findings": []`) || strings.Contains(b.String(), `"fix"`) {
		t.Errorf("none: %d %s", code, b.String())
	}
}

func TestGuardPrompt(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no installed policy: the built-in one
	gh := "gh" + "p_" + strings.Repeat("a1B2", 9)
	run := func(prompt string) (int, string) {
		ev, _ := json.Marshal(map[string]string{"prompt": prompt, "hook_event_name": "UserPromptSubmit"})
		var errOut strings.Builder
		return guardPrompt(strings.NewReader(string(ev)), &errOut), errOut.String()
	}
	code, msg := run("deploy with this token: " + gh + " please")
	if code != 2 || !strings.Contains(msg, "GitHub token …a1B2") || strings.Contains(msg, gh) || !strings.Contains(msg, "#allow-secret") {
		t.Errorf("token: %d %q", code, msg)
	}
	for _, ok := range []string{
		"refactor the password reset flow and the API_KEY handling",
		"use postgres://user:${DB_PASSWORD}@localhost/app",
		"this is a test value, send it anyway #allow-secret " + gh,
	} {
		if code, msg := run(ok); code != 0 || msg != "" {
			t.Errorf("%q stopped: %s", ok, msg)
		}
	}
	// Anything it cannot read goes through.
	var errOut strings.Builder
	for _, in := range []string{"", "not json", `{"prompt": 5}`} {
		if code := guardPrompt(strings.NewReader(in), &errOut); code != 0 {
			t.Errorf("%q: %d", in, code)
		}
	}
}

func TestGuardCommand(t *testing.T) {
	run := func(cmd string) (int, string) {
		ev, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": cmd}})
		var errOut strings.Builder
		return guardCommand(strings.NewReader(string(ev)), &errOut), errOut.String()
	}
	if code, msg := run("cat .env"); code != 2 || !strings.Contains(msg, "BorderCheck refused this command") {
		t.Errorf("cat .env: %d %q", code, msg)
	}
	if code, msg := run("go test ./..."); code != 0 || msg != "" {
		t.Errorf("go test: %d %q", code, msg)
	}
	var errOut strings.Builder
	if code := guardCommand(strings.NewReader("not json"), &errOut); code != 0 {
		t.Errorf("unreadable: %d", code)
	}
}

func TestGuardOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	gh := "gh" + "p_" + strings.Repeat("a1B2", 9)
	pw := "Zq7" + "pLw9mKx2Tr"
	ev, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_response": map[string]any{
		"stdout": "deploying with " + gh + "\nDB_PASSWORD=" + pw + "\n", "stderr": "", "interrupted": false, "isImage": false}})
	var out strings.Builder
	if code := guardOutput(strings.NewReader(string(ev)), &out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var reply struct {
		HookSpecificOutput struct {
			HookEventName     string         `json:"hookEventName"`
			UpdatedToolOutput map[string]any `json:"updatedToolOutput"`
			AdditionalContext string         `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out.String()), &reply); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	h := reply.HookSpecificOutput
	if h.HookEventName != "PostToolUse" || h.UpdatedToolOutput["stdout"] != "deploying with ***REDACTED***\nDB_PASSWORD=***REDACTED***\n" ||
		h.UpdatedToolOutput["interrupted"] != false || h.UpdatedToolOutput["isImage"] != false || h.UpdatedToolOutput["stderr"] != "" {
		t.Errorf("updated: %+v", h.UpdatedToolOutput)
	}
	if strings.Contains(out.String(), gh) || strings.Contains(out.String(), pw) || !strings.Contains(h.AdditionalContext, "2 secret(s)") {
		t.Errorf("reply: %s", out.String())
	}
	// Nothing to hide, or nothing readable: no reply at all.
	for _, in := range []string{`{"tool_response":{"stdout":"ok\n","stderr":""}}`, "x", `{}`} {
		out.Reset()
		if code := guardOutput(strings.NewReader(in), &out); code != 0 || out.Len() != 0 {
			t.Errorf("%s: %d %q", in, code, out.String())
		}
	}
}

func TestWriteGit(t *testing.T) {
	var b strings.Builder
	found := []checks.GitFinding{{Repo: "~/code/api", Commit: "bf08e167", Date: "2026-03-02", File: ".env", Kind: "GitHub token", Tail: "Q7x9", Commits: 2, Pushed: true}}
	if code := writeGit(&b, found, 3, []string{"~/big"}); code != 1 {
		t.Errorf("exit %d", code)
	}
	for _, want := range []string{"== Git history (3 repositories)", "Read only in part (too large or too slow): ~/big",
		"  1. GitHub token …Q7x9\n     Where: ~/code/api, commit bf08e167 (2026-03-02), .env (added in 2 commits)\n     State: no longer in the current files, still in the history; pushed to a remote.",
		"git filter-repo"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("no %q in:\n%s", want, b.String())
		}
	}
	b.Reset()
	if code := writeGit(&b, nil, 2, nil); code != 0 || !strings.Contains(b.String(), "No secrets found in git history.") {
		t.Errorf("none: %d %s", code, b.String())
	}
}
