package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/checks"
	"github.com/ptrinh/bordercheck/internal/ignore"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// ignoreTestEnv runs the ignore commands on a temporary install folder against
// made-up findings; nothing on this machine is scanned.
func ignoreTestEnv(t *testing.T, items []checks.Item) (ignoreEnv, *strings.Builder) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	out := &strings.Builder{}
	return ignoreEnv{dir: filepath.Join(t.TempDir(), "bordercheck"), pol: policy.Default(), out: out,
		now:  time.Date(2026, 11, 11, 10, 0, 0, 0, time.Local),
		scan: func() ([]checks.Item, string, error) { return items, home, nil }}, out
}

const sv = "Secret-looking variable"

var testItems = []checks.Item{
	{Check: "secrets", Path: "~/app/.env", Names: []string{"POSTGRES_PASSWORD"}, Kind: sv},
	{Check: "secrets", Path: "~/app/.env", Names: []string{"API_TOKEN"}, Kind: sv},
	{Check: "secrets", Path: "~/app/.env.production", Names: []string{"DB_PASSWORD"}, Kind: sv},
	{Check: "secrets", Path: "~/mixed/.env", Names: []string{"A_TOKEN"}, Kind: sv},
	{Check: "secrets", Path: "~/mixed/.env", Names: []string{"LIVE_TOKEN"}, Kind: sv},
	{Check: "ai-agents", Path: "~/.claude.json", Names: []string{"mcpServers.mcp-trinh.headers.Authorization", "Authorization"},
		Kind: "Claude Code: Token in an HTTP header in plain text"},
	{Check: "ai-agents", Path: "~/.codex/config.toml", Kind: "Codex: commands run without a sandbox", Blocked: checks.BlockedGuardrail},
	{Check: "ssh-keys", Path: "~/.ssh/aur", Names: []string{"ssh-ed25519"}, Kind: "no passphrase"},
	{Check: "ssh-keys", Path: "~/.ssh/open", Kind: "no passphrase", Blocked: checks.BlockedPerms},
	{Check: "ssh-keys", Path: "~/.ssh/authorized_keys", Names: []string{"bob@acme.com"}, Kind: "can log in here", Blocked: checks.BlockedAuthorized},
	{Check: "ssh-keys", Path: "~/.ssh/config", Names: []string{"ForwardAgent yes"}, Kind: "ForwardAgent yes", Blocked: checks.BlockedSSHConfig},
	// A file two checks find something in.
	{Check: "secrets", Path: "~/.continue/config.json", Names: []string{"apiKey"}, Kind: sv},
	{Check: "ai-agents", Path: "~/.continue/config.json", Names: []string{"apiKey"}, Kind: "Continue: Secret-looking variable in plain text"},
}

func load(t *testing.T, env ignoreEnv) []ignore.Entry {
	t.Helper()
	es, err := ignore.Load(env.dir)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func TestIgnoreByFileAndByName(t *testing.T) {
	env, out := ignoreTestEnv(t, testItems)
	if err := ignoreAdd(env, "", "~/app/.env", "POSTGRES_PASSWORD", "  local docker\ndatabase "); err != nil {
		t.Fatal(err)
	}
	if got := plural(2, "it", "them") + " " + plural(2, "1 entry", "%d entries"); got != "them 2 entries" {
		t.Errorf("plural: %q", got)
	}
	if s := out.String(); !strings.Contains(s, "for the secrets check: 1 finding no longer counts") || !strings.Contains(s, "IT will see it in the report") {
		t.Errorf("output: %s", s)
	}
	if err := ignoreAdd(env, "", "~/app/.env", "", "whole file is for tests"); err != nil {
		t.Fatal(err)
	}
	want := []ignore.Entry{{Check: "secrets", Path: "~/app/.env", Name: "POSTGRES_PASSWORD", Reason: "local docker database", Since: "2026-11-11"},
		{Check: "secrets", Path: "~/app/.env", Reason: "whole file is for tests", Since: "2026-11-11"}}
	if es := load(t, env); len(es) != 2 || es[0] != want[0] || es[1] != want[1] {
		t.Fatalf("saved: %+v", es)
	}
	// The same target again replaces its reason rather than adding a second entry.
	if err := ignoreAdd(env, "secrets", "~/app/.env", "", "new reason"); err != nil {
		t.Fatal(err)
	}
	if es := load(t, env); len(es) != 2 || es[1].Reason != "new reason" {
		t.Errorf("replace: %+v", es)
	}
	// A file with a production finding: it is ignored with the rest.
	out.Reset()
	if err := ignoreAdd(env, "", "~/mixed/.env", "", "sandbox"); err != nil || !strings.Contains(out.String(), "2 findings no longer count") {
		t.Errorf("mixed: %v %s", err, out)
	}
	// An absolute path names the same file; the entry keeps the report's spelling.
	_, home, _ := env.scan()
	if err := ignoreAdd(env, "", filepath.Join(home, "app", ".env"), "API_TOKEN", "fake"); err != nil {
		t.Fatal(err)
	}
	if es := load(t, env); len(es) != 4 || es[3].Path != "~/app/.env" || es[3].Name != "API_TOKEN" {
		t.Errorf("absolute path: %+v", es)
	}
}

func TestIgnoreAIAgentsAndSSHKeys(t *testing.T) {
	env, _ := ignoreTestEnv(t, testItems)
	// An AI config token, by the setting the evidence shows or by the header name.
	if err := ignoreAdd(env, "", "~/.claude.json", "mcpServers.mcp-trinh.headers.Authorization", "local MCP server, no secret behind it"); err != nil {
		t.Fatal(err)
	}
	if err := ignoreAdd(env, "ai-agents", "~/.claude.json", "Authorization", "same"); err != nil {
		t.Fatal(err)
	}
	// A key without a passphrase.
	if err := ignoreAdd(env, "", "~/.ssh/aur", "", "AUR upload key, nothing else"); err != nil {
		t.Fatal(err)
	}
	es := load(t, env)
	if len(es) != 3 || es[0].Check != "ai-agents" || es[2].Check != "ssh-keys" || es[2].Path != "~/.ssh/aur" {
		t.Errorf("saved: %+v", es)
	}
	// Two checks find something in one file: -check decides.
	err := ignoreAdd(env, "", "~/.continue/config.json", "", "r")
	if err == nil || !strings.Contains(err.Error(), "both secrets and ai-agents") || !strings.Contains(err.Error(), "-check") {
		t.Errorf("ambiguous: %v", err)
	}
	if err := ignoreAdd(env, "ai-agents", "~/.continue/config.json", "", "r"); err != nil {
		t.Error(err)
	}
}

func TestIgnoreRefuses(t *testing.T) {
	env, _ := ignoreTestEnv(t, testItems)
	for _, c := range []struct{ check, path, name, reason, want string }{
		{"", "~/app/.env", "", "", "a reason is required"},
		{"", "~/app/.env", "", strings.Repeat("x", ignore.MaxReason+1), "too long"},
		{"", "~/nothing/.env", "", "r", "finds nothing in"},
		{"ssh-keys", "~/app/.env", "", "r", "the ssh-keys check finds nothing in"},
		{"", "~/app/.env", "POSTGRES_PASSWRD", "r", "what the secrets check finds there: Secret-looking variable (POSTGRES_PASSWORD), Secret-looking variable (API_TOKEN)"},
		{"", "~/.codex/config.toml", "", "r", "is an AI agent guardrail"},
		{"", "~/.ssh/open", "", "r", "chmod 600 ~/.ssh/open"},
		{"", "~/.ssh/authorized_keys", "", "r", "who can log in to this computer is for IT to decide"},
		{"", "~/.ssh/config", "", "r", "an SSH client setting cannot be ignored"},
	} {
		err := ignoreAdd(env, c.check, c.path, c.name, c.reason)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s %q: got %v, want %q", c.path, c.name, c.reason, err, c.want)
		}
	}
	if _, err := os.Stat(filepath.Join(env.dir, ignore.FileName)); err == nil {
		t.Error("a refused ignore wrote the list")
	}
	for _, id := range []string{"secrets", "ai-agents", "ssh-keys"} {
		off := env
		off.pol = policy.Default()
		path := map[string]string{"secrets": "~/app/.env", "ai-agents": "~/.claude.json", "ssh-keys": "~/.ssh/aur"}[id]
		switch id {
		case "secrets":
			off.pol.Checks.Secrets.UserIgnore = false
		case "ai-agents":
			off.pol.Checks.AIAgents.UserIgnore = false
		case "ssh-keys":
			off.pol.Checks.SSHKeys.UserIgnore = false
		}
		if err := ignoreAdd(off, "", path, "", "r"); err == nil || !strings.Contains(err.Error(), "checks."+id+".user_ignore") {
			t.Errorf("%s policy off: %v", id, err)
		}
	}
	// An unreadable list is not overwritten.
	if err := os.MkdirAll(env.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.dir, ignore.FileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ignoreAdd(env, "", "~/app/.env", "", "r"); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("corrupt list: %v", err)
	}
}

func TestUnignoreAndList(t *testing.T) {
	env, out := ignoreTestEnv(t, testItems)
	if err := ignoreList(env); err != nil || !strings.Contains(out.String(), "Nothing is ignored") {
		t.Errorf("empty list: %v %s", err, out)
	}
	for _, name := range []string{"POSTGRES_PASSWORD", "API_TOKEN"} {
		if err := ignoreAdd(env, "", "~/app/.env", name, "test values"); err != nil {
			t.Fatal(err)
		}
	}
	if err := ignoreAdd(env, "", "~/.ssh/aur", "", "AUR key"); err != nil {
		t.Fatal(err)
	}
	// The finding goes away (the line was deleted): the entry stays, reported stale.
	env.scan = func() ([]checks.Item, string, error) {
		return testItems[1:], filepath.Join(t.TempDir(), "home"), nil
	}
	out.Reset()
	if err := ignoreList(env); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"[secrets] ~/app/.env (POSTGRES_PASSWORD): test values (since 2026-11-11)  [stale: matches nothing now]",
		"[secrets] ~/app/.env (API_TOKEN): test values (since 2026-11-11)  [1 finding]",
		"[ssh-keys] ~/.ssh/aur: AUR key (since 2026-11-11)  [1 finding]",
		"1 stale entry matches nothing",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("list lacks %q:\n%s", want, s)
		}
	}
	if es := load(t, env); len(es) != 3 {
		t.Errorf("a stale entry was removed: %+v", es)
	}

	if err := ignoreRemove(env, "", "~/app/.env", "POSTGRES_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	if es := load(t, env); len(es) != 2 || es[0].Name != "API_TOKEN" {
		t.Errorf("after unignore -name: %+v", es)
	}
	if err := ignoreRemove(env, "", "~/app/.env", "POSTGRES_PASSWORD"); err == nil {
		t.Error("removing it twice should say nothing is ignored")
	}
	if err := ignoreRemove(env, "ai-agents", "~/.ssh/aur", ""); err == nil {
		t.Error("-check should narrow unignore")
	}
	if err := ignoreRemove(env, "", "~/app/.env", ""); err != nil {
		t.Fatal(err)
	}
	if es := load(t, env); len(es) != 1 || es[0].Check != "ssh-keys" {
		t.Errorf("after unignore: %+v", es)
	}

	// The policy turns it off for a check: the list says its entries are not applied.
	env.pol.Checks.SSHKeys.UserIgnore = false
	out.Reset()
	if err := ignoreList(env); err != nil || !strings.Contains(out.String(), "[ssh-keys] ~/.ssh/aur: AUR key (since 2026-11-11)  [not applied") {
		t.Errorf("policy off: %v %s", err, out)
	}
	// A corrupt list is reported, not a crash.
	if err := os.WriteFile(filepath.Join(env.dir, ignore.FileName), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := ignoreList(env); err != nil || !strings.Contains(out.String(), "cannot be read") {
		t.Errorf("corrupt: %v %s", err, out)
	}
}
