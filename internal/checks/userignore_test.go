package checks

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/ignore"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// ui is a person's list for one check, applied.
func ui(id string, es ...ignore.Entry) *userIgnore {
	for i := range es {
		es[i].Check = id
	}
	return newUserIgnore(id, Local{Ignored: es}, true, "/home/an")
}

func TestEvalSecretsUserIgnored(t *testing.T) {
	found := []secretFinding{
		{path: "~/app/.env", line: 1, kind: "Secret-looking variable", name: "POSTGRES_PASSWORD"},
		{path: "~/app/.env", line: 2, kind: "Secret-looking variable", name: "REDIS_PASSWORD"},
		{path: "~/app/.env.production", line: 1, kind: "Secret-looking variable", name: "DB_PASSWORD", prod: true},
		{path: "~/.zshrc", line: 9, kind: "OpenAI API key", name: "OPENAI_API_KEY", tail: "ab12"},
	}
	byName := ignore.Entry{Path: "~/app/.env", Name: "POSTGRES_PASSWORD", Reason: "local docker db", Since: "2026-11-01"}
	byFile := ignore.Entry{Path: "~/app/.env", Reason: "local only", Since: "2026-11-02"}
	prodFile := ignore.Entry{Path: "~/app/.env.production", Reason: "trying"}

	// By name: only that finding is set aside, and the rest still count.
	r := evalSecretsWith(found, nil, false, nil, ui("secrets", byName))
	if r.Status != check.Fail || len(r.UserIgnored) != 1 || r.UserIgnored[0].Name != "POSTGRES_PASSWORD" ||
		!strings.Contains(r.Summary, "3 secrets") || !strings.HasSuffix(r.Summary, "1 more ignored by you.") {
		t.Errorf("by name: %s %q %+v", r.Status, r.Summary, r.UserIgnored)
	}
	for _, e := range r.Evidence {
		if strings.Contains(e, "POSTGRES_PASSWORD") {
			t.Errorf("an ignored finding is in the evidence: %q", e)
		}
	}
	// By file, and a production entry that must not apply: production still fails.
	r = evalSecretsWith(found, []string{"~/app/c.p12"}, false, nil, ui("secrets", byFile, prodFile))
	if r.Status != check.Fail || len(r.UserIgnored) != 2 || !strings.Contains(r.Summary, "1 marked production") {
		t.Errorf("by file: %s %q %+v", r.Status, r.Summary, r.UserIgnored)
	}
	if got := r.UserIgnored[0]; got != (check.Ignored{Path: "~/app/.env", Name: "POSTGRES_PASSWORD", Kind: "Secret-looking variable", Reason: "local only", Since: "2026-11-02"}) {
		t.Errorf("entry: %+v", got)
	}
	// Another check's entries do not apply.
	other := ui("ai-agents", byFile)
	other.check = "secrets"
	if r = evalSecretsWith(found, nil, false, nil, other); len(r.UserIgnored) != 0 {
		t.Errorf("an ai-agents entry applied to secrets: %+v", r.UserIgnored)
	}

	// Everything ignored: a pass that says so; the list carries no value or tail.
	some := []secretFinding{found[0], found[3]}
	r = evalSecretsWith(some, []string{"~/app/c.p12"}, true, nil, ui("secrets", byFile,
		ignore.Entry{Path: "~/.zshrc", Reason: "revoked key"}, ignore.Entry{Path: "~/app/c.p12", Name: "certificate bundle", Reason: "test cert"}))
	if r.Status != check.Pass || len(r.UserIgnored) != 3 || len(r.Evidence) != 0 || r.SummaryParts[0].Key != "ignore.all" ||
		r.Summary != "The only findings are 3 you marked as not sensitive. The scan hit its time limit, so some folders were not checked." {
		t.Errorf("all ignored: %s %q %+v %q", r.Status, r.Summary, r.UserIgnored, r.Evidence)
	}
	if data, _ := json.Marshal(r); strings.Contains(string(data), "ab12") || !strings.Contains(string(data), `"user_ignored":[`) {
		t.Errorf("json: %s", data)
	}

	// The policy does not allow it: nothing is set aside, and the summary says why.
	off := newUserIgnore("secrets", Local{Ignored: []ignore.Entry{{Check: "secrets", Path: "~/app/.env", Reason: "r"}}}, false, "/home/an")
	if r = evalSecretsWith(some, nil, false, nil, off); r.Status != check.Warn || r.UserIgnored != nil || !strings.Contains(r.Summary, "does not allow") {
		t.Errorf("policy off: %s %q", r.Status, r.Summary)
	}
	// A list that cannot be read applies nothing and says so.
	broken := newUserIgnore("secrets", Local{IgnoreErr: errors.New("bad")}, true, "/home/an")
	if r = evalSecretsWith(some, nil, false, nil, broken); r.Status != check.Warn || r.UserIgnored != nil || !strings.Contains(r.Summary, "could not be read") {
		t.Errorf("unreadable: %q", r.Summary)
	}
}

func TestUserIgnoredCap(t *testing.T) {
	var found []secretFinding
	for i := range maxIgnoredListed + 50 {
		found = append(found, secretFinding{path: "~/big/.env", line: i + 1, kind: "Secret-looking variable", name: "K"})
	}
	r := evalSecretsWith(found, nil, false, nil, ui("secrets", ignore.Entry{Path: "~/big/.env", Reason: "fixtures"}))
	if r.Status != check.Pass || len(r.UserIgnored) != maxIgnoredListed || !strings.Contains(r.Summary, "250") {
		t.Errorf("cap: %s %d %q", r.Status, len(r.UserIgnored), r.Summary)
	}
}

func TestEvalAIAgentsUserIgnored(t *testing.T) {
	token := aiFinding{path: "~/.claude.json", where: "mcpServers.mcp-trinh.headers.Authorization", what: "Claude Code: Token in an HTTP header in plain text",
		sev: check.Medium, token: true, setting: "mcpServers.mcp-trinh.headers.Authorization", name: "Authorization", tail: "zz99"}
	prod := aiFinding{path: "~/.claude.json", where: "mcpServers.live.env.API_KEY", what: "Claude Code: Secret-looking variable in plain text",
		sev: check.High, token: true, prod: true, setting: "mcpServers.live.env.API_KEY", name: "API_KEY"}
	guard := aiFinding{path: "~/.codex/config.toml", where: `sandbox_mode = "danger-full-access"`, what: "Codex: commands run without a sandbox", sev: check.High}

	// By setting, and by the header name.
	for _, name := range []string{"mcpServers.mcp-trinh.headers.Authorization", "Authorization"} {
		r := evalAIAgentsWith([]aiFinding{token, guard}, 2, ui("ai-agents", ignore.Entry{Path: "~/.claude.json", Name: name, Reason: "local MCP"}))
		if r.Status != check.Fail || len(r.UserIgnored) != 1 || r.UserIgnored[0].Name != "mcpServers.mcp-trinh.headers.Authorization" ||
			!strings.HasSuffix(r.Summary, "1 more ignored by you.") || len(r.Evidence) != 1 {
			t.Errorf("by %s: %s %q %+v %q", name, r.Status, r.Summary, r.UserIgnored, r.Evidence)
		}
	}
	// A whole-file entry never covers guardrails or production tokens.
	r := evalAIAgentsWith([]aiFinding{token, prod, guard}, 2, ui("ai-agents",
		ignore.Entry{Path: "~/.claude.json", Reason: "r"}, ignore.Entry{Path: "~/.codex/config.toml", Reason: "r"}))
	if r.Status != check.Fail || len(r.UserIgnored) != 1 || len(r.Evidence) != 2 {
		t.Errorf("guardrails and production: %s %q %+v %q", r.Status, r.Summary, r.UserIgnored, r.Evidence)
	}
	// Only the token: all ignored, a pass.
	r = evalAIAgentsWith([]aiFinding{token}, 1, ui("ai-agents", ignore.Entry{Path: "~/.claude.json", Reason: "r"}))
	if r.Status != check.Pass || r.SummaryParts[0].Key != "ignore.all" || len(r.UserIgnored) != 1 {
		t.Errorf("all ignored: %s %q", r.Status, r.Summary)
	}
	if data, _ := json.Marshal(r); strings.Contains(string(data), "zz99") {
		t.Errorf("tail in the result: %s", data)
	}
}

// setHome points the home folder at a temporary one, on every OS.
func setHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	return home
}

// The three checks on a made-up home folder: the person's list applies by the
// path the report shows, and IgnorableItems sees every finding regardless,
// with what cannot be ignored marked.
func TestUserIgnoreOnMadeUpHome(t *testing.T) {
	home := setHome(t)
	writeFile(t, home, "app/.env", "POSTGRES_PASSWORD=Xq7rT2mVb9pL\nAPI_TOKEN=Zk3nW8sQe4yU\n", 0o600)
	writeFile(t, home, ".claude.json", `{"mcpServers": {"mcp-trinh": {"url": "https://x.example", "headers": {"Authorization": "Bearer Qw8eR4tY6uI2oP0aS9dF"}}}}`, 0o600)
	writeFile(t, home, ".codex/config.toml", "sandbox_mode = \"danger-full-access\"\n", 0o600)
	writeFile(t, home, ".ssh/aur", openSSHKey(t, "ssh-ed25519", "none"), 0o600)
	writeFile(t, home, ".ssh/open", openSSHKey(t, "ssh-ed25519", "none"), 0o644)
	line, _ := authorizedLine(t, "", "bob@acme.com")
	writeFile(t, home, ".ssh/authorized_keys", line+"\n", 0o600)
	writeFile(t, home, ".ssh/config", "Host *\n  ForwardAgent yes\n", 0o600)

	pol := policy.Default()
	items, gotHome, err := IgnorableItems(t.Context(), pol)
	if err != nil || gotHome != home {
		t.Fatalf("%v %q", err, gotHome)
	}
	blocked := map[string]string{}
	for _, it := range items {
		blocked[it.Check+" "+filepath.ToSlash(it.Path)+" "+it.Kind] = it.Blocked
	}
	want := map[string]string{
		"secrets ~/app/.env Secret-looking variable":                                  "",
		"ai-agents ~/.claude.json Claude Code: Token in an HTTP header in plain text": "",
		"ai-agents ~/.codex/config.toml Codex: commands run without a sandbox":        BlockedGuardrail,
		"ssh-keys ~/.ssh/aur no passphrase":                                           "",
		"ssh-keys ~/.ssh/authorized_keys can log in here":                             BlockedAuthorized,
		"ssh-keys ~/.ssh/config ForwardAgent yes":                                     BlockedSSHConfig,
	}
	if runtime.GOOS != "windows" {
		want["ssh-keys ~/.ssh/open no passphrase"] = BlockedPerms
	}
	for k, v := range want {
		if got, ok := blocked[k]; !ok || got != v {
			t.Errorf("%s: blocked %q (found %v), want %q; all: %v", k, got, ok, v, blocked)
		}
	}

	local := Local{Ignored: []ignore.Entry{
		{Check: "secrets", Path: "~/app/.env", Name: "POSTGRES_PASSWORD", Reason: "local db"},
		{Check: "ai-agents", Path: "~/.claude.json", Name: "Authorization", Reason: "local MCP"},
		{Check: "ai-agents", Path: "~/.codex/config.toml", Reason: "cannot apply"},
		{Check: "ssh-keys", Path: filepath.Join(home, ".ssh", "aur"), Reason: "AUR key, nothing else"},
		{Check: "ssh-keys", Path: "~/.ssh/open", Reason: "cannot apply: readable"},
	}}
	all := map[string]check.Result{}
	for _, c := range AllWith(pol, local) {
		if c.ID == "secrets" || c.ID == "ai-agents" || c.ID == "ssh-keys" {
			all[c.ID] = c.Run(t.Context())
		}
	}
	if r := all["secrets"]; r.Status != check.Warn || len(r.UserIgnored) != 1 || !strings.Contains(strings.Join(r.Evidence, " "), "API_TOKEN") {
		t.Errorf("secrets: %s %q %+v", r.Status, r.Summary, r.UserIgnored)
	}
	if r := all["ai-agents"]; r.Status != check.Fail || len(r.UserIgnored) != 1 || len(r.Evidence) != 1 || !strings.Contains(r.Evidence[0], "sandbox") {
		t.Errorf("ai-agents: %s %q %+v %q", r.Status, r.Summary, r.UserIgnored, r.Evidence)
	}
	r := all["ssh-keys"]
	if len(r.UserIgnored) != 1 || r.UserIgnored[0].Kind != "no passphrase (OpenSSH ssh-ed25519)" || strings.Contains(strings.Join(r.Evidence, " "), "aur ") ||
		!strings.Contains(r.Summary, "1 more ignored by you.") {
		t.Errorf("ssh-keys: %s %q %+v %q", r.Status, r.Summary, r.UserIgnored, r.Evidence)
	}
	if runtime.GOOS != "windows" && !strings.Contains(strings.Join(r.Evidence, " "), "open") {
		t.Errorf("a readable key was ignored: %q", r.Evidence)
	}
	data, _ := json.Marshal(all)
	for _, v := range []string{"Xq7rT2mVb9pL", "Zk3nW8sQe4yU", "Qw8eR4tY6uI2oP0aS9dF"} {
		if strings.Contains(string(data), v) {
			t.Errorf("a value is in a result: %s", v)
		}
	}

	// Each check's own policy switch.
	pol.Checks.SSHKeys.UserIgnore = false
	for _, c := range AllWith(pol, local) {
		if c.ID == "ssh-keys" {
			if r := c.Run(t.Context()); len(r.UserIgnored) != 0 || !strings.Contains(r.Summary, "does not allow") {
				t.Errorf("ssh-keys off: %q", r.Summary)
			}
		}
	}
}
