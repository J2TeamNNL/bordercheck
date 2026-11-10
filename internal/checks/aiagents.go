package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Config files of AI coding agents, from each vendor's documentation. Only
// documented locations and settings are listed.
type aiConfig struct {
	agent    string
	paths    func(home, goos string) []string
	format   string   // "json", "jsonc" (comments allowed), "toml" or "text"
	scope    []string // keys whose subtrees hold MCP servers; nil = the whole file
	noTokens bool     // the file holds settings only; don't scan it for tokens
	guards   []aiGuard
}

// aiGuard is a documented setting that turns an agent's guardrails off.
type aiGuard struct {
	key  string // dotted path; also tried as one flat key, as VS Code writes them
	bad  func(v any) bool
	what string
	sev  check.Severity
}

func is(want any) func(any) bool { return func(v any) bool { return v == want } }

func oneOf(want ...string) func(any) bool {
	return func(v any) bool {
		s, ok := v.(string)
		for _, w := range want {
			if ok && s == w {
				return true
			}
		}
		return false
	}
}

// appSupport is where desktop apps keep per-user settings.
func appSupport(home, goos string) string {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support")
	case "windows":
		return appData(home)
	}
	return filepath.Join(home, ".config")
}

var aiConfigs = []aiConfig{
	// https://code.claude.com/docs/en/mcp, /settings, /permission-modes
	{agent: "Claude Code", paths: homeFiles(".claude.json"), format: "json", scope: []string{"mcpServers"}},
	{agent: "Claude Code", paths: homeFiles(".claude/settings.json"), format: "json", noTokens: true, guards: []aiGuard{
		{key: "permissions.defaultMode", bad: is("bypassPermissions"), sev: check.High,
			what: "every action runs without asking (bypassPermissions)"},
		{key: "skipDangerousModePermissionPrompt", bad: is(true), sev: check.Medium,
			what: "the bypass-permissions warning was turned off"},
		{key: "enableAllProjectMcpServers", bad: is(true), sev: check.Medium,
			what: "every MCP server a repository's .mcp.json names starts without asking"},
	}},
	// https://modelcontextprotocol.io/docs/develop/connect-local-servers
	{agent: "Claude Desktop", format: "json", paths: func(home, goos string) []string {
		return []string{filepath.Join(appSupport(home, goos), "Claude", "claude_desktop_config.json")}
	}},
	// https://cursor.com/docs/context/mcp, https://cursor.com/docs/cli/reference/configuration
	{agent: "Cursor", paths: homeFiles(".cursor/mcp.json"), format: "json"},
	{agent: "Cursor CLI", paths: homeFiles(".cursor/cli-config.json"), format: "json", noTokens: true, guards: []aiGuard{
		{key: "approvalMode", bad: is("unrestricted"), sev: check.High, what: "commands run without asking"},
	}},
	// https://code.visualstudio.com/docs/agents/reference/ai-settings
	{agent: "VS Code", format: "jsonc", noTokens: true, paths: func(home, goos string) []string {
		return []string{filepath.Join(appSupport(home, goos), "Code", "User", "settings.json")}
	}, guards: []aiGuard{
		{key: "chat.tools.global.autoApprove", bad: is(true), sev: check.High, what: "every tool call is approved automatically"},
		{key: "chat.permissions.default", bad: oneOf("autoApprove", "autopilot"), sev: check.High,
			what: "agent actions are approved automatically"},
		{key: "github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions", bad: is(true), sev: check.High,
			what: "the Claude agent may skip permission prompts"},
		{key: "chat.tools.terminal.ignoreDefaultAutoApproveRules", bad: is(true), sev: check.Medium,
			what: "the built-in deny list for auto-approved terminal commands is ignored"},
	}},
	// https://code.visualstudio.com/docs/copilot/customization/mcp-servers
	{agent: "GitHub Copilot", paths: homeFiles(".copilot/mcp-config.json"), format: "json"},
	// https://docs.devin.ai/windsurf/plugins/cascade/mcp
	{agent: "Windsurf", format: "json", paths: func(home, goos string) []string {
		return []string{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
			filepath.Join(home, ".codeium", "windsurf-next", "mcp_config.json"),
			filepath.Join(userConfig(home, goos), "devin", "mcp_config.json")}
	}},
	// https://learn.chatgpt.com/docs/config-file/config-reference (Codex docs)
	{agent: "Codex", paths: homeFiles(".codex/config.toml"), format: "toml", scope: []string{"mcp_servers"}, guards: []aiGuard{
		{key: "sandbox_mode", bad: is("danger-full-access"), sev: check.High, what: "commands run without a sandbox"},
		{key: "approval_policy", bad: is("never"), sev: check.Medium, what: "commands run without asking"},
	}},
	// https://geminicli.com/docs/reference/configuration
	{agent: "Gemini CLI", paths: homeFiles(".gemini/settings.json"), format: "json", scope: []string{"mcpServers"}, guards: []aiGuard{
		{key: "mcpServers.*.trust", bad: is(true), sev: check.Medium, what: "an MCP server's tools run without asking"},
	}},
	// https://docs.continue.dev/customize/deep-dives/configuration (model API keys live here too)
	{agent: "Continue", paths: homeFiles(".continue/config.yaml", ".continue/config.json"), format: "text"},
	// https://zed.dev/docs/ai/mcp; Zed documents ~/.zed on macOS in one place and ~/.config/zed in others, so both
	{agent: "Zed", format: "jsonc", scope: []string{"context_servers"}, paths: func(home, goos string) []string {
		switch goos {
		case "darwin":
			return []string{filepath.Join(home, ".config", "zed", "settings.json"), filepath.Join(home, ".zed", "settings.json")}
		case "windows":
			return nil // not documented
		}
		return []string{filepath.Join(home, ".config", "zed", "settings.json")}
	}, guards: []aiGuard{
		{key: "agent.tool_permissions.default", bad: is("allow"), sev: check.High, what: "every tool runs without asking"},
		{key: "agent.always_allow_tool_actions", bad: is(true), sev: check.High, what: "every tool runs without asking"},
	}},
}

// Rules for shapes that appear in MCP configs and not in shell files.
var aiRules = []secretRule{
	{kind: "Token in an HTTP header", valueGroup: 1,
		re: regexp.MustCompile(`(?i)\b(?:authorization|x-api-key|api-key|x-auth-token)["']?\s*[:=]\s*["']?(?:bearer\s+|token\s+|basic\s+)?([^\s"',]{8,})`)},
	{kind: "Secret in a command-line argument", valueGroup: 1,
		re: regexp.MustCompile(`(?i)--(?:api[-_]?key|access[-_]?token|auth[-_]?token|token|password|secret|client[-_]secret)(?:=|\s+)["']?([^\s"',]{8,})`)},
}

type aiFinding struct {
	path, where, what string
	tail              string
	sev               check.Severity
}

func (f aiFinding) String() string {
	s := f.path
	if f.where != "" {
		s += "  " + f.where
	}
	s += "  " + f.what
	if f.tail != "" {
		s += " …" + f.tail
	}
	return s
}

func aiAgents(p policy.AIAgents, sp policy.Secrets) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		home, err := os.UserHomeDir()
		if err != nil {
			return check.Errored(err)
		}
		s, err := newAIScanner(p, sp, home)
		if err != nil {
			return check.Errored(err)
		}
		found, files := s.scanAll(home, runtime.GOOS, p)
		return evalAIAgents(found, files)
	}
}

type aiScanner struct {
	*secretScanner
	rules []secretRule
}

func newAIScanner(p policy.AIAgents, sp policy.Secrets, home string) (*aiScanner, error) {
	sp.IgnorePaths, sp.ExtraFiles = p.IgnorePaths, nil
	s, err := newSecretScanner(sp, home)
	if err != nil {
		return nil, err
	}
	return &aiScanner{secretScanner: s, rules: append(slices.Clone(s.rules), aiRules...)}, nil
}

// scanAll reads every known config that exists plus the policy's extra paths,
// and returns the findings and how many files were read.
func (s *aiScanner) scanAll(home, goos string, p policy.AIAgents) ([]aiFinding, int) {
	configs := slices.Clone(aiConfigs)
	for _, x := range p.ExtraPaths {
		path := expandHome(x, home)
		format := "text"
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			format = "jsonc"
		case ".toml":
			format = "toml"
		}
		configs = append(configs, aiConfig{agent: "extra", format: format,
			paths: func(string, string) []string { return []string{path} }})
	}
	var out []aiFinding
	files := 0
	seen := map[string]bool{}
	for _, c := range configs {
		for _, path := range c.paths(home, goos) {
			shown := tildePath(home, path)
			if seen[path] || s.ignored(shown) {
				continue
			}
			seen[path] = true
			st, err := os.Stat(path)
			if err != nil || !st.Mode().IsRegular() || st.Size() > secretMaxFileSize {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			files++
			out = append(out, s.scanConfig(c, shown, data, p.Tokens, p.Guardrails)...)
		}
	}
	return out, files
}

// scanConfig judges one config file's content.
func (s *aiScanner) scanConfig(c aiConfig, shown string, data []byte, tokens, guards bool) []aiFinding {
	var out []aiFinding
	switch c.format {
	case "json", "jsonc":
		var root map[string]any
		if json.Unmarshal(stripJSONC(data), &root) != nil {
			return nil
		}
		if guards {
			for _, g := range c.guards {
				for _, hit := range lookupAll(root, g.key) {
					if g.bad(hit.v) {
						out = append(out, aiFinding{path: shown, where: fmt.Sprintf("%s = %v", hit.key, hit.v),
							what: c.agent + ": " + g.what, sev: g.sev})
					}
				}
			}
		}
		if tokens && !c.noTokens {
			if c.scope == nil {
				out = append(out, s.scanTree(shown, c.agent, "", root)...)
			} else {
				for _, key := range c.scope {
					for _, sub := range findKey(root, key, "") {
						out = append(out, s.scanTree(shown, c.agent, sub.key, sub.v)...)
					}
				}
			}
		}
	case "toml":
		lines, settings := splitTOML(data, c.scope)
		if guards {
			for _, g := range c.guards {
				for key, v := range settings {
					if (key == g.key || strings.HasSuffix(key, "."+g.key)) && g.bad(v) {
						out = append(out, aiFinding{path: shown, where: fmt.Sprintf("%s = %q", key, v),
							what: c.agent + ": " + g.what, sev: g.sev})
					}
				}
			}
		}
		if tokens && !c.noTokens {
			out = append(out, s.scanLines(shown, c.agent, lines)...)
		}
	default:
		if tokens && !c.noTokens {
			out = append(out, s.scanLines(shown, c.agent, string(data))...)
		}
	}
	return out
}

func (s *aiScanner) scanLines(shown, agent, text string) []aiFinding {
	var out []aiFinding
	for _, f := range s.scan(strings.NewReader(text), shown, s.rules) {
		where := fmt.Sprintf("line %d", f.line)
		if f.name != "" {
			where += " (" + f.name + ")"
		}
		out = append(out, s.tokenFinding(f, agent, where))
	}
	return out
}

func (s *aiScanner) tokenFinding(f secretFinding, agent, where string) aiFinding {
	sev := check.Medium
	if f.high() {
		sev = check.High
	}
	return aiFinding{path: f.path, where: where, what: agent + ": " + f.kind + " in plain text", tail: f.tail, sev: sev}
}

// scanTree checks every string in a JSON subtree. Each one is scanned as
// "key=value" so the name-based rules see the variable or header name; an
// array (command arguments) is scanned as one line.
func (s *aiScanner) scanTree(shown, agent, at string, v any) []aiFinding {
	var out []aiFinding
	var walk func(key, path string, v any)
	walk = func(key, path string, v any) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(k, joinKey(path, k), t[k])
			}
		case []any:
			var strs []string
			for i, e := range t {
				if str, ok := e.(string); ok {
					strs = append(strs, str)
				} else {
					walk(key, fmt.Sprintf("%s[%d]", path, i), e)
				}
			}
			if len(strs) > 0 {
				out = append(out, s.scanValue(shown, agent, path, key, strings.Join(strs, " "))...)
			}
		case string:
			out = append(out, s.scanValue(shown, agent, path, key, t)...)
		}
	}
	walk(lastKey(at), at, v)
	return out
}

func (s *aiScanner) scanValue(shown, agent, path, key, value string) []aiFinding {
	var out []aiFinding
	for _, f := range s.scan(strings.NewReader(key+"="+value), shown, s.rules) {
		out = append(out, s.tokenFinding(f, agent, path))
	}
	return out
}

func joinKey(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func lastKey(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

type keyed struct {
	key string
	v   any
}

// findKey returns every subtree under a key with this name, at any depth
// (Claude Code keeps per-project servers under projects.<path>.mcpServers).
func findKey(v any, name, path string) []keyed {
	var out []keyed
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := joinKey(path, k)
		if k == name {
			out = append(out, keyed{p, m[k]})
			continue
		}
		out = append(out, findKey(m[k], name, p)...)
	}
	return out
}

// lookupAll resolves a dotted key, where * matches any key and any prefix of
// the path may be written as one flat key ("chat.tools.global.autoApprove": true).
func lookupAll(v any, key string) []keyed {
	var out []keyed
	var walk func(v any, rest, path string)
	walk = func(v any, rest, path string) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		parts := strings.Split(rest, ".")
		for i := 1; i <= len(parts); i++ {
			head, tail := strings.Join(parts[:i], "."), strings.Join(parts[i:], ".")
			var subs []keyed
			if head == "*" {
				for k, sub := range m {
					subs = append(subs, keyed{k, sub})
				}
				sort.Slice(subs, func(a, b int) bool { return subs[a].key < subs[b].key })
			} else if sub, ok := m[head]; ok {
				subs = append(subs, keyed{head, sub})
			}
			for _, sub := range subs {
				if tail == "" {
					out = append(out, keyed{joinKey(path, sub.key), sub.v})
				} else {
					walk(sub.v, tail, joinKey(path, sub.key))
				}
			}
		}
	}
	walk(v, key, "")
	return out
}

// stripJSONC removes // and /* */ comments and trailing commas outside strings,
// so VS Code and Zed settings parse as JSON.
func stripJSONC(b []byte) []byte {
	var out bytes.Buffer
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(b) {
				i++
				out.WriteByte(b[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := bytes.Index(b[i+2:], []byte("*/"))
			if end < 0 {
				return out.Bytes()
			}
			i += end + 3
		case c == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

var (
	tomlTableRe  = regexp.MustCompile(`^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$`)
	tomlKVRe     = regexp.MustCompile(`^\s*([A-Za-z0-9_."-]+)\s*=\s*"([^"]*)"`)
	tomlEnvRefRe = regexp.MustCompile(`^\s*"?[A-Za-z0-9_-]*env_vars?"?\s*=`)
)

// splitTOML returns the file with every line outside the scoped tables blanked
// (so line numbers stay right), and the string settings at the top level or in
// [profiles.*] tables, keyed by their dotted path.
func splitTOML(data []byte, scope []string) (string, map[string]string) {
	var b strings.Builder
	settings := map[string]string{}
	table := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := tomlTableRe.FindStringSubmatch(line); m != nil {
			table = strings.ReplaceAll(m[1], `"`, "")
			b.WriteString("\n")
			continue
		}
		inScope := false
		for _, s := range scope {
			if table == s || strings.HasPrefix(table, s+".") {
				inScope = true
			}
		}
		// Keys that name an environment variable (bearer_token_env_var, env_vars,
		// env_http_headers) point at a secret instead of holding one.
		if inScope && !strings.HasSuffix(table, "env_http_headers") && !tomlEnvRefRe.MatchString(line) {
			b.WriteString(line)
		}
		b.WriteString("\n")
		if m := tomlKVRe.FindStringSubmatch(line); m != nil && (table == "" || strings.HasPrefix(table, "profiles.")) {
			settings[joinKey(table, strings.Trim(m[1], `"`))] = m[2]
		}
	}
	return b.String(), settings
}

func evalAIAgents(found []aiFinding, files int) check.Result {
	if len(found) == 0 {
		return check.Result{Status: check.Pass,
			Summary: fmt.Sprintf("%d AI agent config file(s) checked: no plain-text tokens, guardrails on.", files)}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].sev == check.High && found[j].sev != check.High })
	var ev []string
	high, tokens, guards := false, 0, 0
	for _, f := range found {
		ev = append(ev, f.String())
		high = high || f.sev == check.High
		if strings.HasSuffix(f.what, " in plain text") {
			tokens++
		} else {
			guards++
		}
	}
	ev = uniqKeepOrder(ev)
	if len(ev) > secretMaxEvidence {
		ev = append(ev[:secretMaxEvidence], fmt.Sprintf("… and %d more", len(ev)-secretMaxEvidence))
	}
	var parts []string
	if tokens > 0 {
		parts = append(parts, fmt.Sprintf("%d plain-text token(s) in AI agent / MCP configs", tokens))
	}
	if guards > 0 {
		parts = append(parts, fmt.Sprintf("%d agent setting(s) that skip approvals or the sandbox", guards))
	}
	r := check.Result{Status: check.Warn, Severity: check.Medium, Summary: strings.Join(parts, ", ") + ".", Evidence: ev,
		Fix: "Keep tokens out of MCP configs: reference an environment variable instead (\"env\": {\"API_KEY\": " +
			"\"${env:API_KEY}\"} or the agent's own input/secret mechanism) and load it from the OS keychain " +
			"(touchenv run on macOS). Rotate tokens that sat in these files. Turn approvals and the sandbox back on: " +
			"a prompt injection in any file, web page or issue the agent reads can then run commands as you."}
	if high {
		r.Status, r.Severity = check.Fail, check.High
	}
	return r
}
