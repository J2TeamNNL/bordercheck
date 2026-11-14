// Package guard keeps secrets out of what is sent to an AI assistant, before
// it is sent: `bordercheck guard install` registers Claude Code hooks (see
// Hooks) that stop a prompt holding a secret, refuse a command that prints
// secrets wholesale, and hide secrets in a command's output. It changes only
// the hook entries it added to ~/.claude/settings.json (or
// $CLAUDE_CONFIG_DIR/settings.json), and only when the person runs install or
// uninstall.
package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Hook is one of the guard's Claude Code hooks.
type Hook struct {
	Event   string // Claude Code's hook event
	Matcher string // the tools it applies to; "" for an event without tools
	Sub     string // what it runs: bordercheck guard <Sub>
}

// Hooks are what `bordercheck guard install` sets up:
//
//	prompt   UserPromptSubmit: stops a prompt that holds a secret
//	command  PreToolUse on Bash: refuses a command that prints secrets wholesale (env, cat .env, touchenv get…)
//	output   PostToolUse on Bash: replaces secrets in a command's output before the model sees it
//
// Only Bash: a file read with the Read tool and changed with Edit or Write
// must reach the model as it is, or an edit could write ***REDACTED*** into it.
var Hooks = []Hook{
	{Event: "UserPromptSubmit", Sub: "prompt"},
	{Event: "PreToolUse", Matcher: "Bash", Sub: "command"},
	{Event: "PostToolUse", Matcher: "Bash", Sub: "output"},
}

// SettingsPath is Claude Code's user settings file.
func SettingsPath(home string) string {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); filepath.IsAbs(d) {
		return filepath.Join(d, "settings.json")
	}
	return filepath.Join(home, ".claude", "settings.json")
}

// Command is the hook's command line for the program at bin. The path is in
// double quotes, as Claude Code's documentation writes paths for the shell it
// runs a hook with: install folders have spaces ("Application Support").
func Command(bin, sub string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(bin) + `" guard ` + sub
}

type hookCmd struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type matcherGroup struct {
	Matcher *string           `json:"matcher,omitempty"`
	Hooks   []json.RawMessage `json:"hooks"`
}

// isOurs: one of the guard's hooks; with only != "", one that runs that program.
func isOurs(raw json.RawMessage, only string) bool {
	var h hookCmd
	if json.Unmarshal(raw, &h) != nil || h.Type != "command" {
		return false
	}
	for _, k := range Hooks {
		if strings.HasSuffix(h.Command, " guard "+k.Sub) && (only == "" || h.Command == Command(only, k.Sub)) {
			return true
		}
	}
	return false
}

// Installed reports which of the guard's hooks (by Sub) the settings at path have.
func Installed(path string) map[string]bool {
	on := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return on
	}
	o, err := parseObject(data)
	if err != nil {
		return on
	}
	for _, k := range Hooks {
		groups, err := eventGroups(o, k.Event)
		if err != nil {
			continue
		}
		for _, g := range groups {
			for _, raw := range g.Hooks {
				var h hookCmd
				if isOurs(raw, "") && json.Unmarshal(raw, &h) == nil && strings.HasSuffix(h.Command, " guard "+k.Sub) {
					on[k.Sub] = true
				}
			}
		}
	}
	return on
}

func eventGroups(settings *object, event string) ([]matcherGroup, error) {
	hooksRaw, ok := settings.get("hooks")
	if !ok {
		return nil, nil
	}
	hooks, err := parseObject(hooksRaw)
	if err != nil {
		return nil, fmt.Errorf("its \"hooks\" is not an object: %w", err)
	}
	raw, ok := hooks.get(event)
	if !ok {
		return nil, nil
	}
	var groups []matcherGroup
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil, fmt.Errorf("its hooks.%s is not a list of hook groups: %w", event, err)
	}
	return groups, nil
}

// Install adds the guard's hooks for the program at bin to the settings at
// path, or replaces those there (after the program moved). The person's
// other settings and hooks are kept, in their order. It refuses a settings
// file it cannot read as JSON rather than overwrite it.
func Install(path, bin string) (changed bool, err error) {
	return edit(path, func(event string, groups []matcherGroup) []matcherGroup {
		groups = without(groups, "")
		for _, k := range Hooks {
			if k.Event != event {
				continue
			}
			want, _ := json.Marshal(hookCmd{Type: "command", Command: Command(bin, k.Sub), Timeout: 10})
			g := matcherGroup{Hooks: []json.RawMessage{want}}
			if k.Matcher != "" {
				g.Matcher = &k.Matcher
			}
			groups = append(groups, g)
		}
		return groups
	})
}

// Uninstall removes the guard's hooks, and nothing else. With bin != "",
// only hooks that run that program: what `bordercheck uninstall` removes, so
// a guard set up with another copy of BorderCheck stays.
func Uninstall(path, bin string) (changed bool, err error) {
	if len(Installed(path)) == 0 {
		return false, nil
	}
	return edit(path, func(_ string, g []matcherGroup) []matcherGroup { return without(g, bin) })
}

// without drops the guard's hooks (see isOurs), and groups left empty by that.
func without(groups []matcherGroup, only string) []matcherGroup {
	var out []matcherGroup
	for _, g := range groups {
		var keep []json.RawMessage
		for _, h := range g.Hooks {
			if !isOurs(h, only) {
				keep = append(keep, h)
			}
		}
		if len(keep) == 0 && len(g.Hooks) > 0 {
			continue
		}
		g.Hooks = keep
		out = append(out, g)
	}
	return out
}

// events are the hook events the guard uses, each once, in order.
func events() []string {
	var out []string
	for _, k := range Hooks {
		if !slices.Contains(out, k.Event) {
			out = append(out, k.Event)
		}
	}
	return out
}

func edit(path string, change func(event string, groups []matcherGroup) []matcherGroup) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	settings, err := parseObject(data)
	if err != nil {
		return false, fmt.Errorf("%s is not valid JSON (%v); not changed", path, err)
	}
	hooks := &object{vals: map[string]json.RawMessage{}}
	if raw, ok := settings.get("hooks"); ok {
		if hooks, err = parseObject(raw); err != nil {
			return false, fmt.Errorf("%s: its \"hooks\" is not an object (%v); not changed", path, err)
		}
	}
	for _, event := range events() {
		groups, err := eventGroups(settings, event)
		if err != nil {
			return false, fmt.Errorf("%s: %v; not changed", path, err)
		}
		newGroups := change(event, groups)
		if len(newGroups) == 0 {
			hooks.del(event)
			continue
		}
		raw, err := json.Marshal(newGroups)
		if err != nil {
			return false, err
		}
		hooks.set(event, raw)
	}
	if hooks.len() == 0 {
		settings.del("hooks")
	} else {
		raw, err := hooks.MarshalJSON()
		if err != nil {
			return false, err
		}
		settings.set("hooks", raw)
	}
	out, err := indent(settings)
	if err != nil {
		return false, err
	}
	if before, _ := indentRaw(data); string(before) == string(out) {
		return false, nil
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	// Written in place, not replaced: a settings file that is a link into a
	// dotfiles folder stays one.
	return true, os.WriteFile(path, out, mode)
}

// indentRaw is data as edit would write it unchanged, to tell whether anything changed.
func indentRaw(data []byte) ([]byte, error) {
	o, err := parseObject(data)
	if err != nil {
		return nil, err
	}
	return indent(o)
}

// Allow in a prompt lets it through unchecked: for a secret that is meant to
// be sent (a test value), or a prompt the guard has wrongly stopped.
const Allow = "#allow-secret"

// Reason is what Claude Code shows when the guard refuses a prompt: the
// secrets by kind, never their values.
func Reason(items []string) string {
	return "BorderCheck stopped this prompt before it was sent: it holds " + plural(len(items)) + " (" +
		strings.Join(items, "; ") + "). Take it out, or put it in a file the assistant reads or an environment " +
		"variable, and send the prompt again. The prompt is still in Claude Code's history on this computer " +
		"(~/.claude); bordercheck full-scan lists such leftovers. If it is not a real secret, or is meant to be sent, " +
		"add " + Allow + " anywhere in the prompt."
}

func plural(n int) string {
	if n == 1 {
		return "a secret"
	}
	return fmt.Sprintf("%d secrets", n)
}
