package checks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// AI coding assistants keep every conversation on disk in plain text, so a key
// pasted into a chat, or printed by a command the assistant ran, stays there
// after it has been moved out of the file it came from. These are the stores
// read here, newest first:
//
//	Claude Code   $CLAUDE_CONFIG_DIR or ~/.claude: projects/**/*.jsonl, history.jsonl
//	Codex CLI     $CODEX_HOME or ~/.codex: sessions/**/*.jsonl, history.jsonl
//
// They are large (gigabytes on a busy machine), so the secrets check reads
// every prompt typed (history.jsonl, a few megabytes) but of the conversations
// only what was written within policy ai_chat_hours (48 by default), at most
// ai_chat_max_mb in all, and reports what it finds for information only;
// `bordercheck full-scan` (ScanAIChats) reads the whole history. Only provider
// token formats, private keys, passwords in URLs and passwords assigned to a
// name are looked for: the generic NAME=value rule would flag every snippet
// of code discussed in a chat. Each distinct secret is reported once per
// conversation.

// chatStore is one assistant's folders of conversations.
type chatStore struct {
	app     string
	roots   func(home, goos string) []string
	files   []string // prompt histories under a root: what was typed, read whatever their age
	folders []string // folders under a root whose matching files, at any depth below, are conversations
	exts    []string // matching: these extensions (default .jsonl) ...
	names   []string // ... or exactly these names, or names ending so (an entry starting "*")
	inDir   []string // and, when set, only in a folder of one of these names
	prompts []string // names of files under folders that hold only what was typed
}

// chatStores are the assistants whose history is plain text (JSON, JSONL).
// Not read: Cursor's editor chats, opencode and Goose (SQLite), Windsurf
// (protobuf), and Codex sessions compressed to .jsonl.zst.
var chatStores = []chatStore{
	{app: "Claude Code", roots: envDirOr("CLAUDE_CONFIG_DIR", ".claude"), files: []string{"history.jsonl"}, folders: []string{"projects"}},
	{app: "Codex", roots: envDirOr("CODEX_HOME", ".codex"), files: []string{"history.jsonl"}, folders: []string{"sessions", "archived_sessions"}},
	// Gemini CLI: tmp/<project>/chats/session-*.jsonl (older: .json), logs.json (prompts), checkpoint-*.json, shell_history.
	{app: "Gemini CLI", roots: geminiRoots, folders: []string{"tmp"}, exts: []string{".jsonl", ".json"},
		names: []string{"shell_history"}, prompts: []string{"logs.json", "shell_history"}},
	// GitHub Copilot CLI.
	{app: "Copilot CLI", roots: envDirOr("COPILOT_HOME", ".copilot"), folders: []string{"session-state"}},
	// Cursor's agent: plain-text transcripts and the prompt history (its editor chats are SQLite).
	{app: "Cursor", roots: homeDir(".cursor"), files: []string{"prompt_history.json"}, folders: []string{"projects"}, inDir: []string{"agent-transcripts"}},
	// Chat in VS Code (GitHub Copilot) and the editors built on it: <user data>/User/workspaceStorage/<id>/chatSessions,
	// and globalStorage/emptyWindowChatSessions.
	{app: "VS Code chat", roots: vscodeUserDirs, folders: []string{"workspaceStorage", "globalStorage"}, exts: []string{".jsonl", ".json"},
		inDir: []string{"chatSessions", "emptyWindowChatSessions"}},
	// Cline, Roo Code and Kilo Code: tasks/<id>/api_conversation_history.json and ui_messages.json, in ~/.cline/data
	// or the extension's folder in an editor's globalStorage; newer Cline also sessions/<id>/<id>.messages.json.
	{app: "Cline", roots: clineRoots, folders: []string{"tasks", "sessions"},
		names: []string{"api_conversation_history.json", "ui_messages.json", "*.messages.json"}},
}

// envDirOr: the folder an environment variable names, else ~/<dir>.
func envDirOr(env, dir string) func(string, string) []string {
	return func(home, _ string) []string {
		if d := os.Getenv(env); filepath.IsAbs(d) {
			return []string{d}
		}
		return []string{filepath.Join(home, dir)}
	}
}

func homeDir(dir string) func(string, string) []string {
	return func(home, _ string) []string { return []string{filepath.Join(home, dir)} }
}

// geminiRoots: ~/.gemini ($GEMINI_CLI_HOME stands for the home folder), and
// ~/.cache/.gemini, where it keeps its state when run in macOS's sandbox.
func geminiRoots(home, _ string) []string {
	if d := os.Getenv("GEMINI_CLI_HOME"); filepath.IsAbs(d) {
		home = d
	}
	return []string{filepath.Join(home, ".gemini"), filepath.Join(home, ".cache", ".gemini")}
}

// editors are VS Code and the editors built on it, by their user data folder's name.
var editors = []string{"Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"}

// vscodeUserDirs: each editor's <user data>/User: under ~/Library/Application
// Support on macOS, %APPDATA% on Windows, $XDG_CONFIG_HOME (~/.config) on Linux.
func vscodeUserDirs(home, goos string) []string {
	base := filepath.Join(home, ".config")
	switch {
	case goos == "darwin":
		base = filepath.Join(home, "Library", "Application Support")
	case goos == "windows":
		base = appData(home)
	case filepath.IsAbs(os.Getenv("XDG_CONFIG_HOME")):
		base = os.Getenv("XDG_CONFIG_HOME")
	}
	var out []string
	for _, e := range editors {
		out = append(out, filepath.Join(base, e, "User"))
	}
	return out
}

// clineRoots: Cline's own folder, and the extensions' folders in each editor.
func clineRoots(home, goos string) []string {
	var out []string
	switch {
	case filepath.IsAbs(os.Getenv("CLINE_DATA_DIR")):
		out = append(out, os.Getenv("CLINE_DATA_DIR"))
	case filepath.IsAbs(os.Getenv("CLINE_DIR")):
		out = append(out, filepath.Join(os.Getenv("CLINE_DIR"), "data"))
	default:
		out = append(out, filepath.Join(home, ".cline", "data"))
	}
	for _, u := range vscodeUserDirs(home, goos) {
		for _, ext := range []string{"saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline", "kilocode.kilo-code"} {
			out = append(out, filepath.Join(u, "globalStorage", ext))
		}
	}
	return out
}

// matches: a conversation file of the store, at path p.
func (st chatStore) matches(p string) bool {
	name := filepath.Base(p)
	if len(st.inDir) > 0 && !slices.ContainsFunc(st.inDir, func(d string) bool {
		return slices.Contains(strings.Split(filepath.ToSlash(filepath.Dir(p)), "/"), d)
	}) {
		return false
	}
	for _, n := range st.names {
		if n == name || strings.HasPrefix(n, "*") && strings.HasSuffix(name, n[1:]) {
			return true
		}
	}
	if len(st.names) > 0 && len(st.exts) == 0 {
		return false
	}
	exts := st.exts
	if len(exts) == 0 {
		exts = []string{".jsonl"}
	}
	return slices.ContainsFunc(exts, func(e string) bool { return strings.EqualFold(filepath.Ext(name), e) })
}

// maxPromptHistory is how large a prompt history may be and still be read in
// full whatever the budget (a busy one is a few megabytes).
const maxPromptHistory = 64 << 20

// Aider writes these in the folder it runs in (a project's root): the chat as
// Markdown, a "# aider chat started at <time>" line opening each session, and
// what was typed, a "# <time>" line before each prompt.
const (
	aiderChat  = ".aider.chat.history.md"
	aiderInput = ".aider.input.history"
)

// chatMaxDepth bounds the walk below a conversations folder
// (Codex: sessions/YYYY/MM/DD/…; Claude Code: projects/<project>/<session>/subagents/…).
const chatMaxDepth = 5

// chatRule is a secretRule found by a literal part of it: each anchor is
// searched for with bytes.Index over the whole file, start finds where a match
// would begin (or rules the hit out cheaply), and the rule's pattern, anchored
// there, is tried on a short window. Running the patterns over every line
// instead is several times slower on hundreds of megabytes of chat.
type chatRule struct {
	secretRule
	anchors []string
	start   func(data []byte, at int) int // where a match containing the anchor at `at` begins; -1 = none
	random  bool                          // the value (or the whole match) must look random: see randomToken
	pre     *regexp.Regexp                // the pattern anchored at start
	edge    bool                          // the pattern begins with \b: the byte before start must not be a word byte
}

// chatWindow is how much text a match may span.
const chatWindow = 512

// chatPasswordRule finds a password assigned to a name in code, config or a
// command pasted into a chat (DB_PASSWORD=…, "password": "…"); a password
// given as a separate argument (--password …) is not found. The value must
// look random (randomToken), as code that names a password is everywhere in
// chats. In files the generic NAME=value rule covers passwords.
var chatPasswordRule = secretRule{kind: "Password", nameGroup: 1, valueGroup: 2,
	re: regexp.MustCompile(`([A-Za-z0-9_.-]*(?i:pass(?:word|wd))[A-Za-z0-9_]*)\\{0,2}["']?\s*[:=]\s*\\{0,2}["']?([^\s"'\\#;,` + "`" + `(){}\[\]<>]{8,64})`)}

// chatKeyRule is a private key with its body: code that reads a key, and
// examples of the header, are common in chats; a pasted key has the base64
// lines after it (in a .jsonl file a line break is written \n).
var chatKeyRule = secretRule{kind: privateKeyRule.kind, high: true,
	re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\[rn]|\s)+(?:[A-Za-z0-9+/=]{16,}(?:\\[rn]|\s)*){4}`)}

func at(back int) func([]byte, int) int {
	return func(data []byte, i int) int {
		if i < back {
			return -1
		}
		return i - back
	}
}

// backOver walks back from i over bytes in set, at most limit of them.
func backOver(set string, limit int) func([]byte, int) int {
	return func(data []byte, i int) int {
		j := i
		for j > 0 && i-j < limit && strings.IndexByte(set, data[j-1]) >= 0 {
			j--
		}
		return j
	}
}

const identBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"

// urlStart: a password in a URL has an "@" before the next "/", space or
// quote after "://"; most URLs do not, and are ruled out without the pattern.
func urlStart(data []byte, i int) int {
	for k := i + 3; k < len(data) && k < i+256; k++ {
		switch data[k] {
		case '@':
			j := backOver("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.-", 32)(data, i)
			if j == i {
				return -1
			}
			return j
		case '/', ' ', '"', '\'', '\\', '\n', '\t', '<', '>':
			return -1
		}
	}
	return -1
}

// nameStart walks back over a variable name, stopping at a JSON escape such
// as \n: in "…\nPassword=…" the name is Password, not nPassword.
func nameStart(data []byte, i int) int {
	j := backOver(identBytes, 64)(data, i)
	for k := j; k < i; k++ {
		if k > 0 && data[k-1] == '\\' {
			j = k + 1
		}
	}
	return min(j, i)
}

func keyStart(data []byte, i int) int {
	lo := max(0, i-40)
	if k := bytes.LastIndex(data[lo:i], []byte("-----BEGIN")); k >= 0 {
		return lo + k
	}
	return -1
}

var chatRules = func() []chatRule {
	byKind := map[string]secretRule{}
	for _, r := range secretRules {
		byKind[r.kind] = r
	}
	rules := []chatRule{
		{secretRule: chatKeyRule, anchors: []string{"PRIVATE KEY-----"}, start: keyStart},
		{secretRule: byKind["AWS access key"], anchors: []string{"AKIA", "ASIA"}, start: at(0), random: true},
		{secretRule: byKind["GitHub token"], anchors: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, start: at(0), random: true},
		{secretRule: byKind["Anthropic API key"], anchors: []string{"sk-ant-"}, start: at(0), random: true},
		{secretRule: byKind["OpenAI API key"], anchors: []string{"sk-"}, start: at(0), random: true},
		{secretRule: byKind["Stripe live key"], anchors: []string{"k_live_"}, start: at(1), random: true},
		{secretRule: byKind["Slack token"], anchors: []string{"xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-"}, start: at(0), random: true},
		{secretRule: byKind["Google API key"], anchors: []string{"AIza"}, start: at(0), random: true},
		{secretRule: byKind["npm token"], anchors: []string{"npm_"}, start: at(0), random: true},
		{secretRule: byKind["Password in URL"], anchors: []string{"://"}, start: urlStart},
		{secretRule: chatPasswordRule, anchors: []string{"assword", "ASSWORD", "asswd", "ASSWD"}, start: nameStart, random: true},
	}
	for i, r := range rules {
		src := r.re.String()
		src, rules[i].edge = strings.CutPrefix(src, `\b`)
		rules[i].pre = regexp.MustCompile(`^(?:` + src + `)`)
	}
	return rules
}()

// chatFile is a conversation file to read.
type chatFile struct {
	raw     bool // a database or a log, read as bytes: no lines, no message context
	app     string
	path    string
	mod     time.Time
	size    int64
	prompts bool // a prompt history (history.jsonl): what was typed into the prompt, small
}

// findChats lists the conversation files changed since `since`, newest first.
func findChats(ctx context.Context, home string, since time.Time, aider []string) []chatFile {
	var out []chatFile
	seen := map[string]bool{}
	add := func(app, p string, info fs.FileInfo, prompts bool) {
		// A prompt history is read whatever its age: see scanChats.
		if !seen[p] && info.Mode().IsRegular() && (prompts || !info.ModTime().Before(since)) && !cloudPlaceholder(info) {
			seen[p] = true
			out = append(out, chatFile{app: app, path: p, mod: info.ModTime(), size: info.Size(), prompts: prompts})
		}
	}
	for _, st := range chatStores {
		for _, root := range st.roots(home, runtime.GOOS) {
			for _, f := range st.files {
				p := filepath.Join(root, f)
				if info, err := os.Lstat(p); err == nil {
					add(st.app, p, info, true)
				}
			}
			for _, f := range st.folders {
				top := filepath.Join(root, f)
				_ = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
					if err != nil || ctx.Err() != nil {
						if ctx.Err() != nil {
							return filepath.SkipAll
						}
						return nil
					}
					if d.IsDir() {
						if rel, _ := filepath.Rel(top, p); strings.Count(rel, string(filepath.Separator)) >= chatMaxDepth {
							return filepath.SkipDir
						}
						return nil
					}
					if st.matches(p) {
						if info, err := d.Info(); err == nil {
							add(st.app, p, info, slices.Contains(st.prompts, d.Name()))
						}
					}
					return nil
				})
			}
		}
	}
	// Databases of tools that keep chats or a clipboard in SQLite, read as
	// bytes (their -wal file holds the latest writes).
	for _, rs := range rawStores {
		for _, p := range rs.paths(home, runtime.GOOS) {
			for _, q := range []string{p, p + "-wal"} {
				if info, err := os.Lstat(q); err == nil && !seen[q] && info.Mode().IsRegular() && !info.ModTime().Before(since) {
					seen[q] = true
					out = append(out, chatFile{app: rs.app, path: q, mod: info.ModTime(), size: info.Size(), raw: true})
				}
			}
		}
	}
	// Aider keeps its histories in each project, found by the secrets walk.
	for _, env := range []string{"AIDER_CHAT_HISTORY_FILE", "AIDER_INPUT_HISTORY_FILE"} {
		if p := os.Getenv(env); filepath.IsAbs(p) {
			aider = append(aider, p)
		}
	}
	for _, p := range aider {
		if info, err := os.Lstat(p); err == nil {
			add("Aider", p, info, filepath.Base(p) == aiderInput || p == os.Getenv("AIDER_INPUT_HISTORY_FILE"))
		}
	}
	// Prompt histories first: they are small, and always read in full.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].prompts != out[j].prompts {
			return out[i].prompts
		}
		return out[i].mod.After(out[j].mod)
	})
	return out
}

// scanChats reads the conversation files changed since `since`, newest first,
// up to budget bytes in all and a quarter of it per file. A file larger than
// that is read from its end (conversations grow at the end); partial reports
// that something was left unread. ignored says which shown paths to leave out.
func (s *secretScanner) scanChats(ctx context.Context, home string, since time.Time, budget int64, ignored func(string) bool) (found []secretFinding, partial bool) {
	if budget <= 0 {
		return nil, false
	}
	extra := s.extraRules()
	if budget == math.MaxInt64 { // no limit (bordercheck full-scan): several files at once
		return s.scanAllChats(ctx, home, since, ignored, extra), false
	}
	perFile := max(1, budget/4)
	for _, f := range findChats(ctx, home, since, s.aider) {
		if ctx.Err() != nil || budget <= 0 {
			return found, true
		}
		shown := tildePath(home, f.path)
		if ignored(shown) {
			continue
		}
		// One long conversation may not take the whole budget: at most a
		// quarter of it, read from the end, where the newest messages are.
		n, from := f.size, int64(0)
		if limit := min(budget, perFile); n > limit && !(f.prompts && n <= maxPromptHistory) {
			n, from, partial = limit, f.size-limit, true
		}
		found1, text, err := s.scanChatFile(f, shown, from, n, since, extra)
		if err != nil {
			continue
		}
		budget -= text
		found = append(found, found1...)
	}
	return found, partial
}

// scanChatFile reads n bytes of f from `from` and returns what it holds, and
// how much of it was text: encoded strings (images, signatures: see
// blobStarts) are not searched and do not count against a budget.
func (s *secretScanner) scanChatFile(f chatFile, shown string, from, n int64, since time.Time, extra []secretRule) ([]secretFinding, int64, error) {
	data, err := readRange(f.path, from, n)
	if err != nil {
		return nil, 0, err
	}
	segs, text := textSegments(data)
	var found []secretFinding
	for _, c := range s.scanChatIn(data, segs, shown, from == 0 && !f.raw, extra) {
		if f.raw {
			c.ctx = chatContext{app: f.app, host: c.ctx.host, tail: c.ctx.tail, rep: c.ctx.rep}
			found = append(found, c)
			continue
		}
		// Every prompt ever typed counts: the prompt history is small and
		// what was typed is what most needs taking out. In a conversation,
		// changed recently but holding older messages too, a message that
		// says when it was written counts only if that is after since.
		if f.prompts || c.ctx.when.IsZero() || !c.ctx.when.Before(since) {
			c.ctx.app = f.app
			found = append(found, c)
		}
	}
	return found, int64(text), nil
}

// scanAllChats reads every conversation file whole, a few at a time, and
// returns what they hold in the order findChats lists them.
func (s *secretScanner) scanAllChats(ctx context.Context, home string, since time.Time, ignored func(string) bool, extra []secretRule) []secretFinding {
	files := append(findChats(ctx, home, since, s.aider), s.logs...)
	results := make([][]secretFinding, len(files))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4) // each file already searches with every core; this keeps the disk busy
	for i, f := range files {
		shown := tildePath(home, f.path)
		if ignored(shown) || ctx.Err() != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			results[i], _, _ = s.scanChatFile(f, shown, 0, f.size, since, extra)
		}()
	}
	wg.Wait()
	var out []secretFinding
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

// extraRules are the policy's own patterns (extra_patterns): they have no
// known start, so they are run over the whole text.
func (s *secretScanner) extraRules() []secretRule {
	var out []secretRule
	for _, r := range s.rules {
		if !slices.ContainsFunc(secretRules, func(b secretRule) bool { return b.re == r.re }) {
			out = append(out, r)
		}
	}
	return out
}

func readRange(p string, from, n int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, n))
}

// chatHit is a match at an offset in a conversation file.
type chatHit struct {
	at       int
	rule     secretRule
	match    string
	name     string
	value    string // the password part of a password rule's match
	vlo, vhi int    // what to hide: the value of a NAME=value or URL match, else all of it
}

// scanChat finds secrets in one conversation's text. withLines: the text is
// the whole file, so offsets can be turned into line numbers (one message per
// line); read from the end, they cannot, and the finding has none.
func (s *secretScanner) scanChat(data []byte, shown string, withLines bool, extra []secretRule) []secretFinding {
	return s.scanChatIn(data, [][2]int{{0, len(data)}}, shown, withLines, extra)
}

// scanChatIn is scanChat looking for anchors only within segs.
func (s *secretScanner) scanChatIn(data []byte, segs [][2]int, shown string, withLines bool, extra []secretRule) []secretFinding {
	return s.findingsOf(data, s.chatHits(data, segs, extra), shown, withLines)
}

// chatHits finds every secret in data within segs, in order, each once
// (where rules overlap, the more specific one's).
func (s *secretScanner) chatHits(data []byte, segs [][2]int, extra []secretRule) []chatHit {
	// Each anchor is searched for on its own core: bytes.Index over
	// hundreds of megabytes, once per anchor, is most of the time.
	type job struct {
		r chatRule
		a string
	}
	var jobs []job
	for _, r := range chatRules {
		for _, a := range r.anchors {
			jobs = append(jobs, job{r, a})
		}
	}
	perRule := make([][]chatHit, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))
	for ri, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			var hits []chatHit
			r := j.r
			a := j.a
			for _, seg := range segs {
				for off := seg[0]; off < seg[1]; {
					i := bytes.Index(data[off:seg[1]], []byte(a))
					if i < 0 {
						break
					}
					hit := off + i
					off = hit + len(a)
					st := r.start(data, hit)
					if st < 0 || (r.edge && st > 0 && isWordByte(data[st-1])) {
						continue
					}
					win := data[st:min(len(data), st+chatWindow)]
					loc := r.pre.FindSubmatchIndex(win)
					if loc == nil || loc[1] < hit-st+len(a) {
						continue // no match here, or one that stops before the anchor
					}
					m := string(win[:loc[1]])
					v := m
					if g := r.valueGroup; g > 0 && loc[2*g] >= 0 {
						v = string(win[loc[2*g]:loc[2*g+1]])
						if isPlaceholder(v) {
							continue
						}
					}
					if r.random && !randomToken(v) {
						continue
					}
					if r.kind == chatPasswordRule.kind && codeValue(v) {
						continue
					}
					if r.kind == "Password in URL" && !realHost(urlHost(m+string(data[st+loc[1]:min(len(data), st+loc[1]+256)]))) {
						continue
					}
					h := chatHit{at: st, rule: r.secretRule, match: m, vlo: st, vhi: st + loc[1]}
					if g := r.valueGroup; g > 0 {
						h.value = v
						h.vlo, h.vhi = st+loc[2*g], st+loc[2*g+1]
					}
					if g := r.nameGroup; g > 0 && loc[2*g] >= 0 {
						h.name = safeName(string(win[loc[2*g]:loc[2*g+1]]))
						if l := strings.ToLower(h.name); strings.Contains(l, "hash") || strings.Contains(l, "salt") {
							continue // a password's hash, not the password
						}
					}
					hits = append(hits, h)
					off = max(off, st+loc[1])
				}
			}
			perRule[ri] = hits
		}()
	}
	wg.Wait()
	var hits []chatHit
	for _, h := range perRule {
		hits = append(hits, h...)
	}
	for _, r := range extra {
		for _, seg := range segs {
			for _, loc := range r.re.FindAllIndex(data[seg[0]:seg[1]], -1) {
				at := seg[0] + loc[0]
				hits = append(hits, chatHit{at: at, rule: r, match: string(data[at : seg[0]+loc[1]]), vlo: at, vhi: seg[0] + loc[1]})
			}
		}
	}
	// A more specific rule found the same text (an Anthropic key is also
	// "sk-…"): keep the first rule's, as the line scan does.
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].at < hits[j].at })
	var kept []chatHit
	lastEnd := -1
	for _, h := range hits {
		if h.at >= lastEnd {
			kept = append(kept, h)
			lastEnd = h.at + len(h.match)
		}
	}
	return kept
}

// findingsOf makes findings of hits: each distinct secret once.
func (s *secretScanner) findingsOf(data []byte, hits []chatHit, shown string, withLines bool) []secretFinding {
	var out []secretFinding
	seen := map[[32]byte]int{} // index in out
	line, counted := 1, 0
	pathProd := s.prodRe.MatchString(shown)
	for _, h := range hits {
		if withLines {
			line += bytes.Count(data[counted:h.at], []byte{'\n'})
			counted = h.at
		}
		key := sha256.Sum256([]byte(h.rule.kind + "\x00" + h.match))
		if i, ok := seen[key]; ok {
			// The same secret again in this conversation: one finding, every line it is on.
			r := out[i].ctx.rep
			r.times++
			if withLines && !slices.Contains(r.lines, line) {
				r.lines = append(r.lines, line)
			}
			continue
		}
		seen[key] = len(out)
		f := secretFinding{path: shown, kind: h.rule.kind, name: h.name, severe: h.rule.high, prod: pathProd, chat: true}
		if withLines {
			f.line = line
		}
		if s.showTail && h.rule.showTail && len(h.match) >= 20 {
			f.tail = h.match[len(h.match)-4:]
		}
		if h.rule.showTail {
			f.token = s.tokens.keep(h.rule.kind, h.match)
		}
		// For `bordercheck full-scan` only, never in a report: where in the
		// conversation it was, and the end of a password long enough that
		// four characters give little away.
		f.ctx = chatContextAt(data, h.at, shown)
		if h.rule.kind == "Password in URL" { // the match ends at the "@": the host follows it
			end := h.at + len(h.match)
			f.ctx.host = urlHost(h.match + string(data[end:min(len(data), end+256)]))
		}
		if s.showTail && len(h.value) >= 12 {
			f.ctx.tail = h.value[len(h.value)-4:]
		}
		f.ctx.rep = &repeats{times: 1}
		if withLines {
			f.ctx.rep.lines = []int{line}
		}
		out = append(out, f)
	}
	return out
}

var (
	hasDigit = regexp.MustCompile(`[0-9]`)
	hasAlpha = regexp.MustCompile(`[A-Za-z]`)
)

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// randomToken tells a real provider token from one written out in a chat as
// an example: a real one has digits and letters, and no placeholder words.
func randomToken(m string) bool {
	return hasDigit.MatchString(m) && hasAlpha.MatchString(m) && !isPlaceholder(m)
}

// ChatFinding is a secret found in AI chat history, without its value. Its
// JSON form is what `bordercheck full-scan -json` prints.
type ChatFinding struct {
	Path string `json:"path"`           // ~ for the home folder
	Line int    `json:"line,omitempty"` // the message's line in the .jsonl file; 0 = not known
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"` // the variable it was assigned to, if any
	// Tail is the last 4 characters: of a provider token, as its dashboard
	// shows them, or of a password of 12 characters or more.
	Tail      string    `json:"tail,omitempty"`
	Host      string    `json:"host,omitempty"`    // for a password in a URL: what it logs in to
	When      time.Time `json:"when,omitzero"`     // when the message was written, if the file says
	Source    string    `json:"source,omitempty"`  // "prompt", "tool", "assistant", "user"
	Project   string    `json:"project,omitempty"` // the folder the assistant was working in, if the file says
	Assistant string    `json:"-"`                 // the assistant whose history it is; see App
	// Times is how many times the same secret is in the file, and Lines every
	// line it is on: deleting only the first would leave the others.
	Times int   `json:"times"`
	Lines []int `json:"lines,omitempty"`
	// Verified is what the provider said of the token (KeyLive…), with -verify only.
	Verified string `json:"verified,omitempty"`
	tokenKey string
}

// Item is the finding in a few words: "Stripe live key …p7dc",
// "Password (DB_PASSWORD) …x9Qa".
func (f ChatFinding) Item() string {
	s := f.Kind
	if f.Name != "" {
		s += " (" + f.Name + ")"
	}
	if f.Tail != "" {
		s += " …" + f.Tail
	}
	return s
}

// Where is the file and every line the secret is on, or how many times it
// is there when lines are not known.
func (f ChatFinding) Where() string {
	switch {
	case len(f.Lines) > 1:
		var ls []string
		for _, l := range f.Lines {
			ls = append(ls, strconv.Itoa(l))
		}
		return fmt.Sprintf("%s, lines %s", f.Path, strings.Join(ls, ", "))
	case f.Line > 0 && f.Times > 1:
		return fmt.Sprintf("%s, line %d (%d times on it)", f.Path, f.Line, f.Times)
	case f.Line > 0:
		return fmt.Sprintf("%s, line %d", f.Path, f.Line)
	case f.Times > 1:
		return fmt.Sprintf("%s (%d times)", f.Path, f.Times)
	}
	return f.Path
}

// App is the assistant whose history it is: as found, or told by the path.
func (f ChatFinding) App() string {
	if f.Assistant != "" {
		return f.Assistant
	}
	p := filepath.ToSlash(f.Path)
	switch {
	case strings.HasSuffix(p, "/"+aiderChat) || strings.HasSuffix(p, "/"+aiderInput):
		return "Aider"
	case strings.Contains(p, "/.codex/"):
		return "Codex"
	}
	return "Claude Code"
}

// Explain says, as far as the file tells, which assistant, which project,
// when, who wrote it, and what the secret allows.
func (f ChatFinding) Explain(home string) string {
	parts := []string{f.App()}
	if f.Project != "" {
		parts = append(parts, "in "+underHome(home, f.Project))
	}
	if !f.When.IsZero() {
		parts = append(parts, f.When.Format("2 Jan 2006"))
	}
	if s := map[string]string{
		"prompt":    "typed or pasted into the prompt",
		"tool":      "in the output of a command or tool the assistant ran",
		"assistant": "written by the assistant",
		"user":      "in a message you sent",
	}[f.Source]; s != "" {
		parts = append(parts, s)
	}
	out := strings.Join(parts, ", ") + "."
	switch {
	case f.Kind == "Password in URL" && f.Host != "":
		out += " A password in a URL that logs in to " + f.Host + "."
	case f.Kind == "Password" && f.Name != "":
		out += " A password, assigned to " + f.Name + "."
	case chatMeaning[f.Kind] != "":
		out += " " + chatMeaning[f.Kind]
	}
	return out
}

// ChatFix is how to remove secrets from AI chat history, in English.
func ChatFix() string { return msg.Of("secrets.fix.aiChat").English() }

// ScanAIChats is `bordercheck full-scan`: every conversation changed since
// `since` (the zero time: all of them), with no size limit and none of the
// secrets check's time limit; the policy's ignore_paths and extra_patterns
// apply. It only reads.
func ScanAIChats(ctx context.Context, p policy.Secrets, since time.Time) ([]ChatFinding, error) {
	return ScanChatsAndLogs(ctx, p, since, false)
}

// ScanChatsAndLogs is ScanAIChats, and with logs the log files (findLogs) too.
func ScanChatsAndLogs(ctx context.Context, p policy.Secrets, since time.Time, logs bool) ([]ChatFinding, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	s, err := newSecretScanner(p, home)
	if err != nil {
		return nil, err
	}
	s.tokens = tokensFrom(ctx)
	s.find(ctx, home) // for Aider's histories, kept in each project
	if logs {
		s.logs = findLogs(ctx, home, runtime.GOOS)
	}
	return s.chatFindings(ctx, home, since)
}

func (s *secretScanner) chatFindings(ctx context.Context, home string, since time.Time) ([]ChatFinding, error) {
	found, _ := s.scanChats(ctx, home, since, math.MaxInt64, s.ignored)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]ChatFinding, len(found))
	for i, f := range found {
		out[i] = ChatFinding{Path: f.path, Line: f.line, Kind: f.kind, Name: f.name, Tail: f.tail,
			Host: f.ctx.host, When: f.ctx.when, Source: f.ctx.source, Project: f.ctx.project, Assistant: f.ctx.app, Times: 1, tokenKey: f.token}
		if r := f.ctx.rep; r != nil {
			out[i].Times, out[i].Lines = r.times, r.lines
		}
		if out[i].Tail == "" {
			out[i].Tail = f.ctx.tail
		}
	}
	return out, nil
}

// chatContext is what `bordercheck full-scan` says about where a secret was. It
// never goes into a report.
type chatContext struct {
	app     string // the assistant whose history it is
	when    time.Time
	source  string   // "prompt", "tool", "assistant", "user" or ""
	project string   // the folder the assistant was working in
	host    string   // for a password in a URL
	tail    string   // the last 4 characters of a long password
	rep     *repeats // how often and on which lines it is in the file (a pointer keeps findings comparable)
}

// repeats: how many times one secret is in a file, and every line it is on.
type repeats struct {
	times int
	lines []int
}

var (
	isoTimeRe = regexp.MustCompile(`"timestamp"\s*:\s*"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)`)
	msTimeRe  = regexp.MustCompile(`"timestamp"\s*:\s*(\d{13})\b`)
	folderRe  = regexp.MustCompile(`"(?:cwd|project)"\s*:\s*("(?:[^"\\]|\\.){1,512}")`)
)

// chatContextAt is chatContextOf for the file shown: Aider's Markdown and
// input history have their own form.
func chatContextAt(data []byte, at int, shown string) chatContext {
	switch filepath.Base(shown) {
	case aiderChat, aiderInput:
		c := aiderContext(data, at, []byte("\n# aider chat started at "), false)
		if filepath.Base(shown) == aiderInput {
			c = aiderContext(data, at, []byte("\n# "), true)
		}
		c.project = filepath.Dir(shown) // Aider runs in the project's folder
		return c
	}
	return chatContextOf(data, at)
}

// aiderContext: the time from the last header before at, and who wrote the
// line: in the chat, "#### " starts what the person typed and "> " output
// Aider shows (a command's, for one); in the input history every line is typed.
func aiderContext(data []byte, at int, header []byte, typed bool) chatContext {
	var c chatContext
	if i := bytes.LastIndex(data[:at], header); i >= 0 {
		rest := data[i+len(header):]
		if len(rest) >= 19 {
			c.when, _ = time.ParseInLocation("2006-01-02 15:04:05", string(rest[:19]), time.Local)
		}
	}
	if typed {
		c.source = "prompt"
		return c
	}
	line := data[bytes.LastIndexByte(data[:at], '\n')+1:]
	switch {
	case bytes.HasPrefix(line, []byte("#### ")):
		c.source = "user"
	case bytes.HasPrefix(line, []byte("> ")):
		c.source = "tool"
	default:
		c.source = "assistant"
	}
	return c
}

// chatContextOf reads the line holding offset at: its time, who wrote it and
// the project folder, from the fields Claude Code and Codex write.
func chatContextOf(data []byte, at int) chatContext {
	lo := bytes.LastIndexByte(data[:at], '\n') + 1
	hi := len(data)
	if i := bytes.IndexByte(data[at:], '\n'); i >= 0 {
		hi = at + i
	}
	line := data[lo:hi]
	var c chatContext
	if m := isoTimeRe.FindSubmatch(line); m != nil {
		c.when, _ = time.Parse("2006-01-02T15:04:05", string(m[1]))
	} else if m := msTimeRe.FindSubmatch(line); m != nil {
		var ms int64
		fmt.Sscan(string(m[1]), &ms)
		c.when = time.UnixMilli(ms).UTC()
	}
	if m := folderRe.FindSubmatch(line); m != nil {
		_ = json.Unmarshal(m[1], &c.project) // a JSON string: C:\\Users\\… on Windows
	}
	switch {
	case bytes.Contains(line, []byte(`"tool_result"`)) || bytes.Contains(line, []byte(`"function_call_output"`)):
		c.source = "tool"
	case bytes.Contains(line, []byte(`"type":"assistant"`)) || bytes.Contains(line, []byte(`"role":"assistant"`)) ||
		bytes.Contains(line, []byte(`"type":"gemini"`)):
		c.source = "assistant"
	case bytes.Contains(line, []byte(`"type":"user"`)) || bytes.Contains(line, []byte(`"role":"user"`)):
		c.source = "user"
	case bytes.Contains(line, []byte(`"display"`)) || bytes.Contains(line, []byte(`"text"`)) && !bytes.Contains(line, []byte(`"type"`)):
		c.source = "prompt" // history.jsonl: what was typed into the prompt
	}
	return c
}

// underHome is p with the home folder written ~, whichever way the path was
// written (Windows: either slash, any case).
func underHome(home, p string) string {
	h, q := filepath.ToSlash(home), filepath.ToSlash(p)
	if runtime.GOOS == "windows" {
		h, q = strings.ToLower(h), strings.ToLower(q)
	}
	if home != "" && (q == h || strings.HasPrefix(q, h+"/")) {
		return "~" + p[len(home):]
	}
	return p
}

var (
	dottedName = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$`) // process.env.DB_PASSWORD, settings.password
	envName    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)                         // DATABASE_PASSWORD
	hostName   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?$`)
)

// codeValue: what is assigned to a password name in code rather than a
// password: another variable, a field, a query string.
func codeValue(v string) bool {
	if strings.HasPrefix(v, "eyJ") { // a JWT: three base64 parts with dots, not a field name
		return false
	}
	return dottedName.MatchString(v) || envName.MatchString(v) || strings.ContainsAny(v, "=&")
}

// realHost: what follows the "@" of a password in a URL is a host a login
// could be for: a host name with an optional port, not a fragment of a
// pattern or of prose, and not one used in examples.
func realHost(h string) bool {
	if !hostName.MatchString(h) {
		return false
	}
	name := strings.ToLower(h)
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	switch name {
	case "host", "hostname", "server", "domain", "example.com", "example.org", "example.net":
		return false
	}
	for _, s := range []string{".example", ".example.com", ".example.org", ".example.net", ".invalid", ".test"} {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

// urlHost is the host of a URL with a password in it (and what follows),
// without the login or the path.
func urlHost(u string) string {
	i := strings.IndexByte(u, '@')
	if i < 0 {
		return ""
	}
	host := u[i+1:]
	if j := strings.IndexAny(host, "/?#\\\"' `)<>,;\n"); j >= 0 {
		host = host[:j]
	}
	return host
}

// chatMeaning says what a kind of secret lets someone do, for `bordercheck full-scan`.
var chatMeaning = map[string]string{
	"Private key":       "A private key: whoever has it can sign in, or sign, wherever its public key is trusted.",
	"AWS access key":    "Access to an AWS account, with whatever permissions this key has.",
	"GitHub token":      "Access to GitHub as you: your repositories, and possibly your organisation's.",
	"Anthropic API key": "Calls to the Anthropic API, billed to the key's account.",
	"OpenAI API key":    "Calls to the OpenAI API, billed to the key's account.",
	"Stripe live key":   "Live Stripe access: customers and payments, and depending on the key, charges and refunds.",
	"Slack token":       "Access to Slack as a person or a bot: reading and posting messages.",
	"Google API key":    "A Google API key. Often an app's public key (Firebase, Maps) limited to that app; check its restrictions in Google Cloud Console.",
	"npm token":         "Can publish packages under the token's npm account.",
}

// SecretsInText finds secrets in a text about to be sent to an AI assistant
// (`bordercheck guard prompt`), with the rules used on chat history and the
// policy's own patterns. It returns each as Item says it, never the value.
func SecretsInText(p policy.Secrets, text []byte) ([]string, error) {
	s, err := newSecretScanner(p, "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range s.scanChat(text, "", false, s.extraRules()) {
		c := ChatFinding{Kind: f.kind, Name: f.name, Tail: f.tail}
		if c.Tail == "" {
			c.Tail = f.ctx.tail
		}
		out = append(out, c.Item())
	}
	return out, nil
}

// minBlob is how long an encoded string must be to be taken for one.
const minBlob = 1024

// blobStarts open the encoded strings in chat history that are skipped:
// images and documents ("data", data: URLs), the signatures of Claude's
// thinking and Codex's encrypted reasoning. Together about 30% of a busy
// history. A secret inside one is encoded and would not be found anyway.
var blobStarts = []struct {
	open []byte
	end  byte // the byte that ends it; for a data: URL also ')'
}{
	{[]byte(`"data":"`), '"'},
	{[]byte(`\"data\":\"`), '\\'}, // inside a JSON string: a tool's output
	{[]byte(`;base64,`), '"'},
	{[]byte(`"signature":"`), '"'},
	{[]byte(`"encrypted_content":"`), '"'},
}

// textSegments returns the parts of data outside encoded strings, in order,
// and how many bytes they hold. Only where a string starts and ends is
// looked for (bytes.Index and IndexByte, fast), and its first and last bytes
// are checked to be base64.
func textSegments(data []byte) (segs [][2]int, text int) {
	var blobs [][2]int
	for _, b := range blobStarts {
		for off := 0; ; {
			i := bytes.Index(data[off:], b.open)
			if i < 0 {
				break
			}
			lo := off + i + len(b.open)
			n := bytes.IndexByte(data[lo:], b.end)
			if n < 0 {
				n = len(data) - lo
			}
			if b.open[0] == ';' { // a data: URL in Markdown ends at ')'
				if k := bytes.IndexByte(data[lo:lo+n], ')'); k >= 0 {
					n = k
				}
			}
			off = lo + n
			if n >= minBlob && encoded(data[lo:lo+64]) && encoded(data[lo+n-64:lo+n]) {
				blobs = append(blobs, [2]int{lo, lo + n})
			}
		}
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i][0] < blobs[j][0] })
	at := 0
	for _, b := range blobs {
		if b[0] > at {
			segs = append(segs, [2]int{at, b[0]})
			text += b[0] - at
		}
		at = max(at, b[1])
	}
	if at < len(data) {
		segs = append(segs, [2]int{at, len(data)})
		text += len(data) - at
	}
	return segs, text
}

// encoded: every byte is base64 (standard or URL-safe).
func encoded(p []byte) bool {
	for _, b := range p {
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '=' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

// Redact replaces the secrets in text with ***REDACTED*** (for a password
// assigned to a name or in a URL, only the password), with the rules used on
// chat history and the policy's own patterns, and says what it replaced, as
// ChatFinding.Item does: never the values. For `bordercheck guard output`.
func Redact(p policy.Secrets, text string) (string, []string, error) {
	s, err := newSecretScanner(p, "")
	if err != nil {
		return text, nil, err
	}
	data := []byte(text)
	segs, _ := textSegments(data)
	hits := s.chatHits(data, segs, s.extraRules())
	if len(hits) == 0 {
		return text, nil, nil
	}
	var b strings.Builder
	var items []string
	at := 0
	for _, f := range s.findingsOf(data, hits, "", false) {
		c := ChatFinding{Kind: f.kind, Name: f.name, Tail: f.tail}
		if c.Tail == "" {
			c.Tail = f.ctx.tail
		}
		items = append(items, c.Item())
	}
	for _, h := range hits {
		if h.vlo < at {
			continue
		}
		b.Write(data[at:h.vlo])
		b.WriteString(redacted)
		at = h.vhi
	}
	b.Write(data[at:])
	return b.String(), items, nil
}

// redacted is what a secret is replaced with, as touchenv run does.
const redacted = "***REDACTED***"
