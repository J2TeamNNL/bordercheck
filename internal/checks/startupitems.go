package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The startup-items check lists what starts at login or on a schedule
// (LaunchAgents and LaunchDaemons, XDG autostart, systemd user units, the
// crontab, Run keys, the Startup folder, scheduled tasks) and flags only solid
// signs of malware: a command that downloads and runs code, a program started
// from a temporary or download folder or an unknown hidden folder in home, a
// program anyone can modify, a program that is gone. Everything else is only
// counted. It is an inventory with a light touch, not an antivirus. Command
// lines are judged but never shown: they can hold tokens.

const startupMaxItems = 500

// startupItem is one thing that starts by itself.
type startupItem struct {
	Source  string // "LaunchAgent", "LaunchDaemon", "autostart", "systemd user unit", "crontab", "Run key", "Startup folder", "scheduled task"
	Where   string // the file, key or task it comes from, as shown
	Label   string // launchd label, unit, value or task name
	Program string // the program it starts: an absolute path, or a command name
	Command string // the whole command line, for judging only; never shown
	Own     bool   // bordercheck's own service

	// Filled in by statStartup.
	Missing  bool // Program is an absolute path that does not exist
	Writable bool // Program or its folder can be changed by any user
}

// statStartup fills Missing and Writable, without touching folders macOS
// guards with a privacy prompt (the program's existence is then unknown).
func statStartup(items []startupItem, home, goos string) {
	for i := range items {
		it := &items[i]
		p := it.Program
		if !filepath.IsAbs(p) || startupAvoided(home, goos, p) {
			continue
		}
		st, err := os.Stat(p)
		if os.IsNotExist(err) {
			it.Missing = true
			continue
		}
		if err != nil || goos == "windows" {
			continue
		}
		if st.Mode().Perm()&0o002 != 0 {
			it.Writable = true
		} else if dst, err := os.Stat(filepath.Dir(p)); err == nil && dst.Mode().Perm()&0o002 != 0 && dst.Mode()&os.ModeSticky == 0 {
			it.Writable = true
		}
	}
}

// startupAvoided: on macOS, stat in these folders can put a privacy prompt on
// screen, and /Volumes may be a network share.
func startupAvoided(home, goos, p string) bool {
	if goos != "darwin" {
		return false
	}
	if strings.HasPrefix(p, "/Volumes/") {
		return true
	}
	if sshPathAvoided(home, p) {
		rel, _ := filepath.Rel(home, p)
		rel = filepath.ToSlash(rel)
		// Most of ~/Library is fine; only other apps' containers and cloud folders prompt.
		if strings.HasPrefix(rel, "Library/") {
			for _, d := range []string{"Library/Containers/", "Library/Group Containers/", "Library/Mobile Documents/", "Library/CloudStorage/"} {
				if strings.HasPrefix(rel, d) {
					return true
				}
			}
			return false
		}
		return true
	}
	return false
}

// startupDownloadRun matches commands that fetch code and run it on the spot.
var startupDownloadRun = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^|;&]*\|\s*(sudo\s+)?(\S*/)?(ba|z|da|k|fi)?sh\b`),
	regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(\S*/)?(python[0-9.]*|perl|ruby|node|osascript)\b`),
	regexp.MustCompile(`(?i)\b(ba|z|da|k)?sh\s+-c\s+["']?\$\(\s*(curl|wget)\b`),
	regexp.MustCompile(`(?i)\bbase64\s+(-d|-D|--decode)\b[^|;&]*\|\s*(sudo\s+)?(\S*/)?((ba|z|da|k)?sh|python[0-9.]*|perl)\b`),
	regexp.MustCompile(`(?i)\b(powershell|pwsh)(\.exe)?["']?\s.*\s[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[A-Za-z0-9+/=]{20,}`),
	regexp.MustCompile(`(?i)\b(iex|invoke-expression)\b.*\b(downloadstring|downloadfile|invoke-webrequest|iwr|irm|invoke-restmethod|net\.webclient)\b`),
	regexp.MustCompile(`(?i)\b(downloadstring|invoke-webrequest|iwr|irm|invoke-restmethod)\b.*\|\s*(iex|invoke-expression)\b`),
	regexp.MustCompile(`(?i)\bmshta(\.exe)?["']?\s+["']?https?:`),
	regexp.MustCompile(`(?i)\bcertutil(\.exe)?["']?\s.*[-/]urlcache\b`),
}

func startupDownloads(cmd string) bool {
	for _, re := range startupDownloadRun {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// startupKnownHidden are hidden folders in home that developer tools install
// programs into; a program in any other hidden folder directly in home is
// suspicious.
var startupKnownHidden = map[string]bool{
	".local": true, ".config": true, ".cargo": true, ".rustup": true, ".nvm": true, ".volta": true, ".bun": true,
	".deno": true, ".npm": true, ".npm-global": true, ".pnpm": true, ".yarn": true, ".pyenv": true, ".rbenv": true,
	".rvm": true, ".asdf": true, ".sdkman": true, ".jenv": true, ".goenv": true, ".gem": true, ".docker": true,
	".orbstack": true, ".colima": true, ".rd": true, ".lima": true, ".vscode": true, ".vscode-server": true,
	".vscode-insiders": true, ".cursor": true, ".cursor-server": true, ".windsurf": true, ".codeium": true,
	".claude": true, ".ollama": true, ".dotnet": true, ".nix-profile": true, ".krew": true, ".linuxbrew": true,
	".homebrew": true, ".bin": true, ".dotfiles": true, ".oh-my-zsh": true, ".fzf": true, ".composer": true,
	".ghcup": true, ".cabal": true, ".opam": true, ".juliaup": true, ".elan": true, ".poetry": true, ".pixi": true,
	".conda": true, ".miniconda3": true, ".anaconda3": true, ".rye": true, ".wasmtime": true, ".wasmer": true,
	".foundry": true, ".android": true, ".gradle": true, ".jdks": true, ".hammerspoon": true, ".mix": true,
	".tmux": true, ".emacs.d": true, ".vim": true, ".nix-defexpr": true, ".antigen": true, ".zinit": true,
	".jbang": true, ".coursier": true, ".tfenv": true, ".kube": true, ".fly": true, ".swiftpm": true, ".mint": true,
}

var startupInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "python": true, "python3": true,
	"node": true, "perl": true, "ruby": true, "osascript": true, "pwsh": true, "powershell": true, "wscript": true,
	"cscript": true, "bun": true, "deno": true,
}

// startupEnv says what counts as a suspicious place on this machine.
type startupEnv struct {
	home    string
	goos    string
	extra   []string // more folders, absolute
	allow   []*regexp.Regexp
	tempDir string // %TEMP% on Windows
}

func (e startupEnv) norm(p string) string {
	p = filepath.ToSlash(p)
	if e.goos == "windows" {
		p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	}
	return strings.TrimSuffix(p, "/")
}

// suspiciousPlace returns why p is an odd place to start a program from, or "".
func (e startupEnv) suspiciousPlace(p string) string {
	if p == "" || !(filepath.IsAbs(p) || strings.HasPrefix(p, "/") || (len(p) > 2 && p[1] == ':')) {
		return ""
	}
	np := e.norm(p)
	home := e.norm(e.home)
	under := func(dir string) bool {
		d := e.norm(dir)
		return d != "" && strings.HasPrefix(np, d+"/")
	}
	for _, d := range []string{"/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm"} {
		if e.goos != "windows" && under(d) {
			return "a temporary folder"
		}
	}
	if e.goos == "darwin" && under("/Users/Shared") {
		return "/Users/Shared, which every user can write to"
	}
	if under(e.home + "/Downloads") {
		return "the Downloads folder"
	}
	if e.goos == "windows" {
		for _, d := range []string{e.tempDir, e.home + `\AppData\Local\Temp`, `C:\Windows\Temp`} {
			if d != "" && under(d) {
				return "a temporary folder"
			}
		}
	}
	for _, d := range e.extra {
		if under(d) {
			return d
		}
	}
	if rel, ok := strings.CutPrefix(np, home+"/"); ok && home != "" {
		first, rest, nested := strings.Cut(rel, "/")
		if nested && rest != "" && strings.HasPrefix(first, ".") && !startupKnownHidden[strings.ToLower(first)] {
			return "a hidden folder in home (~/" + first + ")"
		}
	}
	return ""
}

// startupScript returns the script an interpreter is told to run, if it is a path.
func startupScript(it startupItem, windows bool) string {
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(strings.ReplaceAll(it.Program, `\`, "/")), ".exe"))
	if !startupInterpreters[strings.TrimRight(base, "0123456789.")] {
		return ""
	}
	args := splitCommand(it.Command, windows)
	start := 1
	if i := slices.Index(args, it.Program); i >= 0 {
		start = i + 1
	}
	for _, a := range args[min(start, len(args)):] {
		if strings.HasPrefix(a, "-") || (windows && strings.HasPrefix(a, "/")) {
			continue
		}
		return a
	}
	return ""
}

// splitCommand splits a command line into words, honouring quotes. On
// Windows, backslashes are path separators, not escapes.
func splitCommand(s string, windows bool) []string {
	var out []string
	var cur strings.Builder
	quote, started := byte(0), false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && !windows && quote == '"' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote, started = c, true
		case c == ' ' || c == '\t':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
			continue
		case c == '\\' && !windows && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			started = true
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

// windowsProgram finds the program in a Windows command line, where paths
// with spaces are often left unquoted.
func windowsProgram(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			return cmd[1 : end+1]
		}
	}
	l := strings.ToLower(cmd)
	for _, ext := range []string{".exe", ".bat", ".cmd", ".com", ".vbs", ".js", ".ps1", ".lnk"} {
		if i := strings.Index(l, ext); i >= 0 && (i+len(ext) == len(l) || l[i+len(ext)] == ' ') {
			return cmd[:i+len(ext)]
		}
	}
	f, _, _ := strings.Cut(cmd, " ")
	return f
}

// expandWinEnv expands %NAME% variables.
func expandWinEnv(s string, getenv func(string) string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			break
		}
		name := s[i+1 : i+1+j]
		if v := getenv(name); v != "" && name != "" {
			b.WriteString(s[:i] + v)
		} else {
			b.WriteString(s[:i+j+2])
		}
		s = s[i+j+2:]
	}
	return b.String() + s
}

func (e startupEnv) allowed(it startupItem) bool {
	for _, re := range e.allow {
		for _, s := range []string{it.Label, filepath.ToSlash(it.Program), filepath.ToSlash(tildePath(e.home, it.Program))} {
			if s != "" && re.MatchString(s) {
				return true
			}
		}
	}
	return false
}

func newStartupEnv(home, goos string, p policy.StartupItems) startupEnv {
	e := startupEnv{home: home, goos: goos}
	if goos == "windows" {
		e.tempDir = os.Getenv("TEMP")
	}
	for _, d := range p.ExtraSuspiciousPaths {
		e.extra = append(e.extra, expandHome(d, home))
	}
	for _, g := range p.Allow {
		if re, err := policy.Glob(g); err == nil {
			e.allow = append(e.allow, re)
		}
	}
	return e
}

func startupItems(p policy.StartupItems) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		home, err := os.UserHomeDir()
		if err != nil {
			return check.Errored(err)
		}
		items, note, err := gatherStartup(ctx, home)
		if err != nil {
			return check.Errored(err)
		}
		statStartup(items, home, runtime.GOOS)
		return evalStartup(items, note, newStartupEnv(home, runtime.GOOS, p), startupFix(runtime.GOOS))
	}
}

func startupFix(goos string) msg.Text {
	switch goos {
	case "darwin":
		return msg.Of("startup.fix.mac")
	case "windows":
		return msg.Of("startup.fix.win")
	}
	return msg.Of("startup.fix.linux")
}

func evalStartup(items []startupItem, note msg.Text, e startupEnv, fix msg.Text) check.Result {
	var high, medium, low []string
	var compromise []check.Indicator
	nDL, nOdd, nW, nMiss, total := 0, 0, 0, 0, 0
	windows := e.goos == "windows"
	for _, it := range items {
		if it.Own {
			continue
		}
		total++
		if e.allowed(it) {
			continue
		}
		name := it.Label
		if name == "" {
			name = filepath.Base(it.Program)
		}
		head := fmt.Sprintf("%s %s (%s)", it.Source, it.Where, name)
		if it.Where == "" {
			head = fmt.Sprintf("%s (%s)", it.Source, name)
		}
		prog := tildePath(e.home, it.Program)
		if startupDownloads(it.Command) {
			nDL++
			high = append(high, fmt.Sprintf("%s: %s  runs a command that downloads code and runs it", head, prog))
			// A sign of compromise: code fetched from the network at every
			// start is how droppers keep themselves on a machine. (An item
			// the policy allows never gets here.)
			compromise = append(compromise, check.Indicator{What: msg.P("compromise.startupDownloadRun"), Detail: head})
			continue
		}
		why := e.suspiciousPlace(it.Program)
		target := it.Program
		if why == "" {
			if s := startupScript(it, windows); s != "" {
				why, target = e.suspiciousPlace(s), s
			}
		}
		if why != "" {
			nOdd++
			medium = append(medium, fmt.Sprintf("%s: %s  starts from %s", head, tildePath(e.home, target), why))
			continue
		}
		if it.Writable {
			nW++
			medium = append(medium, fmt.Sprintf("%s: %s  the program or its folder can be changed by any user", head, prog))
			continue
		}
		if it.Missing {
			nMiss++
			low = append(low, fmt.Sprintf("%s: %s  the program no longer exists", head, prog))
		}
	}
	if len(high)+len(medium)+len(low) == 0 {
		return check.Result{Status: check.Pass}.WithSummary(append(msg.Of("startup.pass", "n", total), note...))
	}
	var parts msg.Text
	for _, c := range []struct {
		key string
		n   int
	}{{"startup.downloadRun", nDL}, {"startup.suspicious", nOdd}, {"startup.writable", nW}, {"startup.missing", nMiss}} {
		if c.n > 0 {
			parts = append(parts, msg.P(c.key, "n", c.n))
		}
	}
	parts = append(parts, msg.P("startup.total", "n", total))
	r := check.Result{Status: check.Warn, Severity: check.Low, Evidence: slices.Concat(high, medium, low)}.
		WithSummary(append(parts, note...)).WithFix(fix)
	switch {
	case len(high) > 0:
		r.Status, r.Severity = check.Fail, check.High
		r.Compromise = compromise
	case len(medium) > 0:
		r.Severity = check.Medium
	}
	return r
}

// --- parsing shared by the per-OS gatherers ---------------------------------

// launchdItem reads a LaunchAgent or LaunchDaemon property list (as XML).
// ok is false for a plist that is not one, or is disabled.
func launchdItem(doc, source, where string) (startupItem, bool) {
	d, err := plistDict(doc)
	if err != nil {
		return startupItem{}, false
	}
	if dis, _ := d["Disabled"].(bool); dis {
		return startupItem{}, false
	}
	it := startupItem{Source: source, Where: where}
	it.Label, _ = d["Label"].(string)
	var args []string
	if a, ok := d["ProgramArguments"].([]any); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				args = append(args, s)
			}
		}
	}
	it.Program, _ = d["Program"].(string)
	if it.Program == "" && len(args) > 0 {
		it.Program = args[0]
	}
	if it.Program == "" {
		return startupItem{}, false
	}
	if len(args) == 0 {
		args = []string{it.Program}
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = a
		if strings.ContainsAny(a, " \t") {
			quoted[i] = "'" + a + "'"
		}
	}
	it.Command = strings.Join(quoted, " ")
	return it, true
}

// desktopItem reads an XDG autostart .desktop file.
func desktopItem(body, where string) (startupItem, bool) {
	inEntry, exec := false, ""
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inEntry = line == "[Desktop Entry]"
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !inEntry || !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Exec":
			exec = strings.TrimSpace(v)
		case "Hidden":
			if strings.TrimSpace(v) == "true" {
				return startupItem{}, false
			}
		case "X-GNOME-Autostart-enabled":
			if strings.TrimSpace(v) == "false" {
				return startupItem{}, false
			}
		}
	}
	if exec == "" {
		return startupItem{}, false
	}
	return commandItem("autostart", where, strings.TrimSuffix(filepath.Base(where), ".desktop"), exec), true
}

// commandItem makes an item from a Unix command line, skipping env and
// VAR=value prefixes to find the program.
func commandItem(source, where, label, cmd string) startupItem {
	it := startupItem{Source: source, Where: where, Label: label, Command: cmd}
	words := splitCommand(cmd, false)
	for len(words) > 0 && (words[0] == "env" || words[0] == "/usr/bin/env" || (strings.Contains(words[0], "=") && !strings.Contains(words[0], "/"))) {
		words = words[1:]
	}
	if len(words) > 0 {
		it.Program = words[0]
	}
	return it
}

// systemdExec returns the first ExecStart of a unit file.
func systemdExec(body string) string {
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == "ExecStart" {
			return strings.TrimLeft(strings.TrimSpace(v), "-@:+!")
		}
	}
	return ""
}

// cronItems reads `crontab -l`: a command after five time fields or an @word.
func cronItems(tab string) []startupItem {
	var out []startupItem
	for n, line := range strings.Split(tab, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Fields(line)
		if !strings.HasPrefix(f[0], "@") && strings.Contains(f[0], "=") {
			continue // VAR=value
		}
		skip := 5
		if strings.HasPrefix(f[0], "@") {
			skip = 1
		}
		if len(f) <= skip {
			continue
		}
		// The rest of the line, as written, after the time fields.
		rest := line
		for i := 0; i < skip; i++ {
			rest = strings.TrimSpace(rest[len(strings.Fields(rest)[0]):])
		}
		it := commandItem("crontab", "", fmt.Sprintf("line %d", n+1), rest)
		it.Own = strings.Contains(line, "# bordercheck:")
		out = append(out, it)
	}
	return out
}

// winStartupItems reads the tab-separated lines the Windows gatherer prints:
// kind, where, name, command.
func winStartupItems(out string, getenv func(string) string) []startupItem {
	var items []startupItem
	for _, line := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimRight(line, "\r"), "\t", 4)
		if len(f) < 4 || strings.TrimSpace(f[3]) == "" {
			continue
		}
		source := map[string]string{"run": "Run key", "folder": "Startup folder", "task": "scheduled task"}[f[0]]
		if source == "" {
			continue
		}
		cmd := expandWinEnv(strings.TrimSpace(f[3]), getenv)
		it := startupItem{Source: source, Where: f[1], Label: f[2], Command: cmd, Program: windowsProgram(cmd)}
		it.Own = f[0] == "task" && f[1] == `\` && strings.EqualFold(f[2], "bordercheck")
		items = append(items, it)
	}
	return items
}
