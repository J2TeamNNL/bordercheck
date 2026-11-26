package checks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/guard"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

const (
	secretScanTimeout = 30 * time.Second
	secretMaxFileSize = 10 << 20
	secretMaxEvidence = 100
)

// Files under the home folder that often hold keys, on any OS.
var secretFiles = []string{
	".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile",
	".zsh_history", ".bash_history", ".config/fish/config.fish", ".local/share/fish/fish_history",
	".aws/credentials", ".npmrc", // .netrc, .pypirc, .git-credentials, Docker…: see credLocations
	".gradle/gradle.properties", // signing and repository passwords for every Gradle build
	"AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
	"Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
	"Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
}

// Folders the .env walk never enters: big, generated, or not the user's own files.
var secretSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".hg": true, ".svn": true, "Library": true, "AppData": true,
	".Trash": true, ".cache": true, ".npm": true, ".pnpm-store": true, ".yarn": true, ".cargo": true,
	".rustup": true, ".gradle": true, ".m2": true, ".venv": true, "venv": true, "__pycache__": true,
	"vendor": true, "DerivedData": true, "Pictures": true, "Music": true, "Movies": true, "Applications": true,
	".local": true, "snap": true, ".var": true, ".steam": true, // Linux app data (XDG, Snap, Flatpak, Steam)
}

type secretRule struct {
	kind       string
	re         *regexp.Regexp
	nameGroup  int  // submatch holding the variable name; 0 = none
	valueGroup int  // submatch to test for placeholders; 0 = no test
	showTail   bool // a long random provider token: its last 4 characters are safe to show, as provider dashboards do
	high       bool // any match fails the check
}

var privateKeyRule = secretRule{kind: "Private key", high: true, re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)}

// First match wins, so specific token formats come before the generic name=value rule.
var secretRules = []secretRule{
	privateKeyRule,
	{kind: "AWS access key", showTail: true, re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{kind: "GitHub token", showTail: true, re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})`)},
	{kind: "Anthropic API key", showTail: true, re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{kind: "OpenAI API key", showTail: true, re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}`)},
	{kind: "Stripe live key", showTail: true, high: true, re: regexp.MustCompile(`\b[rs]k_live_[0-9A-Za-z]{20,}`)},
	{kind: "Slack token", showTail: true, re: regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{kind: "Google API key", showTail: true, re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
	{kind: "npm token", showTail: true, re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{kind: "Docker registry login", re: regexp.MustCompile(`"auth"\s*:\s*"[A-Za-z0-9+/=]{12,}"`)},
	{kind: "Password in URL", valueGroup: 1,
		re: regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s:/@]{3,})@`)},
	{kind: ".netrc password", valueGroup: 1,
		re: regexp.MustCompile(`(?i)^\s*(?:machine\s+\S+\s+)?(?:login\s+\S+\s+)?password\s+(\S{6,})`)},
	{kind: "Secret-looking variable", nameGroup: 1, valueGroup: 2,
		re: regexp.MustCompile(`(?i)\b([A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?)[A-Z0-9_]*)["']?\s*[:=]\s*["']?([^\s"'#;,]{8,})`)},
}

// safeName is a variable name fit to report, or "" when the "name" is itself a
// secret: a token used as a JSON key ("ghp_…": …) or before a colon
// (ghp_…:x-oauth-basic) is caught as the name by assignNameRe. A name is sent
// with the report, so it must never be a value.
func safeName(name string) string {
	for _, r := range secretRules {
		if r.showTail && r.re.MatchString(name) {
			return ""
		}
	}
	if len(name) > 40 || (len(name) >= 20 && looksRandom(name)) {
		return ""
	}
	return name
}

// looksRandom: mixed case and digits with no word breaks, as a token is and a
// variable name (API_KEY, apiKey, stripeSecret2) is not.
func looksRandom(s string) bool {
	var lower, upper, digit, sep int
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			lower++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= '0' && c <= '9':
			digit++
		default:
			sep++
		}
	}
	return sep == 0 && lower > 0 && upper > 2 && digit > 2
}

var assignNameRe = regexp.MustCompile(`(?:^|[\s;:{,])(?:export\s+|set\s+|\$env:)?["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]`)

// secretFinding locates a secret. It never holds the value, only the last 4
// characters of a provider token so people can match it to their dashboard.
type secretFinding struct {
	path     string // as shown, ~ for the home folder
	line     int
	kind     string
	name     string
	prod     bool
	tail     string
	severe   bool        // the rule itself is high severity, e.g. a private key
	chat     bool        // in an AI assistant's conversation history (secrets_aichats.go)
	signIn   bool        // a cloud CLI's sign-in cache, reported for information (signInKinds)
	store    bool        // a Java/Android keystore where it belongs, reported for information
	synced   string      // the cloud service the file is synced with (syncedBy), if any
	token    string      // for full-scan -verify: the key of the token kept in Tokens, never the value
	ctx      chatContext // where in that conversation; for bordercheck full-scan only
	lineProd bool        // a production keyword on the line itself, not only in the path
}

func (f secretFinding) high() bool { return f.prod || f.severe }

func (f secretFinding) String() string {
	s := fmt.Sprintf("%s:%d  %s", f.path, f.line, f.kind)
	if f.line == 0 { // a format without useful lines, e.g. JSON
		s = f.path + "  " + f.kind
	}
	if f.name != "" {
		s += " (" + f.name + ")"
	}
	if f.tail != "" {
		s += " …" + f.tail
	}
	if f.prod {
		s += "  [production]"
	}
	if f.synced != "" {
		s += "  [synced to " + f.synced + "]"
	}
	return s
}

// secretScanner applies one policy's secret rules.
type secretScanner struct {
	tokens   *Tokens // full-scan -verify only: where the provider tokens found are kept
	rules    []secretRule
	prodRe   *regexp.Regexp
	showTail bool
	depth    int
	ignore   []*regexp.Regexp
	extra    []string
	gitCfgs  []string   // .git/config of repositories the walk passed; see secrets_gitremotes.go
	aider    []string   // Aider's chat and input histories the walk passed; see secrets_aichats.go
	logs     []chatFile // log files to read too (bordercheck full-scan; secrets_raw.go)
	loc      policy.SecretLocations
	jsonKeys []string // small JSON files the walks passed: maybe a key (secrets_more.go)
	postman  []string // exported Postman environments the walks passed
}

// productionRe matches one of the production keywords as a word, in any case.
func productionRe(keywords []string) (*regexp.Regexp, error) {
	kw := make([]string, len(keywords))
	for i, k := range keywords {
		kw[i] = regexp.QuoteMeta(k)
	}
	return regexp.Compile(`(?i)(?:^|[^a-z])(?:` + strings.Join(kw, "|") + `)(?:[^a-z]|$)`)
}

func newSecretScanner(p policy.Secrets, home string) (*secretScanner, error) {
	s := &secretScanner{showTail: p.ShowTail == nil || *p.ShowTail, depth: p.WalkDepth, loc: p.Locations}
	for _, sp := range p.ExtraPatterns { // the org's own formats are the most specific, so they go first
		re, err := regexp.Compile(sp.Regex)
		if err != nil {
			return nil, err
		}
		s.rules = append(s.rules, secretRule{kind: sp.Kind, re: re, high: sp.High, showTail: sp.ShowTail})
	}
	s.rules = append(s.rules, secretRules...)
	var err error
	if s.prodRe, err = productionRe(p.ProductionKeywords); err != nil {
		return nil, err
	}
	for _, g := range p.IgnorePaths {
		re, err := policy.Glob(g)
		if err != nil {
			return nil, err
		}
		s.ignore = append(s.ignore, re)
	}
	for _, f := range p.ExtraFiles {
		s.extra = append(s.extra, expandHome(f, home))
	}
	return s, nil
}

func secrets(p policy.Secrets, local Local) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		home, found, bundles, incomplete, chats, err := scanSecrets(ctx, p)
		chats.fullScanNever = local.FullScanKnown && local.FullScanAt.IsZero()
		if err != nil {
			return check.Errored(err)
		}
		u := newUserIgnore("secrets", local, p.UserIgnore, home)
		sc := newSampleClassifier(ctx, p, home)
		r := evalSecretsSamples(found, bundles, incomplete, chats, secretFix(), u, sc)
		text, ev := touchenvInfo(readTouchenv(ctx, runtime.GOOS), runtime.GOOS)
		return withTouchenvInfo(r, text, ev)
	}
}

// scanSecrets finds what the policy looks for: findings and certificate
// bundles, by the path the report shows.
// chats says how the AI chat history scan went (see chatState).
func scanSecrets(ctx context.Context, p policy.Secrets) (home string, found []secretFinding, bundles []string, incomplete bool, chats chatState, err error) {
	if home, err = os.UserHomeDir(); err != nil {
		return "", nil, nil, false, chatState{}, err
	}
	s, err := newSecretScanner(p, home)
	if err != nil {
		return "", nil, nil, false, chatState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, secretScanTimeout)
	defer cancel()
	files, bs, incomplete := s.find(ctx, home)
	for _, f := range files {
		if shown := tildePath(home, f); !s.ignored(shown) {
			found = append(found, s.scanFile(f, shown)...)
		}
	}
	for _, f := range s.scanLocations(home, runtime.GOOS, p.Locations) {
		f.signIn = p.CLISignInsInfo && signInKinds[f.kind]
		found = append(found, f)
	}
	found = append(found, s.scanGitRemotes(home, p.Locations)...)
	found = append(found, s.scanLooseKeys(home)...)
	for i := range found {
		if p := found[i].path; strings.HasPrefix(p, "~") {
			found[i].synced = syncedBy(home, filepath.Join(home, p[1:]))
		}
	}
	if p.Locations.AIChats && p.AIChatHours > 0 {
		since := time.Now().Add(-time.Duration(p.AIChatHours) * time.Hour)
		inChats, partial := s.scanChats(ctx, home, since, int64(p.AIChatMaxMB)<<20, s.ignored)
		found = append(found, inChats...)
		chats.partial = partial
		if ctx.Err() != nil {
			incomplete, chats.partial = true, false // the time limit, not the size limit, stopped it
		}

	}
	for _, b := range bs {
		shown := tildePath(home, b)
		if s.ignored(shown) {
			continue
		}
		// A keystore needs its passwords to be used, and those are reported where
		// they sit (a .properties file, a shell file). On its own it is
		// information, unless it is in the Trash or a synced folder.
		if bundleLabel(b) == keystoreKind && !inTrash(shown) {
			synced := syncedBy(home, b)
			found = append(found, secretFinding{path: shown, kind: keystoreKind, synced: synced, store: synced == ""})
			continue
		}
		bundles = append(bundles, shown)
	}
	// Claude Code is used here and the guard is not all on: say how to turn it on.
	if settings := guard.SettingsPath(home); len(guard.Installed(settings)) < len(guard.Hooks) {
		if _, err := os.Stat(filepath.Dir(settings)); err == nil {
			chats.unguarded = true
		}
	}
	return home, found, bundles, incomplete, chats, nil
}

func (s *secretScanner) ignored(shown string) bool {
	shown = filepath.ToSlash(shown)
	for _, re := range s.ignore {
		if re.MatchString(shown) {
			return true
		}
	}
	return false
}

func secretFix() msg.Text {
	where := map[string]string{"darwin": "secrets.fix.mac", "windows": "secrets.fix.win", "linux": "secrets.fix.linux"}[runtime.GOOS]
	if where == "" {
		where = "secrets.fix.other"
	}
	return msg.Text{msg.P(where), msg.P("secrets.fix.rotate")}
}

// find returns the known credential files and the policy's extra files that
// exist, plus .env and key files found within s.depth folders of home.
// Certificate bundles (.p12, .pfx) are binary, so they are reported by name
// instead of scanned.
func (s *secretScanner) find(ctx context.Context, home string) (scan, bundles []string, incomplete bool) {
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			scan = append(scan, p)
		}
	}
	candidates := slices.Clone(s.extra)
	for _, rel := range secretFiles {
		candidates = append(candidates, filepath.Join(home, filepath.FromSlash(rel)))
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			add(p)
		}
	}
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			incomplete = true
			return filepath.SkipAll
		}
		if err != nil || p == home {
			return nil
		}
		name := d.Name()
		// A file or folder kept only in iCloud Drive, Dropbox, OneDrive… is a
		// placeholder: reading it makes macOS download it, which can take minutes
		// and gigabytes, and blocks until it is done. A secret that is not on this
		// disk is not this check's business, so placeholders are left alone.
		if info, err := d.Info(); err == nil && cloudPlaceholder(info) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(home, p)
			s.noteGitDir(name, p, rel)
			if secretSkipDirs[name] || strings.Count(rel, string(filepath.Separator)) >= s.depth || isPackageDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if name == aiderChat || name == aiderInput {
			s.aider = append(s.aider, p)
			return nil
		}
		info, _ := d.Info()
		s.lookAt(p, name, info, false, add, &bundles)
		return nil
	})
	if s.walkTrash(ctx, home, add, &bundles) {
		incomplete = true
	}
	return scan, bundles, incomplete
}

// isPackageDir reports folders that macOS shows as one file: apps, photo and
// media libraries, disk images. They hold no dotfiles of yours and can be huge.
func isPackageDir(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".app", ".photoslibrary", ".sparsebundle", ".backupbundle", ".musiclibrary", ".tvlibrary",
		".imovielibrary", ".fcpbundle", ".logicx", ".framework", ".xcarchive":
		return true
	}
	return false
}

func isEnvFile(name string) bool {
	if name != ".env" && !strings.HasPrefix(name, ".env.") && !strings.HasSuffix(name, ".env") {
		return false
	}
	for _, s := range []string{".example", ".sample", ".template", ".dist", ".defaults", ".schema"} {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

func (s *secretScanner) scanFile(p, shown string) []secretFinding {
	if info, err := os.Lstat(p); err == nil && cloudPlaceholder(info) {
		return nil // opening it would download it
	}
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > secretMaxFileSize {
		return nil
	}
	rules := s.rules
	switch strings.ToLower(filepath.Ext(p)) {
	case ".pem", ".key", ".p8":
		rules = []secretRule{privateKeyRule} // only a real private key counts, not app tokens that share the extension
	}
	return s.scan(f, shown, rules)
}

// scan reports secret-looking lines in r, at most one finding per line.
func (s *secretScanner) scan(r io.Reader, path string, rules []secretRule) []secretFinding {
	var out []secretFinding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	pathProd := s.prodRe.MatchString(path)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.ContainsRune(line, 0) {
			continue
		}
		for _, rule := range rules {
			m := rule.re.FindStringSubmatch(line)
			if m == nil || (rule.valueGroup > 0 && isPlaceholder(m[rule.valueGroup])) {
				continue
			}
			lineProd := s.prodRe.MatchString(line)
			f := secretFinding{path: path, line: n, kind: rule.kind, severe: rule.high,
				prod: pathProd || lineProd, lineProd: lineProd}
			if rule.nameGroup > 0 {
				f.name = safeName(m[rule.nameGroup])
			} else if a := assignNameRe.FindStringSubmatch(line); a != nil {
				f.name = safeName(a[1])
			}
			if s.showTail && rule.showTail && len(m[0]) >= 20 {
				f.tail = m[0][len(m[0])-4:]
			}
			out = append(out, f)
			break
		}
	}
	return out
}

// isPlaceholder tells values that only point at a secret (variables, paths,
// templates, examples) from real ones.
func isPlaceholder(v string) bool {
	v = strings.Trim(v, `"'`)
	if v == "" || strings.ContainsAny(v, `$<>{}%\`) || strings.Contains(v, "://") ||
		strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, ".") {
		return true
	}
	l := strings.ToLower(v)
	for _, p := range []string{"example", "changeme", "your", "xxxx", "placeholder", "dummy", "redacted", "****", "password"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return strings.Trim(l, l[:1]) == "" // one character repeated
}

// bundleLabel is how a bundle is listed: a certificate bundle, or a Java or Android keystore.
func bundleLabel(p string) string {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".jks", ".keystore", ".bks":
		return keystoreKind
	}
	return bundleKind + " (may hold a private key)"
}

// keystoreKind is how a Java or Android keystore is listed.
const keystoreKind = "Java/Android keystore (a signing key behind a password)"

// bundleKind is the kind a certificate bundle is matched and listed by.
const bundleKind = "certificate bundle"

func evalSecrets(found []secretFinding, bundles []string, incomplete bool, fix msg.Text) check.Result {
	return evalSecretsWith(found, bundles, incomplete, fix, nil)
}

func evalSecretsWith(found []secretFinding, bundles []string, incomplete bool, fix msg.Text, u *userIgnore) check.Result {
	return evalSecretsSamples(found, bundles, incomplete, chatState{}, fix, u, nil)
}

// evalSecretsSamples sets aside what the person ignored, then likely samples
// (sc; nil = none), and judges the rest.
func evalSecretsSamples(found []secretFinding, bundles []string, incomplete bool, cs chatState, fix msg.Text, u *userIgnore, sc *sampleClassifier) check.Result {
	// A finding marked production can be set aside too; the list IT gets says it was.
	found = slices.DeleteFunc(slices.Clone(found), func(f secretFinding) bool {
		return u.take(f.path, nonEmpty(f.name), f.kind, shownKind(f.kind, f.prod))
	})
	bundles = slices.DeleteFunc(slices.Clone(bundles), func(b string) bool { return u.take(b, nil, bundleKind, bundleKind) })
	found, bundles = sc.setAside(found, bundles)
	// What was found in AI chat history is information: it is named in the
	// summary and the evidence, and does not count toward the check.
	// So are cloud CLIs' sign-in caches (signInKinds), with how to sign out.
	var chats, signIns, stores []secretFinding
	found = slices.DeleteFunc(found, func(f secretFinding) bool {
		switch {
		case f.chat:
			chats = append(chats, f)
		case f.signIn:
			signIns = append(signIns, f)
		case f.store:
			stores = append(stores, f)
		default:
			return false
		}
		return true
	})
	var note, info msg.Text // info: the headline of each kind of information, for Result.Info
	if incomplete {
		note = msg.Of("secrets.incomplete")
	}
	if len(chats) > 0 {
		chatFiles := map[string]bool{}
		for _, f := range chats {
			chatFiles[f.path] = true
		}
		note = append(msg.Of("secrets.chatInfo", "n", len(chats), "files", len(chatFiles)), note...)
		info = append(info, msg.Of("secrets.chatInfo", "n", len(chats), "files", len(chatFiles))...)
	}
	if len(signIns) > 0 {
		head := msg.Of("secrets.signInInfo", "n", len(signIns))
		info = append(head, info...)
		seen := map[string]bool{}
		for _, f := range signIns {
			if key := credFix[f.kind]; key != "" && !seen[key] {
				seen[key] = true
				head = append(head, msg.P(key))
			}
		}
		note = append(head, note...)
	}
	if len(stores) > 0 {
		note = append(msg.Of("secrets.keystoreInfo", "n", len(stores)), note...)
		info = append(msg.Of("secrets.keystoreInfo", "n", len(stores)), info...)
	}
	if cs.unguarded {
		note = append(note, msg.P("secrets.chatGuard"))
	}
	if cs.fullScanNever {
		note = append(note, msg.P("secrets.fullScan"))
	}
	if cs.partial {
		note = append(note, msg.P("secrets.chatsPartial"))
	}
	var chatEv []string
	for _, f := range signIns {
		chatEv = append(chatEv, f.String()+"  [sign-in, information]")
	}
	for _, f := range chats {
		chatEv = append(chatEv, f.String()+"  [AI chat, information]")
	}
	for _, f := range stores {
		chatEv = append(chatEv, f.String()+"  [keystore, information]")
	}
	if len(found)+len(bundles) == 0 {
		head, keep := msg.Of("secrets.pass"), note
		if len(signIns)+len(stores) > 0 {
			head = msg.Of("secrets.passExceptInfo")
		} else if len(chats) > 0 {
			head = msg.Of("secrets.passOutsideChats")
		}
		if sn := sc.note(); sn != nil {
			head, keep = msg.Of("samples.all", "n", len(sc.found)), append(sn, note...)
		}
		r := check.Result{Status: check.Pass, Evidence: capEvidence(chatEv), Info: info}.WithSummary(append(head, note...))
		return sc.finish(u.finish(r, keep))
	}
	note = append(sc.note(), note...)
	sort.SliceStable(found, func(i, j int) bool { return found[i].high() && !found[j].high() })
	files, prod, high := map[string]bool{}, 0, false
	var ev []string
	for _, f := range found {
		files[f.path] = true
		if f.prod {
			prod++
		}
		high = high || f.high()
		ev = append(ev, f.String())
	}
	for _, b := range bundles {
		files[b] = true
		ev = append(ev, b+"  "+bundleLabel(b))
	}
	ev = capEvidence(append(ev, chatEv...))
	summary := msg.Of("secrets.found", "n", len(found)+len(bundles), "files", len(files))
	if prod > 0 {
		summary = msg.Of("secrets.foundProd", "n", len(found)+len(bundles), "files", len(files), "prod", prod)
	}
	r := check.Result{Status: check.Warn, Severity: check.Medium, Evidence: ev, Info: info}.
		WithSummary(append(summary, note...)).WithFix(fixFor(fix, found, bundles))
	if high {
		r.Status, r.Severity = check.Fail, check.High
	}
	return sc.finish(u.finish(r, nil))
}

// signInKinds are the sign-in caches cloud CLIs keep in plain text by design:
// sessions that signing out revokes. With the policy's cli_sign_ins_info they
// are information, not a warning.
var signInKinds = map[string]bool{
	"Azure CLI token cache (plain text)":                      true,
	"Azure CLI token cache (plain text, legacy)":              true,
	"gcloud credential store (tokens in a plain SQLite file)": true,
	"gcloud application default credentials (refresh token)":  true,
}

// credFix is the advice for a kind of finding in a credential store, which
// "move each key into the keychain" does not fit: the tool itself writes the
// file, and has its own way to keep the secret elsewhere or remove it.
var credFix = map[string]string{
	"Azure CLI token cache (plain text)":                          "secrets.fix.azureCache",
	"Azure CLI token cache (plain text, legacy)":                  "secrets.fix.azureLegacy",
	"Azure service principal secret":                              "secrets.fix.azureSP",
	"gcloud application default credentials (refresh token)":      "secrets.fix.gcloudADC",
	"gcloud credential store (tokens in a plain SQLite file)":     "secrets.fix.gcloudStore",
	"Google service account key":                                  "secrets.fix.gcloudKey",
	"Docker registry login":                                       "secrets.fix.docker",
	"Git credential (plain text)":                                 "secrets.fix.gitCreds",
	"git credential.helper=store (saves passwords in plain text)": "secrets.fix.gitCreds",
	"GitHub CLI token":                                            "secrets.fix.gh",
	"Terraform API token":                                         "secrets.fix.terraform",
	"PostgreSQL password":                                         "secrets.fix.pgpass",
	"PyPI password":                                               "secrets.fix.pypi",
	"Kubernetes token":                                            "secrets.fix.kube",
	"Kubernetes client key":                                       "secrets.fix.kube",
	"Kubernetes password":                                         "secrets.fix.kube",
	"Kubernetes auth-provider token":                              "secrets.fix.kube",
	"Kubernetes auth-provider secret":                             "secrets.fix.kube",
	"Postman environment secret":                                  "secrets.fix.postman",
	"Insomnia environment secret":                                 "secrets.fix.insomnia",
	"Insomnia request credential":                                 "secrets.fix.insomnia",
	dbeaverKind:                                                   "secrets.fix.dbeaver",
	keystoreKind:                                                  "secrets.fix.keystore",
}

// inTrash: a shown path in the Trash.
func inTrash(shown string) bool {
	p := filepath.ToSlash(shown)
	return strings.HasPrefix(p, "~/.Trash/") || strings.Contains(p, "/Trash/files/")
}

// fixFor is the fix for what is left to report: the advice for each kind of
// credential store found, and the general one only when something else (a
// key in a shell file, a .env) is among them. The note on rotating comes last.
func fixFor(general msg.Text, found []secretFinding, bundles []string) msg.Text {
	var specific msg.Text
	seen := map[string]bool{}
	other := len(bundles) > 0
	trash := slices.ContainsFunc(bundles, inTrash)
	if slices.ContainsFunc(bundles, func(b string) bool { return bundleLabel(b) == keystoreKind }) {
		seen["secrets.fix.keystore"] = true
		specific = append(specific, msg.P("secrets.fix.keystore"))
	}
	synced := false
	for _, f := range found {
		trash = trash || inTrash(f.path)
		synced = synced || f.synced != ""
		if strings.HasSuffix(f.path, ".properties") && !seen["secrets.fix.keystore"] {
			seen["secrets.fix.keystore"] = true // a signing password next to a keystore
			specific = append(specific, msg.P("secrets.fix.keystore"))
		}
		key, ok := credFix[f.kind]
		if !ok {
			other = true
			continue
		}
		if !seen[key] {
			seen[key] = true
			specific = append(specific, msg.P(key))
		}
	}
	if trash {
		specific = append(specific, msg.P("secrets.fix.trash"))
	}
	if synced {
		specific = append(specific, msg.P("secrets.fix.synced"))
		other = true // and the general advice: move the key out of the file
	}
	if len(specific) == 0 {
		return general
	}
	var out msg.Text
	var rotate msg.Text
	for _, p := range general {
		if p.Key == "secrets.fix.rotate" {
			rotate = append(rotate, p)
		} else if other {
			out = append(out, p)
		}
	}
	return append(append(out, specific...), rotate...)
}

// chatState is how the scan of AI chat history went.
type chatState struct {
	partial       bool // larger than the policy's limit: only the newest part was read
	unguarded     bool // Claude Code is used here without bordercheck guard
	fullScanNever bool // installed here, and bordercheck full-scan has never run
}

func capEvidence(ev []string) []string {
	if len(ev) > secretMaxEvidence {
		return append(ev[:secretMaxEvidence:secretMaxEvidence], fmt.Sprintf("… and %d more", len(ev)-secretMaxEvidence))
	}
	return ev
}

func tildePath(home, p string) string {
	if rest, ok := strings.CutPrefix(p, home); ok {
		return "~" + rest
	}
	return p
}
