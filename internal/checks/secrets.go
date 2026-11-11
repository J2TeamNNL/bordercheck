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

var assignNameRe = regexp.MustCompile(`(?:^|[\s;:{,])(?:export\s+|set\s+|\$env:)?["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]`)

// secretFinding locates a secret. It never holds the value, only the last 4
// characters of a provider token so people can match it to their dashboard.
type secretFinding struct {
	path   string // as shown, ~ for the home folder
	line   int
	kind   string
	name   string
	prod   bool
	tail   string
	severe bool // the rule itself is high severity, e.g. a private key
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
	return s
}

// secretScanner applies one policy's secret rules.
type secretScanner struct {
	rules    []secretRule
	prodRe   *regexp.Regexp
	showTail bool
	depth    int
	ignore   []*regexp.Regexp
	extra    []string
	gitCfgs  []string // .git/config of repositories the walk passed; see secrets_gitremotes.go
}

func newSecretScanner(p policy.Secrets, home string) (*secretScanner, error) {
	s := &secretScanner{showTail: p.ShowTail == nil || *p.ShowTail, depth: p.WalkDepth}
	for _, sp := range p.ExtraPatterns { // the org's own formats are the most specific, so they go first
		re, err := regexp.Compile(sp.Regex)
		if err != nil {
			return nil, err
		}
		s.rules = append(s.rules, secretRule{kind: sp.Kind, re: re, high: sp.High, showTail: sp.ShowTail})
	}
	s.rules = append(s.rules, secretRules...)
	kw := make([]string, len(p.ProductionKeywords))
	for i, k := range p.ProductionKeywords {
		kw[i] = regexp.QuoteMeta(k)
	}
	var err error
	if s.prodRe, err = regexp.Compile(`(?i)(?:^|[^a-z])(?:` + strings.Join(kw, "|") + `)(?:[^a-z]|$)`); err != nil {
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
		home, found, bundles, incomplete, err := scanSecrets(ctx, p)
		if err != nil {
			return check.Errored(err)
		}
		u := newUserIgnore("secrets", local, p.UserIgnore, home)
		sc := newSampleClassifier(ctx, p, home)
		return evalSecretsSamples(found, bundles, incomplete, secretFix(), u, sc)
	}
}

// scanSecrets finds what the policy looks for: findings and certificate
// bundles, by the path the report shows.
func scanSecrets(ctx context.Context, p policy.Secrets) (home string, found []secretFinding, bundles []string, incomplete bool, err error) {
	if home, err = os.UserHomeDir(); err != nil {
		return "", nil, nil, false, err
	}
	s, err := newSecretScanner(p, home)
	if err != nil {
		return "", nil, nil, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, secretScanTimeout)
	defer cancel()
	files, bs, incomplete := s.find(ctx, home)
	for _, f := range files {
		if shown := tildePath(home, f); !s.ignored(shown) {
			found = append(found, s.scanFile(f, shown)...)
		}
	}
	found = append(found, s.scanLocations(home, runtime.GOOS, p.Locations)...)
	found = append(found, s.scanGitRemotes(home, p.Locations)...)
	for _, b := range bs {
		if shown := tildePath(home, b); !s.ignored(shown) {
			bundles = append(bundles, shown)
		}
	}
	return home, found, bundles, incomplete, nil
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
		switch strings.ToLower(filepath.Ext(name)) {
		case ".pem", ".key", ".p8":
			add(p)
		case ".p12", ".pfx":
			bundles = append(bundles, p)
		default:
			if isEnvFile(name) {
				add(p)
			}
		}
		return nil
	})
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
			f := secretFinding{path: path, line: n, kind: rule.kind, severe: rule.high,
				prod: pathProd || s.prodRe.MatchString(line)}
			if rule.nameGroup > 0 {
				f.name = m[rule.nameGroup]
			} else if a := assignNameRe.FindStringSubmatch(line); a != nil {
				f.name = a[1]
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

// bundleKind is the kind a certificate bundle is matched and listed by.
const bundleKind = "certificate bundle"

func evalSecrets(found []secretFinding, bundles []string, incomplete bool, fix msg.Text) check.Result {
	return evalSecretsWith(found, bundles, incomplete, fix, nil)
}

func evalSecretsWith(found []secretFinding, bundles []string, incomplete bool, fix msg.Text, u *userIgnore) check.Result {
	return evalSecretsSamples(found, bundles, incomplete, fix, u, nil)
}

// evalSecretsSamples sets aside what the person ignored, then likely samples
// (sc; nil = none), and judges the rest.
func evalSecretsSamples(found []secretFinding, bundles []string, incomplete bool, fix msg.Text, u *userIgnore, sc *sampleClassifier) check.Result {
	// Findings marked production are for IT alone to set aside.
	found = slices.DeleteFunc(slices.Clone(found), func(f secretFinding) bool {
		return !f.prod && u.take(f.path, nonEmpty(f.name), f.kind, f.kind)
	})
	bundles = slices.DeleteFunc(slices.Clone(bundles), func(b string) bool { return u.take(b, nil, bundleKind, bundleKind) })
	found, bundles = sc.setAside(found, bundles)
	var note msg.Text
	if incomplete {
		note = msg.Of("secrets.incomplete")
	}
	if len(found)+len(bundles) == 0 {
		head, keep := msg.Of("secrets.pass"), note
		if sn := sc.note(); sn != nil {
			head, keep = msg.Of("samples.all", "n", len(sc.found)), append(sn, note...)
		}
		return sc.finish(u.finish(check.Result{Status: check.Pass}.WithSummary(append(head, note...)), keep))
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
		ev = append(ev, b+"  "+bundleKind+" (may hold a private key)")
	}
	if len(ev) > secretMaxEvidence {
		ev = append(ev[:secretMaxEvidence], fmt.Sprintf("… and %d more", len(ev)-secretMaxEvidence))
	}
	summary := msg.Of("secrets.found", "n", len(found)+len(bundles), "files", len(files))
	if prod > 0 {
		summary = msg.Of("secrets.foundProd", "n", len(found)+len(bundles), "files", len(files), "prod", prod)
	}
	r := check.Result{Status: check.Warn, Severity: check.Medium, Evidence: ev}.
		WithSummary(append(summary, note...)).WithFix(fix)
	if high {
		r.Status, r.Severity = check.Fail, check.High
	}
	return sc.finish(u.finish(r, nil))
}

func tildePath(home, p string) string {
	if rest, ok := strings.CutPrefix(p, home); ok {
		return "~" + rest
	}
	return p
}
