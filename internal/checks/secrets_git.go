package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// A secret committed to git stays in the history, in every clone and on the
// remote it was pushed to, after the file is fixed. ScanGitHistory (part of
// `bordercheck full-scan`) reads the history of each repository the secrets
// walk reaches: every line any commit added, on every branch and tag, and the
// stash. It looks for the chat rules' formats (provider tokens, private keys,
// passwords in URLs and assigned to a name): precise enough for code.

// GitFinding is a secret in a repository's history, without its value.
type GitFinding struct {
	Repo    string `json:"repo"`   // ~ for the home folder
	Commit  string `json:"commit"` // the oldest commit that added it, short
	Date    string `json:"date"`   // that commit's date
	File    string `json:"file"`
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Tail    string `json:"tail,omitempty"`
	Commits int    `json:"commits"` // how many commits added it
	Pushed  bool   `json:"pushed"`  // that commit is on a remote branch this clone knows of
	Current bool   `json:"current"` // the files at HEAD still hold it
	Stash   bool   `json:"stash"`   // found in the stash only
	// Verified is what the provider said of the token (KeyLive…), with -verify only.
	Verified string `json:"verified,omitempty"`
	tokenKey string
}

// Item is the finding in a few words, as ChatFinding.Item.
func (f GitFinding) Item() string {
	return ChatFinding{Kind: f.Kind, Name: f.Name, Tail: f.Tail}.Item()
}

// Where is the repository, commit and file.
func (f GitFinding) Where() string {
	if f.Stash {
		return fmt.Sprintf("%s, stash, %s", f.Repo, f.File)
	}
	s := fmt.Sprintf("%s, commit %s (%s), %s", f.Repo, f.Commit, f.Date, f.File)
	if f.Commits > 1 {
		s += fmt.Sprintf(" (added in %d commits)", f.Commits)
	}
	return s
}

// State says where the secret still is.
func (f GitFinding) State() string {
	var parts []string
	if f.Current {
		parts = append(parts, "still in the current files")
	} else {
		parts = append(parts, "no longer in the current files, still in the history")
	}
	if f.Pushed {
		parts = append(parts, "pushed to a remote")
	} else if !f.Stash {
		parts = append(parts, "not on any remote branch this clone knows of")
	}
	return strings.Join(parts, "; ") + "."
}

// GitFix is how to deal with secrets in git history, in English.
func GitFix() string { return msg.Of("secrets.fix.git").English() }

// gitMaxAdded caps how much added text is read from one repository's history.
const gitMaxAdded = 256 << 20

// gitRepoTimeout caps the time spent on one repository.
const gitRepoTimeout = 2 * time.Minute

// ScanGitHistory reads the history of every git repository the secrets walk
// reaches. repos is how many were read; partial names those cut short (too
// large, too slow, or git failed).
func ScanGitHistory(ctx context.Context, p policy.Secrets) (found []GitFinding, repos int, partial []string, err error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, 0, nil, nil // no git: no repositories to read
	}
	home, s, err := scannerFor(p)
	if err != nil {
		return nil, 0, nil, err
	}
	s.tokens = tokensFrom(ctx)
	s.find(ctx, home)
	seen := map[string]bool{}
	for _, cfg := range s.gitCfgs {
		repo := filepath.Dir(filepath.Dir(cfg))
		shown := tildePath(home, repo)
		if seen[repo] || s.ignored(shown) || toolCache(shown) {
			continue
		}
		seen[repo] = true
		if ctx.Err() != nil {
			return found, repos, append(partial, shown), nil
		}
		fs, cut := s.scanRepo(ctx, repo, shown)
		repos++
		found = append(found, fs...)
		if cut {
			partial = append(partial, shown)
		}
	}
	return found, repos, partial, nil
}

// userHome is the home folder; a variable so tests can point it elsewhere.
var userHome = os.UserHomeDir

// scannerFor is the home folder and a scanner for the policy.
func scannerFor(p policy.Secrets) (string, *secretScanner, error) {
	home, err := userHome()
	if err != nil {
		return "", nil, err
	}
	s, err := newSecretScanner(p, home)
	return home, s, err
}

// gitLine is where an added line of the history came from.
type gitLine struct {
	off    int // in the added text
	commit int // index in commits
	file   string
	stash  bool
}

type gitCommit struct{ hash, date string }

func (s *secretScanner) scanRepo(ctx context.Context, repo, shown string) ([]GitFinding, bool) {
	ctx, cancel := context.WithTimeout(ctx, gitRepoTimeout)
	defer cancel()
	mine := authorEmails(ctx, repo)
	var text bytes.Buffer
	var lines []gitLine
	var commits []gitCommit
	cut := false
	read := func(stash bool, args ...string) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo, "-c", "core.quotepath=off"}, args...)...)
		out, err := cmd.StdoutPipe()
		if err != nil {
			cut = true
			return
		}
		if cmd.Start() != nil {
			cut = true
			return
		}
		r := bufio.NewReaderSize(out, 1<<20)
		file := ""
		cur := -1
		for {
			line, err := r.ReadSlice('\n')
			if err == bufio.ErrBufferFull {
				for err == bufio.ErrBufferFull { // a line over 1 MB (minified code): skipped
					_, err = r.ReadSlice('\n')
				}
				continue
			}
			if len(line) == 0 && err != nil {
				break
			}
			switch {
			case bytes.HasPrefix(line, []byte("\x00C ")):
				f := strings.Fields(string(line[3:]))
				cur = -1
				if len(f) >= 2 {
					email := ""
					if len(f) >= 3 {
						email = strings.ToLower(f[2])
					}
					// Only the person's own commits: a cloned project's history is its authors' business.
					if len(mine) == 0 || mine[email] || stash {
						commits = append(commits, gitCommit{hash: f[0], date: f[1]})
						cur = len(commits) - 1
					}
				}
			case bytes.HasPrefix(line, []byte("+++ ")):
				file = strings.TrimPrefix(strings.TrimSpace(string(line[4:])), "b/")
			case len(line) > 1 && line[0] == '+' && cur >= 0 && !generatedPath(file):
				if text.Len() > gitMaxAdded {
					cut = true
					continue
				}
				lines = append(lines, gitLine{off: text.Len(), commit: cur, file: file, stash: stash})
				text.Write(line[1:])
				if line[len(line)-1] != '\n' {
					text.WriteByte('\n')
				}
			}
			if err != nil {
				break
			}
		}
		if cmd.Wait() != nil && ctx.Err() != nil {
			cut = true
		}
	}
	format := "--format=format:%x00C %H %cs %ae"
	read(false, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", format)
	if exec.CommandContext(ctx, "git", "-C", repo, "rev-parse", "-q", "--verify", "refs/stash").Run() == nil {
		// A stash entry is a merge commit: compared with its first parent it shows the stashed changes.
		read(true, "log", "-g", "-p", "-m", "--first-parent", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", format, "refs/stash")
	}
	data := text.Bytes()
	hits := s.chatHits(data, [][2]int{{0, len(data)}}, s.extraRules())
	if len(hits) == 0 {
		return nil, cut
	}
	pushed := remoteCommits(ctx, repo)
	type acc struct {
		f     GitFinding
		match string
		set   map[string]bool
	}
	var order []*acc
	byKey := map[[32]byte]*acc{}
	for _, h := range hits {
		i := sort.Search(len(lines), func(i int) bool { return lines[i].off > h.at }) - 1
		if i < 0 {
			continue
		}
		ln := lines[i]
		c := commits[ln.commit]
		if (h.rule.kind == chatPasswordRule.kind || h.rule.kind == "Password in URL") && sampleFile(ln.file) {
			continue // test and example files are full of made-up passwords; tokens and keys are still reported
		}
		key := sha256.Sum256([]byte(h.rule.kind + "\x00" + h.match))
		a := byKey[key]
		if a == nil {
			a = &acc{f: GitFinding{Repo: shown, Kind: h.rule.kind, Name: h.name, Stash: ln.stash}, match: h.match, set: map[string]bool{}}
			if h.rule.showTail {
				a.f.tokenKey = s.tokens.keep(h.rule.kind, h.match)
			}
			if s.showTail && h.rule.showTail && len(h.match) >= 20 {
				a.f.Tail = h.match[len(h.match)-4:]
			} else if s.showTail && len(h.value) >= 12 {
				a.f.Tail = h.value[len(h.value)-4:]
			}
			byKey[key] = a
			order = append(order, a)
		}
		if !ln.stash {
			a.f.Stash = false
		}
		a.set[c.hash] = true
		// git log lists the newest first: the last one seen is the oldest, where it was added.
		a.f.Commit, a.f.Date, a.f.File = c.hash[:min(len(c.hash), 8)], c.date, ln.file
		a.f.Pushed = a.f.Pushed || pushed[c.hash]
	}
	var out []GitFinding
	for _, a := range order {
		a.f.Commits = len(a.set)
		a.f.Current = inHead(ctx, repo, a.match)
		out = append(out, a.f)
	}
	return out, cut
}

// remoteCommits are the commits reachable from a remote-tracking branch.
func remoteCommits(ctx context.Context, repo string) map[string]bool {
	out, err := exec.CommandContext(ctx, "git", "-C", repo, "rev-list", "--remotes").Output()
	set := map[string]bool{}
	if err != nil {
		return set
	}
	for _, h := range strings.Fields(string(out)) {
		set[h] = true
	}
	return set
}

// inHead reports whether the files at HEAD hold match. The value goes to git
// on its standard input, never on its command line, where `ps` would show it.
func inHead(ctx context.Context, repo, match string) bool {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "grep", "-q", "-F", "-I", "-f", "-", "HEAD", "--")
	cmd.Stdin = strings.NewReader(match + "\n")
	return cmd.Run() == nil
}

// authorEmails are the person's own addresses: user.email in the
// repository's and the global git config, lower case. Empty when none is set:
// then every commit counts.
func authorEmails(ctx context.Context, repo string) map[string]bool {
	set := map[string]bool{}
	out, _ := exec.CommandContext(ctx, "git", "-C", repo, "config", "--get-all", "user.email").Output()
	for _, e := range strings.Fields(strings.ToLower(string(out))) {
		set[e] = true
	}
	return set
}

// generatedPath: dependencies and build output committed by mistake, and
// minified files: someone else's code, not where a person puts a key.
func generatedPath(p string) bool {
	p = "/" + filepath.ToSlash(p)
	for _, d := range []string{"/node_modules/", "/vendor/", "/dist/", "/build/", "/.next/", "/Pods/", "/target/"} {
		if strings.Contains(p, d) {
			return true
		}
	}
	return strings.HasSuffix(p, ".min.js") || strings.HasSuffix(p, ".map") || strings.HasSuffix(p, "-lock.json") ||
		strings.HasSuffix(p, ".lock")
}

// toolCache: a repository a tool keeps for itself (plugin and skill caches),
// not the person's.
func toolCache(shown string) bool {
	p := filepath.ToSlash(shown)
	for _, d := range []string{"~/.claude/plugins/", "~/.codex/.tmp/", "~/.codex/plugins/", "~/.cache/", "~/.cursor/extensions/", "~/.vscode/extensions/"} {
		if strings.HasPrefix(p+"/", d) {
			return true
		}
	}
	return false
}

// sampleFile: a test, fixture or example file, where passwords are made up.
func sampleFile(p string) bool {
	p = strings.ToLower("/" + filepath.ToSlash(p))
	base := filepath.Base(p)
	for _, d := range []string{"/test/", "/tests/", "/testdata/", "/__tests__/", "/spec/", "/fixtures/", "/examples/", "/example/", "/samples/", "/docs/", "/doc/"} {
		if strings.Contains(p, d) {
			return true
		}
	}
	for _, s := range []string{"_test.", ".test.", ".spec.", "test.java", "test.kt", "tests.swift", "test.swift", ".example", ".sample", ".template", ".md"} {
		if strings.Contains(base, s) {
			return true
		}
	}
	return false
}
