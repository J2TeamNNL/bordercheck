package checks

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Likely sample keys (checks.secrets.sample_rules). Many keys on a developer's
// machine are not real: an upstream project's default key in a fork, a CI
// dummy .env, the certificates an SDK ships to everyone, a demo app's signing
// key. A secrets finding that one of these rules matches is set aside: it does
// not count toward the check's status, severity, counts or evidence, and is
// listed in the result's LikelySamples for local and detailed reports. Never set aside: a finding marked [production], anything inside a .git
// folder (a repository's own config holds real remote credentials), and, by
// sample-dir alone, a live-looking provider token.
//
//   - git-tracked: the file is tracked by a git repository below the home
//     folder and its content is exactly what the index records (gitindex.go).
//     A real secret committed to a repository matches too: that is why the
//     list is available for review and production-marked findings are excluded.
//   - sdk: a file an SDK ships identically to every user (sdkSampleDirs).
//   - sample-dir: a folder between the home folder and the file is named
//     like a demo, sample, example, fixture, testdata or mock folder.

// maxSamplesListed caps the findings listed in a result's LikelySamples.
const maxSamplesListed = 200

// sampleClassifyTimeout bounds the time spent reading git indexes and hashing
// files in one run; after it, what is left is not set aside.
const sampleClassifyTimeout = 10 * time.Second

// sampleDirWords are the words that make a folder a sample folder, matched
// against the parts of its name split on - _ and . (case-insensitive). "test"
// and "tests" are left out on purpose: real projects keep real credentials for
// their test environments in such folders.
var sampleDirWords = map[string]bool{
	"demo": true, "demos": true, "sample": true, "samples": true, "example": true, "examples": true,
	"fixture": true, "fixtures": true, "testdata": true, "mock": true, "mocks": true,
}

// sdkSampleDirs: an SDK install folder (a path component with this name) and
// the folder below it, at any depth, whose files the SDK ships to every user.
// Only files verified to be shipped, never ones generated per user: Tizen
// Studio's certificate generator ships the public Tizen developer CA and the
// default distributor signer (tizen-distributor-signer.p12, whose password is
// published in Tizen's documentation) under tools/certificate-generator/
// certificates/; a developer's own author certificate is generated into
// tizen-studio-data/keystore, which does not match. tizen-sdk is the older
// name of the same SDK, with the same layout.
var sdkSampleDirs = []struct{ sdk, sub string }{
	{"tizen-studio", "certificates"},
	{"tizen-sdk", "certificates"},
}

// sampleClassifier applies a policy's sample rules to one run's findings.
type sampleClassifier struct {
	rules   []string
	tokens  map[string]bool // kinds of live-looking provider tokens
	home    string
	ctx     context.Context
	cancel  context.CancelFunc
	indexes map[string]*sampleIndex // by git dir
	located map[string]gitFile      // by shown path, from prepare
	found   []check.LikelySample
}

// gitFile is a file's repository and its path there, with /.
type gitFile struct {
	gitDir, rel string
}

// sampleIndex is one repository's index, read once per run.
type sampleIndex struct {
	repo    gitRepo
	format  gitObjectFormat
	entries map[string]gitIndexEntry // nil: could not be read
}

// newSampleClassifier applies p's sample rules; nil when there are none.
func newSampleClassifier(ctx context.Context, p policy.Secrets, home string) *sampleClassifier {
	if len(p.SampleRules) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, sampleClassifyTimeout)
	c := &sampleClassifier{rules: p.SampleRules, tokens: map[string]bool{}, home: home, ctx: ctx, cancel: cancel,
		indexes: map[string]*sampleIndex{}, located: map[string]gitFile{}}
	// A live-looking provider token is a rule whose last characters may be
	// shown; an org's own pattern counts when it says so.
	for _, r := range secretRules {
		if r.showTail {
			c.tokens[r.kind] = true
		}
	}
	for _, sp := range p.ExtraPatterns {
		if sp.ShowTail {
			c.tokens[sp.Kind] = true
		}
	}
	return c
}

// prepare reads, once per repository, the index entries of every candidate
// path, so a big index is walked once however many findings it has.
func (c *sampleClassifier) prepare(paths []string) {
	if c == nil || !slices.Contains(c.rules, "git-tracked") {
		return
	}
	want := map[string]map[string]bool{}
	repos := map[string]gitRepo{}
	for _, shown := range paths {
		abs, ok := c.abs(shown)
		if !ok || insideDotGit(shown) {
			continue
		}
		repo, ok := findGitRepo(abs, c.home)
		if !ok {
			continue
		}
		rel, err := filepath.Rel(repo.root, abs)
		if err != nil {
			continue
		}
		if want[repo.gitDir] == nil {
			want[repo.gitDir] = map[string]bool{}
			repos[repo.gitDir] = repo
		}
		want[repo.gitDir][filepath.ToSlash(rel)] = true
		c.located[shown] = gitFile{repo.gitDir, filepath.ToSlash(rel)}
	}
	for gd, repo := range repos {
		if c.ctx.Err() != nil {
			return
		}
		idx := &sampleIndex{repo: repo}
		if data, format, err := readGitIndex(repo); err == nil {
			if entries, err := parseGitIndex(data, format, want[gd]); err == nil {
				idx.format, idx.entries = format, entries
			}
		}
		c.indexes[gd] = idx
	}
}

// setAside removes the findings and bundles that look like samples. Findings
// marked [production] are never set aside.
func (c *sampleClassifier) setAside(found []secretFinding, bundles []string) ([]secretFinding, []string) {
	if c == nil {
		return found, bundles
	}
	var paths []string
	for _, f := range found {
		if !f.prod {
			paths = append(paths, f.path)
		}
	}
	c.prepare(append(paths, bundles...))
	found = slices.DeleteFunc(found, func(f secretFinding) bool { return !f.prod && c.take(f.path, f.name, f.kind, c.tokens[f.kind]) })
	bundles = slices.DeleteFunc(bundles, func(b string) bool { return c.take(b, "", bundleKind, false) })
	return found, bundles
}

// abs turns a shown path (~ for the home folder) back into the file's path.
func (c *sampleClassifier) abs(shown string) (string, bool) {
	if rest, ok := strings.CutPrefix(shown, "~"); ok && (rest == "" || rest[0] == '/' || rest[0] == filepath.Separator) {
		return c.home + rest, true
	}
	if filepath.IsAbs(shown) {
		return shown, true
	}
	return "", false
}

// take reports whether a rule sets the finding aside, and if so records it.
// token is a live-looking provider token (one whose last characters may be
// shown), which a folder's name alone never sets aside.
func (c *sampleClassifier) take(shown, name, kind string, token bool) bool {
	if c == nil || insideDotGit(shown) {
		return false
	}
	for _, rule := range c.rules {
		var hit bool
		switch rule {
		case "git-tracked":
			hit = c.gitTracked(shown)
		case "sdk":
			hit = sdkShipped(shown)
		case "sample-dir":
			hit = !token && inSampleDir(shown)
		}
		if hit {
			c.found = append(c.found, check.LikelySample{Path: shown, Name: name, Kind: kind, Rule: rule})
			return true
		}
	}
	return false
}

// gitTracked: prepare found the file in a repository whose index records it
// with exactly the file's current content.
func (c *sampleClassifier) gitTracked(shown string) bool {
	loc, ok := c.located[shown]
	if !ok || c.ctx.Err() != nil {
		return false
	}
	idx := c.indexes[loc.gitDir]
	if idx == nil || idx.entries == nil {
		return false
	}
	e, ok := idx.entries[loc.rel]
	if !ok {
		return false
	}
	abs, _ := c.abs(shown)
	id, ok := gitBlobID(abs, idx.format)
	return ok && bytes.Equal(id, e.oid)
}

// pathParts splits a shown path into its folders and file name.
func pathParts(shown string) []string {
	return strings.FieldsFunc(filepath.ToSlash(shown), func(r rune) bool { return r == '/' })
}

func insideDotGit(shown string) bool {
	parts := pathParts(shown)
	return len(parts) > 1 && slices.Contains(parts[:len(parts)-1], ".git")
}

// sdkShipped: the file is below <sdk>/…/<sub>/ for one of sdkSampleDirs.
func sdkShipped(shown string) bool {
	parts := pathParts(shown)
	if len(parts) < 2 {
		return false
	}
	dirs := parts[:len(parts)-1]
	for _, s := range sdkSampleDirs {
		if i := slices.Index(dirs, s.sdk); i >= 0 && slices.Contains(dirs[i+1:], s.sub) {
			return true
		}
	}
	return false
}

// inSampleDir: a folder between the home folder and the file has a sample
// word in its name. Only for files under the home folder; the file's own
// name does not count.
func inSampleDir(shown string) bool {
	parts := pathParts(shown)
	if len(parts) < 3 || parts[0] != "~" {
		return false
	}
	for _, dir := range parts[1 : len(parts)-1] {
		for _, w := range strings.FieldsFunc(strings.ToLower(dir), func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			if sampleDirWords[w] {
				return true
			}
		}
	}
	return false
}

// note is the summary part saying how many were set aside.
func (c *sampleClassifier) note() msg.Text {
	if c == nil || len(c.found) == 0 {
		return nil
	}
	return msg.Of("samples.more", "n", len(c.found))
}

// finish puts the list on r and ends the run's time limit.
func (c *sampleClassifier) finish(r check.Result) check.Result {
	if c == nil {
		return r
	}
	c.cancel()
	listed := slices.Clone(c.found)
	sort.SliceStable(listed, func(i, j int) bool { return listed[i].Path < listed[j].Path })
	if len(listed) > maxSamplesListed {
		listed = listed[:maxSamplesListed]
	}
	if len(listed) > 0 {
		r.LikelySamples = listed
	}
	return r
}
