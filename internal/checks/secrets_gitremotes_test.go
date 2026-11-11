package checks

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// Fixtures only, in a temp home; tokens are built at run time (see fakeGitHub).
func TestSecretsGitRemotes(t *testing.T) {
	home := t.TempDir()
	random := "Zq8" + strings.Repeat("x7Lm", 8)
	writeFile(t, home, "work/app/.git/config", strings.Join([]string{
		"[core]",
		"\trepositoryformatversion = 0",
		`[remote "origin"]`,
		"\turl = https://" + fakeGitHub + "@github.com/acme/app.git",
		"\tfetch = +refs/heads/*:refs/remotes/origin/*",
		`[remote "gitlab"]`,
		"\turl = https://oauth2:" + fakeSecret + "@gitlab.example.com/acme/app.git",
		"\tpushurl = https://deploy:" + random + "@git.example.org/app",
		`[remote "plain"]`,
		"\turl = git@github.com:acme/app.git",
		"\turl = https://alice@github.com/acme/app.git",
		"\turl = ssh://git@host.example/app",
		"\turl = https://user:${GIT_TOKEN}@ci.example/app",
	}, "\n"), 0o600)
	writeFile(t, home, ".gitconfig", "[user]\n\tname = Demo\n[url \"https://x-access-token:"+fakeSecret+"@github.com/\"]\n\tinsteadOf = https://github.com/\n", 0o600)
	writeFile(t, home, "deep/a/b/c/d/e/.git/config", "[remote \"o\"]\n\turl = https://u:"+fakeSecret+"@too.deep/x\n", 0o600)
	writeFile(t, home, "node_modules/x/.git/config", "[remote \"o\"]\n\turl = https://u:"+fakeSecret+"@skipped.example/x\n", 0o600)
	writeFile(t, home, "fixtures/repo/.git/config", "[remote \"o\"]\n\turl = https://u:"+fakeSecret+"@ignored.example/x\n", 0o600)

	p := policy.Default().Checks.Secrets
	p.IgnorePaths = []string{"~/fixtures/**"}
	s, err := newSecretScanner(p, home)
	if err != nil {
		t.Fatal(err)
	}
	s.find(context.Background(), home, Privacy{CredentialStores: true})
	found := s.scanGitRemotes(home, p.Locations)
	var got []string
	for _, f := range found {
		got = append(got, filepath.ToSlash(f.String()))
	}
	sort.Strings(got)
	want := []string{
		"~/.gitconfig:3  Token in a git URL rewrite (url.insteadOf) (github.com)",
		"~/work/app/.git/config:4  Token in a git remote URL (github.com) …WXYZ",
		"~/work/app/.git/config:7  Token in a git remote URL (gitlab.example.com)",
		"~/work/app/.git/config:8  Token in a git remote URL (git.example.org)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	assertNoLeak(t, "git remotes", got...)
	for _, g := range got {
		if strings.Contains(g, random) {
			t.Errorf("leaks: %s", g)
		}
	}

	// show_tail off hides even the last 4 characters.
	off := false
	p.ShowTail = &off
	s, _ = newSecretScanner(p, home)
	s.find(context.Background(), home, Privacy{CredentialStores: true})
	for _, f := range s.scanGitRemotes(home, p.Locations) {
		if f.tail != "" {
			t.Errorf("tail shown: %s", f)
		}
	}
	// Location off; and walk_depth limits which repositories are seen.
	p.Locations.GitRemotes = false
	if n := len(s.scanGitRemotes(home, p.Locations)); n != 0 {
		t.Errorf("git_remotes off: %d findings", n)
	}
	p = policy.Default().Checks.Secrets
	p.WalkDepth = 1
	s, _ = newSecretScanner(p, home)
	s.find(context.Background(), home, Privacy{CredentialStores: true})
	if n := len(s.scanGitRemotes(home, p.Locations)); n != 1 { // ~/.gitconfig only: ~/work/app/.git is two folders down
		t.Errorf("walk_depth 1: %d findings", n)
	}
}

func TestGitURLCred(t *testing.T) {
	for raw, want := range map[string]string{
		"https://u:p4ss@h.example/x":            "h.example",
		"https://" + fakeGitHub + "@github.com": "github.com",
		"https://alice@github.com/x":            "",
		"https://alice.smith@corp.example/x":    "",
		"ssh://git@host/x":                      "",
		"git@github.com:a/b":                    "",
		"https://h.example/x":                   "",
	} {
		host, _, ok := gitURLCred(raw)
		if (want != "") != ok || host != want {
			t.Errorf("%s: got %q %v", raw, host, ok)
		}
	}
}
