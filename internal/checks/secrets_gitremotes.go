package checks

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// The secrets location git_remotes finds credentials written into git URLs:
// a remote added as https://user:TOKEN@host/repo or https://TOKEN@github.com/…
// sits in plain text in that repository's .git/config (and is copied into
// every clone of the folder), and a url.<base>.insteadOf rule in ~/.gitconfig
// can carry one for every repository. Repositories are the ones the secrets
// walk already passes, so walk_depth, ignore_paths, cloud placeholders and
// the skipped folders apply. credential.helper=store and ~/.git-credentials
// belong to git_credentials.

// noteGitDir remembers a .git folder the walk reaches, if the walk would
// have entered it. Called for every folder, before the skip rules.
func (s *secretScanner) noteGitDir(name, p, rel string) {
	if name == ".git" && strings.Count(rel, string(filepath.Separator)) < s.depth {
		s.gitCfgs = append(s.gitCfgs, filepath.Join(p, "config"))
	}
}

// scanGitRemotes reads the remembered .git/config files and the user's git config.
func (s *secretScanner) scanGitRemotes(home string, on policy.SecretLocations) []secretFinding {
	if !on.GitRemotes {
		return nil
	}
	paths := append([]string{filepath.Join(home, ".gitconfig"), filepath.Join(home, ".config", "git", "config")}, s.gitCfgs...)
	var out []secretFinding
	seen := map[string]bool{}
	for _, p := range paths {
		shown := tildePath(home, p)
		if seen[p] || s.ignored(shown) {
			continue
		}
		seen[p] = true
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() > secretMaxFileSize || cloudPlaceholder(st) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, h := range readGitURLCreds(data) {
			out = append(out, s.fromHit(shown, h))
		}
	}
	return out
}

var (
	gitHeaderRe  = regexp.MustCompile(`^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]`)
	gitKeyRe     = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*?)\s*$`)
	gitURLCredRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*)://([^/@\s]+)@([^/\s:?#]+)`)
	gitTokenRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{30,}$`)
)

// readGitURLCreds finds URLs with a password or token in a git config file:
// the values of url, pushurl, insteadOf and pushInsteadOf, and the base URL
// of a [url "…"] section.
func readGitURLCreds(data []byte) []credHit {
	var hs []credHit
	section := ""
	check := func(n int, raw, kind string) {
		if host, secret, ok := gitURLCred(raw); ok {
			hs = append(hs, credHit{line: n, kind: kind, name: host, value: secret})
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if t := strings.TrimSpace(line); t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		if m := gitHeaderRe.FindStringSubmatch(line); m != nil {
			section = strings.ToLower(m[1])
			if section == "url" {
				check(n, m[2], "Token in a git URL rewrite (url.insteadOf)")
			}
			continue
		}
		m := gitKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch strings.ToLower(m[1]) {
		case "url", "pushurl":
			check(n, strings.Trim(m[2], `"`), "Token in a git remote URL")
		case "insteadof", "pushinsteadof":
			check(n, strings.Trim(m[2], `"`), "Token in a git URL rewrite (url.insteadOf)")
		}
	}
	return keep(hs)
}

// gitURLCred returns the host and the secret part of a URL that carries one:
// the password of user:password@, or a token-shaped user name over http(s)
// (https://TOKEN@github.com/…). A plain user name (git@, me@) is not a secret.
func gitURLCred(raw string) (host, secret string, ok bool) {
	m := gitURLCredRe.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return "", "", false
	}
	scheme, userinfo, host := strings.ToLower(m[1]), m[2], strings.ToLower(m[3])
	if _, pass, found := strings.Cut(userinfo, ":"); found {
		return host, pass, pass != ""
	}
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	if gitTokenShaped(userinfo) {
		return host, userinfo, true
	}
	return "", "", false
}

// gitTokenShaped tells a provider token or long random string from a user name.
func gitTokenShaped(s string) bool {
	for _, r := range secretRules {
		if r.showTail && r.re.MatchString(s) {
			return true
		}
	}
	return gitTokenRe.MatchString(s) && strings.ContainsAny(s, "0123456789") &&
		strings.ContainsAny(strings.ToLower(s), "abcdefghijklmnopqrstuvwxyz")
}
