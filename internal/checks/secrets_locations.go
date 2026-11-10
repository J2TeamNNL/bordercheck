package checks

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// credHit is one credential a format-aware reader found. value is only used
// to test for placeholders and take the last 4 characters of provider tokens;
// it never leaves this file.
type credHit struct {
	line   int // 0 when the format has no useful line, e.g. JSON
	kind   string
	name   string
	value  string
	severe bool
}

// credLocation is a well-known credential store with its own reader.
type credLocation struct {
	on    func(policy.SecretLocations) bool
	paths func(home, goos string) []string
	read  func(data []byte) []credHit // nil: report that the file exists
	kind  string                      // for read == nil
}

func appData(home string) string { return filepath.Join(home, "AppData", "Roaming") }

// userConfig is where CLIs following XDG (or %APPDATA% on Windows) keep config.
func userConfig(home, goos string) string {
	if goos == "windows" {
		return appData(home)
	}
	return filepath.Join(home, ".config")
}

func homeFiles(rel ...string) func(string, string) []string {
	return func(home, _ string) []string {
		out := make([]string, len(rel))
		for i, r := range rel {
			out[i] = filepath.Join(home, filepath.FromSlash(r))
		}
		return out
	}
}

var credLocations = []credLocation{
	{on: func(l policy.SecretLocations) bool { return l.Docker }, paths: homeFiles(".docker/config.json"), read: readDockerConfig},
	{on: func(l policy.SecretLocations) bool { return l.Kube }, paths: homeFiles(".kube/config"), read: readKubeConfig},
	{on: func(l policy.SecretLocations) bool { return l.Netrc }, paths: homeFiles(".netrc", "_netrc"), read: readNetrc},
	{on: func(l policy.SecretLocations) bool { return l.GitCredentials }, read: readGitCredentials,
		paths: func(home, goos string) []string {
			return []string{filepath.Join(home, ".git-credentials"), filepath.Join(userConfig(home, "linux"), "git", "credentials")}
		}},
	{on: func(l policy.SecretLocations) bool { return l.GitCredentials }, read: readGitConfigHelper,
		paths: func(home, goos string) []string {
			return []string{filepath.Join(home, ".gitconfig"), filepath.Join(userConfig(home, "linux"), "git", "config")}
		}},
	{on: func(l policy.SecretLocations) bool { return l.GCloud }, read: readGCloudADC, paths: gcloudADCPaths},
	{on: func(l policy.SecretLocations) bool { return l.GCloud }, kind: "gcloud credential store (tokens in a plain SQLite file)",
		paths: func(home, goos string) []string {
			d := gcloudDir(home, goos)
			return []string{filepath.Join(d, "credentials.db"), filepath.Join(d, "access_tokens.db")}
		}},
	{on: func(l policy.SecretLocations) bool { return l.Azure }, read: readAzureTokenCache,
		paths: homeFiles(".azure/msal_token_cache.json", ".azure/accessTokens.json")},
	{on: func(l policy.SecretLocations) bool { return l.Azure }, read: readAzureServicePrincipals,
		paths: homeFiles(".azure/service_principal_entries.json")},
	{on: func(l policy.SecretLocations) bool { return l.PyPI }, paths: homeFiles(".pypirc"),
		read: iniPasswords("PyPI password", "password")},
	{on: func(l policy.SecretLocations) bool { return l.GitHubCLI }, read: readGHHosts,
		paths: func(home, goos string) []string {
			if goos == "windows" {
				return []string{filepath.Join(appData(home), "GitHub CLI", "hosts.yml")}
			}
			return []string{filepath.Join(home, ".config", "gh", "hosts.yml")}
		}},
	{on: func(l policy.SecretLocations) bool { return l.Terraform }, read: readTerraformCreds,
		paths: func(home, goos string) []string {
			if goos == "windows" {
				return []string{filepath.Join(appData(home), "terraform.d", "credentials.tfrc.json")}
			}
			return []string{filepath.Join(home, ".terraform.d", "credentials.tfrc.json")}
		}},
	{on: func(l policy.SecretLocations) bool { return l.PgPass }, read: readPgPass,
		paths: func(home, goos string) []string {
			if goos == "windows" {
				return []string{filepath.Join(appData(home), "postgresql", "pgpass.conf")}
			}
			return []string{filepath.Join(home, ".pgpass")}
		}},
	{on: func(l policy.SecretLocations) bool { return l.MySQL }, paths: homeFiles(".my.cnf"),
		read: iniPasswords("MySQL password", "password")},
}

func gcloudDir(home, goos string) string {
	if goos == "windows" {
		return filepath.Join(appData(home), "gcloud")
	}
	return filepath.Join(home, ".config", "gcloud")
}

func gcloudADCPaths(home, goos string) []string {
	d := gcloudDir(home, goos)
	out := []string{filepath.Join(d, "application_default_credentials.json")}
	if m, err := filepath.Glob(filepath.Join(d, "legacy_credentials", "*", "adc.json")); err == nil {
		sort.Strings(m)
		out = append(out, m...)
	}
	return out
}

// scanLocations reads every enabled credential store that exists.
func (s *secretScanner) scanLocations(home, goos string, on policy.SecretLocations) []secretFinding {
	var out []secretFinding
	seen := map[string]bool{}
	for _, loc := range credLocations {
		if !loc.on(on) {
			continue
		}
		for _, p := range loc.paths(home, goos) {
			shown := tildePath(home, p)
			if seen[p+"\x00"+loc.kind] || s.ignored(shown) {
				continue
			}
			seen[p+"\x00"+loc.kind] = true
			st, err := os.Stat(p)
			if err != nil || !st.Mode().IsRegular() || st.Size() > secretMaxFileSize {
				continue
			}
			if loc.read == nil {
				if st.Size() > 0 {
					out = append(out, secretFinding{path: shown, kind: loc.kind, prod: s.prodRe.MatchString(shown)})
				}
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			for _, h := range loc.read(data) {
				out = append(out, s.fromHit(shown, h))
			}
		}
	}
	return out
}

// fromHit turns a hit into a finding, dropping placeholders and keeping at
// most the last 4 characters of a provider token.
func (s *secretScanner) fromHit(shown string, h credHit) secretFinding {
	f := secretFinding{path: shown, line: h.line, kind: h.kind, name: h.name, severe: h.severe,
		prod: s.prodRe.MatchString(shown) || s.prodRe.MatchString(h.name)}
	if s.showTail && len(h.value) >= 20 {
		for _, r := range s.rules {
			if m := r.re.FindString(h.value); r.showTail && m != "" && len(m) >= 20 {
				f.tail = m[len(m)-4:]
				break
			}
		}
	}
	return f
}

// keep drops hits whose value is a placeholder, a variable or a path.
func keep(hs []credHit) []credHit {
	out := hs[:0]
	for _, h := range hs {
		if h.value != "" && !isPlaceholder(h.value) {
			out = append(out, h)
		}
	}
	return out
}

// readDockerConfig: auths.<registry>.auth or identitytoken is an inline login;
// credsStore and credHelpers keep logins in the OS keychain and are fine.
func readDockerConfig(data []byte) []credHit {
	var c struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
			RegistryToken string `json:"registrytoken"`
		} `json:"auths"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	var hs []credHit
	for reg, a := range c.Auths {
		for _, v := range []string{a.Auth, a.IdentityToken, a.RegistryToken} {
			if v != "" {
				hs = append(hs, credHit{kind: "Docker registry login", name: reg, value: v})
				break
			}
		}
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].name < hs[j].name })
	return keep(hs)
}

var (
	yamlKeyRe   = regexp.MustCompile(`^(\s*)(?:-\s+)?([A-Za-z0-9_.-]+):\s*(.*?)\s*$`)
	kubeSecrets = map[string]string{
		"token": "Kubernetes token", "client-key-data": "Kubernetes client key", "password": "Kubernetes password",
		"access-token": "Kubernetes auth-provider token", "refresh-token": "Kubernetes auth-provider token",
		"id-token": "Kubernetes auth-provider token", "client-secret": "Kubernetes auth-provider secret",
	}
)

// readKubeConfig finds inline credentials in a kubeconfig. exec plugins,
// tokenFile and client-key (a path) keep the secret elsewhere and are fine.
func readKubeConfig(data []byte) []credHit {
	var hs []credHit
	section, user := "", ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		m := yamlKeyRe.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		key, value := m[2], strings.Trim(m[3], `"'`)
		if m[1] == "" && !strings.HasPrefix(line, "-") {
			section, user = key, ""
			continue
		}
		if section != "users" {
			continue
		}
		if key == "name" && strings.HasPrefix(strings.TrimSpace(line), "-") {
			user = value
			continue
		}
		if kind, ok := kubeSecrets[key]; ok {
			hs = append(hs, credHit{line: n, kind: kind, name: user, value: value, severe: key == "client-key-data"})
		}
	}
	return keep(hs)
}

// readNetrc reads netrc tokens across lines: "password" is followed by the password.
func readNetrc(data []byte) []credHit {
	var hs []credHit
	machine := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		f := strings.Fields(sc.Text())
		for i := 0; i < len(f); i++ {
			switch f[i] {
			case "machine":
				if i+1 < len(f) {
					machine = f[i+1]
				}
			case "default":
				machine = "default"
			case "macdef": // a macro runs to the next blank line; it holds no password
				return keep(hs)
			case "password":
				if i+1 < len(f) {
					hs = append(hs, credHit{line: n, kind: "netrc password", name: machine, value: f[i+1]})
					i++
				}
			}
		}
	}
	return keep(hs)
}

var credURLRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://([^\s:/@]*):([^\s/@]+)@([^\s/:]+)`)

// readGitCredentials reads git's credential store: one URL with a password per line.
func readGitCredentials(data []byte) []credHit {
	var hs []credHit
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		if m := credURLRe.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
			hs = append(hs, credHit{line: n, kind: "Git credential (plain text)", name: m[3], value: m[2]})
		}
	}
	return keep(hs)
}

var (
	gitSectionRe = regexp.MustCompile(`^\s*\[\s*([A-Za-z0-9.-]+)`)
	gitHelperRe  = regexp.MustCompile(`(?i)^\s*helper\s*=\s*"?store\b`)
)

// readGitConfigHelper flags credential.helper=store, which saves every
// password git is given to ~/.git-credentials in plain text.
func readGitConfigHelper(data []byte) []credHit {
	var hs []credHit
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if m := gitSectionRe.FindStringSubmatch(line); m != nil {
			section = strings.ToLower(m[1])
			continue
		}
		if section == "credential" && gitHelperRe.MatchString(line) {
			hs = append(hs, credHit{line: n, kind: "git credential.helper=store (saves passwords in plain text)",
				name: "credential.helper", value: "store-helper"})
		}
	}
	return hs
}

// readGCloudADC tells the kinds of application default credentials apart:
// a refresh token or a service account key are secrets; external_account
// (workload identity federation) only points at one.
func readGCloudADC(data []byte) []credHit {
	var c struct {
		Type              string          `json:"type"`
		RefreshToken      string          `json:"refresh_token"`
		PrivateKey        string          `json:"private_key"`
		ClientEmail       string          `json:"client_email"`
		SourceCredentials json.RawMessage `json:"source_credentials"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	switch c.Type {
	case "authorized_user":
		return keep([]credHit{{kind: "gcloud application default credentials (refresh token)", value: c.RefreshToken}})
	case "service_account":
		return keep([]credHit{{kind: "Google service account key", name: c.ClientEmail, value: c.PrivateKey, severe: true}})
	case "impersonated_service_account":
		if hs := readGCloudADC(c.SourceCredentials); len(hs) > 0 {
			return hs
		}
	}
	return nil
}

// readAzureTokenCache: MSAL's cache (plain JSON where the CLI can't encrypt it)
// and the legacy ADAL accessTokens.json hold refresh tokens.
func readAzureTokenCache(data []byte) []credHit {
	var msal struct {
		RefreshToken map[string]json.RawMessage `json:"RefreshToken"`
		AccessToken  map[string]json.RawMessage `json:"AccessToken"`
	}
	if json.Unmarshal(data, &msal) == nil && len(msal.RefreshToken)+len(msal.AccessToken) > 0 {
		return []credHit{{kind: "Azure CLI token cache (plain text)", value: "msal-cache"}}
	}
	var adal []struct {
		RefreshToken string `json:"refreshToken"`
		AccessToken  string `json:"accessToken"`
	}
	if json.Unmarshal(data, &adal) == nil {
		for _, t := range adal {
			if t.RefreshToken != "" || t.AccessToken != "" {
				return []credHit{{kind: "Azure CLI token cache (plain text, legacy)", value: "adal-cache"}}
			}
		}
	}
	return nil
}

func readAzureServicePrincipals(data []byte) []credHit {
	var sps []struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		AccessToken  string `json:"accessToken"`
	}
	if json.Unmarshal(data, &sps) != nil {
		return nil
	}
	var hs []credHit
	for _, sp := range sps {
		v := sp.ClientSecret
		if v == "" {
			v = sp.AccessToken
		}
		hs = append(hs, credHit{kind: "Azure service principal secret", name: sp.ClientID, value: v})
	}
	return keep(hs)
}

var iniSectionRe = regexp.MustCompile(`^\s*\[([^\]]+)\]`)

// iniPasswords reads key = value pairs in an INI file (pypirc, my.cnf).
func iniPasswords(kind string, keys ...string) func([]byte) []credHit {
	return func(data []byte) []credHit {
		var hs []credHit
		section := ""
		sc := bufio.NewScanner(bytes.NewReader(data))
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			if m := iniSectionRe.FindStringSubmatch(line); m != nil {
				section = strings.TrimSpace(m[1])
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				k, v, ok = strings.Cut(line, ":")
			}
			if !ok {
				continue
			}
			for _, want := range keys {
				if strings.EqualFold(strings.TrimSpace(k), want) {
					hs = append(hs, credHit{line: n, kind: kind, name: section, value: strings.Trim(strings.TrimSpace(v), `"'`)})
				}
			}
		}
		return keep(hs)
	}
}

// readGHHosts finds oauth_token in gh's hosts.yml. gh writes it there only
// when it can't use the OS keychain (or was told --insecure-storage).
func readGHHosts(data []byte) []credHit {
	var hs []credHit
	host := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		m := yamlKeyRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if m[1] == "" {
			host = m[2]
			continue
		}
		if m[2] == "oauth_token" {
			hs = append(hs, credHit{line: n, kind: "GitHub CLI token", name: host, value: strings.Trim(m[3], `"'`)})
		}
	}
	return keep(hs)
}

func readTerraformCreds(data []byte) []credHit {
	var c struct {
		Credentials map[string]struct {
			Token string `json:"token"`
		} `json:"credentials"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	var hs []credHit
	for host, cr := range c.Credentials {
		hs = append(hs, credHit{kind: "Terraform API token", name: host, value: cr.Token})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].name < hs[j].name })
	return keep(hs)
}

// readPgPass reads hostname:port:database:username:password lines, where \:
// is a literal colon.
func readPgPass(data []byte) []credHit {
	var hs []credHit
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(strings.ReplaceAll(line, `\:`, "\x00"), ":")
		if len(f) < 5 {
			continue
		}
		pw := strings.ReplaceAll(strings.Join(f[4:], ":"), "\x00", ":")
		// Postgres passwords may be anything, so only an empty one is skipped.
		if pw != "" {
			hs = append(hs, credHit{line: n, kind: "PostgreSQL password", name: strings.ReplaceAll(f[0], "\x00", ":"), value: pw})
		}
	}
	return hs
}
