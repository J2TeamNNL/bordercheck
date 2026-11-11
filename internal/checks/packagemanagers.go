package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// The package-managers check judges how the package managers on this machine
// are configured to fetch packages: a registry over plain http, certificate
// or checksum checks turned off, dependencies' install scripts allowed to run,
// a release-age gate turned off. Supply-chain attacks through npm and PyPI are
// the commonest way a developer's machine is compromised. It reads user (and
// site-wide) config files only: it never runs the tools, never reads
// node_modules and never goes online. Evidence shows the file, line, setting
// and at most a host name: URLs can hold tokens, so they are never shown whole.

const pmMaxConfig = 1 << 20

// pmConfig is one config file that exists.
type pmConfig struct {
	Tool string // one of policy.PackageManagerTools
	Path string // as shown, ~ for the home folder
	Kind string // how to read it: "npmrc", "pnpm-yaml", "pnpm-rc", "yarnrc", "bunfig", "pip", "uv", "goenv", "cargo"
	Body string
}

// pmFacts is what the gathering found.
type pmFacts struct {
	Present map[string]bool // tools found by binary or config file
	Configs []pmConfig
	// NpmMajor is the installed npm's major version, 0 when not known. From
	// npm 12 on, dependencies' install scripts only run once approved.
	NpmMajor int
}

// npmMajor reads the major version from the package.json of the npm a
// command (npm, npm.cmd, a symlink to npm-cli.js) belongs to; 0 if not found.
func npmMajor(bin string) int {
	if real, err := filepath.EvalSymlinks(bin); err == nil {
		bin = real
	}
	dir := filepath.Dir(bin)
	candidates := []string{
		filepath.Join(dir, "..", "package.json"),                               // …/node_modules/npm/bin/npm-cli.js
		filepath.Join(dir, "..", "lib", "node_modules", "npm", "package.json"), // …/bin/npm
		filepath.Join(dir, "node_modules", "npm", "package.json"),              // Windows: nodejs\npm.cmd
	}
	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err != nil || len(b) > 64<<10 {
			continue
		}
		var pkg struct{ Name, Version string }
		if json.Unmarshal(b, &pkg) == nil && pkg.Name == "npm" {
			major, _, _ := strings.Cut(pkg.Version, ".")
			n, _ := strconv.Atoi(major)
			return n
		}
	}
	return 0
}

// pmFinding is one setting that weakens package installs.
type pmFinding struct {
	tool, path string
	line       int
	what       string // setting and why, never a URL or value beyond a host
	kind       string // "insecure", "checksum", "scripts", "age"
}

// pmConfigPaths lists the config files each tool reads for the user (and the
// machine), in the order the tool documents them.
func pmConfigPaths(home, goos string, env func(string) string) []pmConfig {
	xdg := env("XDG_CONFIG_HOME")
	if xdg == "" || !filepath.IsAbs(xdg) {
		xdg = filepath.Join(home, ".config")
	}
	local := env("LOCALAPPDATA")
	if local == "" {
		local = filepath.Join(home, "AppData", "Local")
	}
	j := filepath.Join
	var c []pmConfig
	add := func(tool, kind string, paths ...string) {
		for _, p := range paths {
			c = append(c, pmConfig{Tool: tool, Kind: kind, Path: p})
		}
	}
	add("npm", "npmrc", j(home, ".npmrc"))
	switch goos {
	case "darwin":
		add("pnpm", "pnpm-yaml", j(home, "Library", "Preferences", "pnpm", "config.yaml"))
		add("pnpm", "pnpm-rc", j(home, "Library", "Preferences", "pnpm", "rc"))
		add("pip", "pip", j(home, "Library", "Application Support", "pip", "pip.conf"), j(xdg, "pip", "pip.conf"),
			j(home, ".pip", "pip.conf"), "/Library/Application Support/pip/pip.conf", "/etc/pip.conf")
		add("uv", "uv", j(xdg, "uv", "uv.toml"), "/etc/uv/uv.toml")
		add("go", "goenv", j(home, "Library", "Application Support", "go", "env"))
	case "windows":
		add("pnpm", "pnpm-yaml", j(local, "pnpm", "config", "config.yaml"))
		add("pnpm", "pnpm-rc", j(local, "pnpm", "config", "rc"))
		add("pip", "pip", j(appData(home), "pip", "pip.ini"), j(home, "pip", "pip.ini"), `C:\ProgramData\pip\pip.ini`)
		add("uv", "uv", j(appData(home), "uv", "uv.toml"))
		add("go", "goenv", j(appData(home), "go", "env"))
	default:
		add("pnpm", "pnpm-yaml", j(xdg, "pnpm", "config.yaml"))
		add("pnpm", "pnpm-rc", j(xdg, "pnpm", "rc"))
		add("pip", "pip", j(xdg, "pip", "pip.conf"), j(home, ".pip", "pip.conf"), "/etc/xdg/pip/pip.conf", "/etc/pip.conf")
		add("uv", "uv", j(xdg, "uv", "uv.toml"), "/etc/xdg/uv/uv.toml", "/etc/uv/uv.toml")
		add("go", "goenv", j(xdg, "go", "env"))
	}
	add("yarn", "yarnrc", j(home, ".yarnrc.yml"))
	if x := env("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
		add("bun", "bunfig", j(x, ".bunfig.toml")) // Bun then reads this one, not the one in home
	} else {
		add("bun", "bunfig", j(home, ".bunfig.toml"))
	}
	cargo := env("CARGO_HOME")
	if cargo == "" {
		cargo = j(home, ".cargo")
	}
	add("cargo", "cargo", j(cargo, "config.toml"), j(cargo, "config"))
	return c
}

// pmBinaries are where each tool's command is looked for besides PATH, which
// is short when bordercheck runs as a service.
func pmBinaries(home, goos string) map[string][]string {
	j := filepath.Join
	bins := []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", j(home, ".local", "bin"), j(home, ".volta", "bin")}
	if goos == "windows" {
		bins = []string{j(appData(home), "npm"), `C:\Program Files\nodejs`, j(home, ".local", "bin")}
	}
	in := func(name string, extra ...string) []string {
		var out []string
		for _, b := range bins {
			out = append(out, j(b, name))
		}
		return append(out, extra...)
	}
	nvm, _ := filepath.Glob(j(home, ".nvm", "versions", "node", "*", "bin", "npm"))
	return map[string][]string{
		"npm":   in("npm", nvm...),
		"pnpm":  in("pnpm", j(home, "Library", "pnpm", "pnpm"), j(home, ".local", "share", "pnpm", "pnpm")),
		"yarn":  in("yarn"),
		"bun":   in("bun", j(home, ".bun", "bin", "bun")),
		"pip":   in("pip3", "/usr/bin/pip3"),
		"uv":    in("uv", j(home, ".cargo", "bin", "uv")),
		"go":    in("go", "/usr/local/go/bin/go", `C:\Program Files\Go\bin\go.exe`),
		"cargo": in("cargo", j(home, ".cargo", "bin", "cargo")),
	}
}

func gatherPackageManagers(ctx context.Context, home, goos string, tools []string) pmFacts {
	f := pmFacts{Present: map[string]bool{}}
	for _, c := range pmConfigPaths(home, goos, os.Getenv) {
		if ctx.Err() != nil || !slices.Contains(tools, c.Tool) {
			continue
		}
		st, err := os.Stat(c.Path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > pmMaxConfig {
			continue
		}
		b, err := os.ReadFile(c.Path)
		if err != nil {
			continue
		}
		c.Body, c.Path = string(b), tildePath(home, c.Path)
		f.Configs = append(f.Configs, c)
		f.Present[c.Tool] = true
	}
	bins := pmBinaries(home, goos)
	names := map[string]string{"pip": "pip3"}
	for _, t := range tools {
		if f.Present[t] {
			continue
		}
		name := t
		if n, ok := names[t]; ok {
			name = n
		}
		if _, ok := sysx.Find(name, bins[t]...); ok {
			f.Present[t] = true
		} else if t == "pip" {
			_, f.Present[t] = sysx.Find("pip", bins[t]...)
		}
	}
	if slices.Contains(tools, "npm") {
		if bin, ok := sysx.Find("npm", bins["npm"]...); ok {
			f.NpmMajor = npmMajor(bin)
		}
	}
	return f
}

func packageManagers(p policy.PackageManagers) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		home, err := os.UserHomeDir()
		if err != nil {
			return check.Errored(err)
		}
		return evalPackageManagers(gatherPackageManagers(ctx, home, runtime.GOOS, p.Tools), p)
	}
}

// pmHost returns a URL's host without port, or "" if it has none.
func pmHost(raw string) string {
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "sparse+"), "registry+")
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// pmLoopback reports hosts on this machine: a local proxy over http is fine.
func pmLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type pmJudge struct {
	p        policy.PackageManagers
	allow    []*regexp.Regexp
	out      []pmFinding
	npmMajor int
}

func (j *pmJudge) allowed(host string) bool {
	if host == "" || pmLoopback(host) {
		return host != ""
	}
	for _, re := range j.allow {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func (j *pmJudge) add(c pmConfig, line int, kind, what string) {
	j.out = append(j.out, pmFinding{tool: c.Tool, path: c.Path, line: line, kind: kind, what: what})
}

// httpURL flags a plain-http URL that is not on this machine or allowed.
func (j *pmJudge) httpURL(c pmConfig, line int, setting, raw string) {
	raw = strings.Trim(strings.TrimSpace(raw), `"'`)
	l := strings.ToLower(raw)
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "sparse+http://") && !strings.HasPrefix(l, "registry+http://") {
		return
	}
	host := pmHost(raw)
	if j.allowed(host) {
		return
	}
	j.add(c, line, "insecure", fmt.Sprintf("%s uses plain http (%s): anyone on the network can swap the packages", setting, host))
}

// trustedHost flags a host whose TLS errors the tool is told to ignore.
func (j *pmJudge) trustedHost(c pmConfig, line int, setting, host string) {
	host = strings.Trim(strings.TrimSpace(host), `"'`)
	if host == "" {
		return
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	if j.allowed(strings.ToLower(name)) {
		return
	}
	j.add(c, line, "insecure", fmt.Sprintf("%s %s: certificate errors for this host are ignored", setting, host))
}

var pmQuotedRe = regexp.MustCompile(`"([^"]*)"|'([^']*)'`)

// pmLines yields each line of a config with its number, without comments
// that start the line.
func pmLines(body string, f func(n int, line string)) {
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if t := strings.TrimSpace(line); t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		f(n, line)
	}
}

// pmKV splits "key = value" or "key: value", trimming quotes from the value.
func pmKV(line, sep string) (string, string, bool) {
	k, v, ok := strings.Cut(line, sep)
	if !ok {
		return "", "", false
	}
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " #"); i >= 0 && !strings.HasPrefix(v, `"`) && !strings.HasPrefix(v, "'") {
		v = strings.TrimSpace(v[:i])
	}
	return strings.TrimSpace(k), strings.Trim(v, `"'`), true
}

func pmTrue(v string) bool  { return strings.EqualFold(v, "true") }
func pmFalse(v string) bool { return strings.EqualFold(v, "false") }

// npmrc: registry and @scope:registry, strict-ssl, ignore-scripts, min-release-age.
func (j *pmJudge) npmrc(c pmConfig) {
	ignore, age := false, false
	pmLines(c.Body, func(n int, line string) {
		k, v, ok := pmKV(line, "=")
		if !ok {
			return
		}
		switch k = strings.ToLower(k); {
		case k == "registry" || strings.HasSuffix(k, ":registry"):
			j.httpURL(c, n, k, v)
		case k == "strict-ssl" && pmFalse(v):
			j.add(c, n, "insecure", "strict-ssl=false: certificate errors from the registry are ignored")
		case k == "ignore-scripts":
			ignore = pmTrue(v)
		case k == "dangerously-allow-all-scripts" && pmTrue(v):
			if j.p.RequireIgnoreScripts && !ignore {
				j.add(c, n, "scripts", "dangerously-allow-all-scripts=true: every package's install scripts run, approved or not")
			}
			ignore = true // reported here; npmDefaults must not report it again
		case k == "min-release-age":
			d, err := strconv.Atoi(v)
			age = err == nil && d > 0
		}
	})
	j.npmDefaults(c, ignore, age)
}

// npmDefaults judges npm's script and release-age settings, which apply even
// when there is no ~/.npmrc. npm 12 and later run a dependency's install
// scripts only once the project approves them (allowScripts), so only npm 11
// and older (or an npm whose version is unknown) need ignore-scripts.
func (j *pmJudge) npmDefaults(c pmConfig, ignore, age bool) {
	if j.p.RequireIgnoreScripts && !ignore && j.npmMajor < 12 {
		j.add(c, 0, "scripts", "ignore-scripts is not true: every package's install scripts run on npm install")
	}
	if j.p.RequireReleaseAge && !age {
		j.add(c, 0, "age", "min-release-age is not set: versions published minutes ago are installed")
	}
}

// pnpm's YAML config (pnpm 11) and older INI rc file. pnpm does not run
// dependencies' build scripts unless they are approved, and pnpm 11 waits a
// day before installing a new version, so only settings that undo that count.
func (j *pmJudge) pnpm(c pmConfig) {
	sep := ":"
	if c.Kind == "pnpm-rc" {
		sep = "="
	}
	pmLines(c.Body, func(n int, line string) {
		k, v, ok := pmKV(line, sep)
		if !ok {
			return
		}
		switch strings.ToLower(strings.ReplaceAll(k, "-", "")) {
		case "dangerouslyallowallbuilds":
			if pmTrue(v) && j.p.RequireIgnoreScripts {
				j.add(c, n, "scripts", k+": true: every dependency's build scripts run")
			}
		case "minimumreleaseage":
			if v == "0" {
				j.add(c, n, "age", k+": 0: versions published minutes ago are installed")
			}
		case "registry":
			j.httpURL(c, n, k, v)
		case "strictssl":
			if pmFalse(v) {
				j.add(c, n, "insecure", k+": false: certificate errors from the registry are ignored")
			}
		}
	})
}

// yarnrc: Yarn (Berry) settings, at any depth (npmScopes and npmRegistries
// nest their own npmRegistryServer).
func (j *pmJudge) yarn(c pmConfig) {
	pmLines(c.Body, func(n int, line string) {
		k, v, ok := pmKV(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- ")), ":")
		if !ok {
			return
		}
		switch k {
		case "enableScripts":
			if pmTrue(v) && j.p.RequireIgnoreScripts {
				j.add(c, n, "scripts", "enableScripts: true: third-party packages' postinstall scripts run")
			}
		case "npmMinimalAgeGate":
			if v == "0" {
				j.add(c, n, "age", "npmMinimalAgeGate: 0: versions published minutes ago are installed")
			}
		case "npmRegistryServer":
			j.httpURL(c, n, k, v)
		case "enableStrictSsl":
			if pmFalse(v) {
				j.add(c, n, "insecure", "enableStrictSsl: false: certificate errors from the registry are ignored")
			}
		}
	})
}

// tomlish walks a TOML file: section, key, value and line, joining arrays that
// span lines. Enough for the flat settings judged here.
func tomlish(body string, f func(section, key, value string, line int)) {
	section, pending, start := "", "", 0
	var pendingKey string
	pmLines(body, func(n int, line string) {
		t := strings.TrimSpace(line)
		if pending != "" {
			pending += " " + t
			if strings.Contains(t, "]") {
				f(section, pendingKey, pending, start)
				pending = ""
			}
			return
		}
		if strings.HasPrefix(t, "[") {
			section = strings.Trim(strings.TrimSpace(strings.Trim(t, "[]")), " ")
			return
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return
		}
		k, v = strings.Trim(strings.TrimSpace(k), `"'`), strings.TrimSpace(v)
		if strings.HasPrefix(v, "[") && !strings.Contains(v, "]") {
			pending, pendingKey, start = v, k, n
			return
		}
		f(section, k, v, n)
	})
}

// pmStrings returns the quoted strings in a TOML value.
func pmStrings(v string) []string {
	var out []string
	for _, m := range pmQuotedRe.FindAllStringSubmatch(v, -1) {
		out = append(out, m[1]+m[2])
	}
	return out
}

// bunfig: [install] registry and scoped registries, minimumReleaseAge. Bun runs
// only trusted dependencies' lifecycle scripts by default.
func (j *pmJudge) bun(c pmConfig) {
	age := false
	tomlish(c.Body, func(section, k, v string, n int) {
		if section != "install" && !strings.HasPrefix(section, "install.") {
			return
		}
		switch {
		case k == "minimumReleaseAge":
			d, err := strconv.Atoi(v)
			age = err == nil && d > 0
		case k == "registry" || section == "install.scopes":
			for _, s := range pmStrings(v) {
				j.httpURL(c, n, k, s)
			}
		}
	})
	if j.p.RequireReleaseAge && !age {
		j.add(c, 0, "age", "minimumReleaseAge is not set under [install]: versions published minutes ago are installed")
	}
}

// pip.conf / pip.ini: INI with values continued on indented lines.
func (j *pmJudge) pip(c pmConfig) {
	key, keyLine := "", 0
	value := func(n int, v string) {
		for _, f := range strings.Fields(v) {
			switch key {
			case "index-url", "extra-index-url", "find-links":
				j.httpURL(c, n, key, f)
			case "trusted-host":
				j.trustedHost(c, n, key, f)
			}
		}
	}
	pmLines(c.Body, func(n int, line string) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			key = ""
			return
		}
		if line[0] == ' ' || line[0] == '\t' { // continuation of the last key
			if key != "" {
				value(n, t)
			}
			return
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			k, v, ok = strings.Cut(t, ":")
		}
		if !ok {
			key = ""
			return
		}
		key, keyLine = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k)), "_", "-"), n
		value(keyLine, v)
	})
}

// uv.toml: index URLs and allow-insecure-host, at the top level, in [pip] and
// in [[index]] tables.
func (j *pmJudge) uv(c pmConfig) {
	tomlish(c.Body, func(section, k, v string, n int) {
		switch k {
		case "index-url", "extra-index-url", "find-links", "url":
			for _, s := range pmStrings(v) {
				j.httpURL(c, n, k, s)
			}
		case "allow-insecure-host", "trusted-host":
			for _, s := range pmStrings(v) {
				j.trustedHost(c, n, k, s)
			}
		}
	})
}

// goenv: the file `go env -w` writes. GOINSECURE fetches over http or without
// certificate checks; GOSUMDB=off, and GONOSUMDB or GOPRIVATE matching every
// module, skip the checksum database that catches a tampered module.
func (j *pmJudge) goEnv(c pmConfig) {
	pmLines(c.Body, func(n int, line string) {
		k, v, ok := pmKV(line, "=")
		if !ok {
			return
		}
		switch k {
		case "GOINSECURE":
			var bad []string
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" && !j.allowed(strings.ToLower(strings.SplitN(p, "/", 2)[0])) {
					bad = append(bad, p)
				}
			}
			if len(bad) > 0 {
				j.add(c, n, "insecure", fmt.Sprintf("GOINSECURE covers %s: those modules are fetched over http or without certificate checks", strings.Join(bad, ", ")))
			}
		case "GOSUMDB":
			if strings.EqualFold(v, "off") {
				j.add(c, n, "checksum", "GOSUMDB=off: no module is checked against the checksum database")
			}
		case "GONOSUMDB", "GOPRIVATE":
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p == "*" || p == "*/*" {
					j.add(c, n, "checksum", k+"="+v+": no module is checked against the checksum database")
					break
				}
			}
		case "GOPROXY":
			for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '|' }) {
				j.httpURL(c, n, k, p)
			}
		}
	})
}

// cargo: registries and source replacements over http.
func (j *pmJudge) cargo(c pmConfig) {
	tomlish(c.Body, func(section, k, v string, n int) {
		if k == "index" || k == "registry" {
			for _, s := range pmStrings(v) {
				j.httpURL(c, n, "["+section+"] "+k, s)
			}
		}
	})
}

func evalPackageManagers(f pmFacts, p policy.PackageManagers) check.Result {
	var present []string
	for _, t := range policy.PackageManagerTools {
		if f.Present[t] && slices.Contains(p.Tools, t) {
			present = append(present, t)
		}
	}
	if len(present) == 0 {
		return check.SkippedMsg(msg.Of("pm.none"))
	}
	j := &pmJudge{p: p, npmMajor: f.NpmMajor}
	for _, g := range p.AllowHosts {
		if re, err := policy.Glob(strings.ToLower(g)); err == nil {
			j.allow = append(j.allow, re)
		}
	}
	npmSeen := false
	for _, c := range f.Configs {
		if !slices.Contains(present, c.Tool) {
			continue
		}
		switch c.Kind {
		case "npmrc":
			npmSeen = true
			j.npmrc(c)
		case "pnpm-yaml", "pnpm-rc":
			j.pnpm(c)
		case "yarnrc":
			j.yarn(c)
		case "bunfig":
			j.bun(c)
		case "pip":
			j.pip(c)
		case "uv":
			j.uv(c)
		case "goenv":
			j.goEnv(c)
		case "cargo":
			j.cargo(c)
		}
	}
	if slices.Contains(present, "npm") && !npmSeen {
		j.npmDefaults(pmConfig{Tool: "npm", Path: "~/.npmrc (none)"}, false, false)
	}
	if slices.Contains(present, "bun") && p.RequireReleaseAge && !slices.ContainsFunc(f.Configs, func(c pmConfig) bool { return c.Tool == "bun" }) {
		j.add(pmConfig{Tool: "bun", Path: "~/.bunfig.toml (none)"}, 0, "age", "minimumReleaseAge is not set: versions published minutes ago are installed")
	}
	if len(j.out) == 0 {
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("pm.pass", "n", len(present), "tools", strings.Join(present, ", ")))
	}
	count := map[string]int{}
	tools := map[string]map[string]bool{}
	var ev []string
	for _, kind := range []string{"insecure", "checksum", "scripts", "age"} {
		for _, fd := range j.out {
			if fd.kind != kind {
				continue
			}
			count[kind]++
			if tools[kind] == nil {
				tools[kind] = map[string]bool{}
			}
			tools[kind][fd.tool] = true
			where := fd.path
			if fd.line > 0 {
				where = fmt.Sprintf("%s:%d", fd.path, fd.line)
			}
			ev = append(ev, fmt.Sprintf("%s  %s: %s", where, fd.tool, fd.what))
		}
	}
	var summary, fix msg.Text
	r := check.Result{Status: check.Warn, Severity: check.Low, Evidence: ev}
	if n := count["insecure"]; n > 0 {
		summary = append(summary, msg.P("pm.insecure", "n", n))
		fix = append(fix, msg.P("pm.fix.insecure"))
		r.Status, r.Severity = check.Fail, check.Medium
	}
	if n := count["checksum"]; n > 0 {
		summary = append(summary, msg.P("pm.checksum", "n", n))
		fix = append(fix, msg.P("pm.fix.checksum"))
		if r.Status != check.Fail {
			r.Severity = check.Medium
		}
	}
	if n := len(tools["scripts"]); n > 0 {
		summary = append(summary, msg.P("pm.scripts", "n", n))
		fix = append(fix, msg.P("pm.fix.scripts"))
	}
	if n := len(tools["age"]); n > 0 {
		summary = append(summary, msg.P("pm.releaseAge", "n", n))
		fix = append(fix, msg.P("pm.fix.releaseAge"))
	}
	return r.WithSummary(summary).WithFix(fix)
}
