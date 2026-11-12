package checks

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func pmEval(t *testing.T, p policy.PackageManagers, present []string, cfgs ...pmConfig) check.Result {
	t.Helper()
	f := pmFacts{Present: map[string]bool{}, Configs: cfgs}
	for _, x := range present {
		f.Present[x] = true
	}
	return evalPackageManagers(f, p)
}

func pmEvidence(r check.Result) string { return strings.Join(r.Evidence, "\n") }

func TestPackageManagersNone(t *testing.T) {
	r := pmEval(t, policy.Default().Checks.PackageManagers, nil)
	if r.Status != check.Skip || !strings.Contains(r.Summary, "No npm") {
		t.Errorf("got %s %q", r.Status, r.Summary)
	}
}

func TestPackageManagersPass(t *testing.T) {
	p := policy.Default().Checks.PackageManagers
	r := pmEval(t, p, []string{"npm", "go"},
		pmConfig{Tool: "npm", Kind: "npmrc", Path: "~/.npmrc", Body: "ignore-scripts=true\nregistry=https://registry.npmjs.org/\n"},
		pmConfig{Tool: "go", Kind: "goenv", Path: "~/Library/Application Support/go/env", Body: "GOPRIVATE=git.corp.example/*\nGOTOOLCHAIN=auto\n"})
	if r.Status != check.Pass || !strings.Contains(r.Summary, "2 package managers checked (npm, go)") {
		t.Errorf("got %s %q %v", r.Status, r.Summary, r.Evidence)
	}
}

func TestPackageManagersNpm(t *testing.T) {
	p := policy.Default().Checks.PackageManagers
	// npm installed without ~/.npmrc: scripts run by default.
	r := pmEval(t, p, []string{"npm"})
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(pmEvidence(r), "ignore-scripts is not true") {
		t.Errorf("no npmrc: %s %s %v", r.Status, r.Severity, r.Evidence)
	}
	r = pmEval(t, p, []string{"npm"}, pmConfig{Tool: "npm", Kind: "npmrc", Path: "~/.npmrc", Body: strings.Join([]string{
		"; comment", "ignore-scripts = true", "registry=http://registry.corp.example/npm/",
		"@sample:registry=http://user:hunter2@npm.sample.example/", "strict-ssl=false",
		"@local:registry=http://localhost:4873/", "//npm.sample.example/:_authToken=${NPM_TOKEN}"}, "\n")})
	ev := pmEvidence(r)
	if r.Status != check.Fail || r.Severity != check.Medium || len(r.Evidence) != 3 ||
		!strings.Contains(ev, "~/.npmrc:3  npm: registry uses plain http (registry.corp.example)") ||
		!strings.Contains(ev, "~/.npmrc:4  npm: @sample:registry uses plain http (npm.sample.example)") ||
		!strings.Contains(ev, "~/.npmrc:5  npm: strict-ssl=false") || strings.Contains(ev, "hunter2") || strings.Contains(ev, "localhost") {
		t.Errorf("got %s %s\n%s", r.Status, r.Severity, ev)
	}
	// The org's own registry may be allowed.
	p.AllowHosts = []string{"*.corp.example", "npm.sample.example"}
	r = pmEval(t, p, []string{"npm"}, pmConfig{Tool: "npm", Kind: "npmrc", Path: "~/.npmrc",
		Body: "ignore-scripts=true\nregistry=http://registry.corp.example/\n@sample:registry=http://npm.sample.example/\n"})
	if r.Status != check.Pass {
		t.Errorf("allowed hosts: %s %v", r.Status, r.Evidence)
	}
	// Release age only when required.
	p = policy.Default().Checks.PackageManagers
	p.RequireReleaseAge, p.RequireIgnoreScripts = true, false
	r = pmEval(t, p, []string{"npm"}, pmConfig{Tool: "npm", Kind: "npmrc", Path: "~/.npmrc", Body: "min-release-age=0\n"})
	if r.Status != check.Warn || !strings.Contains(r.Summary, "minutes ago") {
		t.Errorf("age: %s %q", r.Status, r.Summary)
	}
	r = pmEval(t, p, []string{"npm"}, pmConfig{Tool: "npm", Kind: "npmrc", Path: "~/.npmrc", Body: "min-release-age=3\n"})
	if r.Status != check.Pass {
		t.Errorf("age set: %s %v", r.Status, r.Evidence)
	}
}

func TestPackageManagersPnpmYarnBun(t *testing.T) {
	p := policy.Default().Checks.PackageManagers
	r := pmEval(t, p, []string{"pnpm", "yarn", "bun"},
		pmConfig{Tool: "pnpm", Kind: "pnpm-yaml", Path: "~/Library/Preferences/pnpm/config.yaml",
			Body: "dangerouslyAllowAllBuilds: true\nminimumReleaseAge: 0\nstrictSsl: false\n"},
		pmConfig{Tool: "pnpm", Kind: "pnpm-rc", Path: "~/Library/Preferences/pnpm/rc", Body: "minimum-release-age=0\n"},
		pmConfig{Tool: "yarn", Kind: "yarnrc", Path: "~/.yarnrc.yml", Body: "enableScripts: true\nnpmMinimalAgeGate: 0\n" +
			"npmScopes:\n  sample:\n    npmRegistryServer: \"http://npm.sample.example\"\n"},
		pmConfig{Tool: "bun", Kind: "bunfig", Path: "~/.bunfig.toml", Body: "[install]\nregistry = \"http://bun.sample.example/\"\n" +
			"[install.scopes]\nmyorg = { url = \"http://scoped.sample.example/\", token = \"$TOKEN\" }\n[run]\nregistry = \"http://ignored.example\"\n"})
	ev := pmEvidence(r)
	for _, want := range []string{"config.yaml:1  pnpm: dangerouslyAllowAllBuilds: true", "config.yaml:2  pnpm: minimumReleaseAge: 0",
		"config.yaml:3  pnpm: strictSsl: false", "rc:1  pnpm: minimum-release-age: 0", "~/.yarnrc.yml:1  yarn: enableScripts: true",
		"~/.yarnrc.yml:2  yarn: npmMinimalAgeGate: 0", "~/.yarnrc.yml:5  yarn: npmRegistryServer uses plain http (npm.sample.example)",
		"~/.bunfig.toml:2  bun: registry uses plain http (bun.sample.example)", "~/.bunfig.toml:4  bun: myorg uses plain http (scoped.sample.example)"} {
		if !strings.Contains(ev, want) {
			t.Errorf("missing %q in\n%s", want, ev)
		}
	}
	if strings.Contains(ev, "ignored.example") || r.Status != check.Fail {
		t.Errorf("got %s\n%s", r.Status, ev)
	}
	if !strings.Contains(r.Summary, "2 package managers run every package's install scripts") ||
		!strings.Contains(r.Summary, "2 package managers install versions published minutes ago") {
		t.Errorf("summary %q", r.Summary)
	}
	// Defaults are safe: pnpm and Bun without config pass; Bun needs an age only when required.
	r = pmEval(t, p, []string{"pnpm", "bun", "yarn"})
	if r.Status != check.Pass {
		t.Errorf("no config: %s %v", r.Status, r.Evidence)
	}
	p.RequireReleaseAge = true
	r = pmEval(t, p, []string{"bun"}, pmConfig{Tool: "bun", Kind: "bunfig", Path: "~/.bunfig.toml", Body: "[install]\nminimumReleaseAge = 259200\n"})
	if r.Status != check.Pass {
		t.Errorf("bun age: %s %v", r.Status, r.Evidence)
	}
	r = pmEval(t, p, []string{"bun"})
	if r.Status != check.Warn || !strings.Contains(pmEvidence(r), "bun: minimumReleaseAge is not set") {
		t.Errorf("bun no age: %s %v", r.Status, r.Evidence)
	}
}

func TestPackageManagersPip(t *testing.T) {
	p := policy.Default().Checks.PackageManagers
	body := "[global]\nindex-url = http://pypi.corp.example/simple\nextra_index_url =\n    https://pypi.org/simple\n" +
		"    http://mirror.example:8080/simple\ntrusted-host =\n    pypi.corp.example\n    127.0.0.1:3141\n" +
		"[install]\ntrusted-host: files.example.org\nfind-links = https://wheels.example/\n"
	r := pmEval(t, p, []string{"pip", "uv"},
		pmConfig{Tool: "pip", Kind: "pip", Path: "~/.config/pip/pip.conf", Body: body},
		pmConfig{Tool: "uv", Kind: "uv", Path: "~/.config/uv/uv.toml", Body: "index-url = \"http://uv.example/simple\"\n" +
			"allow-insecure-host = [\n  \"uvhost.example:8443\",\n  \"localhost\",\n]\n[[index]]\nname = \"corp\"\nurl = \"http://idx.example/simple\"\n" +
			"[pip]\nextra-index-url = [\"https://ok.example\", \"http://pipx.example\"]\n"})
	ev := pmEvidence(r)
	for _, want := range []string{"pip.conf:2  pip: index-url uses plain http (pypi.corp.example)",
		"pip.conf:5  pip: extra-index-url uses plain http (mirror.example)", "pip.conf:7  pip: trusted-host pypi.corp.example",
		"pip.conf:10  pip: trusted-host files.example.org", "uv.toml:1  uv: index-url uses plain http (uv.example)",
		"uv.toml:2  uv: allow-insecure-host uvhost.example:8443", "uv.toml:8  uv: url uses plain http (idx.example)",
		"uv.toml:10  uv: extra-index-url uses plain http (pipx.example)"} {
		if !strings.Contains(ev, want) {
			t.Errorf("missing %q in\n%s", want, ev)
		}
	}
	if strings.Contains(ev, "127.0.0.1") || strings.Contains(ev, "localhost") || strings.Contains(ev, "wheels") || r.Status != check.Fail {
		t.Errorf("got %s\n%s", r.Status, ev)
	}
}

func TestPackageManagersGoCargo(t *testing.T) {
	p := policy.Default().Checks.PackageManagers
	r := pmEval(t, p, []string{"go", "cargo"},
		pmConfig{Tool: "go", Kind: "goenv", Path: "~/.config/go/env", Body: "GOINSECURE=git.corp.example,*.other.example\n" +
			"GOSUMDB=off\nGONOSUMDB=*\nGOPROXY=http://proxy.example,direct\nGOFLAGS=-mod=mod\n"},
		pmConfig{Tool: "cargo", Kind: "cargo", Path: "~/.cargo/config.toml", Body: "[registries.corp]\nindex = \"sparse+http://crates.corp.example/\"\n" +
			"[source.mirror]\nregistry = \"https://mirror.example/index\"\n[registry]\nindex = \"http://127.0.0.1:9000/\"\n"})
	ev := pmEvidence(r)
	for _, want := range []string{"env:1  go: GOINSECURE covers git.corp.example, *.other.example", "env:2  go: GOSUMDB=off",
		"env:3  go: GONOSUMDB=*", "env:4  go: GOPROXY uses plain http (proxy.example)",
		"config.toml:2  cargo: [registries.corp] index uses plain http (crates.corp.example)"} {
		if !strings.Contains(ev, want) {
			t.Errorf("missing %q in\n%s", want, ev)
		}
	}
	if len(r.Evidence) != 5 || r.Status != check.Fail || !strings.Contains(r.Summary, "2 settings turn off Go's checksum database") {
		t.Errorf("got %s %q\n%s", r.Status, r.Summary, ev)
	}
	// Checksum findings alone warn medium.
	r = pmEval(t, p, []string{"go"}, pmConfig{Tool: "go", Kind: "goenv", Path: "env", Body: "GOPRIVATE=*\n"})
	if r.Status != check.Warn || r.Severity != check.Medium {
		t.Errorf("checksum only: %s %s", r.Status, r.Severity)
	}
	p.AllowHosts = []string{"git.corp.example", "*.other.example"}
	r = pmEval(t, p, []string{"go"}, pmConfig{Tool: "go", Kind: "goenv", Path: "env", Body: "GOINSECURE=git.corp.example\n"})
	if r.Status != check.Pass {
		t.Errorf("allowed GOINSECURE: %s %v", r.Status, r.Evidence)
	}
	// Tools the policy leaves out are not judged.
	p.Tools = []string{"cargo"}
	r = pmEval(t, p, []string{"go"}, pmConfig{Tool: "go", Kind: "goenv", Path: "env", Body: "GOSUMDB=off\n"})
	if r.Status != check.Skip {
		t.Errorf("tools: %s", r.Status)
	}
}

func TestPackageManagerPaths(t *testing.T) {
	env := func(k string) string { return map[string]string{"CARGO_HOME": "/opt/cargo"}[k] }
	has := func(cs []pmConfig, tool, want string) bool {
		for _, c := range cs {
			if c.Tool == tool && filepath.ToSlash(c.Path) == want {
				return true
			}
		}
		return false
	}
	mac := pmConfigPaths("/Users/demo", "darwin", env)
	for tool, want := range map[string]string{"pnpm": "/Users/demo/Library/Preferences/pnpm/config.yaml",
		"pip": "/Users/demo/Library/Application Support/pip/pip.conf", "go": "/Users/demo/Library/Application Support/go/env",
		"cargo": "/opt/cargo/config.toml", "bun": "/Users/demo/.bunfig.toml", "uv": "/Users/demo/.config/uv/uv.toml"} {
		if !has(mac, tool, want) {
			t.Errorf("darwin %s: no %s", tool, want)
		}
	}
	// XDG_CONFIG_HOME counts only when it is an absolute path, and what is absolute depends on the OS
	// the test runs on.
	xdg := filepath.ToSlash(t.TempDir())
	linux := pmConfigPaths("/home/demo", "linux", func(k string) string { return map[string]string{"XDG_CONFIG_HOME": filepath.FromSlash(xdg)}[k] })
	for tool, want := range map[string]string{"pnpm": xdg + "/pnpm/config.yaml", "pip": xdg + "/pip/pip.conf", "bun": xdg + "/.bunfig.toml",
		"go": xdg + "/go/env", "cargo": "/home/demo/.cargo/config.toml"} {
		if !has(linux, tool, want) {
			t.Errorf("linux %s: no %s", tool, want)
		}
	}
	win := pmConfigPaths(`C:\Users\demo`, "windows", func(string) string { return "" })
	if len(win) == 0 || !strings.Contains(filepath.ToSlash(win[len(win)-2].Path), "cargo") {
		t.Errorf("windows: %+v", win)
	}
}

// gatherPackageManagers reads config files from a temp home.
func TestGatherPackageManagers(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".npmrc", "registry=http://r.example/\n", 0o600)
	writeFile(t, home, ".cargo/config.toml", "[registry]\nindex = \"https://x\"\n", 0o600)
	t.Setenv("CARGO_HOME", "")
	f := gatherPackageManagers(context.Background(), home, "linux", []string{"npm", "cargo", "pip"})
	// The machine running the test may have site-wide files of its own (/etc/pip.conf on a CI runner):
	// only the ones under the temp home are this test's.
	var mine []string
	for _, c := range f.Configs {
		if p := filepath.ToSlash(c.Path); strings.HasPrefix(p, "~/") { // shown with the OS's separator
			mine = append(mine, p)
		}
	}
	if !f.Present["npm"] || !f.Present["cargo"] || !slices.Equal(mine, []string{"~/.npmrc", "~/.cargo/config.toml"}) {
		t.Errorf("got %+v (under home: %v)", f, mine)
	}
}

// npm 12 runs dependencies' install scripts only once approved.
func TestPackageManagersNpm12(t *testing.T) {
	p := policy.Default().Checks.PackageManagers
	f := pmFacts{Present: map[string]bool{"npm": true}, NpmMajor: 12}
	if r := evalPackageManagers(f, p); r.Status != check.Pass {
		t.Errorf("npm 12: %s %v", r.Status, r.Evidence)
	}
	f.Configs = []pmConfig{{Tool: "npm", Kind: "npmrc", Path: "~/.npmrc", Body: "dangerously-allow-all-scripts=true\n"}}
	r := evalPackageManagers(f, p)
	if r.Status != check.Warn || len(r.Evidence) != 1 || !strings.Contains(r.Evidence[0], "~/.npmrc:1  npm: dangerously-allow-all-scripts=true") {
		t.Errorf("npm 12 allow all: %s %v", r.Status, r.Evidence)
	}
	f.NpmMajor = 11 // reported once, not twice
	if r := evalPackageManagers(f, p); len(r.Evidence) != 1 {
		t.Errorf("npm 11 allow all: %v", r.Evidence)
	}
}

func TestNpmMajor(t *testing.T) {
	root := t.TempDir()
	// Homebrew / nvm layout: bin/npm -> lib/node_modules/npm/bin/npm-cli.js
	writeFile(t, root, "lib/node_modules/npm/package.json", `{"name": "npm", "version": "12.1.0"}`, 0o644)
	cli := writeFile(t, root, "lib/node_modules/npm/bin/npm-cli.js", "", 0o755)
	if got := npmMajor(cli); got != 12 {
		t.Errorf("npm-cli.js: %d", got)
	}
	bin := writeFile(t, root, "bin/npm", "", 0o755)
	if got := npmMajor(bin); got != 12 {
		t.Errorf("bin/npm: %d", got)
	}
	// Windows layout: nodejs\npm.cmd next to node_modules\npm.
	win := t.TempDir()
	writeFile(t, win, "nodejs/node_modules/npm/package.json", `{"version": "11.6.2", "name": "npm"}`, 0o644)
	if got := npmMajor(writeFile(t, win, "nodejs/npm.cmd", "", 0o755)); got != 11 {
		t.Errorf("npm.cmd: %d", got)
	}
	if got := npmMajor(filepath.Join(t.TempDir(), "bin", "npm")); got != 0 {
		t.Errorf("unknown: %d", got)
	}
}
