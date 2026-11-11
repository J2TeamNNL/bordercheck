package checks

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The ssh-keys check also reads the user's ssh client config (~/.ssh/config
// and the files it Includes under ~/.ssh) for settings that weaken every
// connection: ForwardAgent lets each server the setting covers use your keys
// while you are logged in to it; StrictHostKeyChecking no and
// UserKnownHostsFile /dev/null accept any server key, so a machine in the
// middle is never noticed. For every host (top level, Host *, Match all) they
// warn medium; for named hosts, low.

// sshSetting is one weakening setting found in an ssh config file.
type sshSetting struct {
	path    string // as shown
	line    int
	hosts   string // the Host or Match line it sits under; "" at the top level
	all     bool   // applies to every host
	setting string // e.g. "ForwardAgent yes"
}

var sshOptRe = regexp.MustCompile(`^\s*([A-Za-z]+)\s*(?:=\s*|\s+)(.*?)\s*$`)

// readSSHClientConfig reads config and the files it Includes, depth-first as
// ssh does. An Include inside a Host or Match block applies under that block.
func readSSHClientConfig(home, config string) []sshSetting {
	var out []sshSetting
	seen := map[string]bool{}
	var read func(p string, depth int, hosts string, all bool)
	read = func(p string, depth int, hosts string, all bool) {
		if depth > 3 || seen[p] || len(seen) >= sshMaxIncludes {
			return
		}
		seen[p] = true
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() > sshMaxConfigFile {
			return
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return
		}
		shown := tildePath(home, p)
		curHosts, curAll := hosts, all
		sc := bufio.NewScanner(bytes.NewReader(data))
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			if t := strings.TrimSpace(line); t == "" || t[0] == '#' {
				continue
			}
			m := sshOptRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			key, args := strings.ToLower(m[1]), sshConfigArgs(m[2])
			if len(args) == 0 {
				continue
			}
			switch key {
			case "host":
				curHosts, curAll = "Host "+strings.Join(args, " "), sshAllHosts(args)
				if depth > 0 && hosts != "" { // a Host line in an included file ends the including block
					curAll = curAll && all
				}
				continue
			case "match":
				curHosts, curAll = "Match "+strings.Join(args, " "), len(args) == 1 && strings.EqualFold(args[0], "all")
				continue
			case "include":
				for _, arg := range args {
					arg = expandHome(arg, home)
					if !filepath.IsAbs(arg) {
						arg = filepath.Join(home, ".ssh", arg)
					}
					matches, _ := filepath.Glob(arg)
					for _, inc := range matches {
						if !sshPathAvoided(home, inc) {
							read(inc, depth+1, curHosts, curAll)
						}
					}
				}
				continue
			}
			v := strings.ToLower(args[0])
			var setting string
			switch {
			case key == "forwardagent" && v != "no":
				setting = "ForwardAgent " + args[0]
			case key == "stricthostkeychecking" && (v == "no" || v == "off"):
				setting = "StrictHostKeyChecking " + args[0]
			case key == "userknownhostsfile" && (v == "/dev/null" || v == "nul"):
				setting = "UserKnownHostsFile " + args[0]
			}
			if setting != "" {
				out = append(out, sshSetting{path: shown, line: n, hosts: curHosts, all: curHosts == "" || curAll, setting: setting})
			}
		}
	}
	read(config, 0, "", true)
	return out
}

// sshAllHosts reports whether a Host line covers (nearly) every host: it
// holds a lone *, even if a negated pattern carves out a few.
func sshAllHosts(patterns []string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
	}
	return false
}

// withSSHClientConfig adds the client config's findings to the key check's result.
func withSSHClientConfig(r check.Result, settings []sshSetting) check.Result {
	if len(settings) == 0 {
		return r
	}
	var ev []string
	all, some := 0, 0
	for _, s := range settings {
		where := s.hosts
		if where == "" {
			where = "top level"
		}
		why := map[bool]string{true: "every host", false: "these hosts"}[s.all]
		ev = append(ev, fmt.Sprintf("%s:%d  %s: %s (%s)", s.path, s.line, where, s.setting, why))
		if s.all {
			all++
		} else {
			some++
		}
	}
	var parts msg.Text
	if all > 0 {
		parts = append(parts, msg.P("sshkeys.config.all", "n", all))
	}
	if some > 0 {
		parts = append(parts, msg.P("sshkeys.config.some", "n", some))
	}
	sev := check.Low
	if all > 0 {
		sev = check.Medium
	}
	if r.Status != check.Warn && r.Status != check.Fail {
		return check.Result{Status: check.Warn, Severity: sev, Evidence: ev}.
			WithSummary(parts).WithFix(msg.Of("sshkeys.fix.config"))
	}
	summary := append(append(msg.Text{}, r.SummaryParts...), parts...)
	fix := append(append(msg.Text{}, r.FixParts...), msg.P("sshkeys.fix.config"))
	r.Evidence = append(r.Evidence, ev...)
	if r.Severity == check.Low && sev == check.Medium {
		r.Severity = sev
	}
	return r.WithSummary(summary).WithFix(fix)
}

// sshClientConfigResult is the hook sshKeys calls.
func sshClientConfigResult(r check.Result, home string, p policy.SSHKeys) check.Result {
	if !p.ClientConfig {
		return r
	}
	return withSSHClientConfig(r, readSSHClientConfig(home, filepath.Join(home, ".ssh", "config")))
}
