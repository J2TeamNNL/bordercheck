package checks

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// All fixtures live in a temp home: the real ~/.ssh is never read.
func TestSSHClientConfig(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".ssh/config", strings.Join([]string{
		"# top level applies to every host",
		"ForwardAgent yes",
		"Include conf.d/*",
		"",
		"Host github.com",
		"  ForwardAgent no",
		"  StrictHostKeyChecking accept-new",
		"",
		"Host lab-* 10.0.0.*",
		"  StrictHostKeyChecking=no",
		"  UserKnownHostsFile /dev/null",
		"",
		"Host * !bastion",
		"  StrictHostKeyChecking off",
		"",
		"Host bastion",
		"  Include bastion.conf",
		"",
		"Match all",
		"  UserKnownHostsFile \"/dev/null\"",
		"Host *",
		"  ForwardAgent $SSH_AUTH_SOCK",
	}, "\n"), 0o600)
	writeFile(t, home, ".ssh/conf.d/work", "Host *\n  StrictHostKeyChecking no\nHost build\n  ForwardAgent yes\n", 0o600)
	writeFile(t, home, ".ssh/bastion.conf", "ForwardAgent yes\n", 0o600)
	got := readSSHClientConfig(home, filepath.Join(home, ".ssh", "config"))
	var lines []string
	for _, s := range got {
		lines = append(lines, strings.Join([]string{filepath.ToSlash(s.path), strconv.Itoa(s.line), s.hosts, s.setting, map[bool]string{true: "all", false: "some"}[s.all]}, "|"))
	}
	want := []string{
		"~/.ssh/config|2||ForwardAgent yes|all",
		"~/.ssh/conf.d/work|2|Host *|StrictHostKeyChecking no|all",
		"~/.ssh/conf.d/work|4|Host build|ForwardAgent yes|some",
		"~/.ssh/config|10|Host lab-* 10.0.0.*|StrictHostKeyChecking no|some",
		"~/.ssh/config|11|Host lab-* 10.0.0.*|UserKnownHostsFile /dev/null|some",
		"~/.ssh/config|14|Host * !bastion|StrictHostKeyChecking off|all",
		"~/.ssh/bastion.conf|1|Host bastion|ForwardAgent yes|some",
		"~/.ssh/config|20|Match all|UserKnownHostsFile /dev/null|all",
		"~/.ssh/config|22|Host *|ForwardAgent $SSH_AUTH_SOCK|all",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	// Merged into a passing key result: warn medium, with the config fix.
	pass := evalSSHKeys(nil, nil, policy.Default().Checks.SSHKeys)
	r := withSSHClientConfig(pass, got)
	if r.Status != check.Warn || r.Severity != check.Medium || len(r.Evidence) != 9 ||
		!strings.Contains(r.Summary, "5 settings in the SSH client config weaken every connection") ||
		!strings.Contains(r.Summary, "4 settings in the SSH client config weaken connections to particular hosts") ||
		!strings.Contains(r.Fix, "StrictHostKeyChecking accept-new") || r.Evidence[0] != "~/.ssh/config:2  top level: ForwardAgent yes (every host)" {
		t.Errorf("got %s %s %q %q\n%v", r.Status, r.Severity, r.Summary, r.Fix, r.Evidence)
	}
	// Specific hosts only: low.
	r = withSSHClientConfig(pass, got[2:3])
	if r.Status != check.Warn || r.Severity != check.Low {
		t.Errorf("some: %s %s", r.Status, r.Severity)
	}
	// Merged into a failing key result: keeps fail/high, adds summary and fix parts.
	fail := evalSSHKeys([]sshKey{{path: "~/.ssh/id_rsa", format: "OpenSSH", mode: 0o644}}, nil, policy.Default().Checks.SSHKeys)
	r = withSSHClientConfig(fail, got[:1])
	if r.Status != check.Fail || r.Severity != check.High || len(r.Evidence) != 2 || !strings.Contains(r.Summary, "1 private key has no passphrase") ||
		!strings.Contains(r.Summary, "1 setting in the SSH client config weakens every connection") || r.Consistent().FixParts == nil {
		t.Errorf("fail: %s %s %q %v", r.Status, r.Severity, r.Summary, r.Evidence)
	}

	// The policy switch, and no config at all.
	p := policy.Default().Checks.SSHKeys
	p.ClientConfig = false
	if r := sshClientConfigResult(pass, home, p); r.Status != check.Pass {
		t.Errorf("client_config off: %s", r.Status)
	}
	if r := sshClientConfigResult(pass, t.TempDir(), policy.Default().Checks.SSHKeys); r.Status != check.Pass {
		t.Errorf("no config: %s", r.Status)
	}
}
