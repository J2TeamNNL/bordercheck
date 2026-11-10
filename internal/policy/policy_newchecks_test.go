package policy

import (
	"strings"
	"testing"
)

func TestNewChecksPolicy(t *testing.T) {
	p, err := load(t, `{"checks": {
	  "ssh-keys": {"authorized_keys": false, "allow_keys": ["~/.ssh/deploy_*"]},
	  "tunnels": {"on_problem": "fail", "allow": ["tailscale-serve"]},
	  "ai-agents": {"guardrails": false, "extra_paths": ["~/work/mcp.json"]},
	  "secrets": {"locations": {"kube": false}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Checks
	if c.SSHKeys.AuthorizedKeys || !c.SSHKeys.NoPassphrase || c.Tunnels.OnProblem != "fail" ||
		len(c.Tunnels.LowerSeverity) != 1 || c.AIAgents.Guardrails || !c.AIAgents.Tokens {
		t.Errorf("got %+v", c)
	}
	if c.Secrets.Locations.Kube || !c.Secrets.Locations.Docker || !c.Secrets.Locations.MySQL {
		t.Errorf("locations: one switch must not reset the others: %+v", c.Secrets.Locations)
	}
}

func TestNewChecksPolicyRejects(t *testing.T) {
	for body, want := range map[string]string{
		`{"checks": {"tunnels": {"allow": ["ngork"]}}}`:                "unknown tool",
		`{"checks": {"tunnels": {"lower_severity": ["x"]}}}`:           "unknown tool",
		`{"checks": {"ssh-keys": {"on_problem": "block"}}}`:            "on_problem",
		`{"checks": {"ai-agents": {"on_problem": "error"}}}`:           "on_problem",
		`{"checks": {"ai-agents": {"extra_paths": [" "]}}}`:            "extra_paths",
		`{"checks": {"secrets": {"locations": {"kubernetes": true}}}}`: "unknown field",
		`{"checks": {"ssh-keys": {"passphrase": true}}}`:               "unknown field",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}
