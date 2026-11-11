package policy

import "testing"

func TestUserIgnoreSwitches(t *testing.T) {
	c := Default().Checks
	if !c.Secrets.UserIgnore || !c.AIAgents.UserIgnore || !c.SSHKeys.UserIgnore {
		t.Error("user_ignore should default to true for secrets, ai-agents and ssh-keys")
	}
	p, err := Parse([]byte(`{"checks": {"secrets": {"walk_depth": 3}}}`), "test")
	if err != nil || !p.Checks.Secrets.UserIgnore || !p.Checks.SSHKeys.UserIgnore {
		t.Errorf("left out: %+v %v", p.Checks.Secrets, err)
	}
	p, err = Parse([]byte(`{"checks": {"secrets": {"user_ignore": false}, "ai-agents": {"user_ignore": false}, "ssh-keys": {"user_ignore": false}}}`), "test")
	if err != nil || p.Checks.Secrets.UserIgnore || p.Checks.AIAgents.UserIgnore || p.Checks.SSHKeys.UserIgnore {
		t.Errorf("false: %v", err)
	}
	for _, id := range []string{"secrets", "ai-agents", "ssh-keys"} {
		if _, err := Parse([]byte(`{"checks": {"`+id+`": {"user_ignore": "no"}}}`), "test"); err == nil {
			t.Errorf("%s: a string was accepted", id)
		}
	}
	if _, err := Parse([]byte(`{"checks": {"firewall": {"user_ignore": true}}}`), "test"); err == nil {
		t.Error("user_ignore on a check that does not take it was accepted")
	}
}
