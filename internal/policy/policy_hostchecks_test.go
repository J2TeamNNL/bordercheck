package policy

import (
	"strings"
	"testing"
)

func TestAdminProtectionsSharingPolicy(t *testing.T) {
	d := Default().Checks
	if d.AdminRights.AllowAdmin || !d.OSProtections.SIP || !d.OSProtections.LSM || !d.OSProtections.SmartScreen ||
		d.Sharing.Allow == nil || len(d.Sharing.Allow) != 0 {
		t.Errorf("defaults: %+v %+v %+v", d.AdminRights, d.OSProtections, d.Sharing)
	}
	p, err := load(t, `{"checks": {
	  "admin-rights": {"allow_admin": true, "on_problem": "warn"},
	  "os-protections": {"secure_boot": false},
	  "sharing": {"allow": ["airdrop", "printer-sharing"]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Checks
	if !c.AdminRights.AllowAdmin || c.AdminRights.OnProblem != "warn" || c.OSProtections.SecureBoot ||
		!c.OSProtections.Gatekeeper || len(c.Sharing.Allow) != 2 {
		t.Errorf("got %+v %+v %+v", c.AdminRights, c.OSProtections, c.Sharing)
	}
	for body, want := range map[string]string{
		`{"checks": {"sharing": {"allow": ["samba"]}}}`:          "unknown service",
		`{"checks": {"sharing": {"on_problem": "nope"}}}`:        "sharing.on_problem",
		`{"checks": {"admin-rights": {"allow_admins": true}}}`:   "unknown field",
		`{"checks": {"os-protections": {"defender": false}}}`:    "unknown field",
		`{"checks": {"os-protections": {"on_problem": "skip"}}}`: "os-protections.on_problem",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}
