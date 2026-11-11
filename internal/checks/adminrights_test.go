package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Samples are written from sudo's and whoami's documented output formats, not
// captured from a machine, except the macOS "password is required" case.

func TestUnixAdminGroups(t *testing.T) {
	if g := unixAdminGroups("macos", parseGroupNames("staff everyone localaccounts admin _appserveradm\n")); len(g) != 1 || g[0] != "admin" {
		t.Errorf("mac: %v", g)
	}
	if g := unixAdminGroups("macos", parseGroupNames("staff wheel\n")); len(g) != 0 {
		t.Errorf("mac wheel is not admin: %v", g)
	}
	if g := unixAdminGroups("linux", parseGroupNames("demo adm cdrom sudo dip plugdev\n")); len(g) != 1 || g[0] != "sudo" {
		t.Errorf("ubuntu: %v", g)
	}
	if g := unixAdminGroups("linux", parseGroupNames("demo wheel\n")); len(g) != 1 {
		t.Errorf("fedora: %v", g)
	}
}

func TestSudoListNoPasswd(t *testing.T) {
	all := `Matching Defaults entries for demo on host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin

User demo may run the following commands on host:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
`
	some := "User demo may run the following commands on host:\n    (ALL : ALL) ALL\n    (root) NOPASSWD: /usr/bin/apt update, /usr/sbin/shutdown\n"
	cached := "User demo may run the following commands on host:\n    (ALL : ALL) ALL\n"
	for out, want := range map[string]sudoNoPass{all: sudoAll, some: sudoLimited, cached: sudoNone, "": sudoNone,
		"Matching Defaults entries for demo on host:\n    !authenticate\n": sudoAll} {
		if got := sudoListNoPasswd(out); got != want {
			t.Errorf("%q: got %v, want %v", out, got, want)
		}
	}
}

func TestSudoersNoPasswd(t *testing.T) {
	groups := []string{"demo", "sudo", "docker"}
	for conf, want := range map[string]sudoNoPass{
		"# demo ALL=(ALL) NOPASSWD: ALL\n%sudo ALL=(ALL:ALL) ALL\n":        sudoNone,
		"demo ALL=(ALL) NOPASSWD: ALL\n":                                   sudoAll,
		"%sudo\tALL=(ALL:ALL) NOPASSWD:ALL\n":                              sudoAll,
		"%docker ALL=(root) NOPASSWD: /usr/bin/systemctl restart docker\n": sudoLimited,
		"alice ALL=(ALL) NOPASSWD: ALL\n%wheel ALL=(ALL) NOPASSWD: ALL\n":  sudoNone,
		"bob,demo ALL=(ALL) \\\n  NOPASSWD: ALL\n":                         sudoAll,
		"Defaults:demo !authenticate\n":                                    sudoAll,
		"Defaults:alice !authenticate\n":                                   sudoNone,
		"Defaults !authenticate\n":                                         sudoAll,
		"Defaults env_reset\n":                                             sudoNone,
	} {
		if got := sudoersNoPasswd(conf, "demo", groups); got != want {
			t.Errorf("%q: got %v, want %v", conf, got, want)
		}
	}
}

func TestWinAdminFacts(t *testing.T) {
	who := `"Everyone","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled group"
"BUILTIN\Administrators","Alias","S-1-5-32-544","Group used for deny only"
"BUILTIN\Users","Alias","S-1-5-32-545","Mandatory group, Enabled by default, Enabled group"
"Mandatory Label\Medium Mandatory Level","Label","S-1-16-8192",""
`
	f := winAdminFacts(parseWhoamiGroups(who), kvLines("enable_lua=1\nconsent_admin=5\nadmin_disabled=True\n"))
	if f.Admin == nil || !*f.Admin || f.Elevated || f.BuiltinAdmin {
		t.Errorf("got %+v", f)
	}
	std := strings.Replace(who, "S-1-5-32-544", "S-1-5-32-546", 1)
	if f := winAdminFacts(parseWhoamiGroups(std), nil); f.Admin == nil || *f.Admin {
		t.Errorf("standard user: %+v", f)
	}
	if f := winAdminFacts(nil, nil); f.Admin != nil {
		t.Errorf("no whoami: %+v", f)
	}
}

func TestEvalAdminRights(t *testing.T) {
	yes, no := true, false
	def := policy.Default().Checks.AdminRights
	cases := []struct {
		name string
		f    adminFacts
		opts policy.AdminRights
		st   check.Status
		sev  check.Severity
		has  string
	}{
		{"mac standard", adminFacts{Family: "macos", Admin: &no, SudoChecked: true}, def, check.Pass, "", "standard user"},
		{"mac admin", adminFacts{Family: "macos", Admin: &yes, AdminGroups: []string{"admin"}, SudoChecked: true}, def,
			check.Warn, check.Medium, "administrator (admin)"},
		{"mac admin allowed", adminFacts{Family: "macos", Admin: &yes, AdminGroups: []string{"admin"}, SudoChecked: true},
			policy.AdminRights{AllowAdmin: true}, check.Pass, "", "policy allows"},
		{"nopasswd all", adminFacts{Family: "linux", Admin: &yes, AdminGroups: []string{"sudo"}, SudoChecked: true,
			NoPasswd: []string{"sudo -l"}, NoPasswdScope: sudoAll}, policy.AdminRights{AllowAdmin: true}, check.Fail, check.High, "every command"},
		{"nopasswd some", adminFacts{Family: "linux", Admin: &no, SudoChecked: true,
			NoPasswd: []string{"/etc/sudoers.d/apt"}, NoPasswdScope: sudoLimited}, def, check.Warn, check.Medium, "some commands"},
		{"uac off", adminFacts{Family: "windows", Admin: &no, EnableLUA: "0"}, def, check.Fail, check.High, "EnableLUA"},
		{"uac silent admin", adminFacts{Family: "windows", Admin: &yes, AdminGroups: []string{"Administrators"}, ConsentAdmin: "0"},
			policy.AdminRights{AllowAdmin: true}, check.Fail, check.High, "without asking"},
		{"uac silent standard", adminFacts{Family: "windows", Admin: &no, ConsentAdmin: "0"}, def, check.Warn, check.Medium, "without asking"},
		{"builtin admin", adminFacts{Family: "windows", Admin: &no, EnableLUA: "1", BuiltinAdmin: true}, def, check.Warn, check.Medium, "built-in"},
		{"unknown", adminFacts{Family: "linux"}, def, check.Error, "", "Could not tell"},
	}
	for _, c := range cases {
		r := evalAdminRights(c.f, c.opts)
		if r.Status != c.st || r.Severity != c.sev || !strings.Contains(r.Summary, c.has) {
			t.Errorf("%s: got %s/%s %q", c.name, r.Status, r.Severity, r.Summary)
		}
		if (r.Status == check.Fail || r.Status == check.Warn) && r.Fix == "" {
			t.Errorf("%s: no fix", c.name)
		}
	}
}
