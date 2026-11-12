package policy

import (
	"slices"
	"strings"
	"testing"
)

// Options of package-managers, startup-items and backup, and the new
// ssh-keys.client_config and secrets.locations.git_remotes switches.
func TestMoreChecksPolicyDefaults(t *testing.T) {
	c := Default().Checks
	if !slices.Equal(c.PackageManagers.Tools, PackageManagerTools) || !c.PackageManagers.RequireIgnoreScripts ||
		c.PackageManagers.RequireReleaseAge || len(c.PackageManagers.AllowHosts) != 0 {
		t.Errorf("package-managers: %+v", c.PackageManagers)
	}
	if len(c.StartupItems.Allow) != 0 || len(c.StartupItems.ExtraSuspiciousPaths) != 0 {
		t.Errorf("startup-items: %+v", c.StartupItems)
	}
	if b := c.Backup; b.RequireBackup || !b.RequireEncrypted || !b.RequireFindMy || b.MaxBackupAgeDays != 0 {
		t.Errorf("backup: %+v", b)
	}
	if !c.SSHKeys.ClientConfig || !c.Secrets.Locations.GitRemotes {
		t.Errorf("ssh-keys.client_config / secrets.locations.git_remotes must default to true")
	}
	// The default list is a copy: changing a policy's list never changes the exported one.
	c.PackageManagers.Tools[0] = "x"
	if PackageManagerTools[0] != "npm" {
		t.Error("Default shares PackageManagerTools")
	}
}

func TestMoreChecksPolicy(t *testing.T) {
	p, err := load(t, `{"checks": {
	  "package-managers": {"tools": ["npm", "pip"], "require_release_age": true, "allow_hosts": ["*.corp.example"]},
	  "startup-items": {"on_problem": "fail", "allow": ["com.sample.*"], "extra_suspicious_paths": ["~/Public"]},
	  "backup": {"require_backup": true, "max_backup_age_days": 14},
	  "ssh-keys": {"client_config": false},
	  "secrets": {"locations": {"git_remotes": false}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Checks
	if !slices.Equal(c.PackageManagers.Tools, []string{"npm", "pip"}) || !c.PackageManagers.RequireIgnoreScripts ||
		!c.PackageManagers.RequireReleaseAge {
		t.Errorf("package-managers: %+v", c.PackageManagers)
	}
	if c.StartupItems.OnProblem != "fail" || c.StartupItems.Allow[0] != "com.sample.*" {
		t.Errorf("startup-items: %+v", c.StartupItems)
	}
	if !c.Backup.RequireBackup || !c.Backup.RequireEncrypted || c.Backup.MaxBackupAgeDays != 14 {
		t.Errorf("backup: %+v", c.Backup)
	}
	if c.SSHKeys.ClientConfig || !c.SSHKeys.NoPassphrase || c.Secrets.Locations.GitRemotes || !c.Secrets.Locations.Kube {
		t.Errorf("switches: %+v %+v", c.SSHKeys, c.Secrets.Locations)
	}
}

func TestMoreChecksPolicyRejects(t *testing.T) {
	for body, want := range map[string]string{
		`{"checks": {"package-managers": {"tools": ["maven"]}}}`:           "unknown tool",
		`{"checks": {"package-managers": {"allow_hosts": [" "]}}}`:         "empty pattern",
		`{"checks": {"package-managers": {"on_problem": "skip"}}}`:         "on_problem",
		`{"checks": {"package-managers": {"ignore_scripts": true}}}`:       "unknown field",
		`{"checks": {"startup-items": {"allow": [""]}}}`:                   "empty pattern",
		`{"checks": {"startup-items": {"extra_suspicious_paths": [" "]}}}`: "extra_suspicious_paths",
		`{"checks": {"backup": {"max_backup_age_days": -1}}}`:              "max_backup_age_days",
		`{"checks": {"backup": {"require_findmy": true}}}`:                 "unknown field",
		`{"checks": {"ssh-keys": {"clientconfig": true}}}`:                 "unknown field",
		`{"checks": {"secrets": {"locations": {"git_remote": true}}}}`:     "unknown field",
	} {
		if _, err := load(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", body, err, want)
		}
	}
}
