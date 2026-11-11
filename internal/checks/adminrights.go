package checks

import (
	"context"
	"encoding/csv"
	"errors"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The admin-rights check asks how much an attacker gets by running code as the
// person at the keyboard: an administrator account, sudo without a password,
// or (Windows) User Account Control turned off or set never to ask.

type adminFacts struct {
	Family      string   // "macos", "windows" or "linux"; picks the fix text
	Admin       *bool    // nil: could not tell
	AdminGroups []string // the admin groups the account is in, for people

	NoPasswd      []string   // where a passwordless sudo rule for this account was found
	NoPasswdScope sudoNoPass // the widest of those rules
	SudoChecked   bool       // sudo said what it allows this account (sudo -n -l, or no sudo at all)
	EnableLUA     string     // Windows; "" if unset (UAC on)
	ConsentAdmin  string     // Windows ConsentPromptBehaviorAdmin; "" if unset (5, prompt for consent)
	BuiltinAdmin  bool       // Windows: the built-in Administrator account is enabled
	Elevated      bool       // Windows: bordercheck itself runs elevated
	Notes         msg.Text   // what could not be read
}

func adminRights(opts policy.AdminRights) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		f, err := adminFactsOS(ctx)
		if errors.Is(err, errUnsupported) {
			return unsupported()
		}
		if err != nil {
			return check.Errored(err)
		}
		return evalAdminRights(f, opts)
	}
}

var adminFixes = map[string]string{"macos": "admin.fix.mac", "windows": "admin.fix.win", "linux": "admin.fix.linux"}

func evalAdminRights(f adminFacts, opts policy.AdminRights) check.Result {
	var p issueList
	notes := f.Notes
	var evidence []string
	if f.Admin != nil && *f.Admin {
		evidence = append(evidence, "administrator: member of "+strings.Join(f.AdminGroups, ", "))
	} else if f.Admin != nil {
		evidence = append(evidence, "standard user")
	}
	switch where := strings.Join(f.NoPasswd, ", "); f.NoPasswdScope {
	case sudoAll:
		evidence = append(evidence, "passwordless sudo for every command: "+where)
		p.add(true, msg.Of("admin.nopasswd", "where", where), msg.P("admin.fix.nopasswd"))
	case sudoLimited:
		evidence = append(evidence, "passwordless sudo for some commands: "+where)
		p.add(false, msg.Of("admin.nopasswdSome", "where", where), msg.P("admin.fix.nopasswd"))
	}
	isAdmin := f.Admin != nil && *f.Admin
	if f.Family == "windows" {
		if f.EnableLUA != "" {
			evidence = append(evidence, "EnableLUA = "+f.EnableLUA)
		}
		if f.ConsentAdmin != "" {
			evidence = append(evidence, "ConsentPromptBehaviorAdmin = "+f.ConsentAdmin)
		}
		switch {
		case f.EnableLUA == "0":
			p.add(true, msg.Of("admin.uacOff"), msg.P("admin.fix.uac"))
		case f.ConsentAdmin == "0":
			// Only administrators are elevated without a prompt; for a standard
			// user it matters once someone makes them an administrator.
			p.add(isAdmin, msg.Of("admin.uacNoPrompt"), msg.P("admin.fix.uac"))
		}
		if f.BuiltinAdmin {
			evidence = append(evidence, "built-in Administrator account enabled")
			p.add(false, msg.Of("admin.builtinAdmin"), msg.P("admin.fix.builtinAdmin"))
		}
		if f.Elevated {
			evidence = append(evidence, "bordercheck ran elevated")
		}
	}
	if isAdmin && !opts.AllowAdmin {
		p.add(false, msg.Of("admin.isAdmin", "groups", strings.Join(f.AdminGroups, ", ")), msg.P(adminFixes[f.Family]))
	}
	if f.Admin == nil {
		notes = append(notes, msg.P("admin.note.unknown"))
	}
	if len(p.high)+len(p.medium) == 0 && f.Admin == nil && !f.SudoChecked && f.Family != "windows" {
		return check.Result{Status: check.Error, Evidence: evidence}.WithSummary(notes)
	}
	var pass msg.Text
	switch {
	case isAdmin:
		pass = msg.Of("admin.pass.allowed")
	case f.Admin != nil:
		pass = msg.Of("admin.pass.standard")
	}
	if f.SudoChecked && f.NoPasswdScope == sudoNone {
		pass = append(pass, msg.P("admin.pass.sudo"))
	}
	return p.result(pass, notes, evidence)
}

// parseGroupNames reads `id -Gn`.
func parseGroupNames(out string) []string { return strings.Fields(out) }

// unixAdminGroups returns the groups that make an account an administrator:
// admin on macOS; sudo, wheel or admin (older Ubuntu) on Linux.
func unixAdminGroups(family string, groups []string) []string {
	admin := []string{"sudo", "wheel", "admin"}
	if family == "macos" {
		admin = []string{"admin"}
	}
	var out []string
	for _, g := range groups {
		if slices.Contains(admin, g) && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

// sudoListNoPasswd reads `sudo -n -l`. sudo lists without a password only when
// one of the account's rules is NOPASSWD (its default listpw=any) or a recent
// sudo is still cached, so look for the rule itself, not for success.
func sudoListNoPasswd(out string) sudoNoPass {
	worst := sudoNone
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.Contains(t, "!authenticate") {
			return sudoAll
		}
		if _, cmds, ok := strings.Cut(t, "NOPASSWD:"); ok {
			worst = max(worst, noPasswdScope(cmds))
		}
	}
	return worst
}

// sudoNoPass says how far a passwordless sudo rule reaches.
type sudoNoPass int

const (
	sudoNone    sudoNoPass = iota
	sudoLimited            // NOPASSWD for some commands only
	sudoAll                // NOPASSWD: ALL, or Defaults !authenticate
)

// noPasswdScope judges the command list after NOPASSWD:.
func noPasswdScope(cmds string) sudoNoPass {
	for _, c := range strings.Split(cmds, ",") {
		if f := strings.Fields(c); len(f) > 0 && f[0] == "ALL" {
			return sudoAll
		}
	}
	return sudoLimited
}

// sudoersNoPasswd reads one sudoers file and reports whether a NOPASSWD rule
// (or Defaults !authenticate) applies to user or one of its groups. Aliases
// are not resolved, so a rule naming a User_Alias is not counted.
func sudoersNoPasswd(content, user string, groups []string) sudoNoPass {
	worst := sudoNone
	applies := func(list string) bool {
		for _, who := range strings.Split(list, ",") {
			who = strings.TrimSpace(who)
			switch {
			case who == "ALL" || who == user:
				return true
			case strings.HasPrefix(who, "%") && slices.Contains(groups, strings.TrimPrefix(who, "%")):
				return true
			}
		}
		return false
	}
	// Join continued lines.
	content = strings.ReplaceAll(content, "\\\n", " ")
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "Defaults"); ok {
			if !strings.Contains(rest, "!authenticate") {
				continue
			}
			scope, _, _ := strings.Cut(rest, " ")
			switch {
			case strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "\t"):
				return sudoAll // Defaults !authenticate: everyone
			case strings.HasPrefix(scope, ":") && applies(strings.TrimPrefix(scope, ":")):
				return sudoAll
			}
			continue
		}
		_, cmds, ok := strings.Cut(line, "NOPASSWD:")
		if !ok {
			continue
		}
		who, _, _ := strings.Cut(strings.ReplaceAll(line, "\t", " "), " ")
		if applies(who) {
			worst = max(worst, noPasswdScope(cmds))
		}
	}
	return worst
}

// ---- Windows ----

const (
	sidAdministrators = "S-1-5-32-544"
	sidHighIntegrity  = "S-1-16-12288"
)

// parseWhoamiGroups reads `whoami /groups /fo csv /nh` and returns the SIDs.
// Group names and attributes are localised; SIDs are not. Under UAC the
// Administrators SID is listed as "deny only", which still makes the account an
// administrator.
func parseWhoamiGroups(out string) []string {
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	recs, _ := r.ReadAll()
	var sids []string
	for _, rec := range recs {
		if len(rec) >= 3 {
			sids = append(sids, strings.TrimSpace(rec[2]))
		}
	}
	return sids
}

// winAdminScript prints the UAC settings and whether the built-in
// Administrator account (SID ending -500) is disabled. A standard user can read
// all of it.
const winAdminScript = `$ErrorActionPreference = 'SilentlyContinue'
$s = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
"enable_lua=$($s.EnableLUA)"
"consent_admin=$($s.ConsentPromptBehaviorAdmin)"
$a = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-500'"
"admin_disabled=$($a.Disabled)"`

func winAdminFacts(sids []string, kv map[string]string) adminFacts {
	f := adminFacts{Family: "windows", EnableLUA: kv["enable_lua"], ConsentAdmin: kv["consent_admin"],
		BuiltinAdmin: strings.EqualFold(kv["admin_disabled"], "False")}
	if len(sids) > 0 {
		admin := slices.Contains(sids, sidAdministrators)
		f.Admin = &admin
		if admin {
			f.AdminGroups = []string{"Administrators"}
		}
		f.Elevated = slices.Contains(sids, sidHighIntegrity)
	}
	return f
}
