package checks

import (
	"context"
	"os"
	"sort"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/ignore"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// What the person at the machine marked as not sensitive (`bordercheck
// ignore`, package ignore) applies to three checks: secrets, ai-agents
// (plain-text tokens only) and ssh-keys (keys without a passphrase only). An
// ignored finding does not count toward its check's status, severity or
// counts, and is listed in the result's UserIgnored instead, which is always
// sent. Findings marked production, AI agent guardrails, key permissions,
// authorized_keys and SSH client settings can never be ignored this way: see
// Blocked.

// maxIgnoredListed caps the findings listed in a result's UserIgnored.
const maxIgnoredListed = 200

// Why a finding cannot be ignored by the person at the machine.
const (
	BlockedGuardrail  = "guardrail"       // an AI agent set to skip approvals or run unsandboxed
	BlockedPerms      = "permissions"     // a key file other users can read
	BlockedAuthorized = "authorized_keys" // who can log in here
	BlockedSSHConfig  = "ssh-config"      // ForwardAgent, StrictHostKeyChecking…
)

// userIgnore is the person's list for one check, and whether it may and could be applied.
type userIgnore struct {
	check   string
	entries []ignore.Entry // this check's entries only
	off     bool           // the policy does not allow it (user_ignore false)
	broken  bool           // the list could not be read
	home    string
	ignored []check.Ignored // what take set aside
}

func newUserIgnore(id string, local Local, allowed bool, home string) *userIgnore {
	u := &userIgnore{check: id, off: !allowed, broken: local.IgnoreErr != nil, home: home}
	for _, e := range local.Ignored {
		if e.Check == id {
			u.entries = append(u.entries, e)
		}
	}
	return u
}

// shownKind is the kind listed for an ignored finding: one marked production
// says so, since IT is who decides what production means.
func shownKind(kind string, prod bool) string {
	if prod {
		return kind + " [production]"
	}
	return kind
}

// take reports whether an entry covers the finding, and if so records it. A
// nil userIgnore takes nothing; so does one that is off or unreadable. names
// are what -name may match (the first is the one shown); shown is the kind
// listed in the report.
func (u *userIgnore) take(path string, names []string, kind, shown string) bool {
	if u == nil || u.broken || u.off {
		return false
	}
	for _, e := range u.entries {
		if e.Covers(u.check, path, names, kind, u.home) {
			name := ""
			if len(names) > 0 {
				name = names[0]
			}
			u.ignored = append(u.ignored, check.Ignored{Path: path, Name: name, Kind: shown, Reason: e.Reason, Since: e.Since})
			return true
		}
	}
	return false
}

// note is the summary part about the list: how many were ignored, or why it
// was not applied.
func (u *userIgnore) note() msg.Text {
	switch {
	case u == nil:
		return nil
	case u.broken:
		return msg.Of("ignore.unreadable")
	case u.off && len(u.entries) > 0:
		return msg.Of("ignore.off")
	case len(u.ignored) > 0:
		return msg.Of("ignore.more", "n", len(u.ignored))
	}
	return nil
}

// finish puts the note and the list on r. When nothing else is left (r
// passes) but something was ignored, the summary says that, followed by keep
// (notes that still apply, such as an incomplete scan).
func (u *userIgnore) finish(r check.Result, keep msg.Text) check.Result {
	if u == nil {
		return r
	}
	if len(u.ignored) > 0 && r.Status == check.Pass {
		r = r.WithSummary(append(msg.Of("ignore.all", "n", len(u.ignored)), keep...))
	} else if n := u.note(); n != nil {
		r = r.WithSummary(append(append(msg.Text{}, r.SummaryParts...), n...))
	}
	listed := u.ignored
	sort.SliceStable(listed, func(i, j int) bool { return listed[i].Path < listed[j].Path })
	if len(listed) > maxIgnoredListed {
		listed = listed[:maxIgnoredListed]
	}
	r.UserIgnored = listed
	return r
}

// Item is one finding as `bordercheck ignore` matches it: never a value, nor
// its last characters.
type Item struct {
	Check   string
	Path    string   // as the report shows it
	Names   []string // what -name may match; the first is the one shown
	Kind    string
	Blocked string // why the person at the machine cannot ignore it; "" = they can
}

// IgnorableItems runs the scans of the enabled checks that take a list of
// ignored findings and returns every finding, ignorable or not, without
// applying any list; and the home folder the paths are shown against.
func IgnorableItems(ctx context.Context, p policy.Policy, privacy Privacy) (items []Item, home string, err error) {
	c := p.Checks
	if home, err = os.UserHomeDir(); err != nil {
		return nil, "", err
	}
	if c.Secrets.IsEnabled() && privacy.scansSecrets() {
		_, found, bundles, _, err := scanSecrets(ctx, c.Secrets, privacy)
		if err != nil {
			return nil, "", err
		}
		for _, f := range found {
			items = append(items, Item{Check: "secrets", Path: f.path, Names: nonEmpty(f.name), Kind: f.kind})
		}
		for _, b := range bundles {
			items = append(items, Item{Check: "secrets", Path: b, Kind: bundleKind})
		}
	}
	if c.AIAgents.IsEnabled() && privacy.CredentialStores {
		if !privacy.allowsExtraPaths() {
			c.AIAgents.ExtraPaths = nil
		}
		_, found, err := scanAIAgents(c.AIAgents, c.Secrets)
		if err != nil {
			return nil, "", err
		}
		for _, f := range found {
			it := Item{Check: "ai-agents", Path: f.path, Names: f.names(), Kind: f.what}
			if !f.token {
				it.Blocked = BlockedGuardrail
			}
			items = append(items, it)
		}
	}
	if c.SSHKeys.IsEnabled() && privacy.CredentialStores {
		_, keys, auth, settings, err := scanSSH(c.SSHKeys)
		if err != nil {
			return nil, "", err
		}
		items = append(items, sshItems(keys, auth, settings, c.SSHKeys)...)
	}
	return items, home, nil
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
