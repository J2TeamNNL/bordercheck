package checks

// OS gathering for admin-rights on Windows: the account's group SIDs from
// whoami, and UAC and the built-in Administrator from the registry and CIM.
// A standard user can read all of it.

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

func adminFactsOS(ctx context.Context) (adminFacts, error) {
	groups, gerr := sysx.Run(ctx, "whoami.exe", "/groups", "/fo", "csv", "/nh")
	out, err := sysx.PowerShellScript(ctx, winAdminScript)
	if err != nil && gerr != nil {
		return adminFacts{}, err
	}
	f := winAdminFacts(parseWhoamiGroups(groups), kvLines(out))
	if err != nil {
		f.Notes = append(f.Notes, msg.P("admin.note.uac"))
	}
	return f, nil
}
