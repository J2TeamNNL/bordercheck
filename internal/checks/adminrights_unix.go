//go:build darwin || linux

package checks

// OS gathering for admin-rights on macOS and Linux: `id`, `sudo -n -l` and the
// sudoers files a normal user may read (usually none). sudo always runs with
// -n, so it never asks for a password or Touch ID.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

func adminFactsOS(ctx context.Context) (adminFacts, error) {
	f := adminFacts{Family: "linux"}
	if runtime.GOOS == "darwin" {
		f.Family = "macos"
	}
	out, err := sysx.Run(ctx, "/usr/bin/id", "-Gn")
	if err != nil {
		return f, err
	}
	groups := parseGroupNames(out)
	f.AdminGroups = unixAdminGroups(f.Family, groups)
	admin := len(f.AdminGroups) > 0
	f.Admin = &admin
	name, _ := sysx.Run(ctx, "/usr/bin/id", "-un")
	name = strings.TrimSpace(name)

	sudo, ok := sysx.Find("sudo", "/usr/bin/sudo", "/bin/sudo")
	if !ok {
		f.SudoChecked = true
		return f, nil
	}
	list, err := sysx.Run(ctx, sudo, "-n", "-l")
	switch {
	case err == nil:
		f.SudoChecked = true
		if s := sudoListNoPasswd(list); s != sudoNone {
			f.NoPasswd, f.NoPasswdScope = append(f.NoPasswd, "sudo -l"), s
		}
	case strings.Contains(err.Error(), "password is required"), strings.Contains(err.Error(), "may not run sudo"):
		// With sudo's default listpw=any, a NOPASSWD rule would have let -l through.
		f.SudoChecked = true
	default:
		f.Notes = append(f.Notes, msg.P("admin.note.sudo", "err", err.Error()))
	}
	files := []string{"/etc/sudoers"}
	more, _ := filepath.Glob("/etc/sudoers.d/*")
	files = append(files, more...)
	for _, p := range files {
		b, err := os.ReadFile(p) // root-only on most systems; fine
		if err != nil {
			continue
		}
		if s := sudoersNoPasswd(string(b), name, groups); s != sudoNone {
			f.NoPasswd, f.NoPasswdScope = append(f.NoPasswd, p), max(f.NoPasswdScope, s)
		}
	}
	return f, nil
}
