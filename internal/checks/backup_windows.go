package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winFindMyScript prints the Find my device setting and the policy that can
// override it. Both are readable without admin rights.
const winFindMyScript = `$ErrorActionPreference = 'SilentlyContinue'
"policy=$((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice').AllowFindMyDevice)"
"setting=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\MdmCommon\SettingValues').LocationSyncEnabled)"`

// gatherBackup reads Find my device. Windows backups (File History, the
// Windows Backup app, OneDrive folder backup) have no cheap, documented state
// to read, so they are not judged.
func gatherBackup(ctx context.Context) backupFacts {
	f := backupFacts{OS: "windows", Notes: msg.Text{msg.P("backup.win.notRead")}}
	if out, err := sysx.PowerShellScript(ctx, winFindMyScript); err == nil {
		f.FindMy, f.FindMyKnown = winFindMy(kvLines(out))
	}
	return f
}
