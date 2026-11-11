package checks

import (
	"context"
	"os"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winStartupScript prints one tab-separated line per startup item: the Run and
// RunOnce keys (user and machine), the user's and everyone's Startup folders
// (shortcuts resolved to their target), and enabled scheduled tasks outside
// \Microsoft\, which are Windows' own. Reading them needs no admin rights.
const winStartupScript = `$ErrorActionPreference = 'SilentlyContinue'
$T = [string][char]9
function Clean($s) { ("" + $s) -replace "[\t\r\n]", " " }
$skip = 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider'
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
  $p = Get-ItemProperty -Path $k
  if ($p) { foreach ($n in $p.PSObject.Properties) { if ($skip -notcontains $n.Name) { 'run' + $T + $k + $T + (Clean $n.Name) + $T + (Clean $n.Value) } } }
}
$sh = New-Object -ComObject WScript.Shell
foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
  if (-not $d) { continue }
  Get-ChildItem -LiteralPath $d -File | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
    $t = '"' + $_.FullName + '"'
    if ($_.Extension -eq '.lnk') { $s = $sh.CreateShortcut($_.FullName); if ($s.TargetPath) { $t = '"' + $s.TargetPath + '" ' + $s.Arguments } }
    'folder' + $T + $d + $T + (Clean $_.Name) + $T + (Clean $t)
  }
}
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object {
  $task = $_
  foreach ($a in $task.Actions) { if ($a.Execute) {
    'task' + $T + $task.TaskPath + $T + (Clean $task.TaskName) + $T + (Clean ('"' + $a.Execute.Trim('"') + '" ' + $a.Arguments))
  } }
}`

func gatherStartup(ctx context.Context, home string) ([]startupItem, msg.Text, error) {
	out, err := sysx.PowerShellScript(ctx, winStartupScript)
	if err != nil && out == "" {
		return nil, nil, err
	}
	items := winStartupItems(out, os.Getenv)
	if len(items) > startupMaxItems {
		items = items[:startupMaxItems]
	}
	return items, nil, nil
}
