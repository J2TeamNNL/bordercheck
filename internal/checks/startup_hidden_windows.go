package checks

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winHiddenScript prints Defender's exclusions ("excl<TAB>path|process|extension<TAB>value";
// "excl<TAB>na" when this user may not read them) and the unsigned programs
// running from a temporary or download folder ("proc<TAB>path"). Get-Process
// shows the path of this user's own processes only, which is what runs from
// their folders.
const winHiddenScript = `$ErrorActionPreference = 'SilentlyContinue'
$T = [string][char]9
$m = Get-MpPreference
if ($m) {
  $all = @($m.ExclusionPath) + @($m.ExclusionProcess) + @($m.ExclusionExtension)
  if ($all -match 'N/A') { 'excl' + $T + 'na' } else {
    foreach ($v in $m.ExclusionPath) { if ($v) { 'excl' + $T + 'path' + $T + $v } }
    foreach ($v in $m.ExclusionProcess) { if ($v) { 'excl' + $T + 'process' + $T + $v } }
    foreach ($v in $m.ExclusionExtension) { if ($v) { 'excl' + $T + 'extension' + $T + $v } }
  }
}
$dirs = @($env:TEMP, (Join-Path $env:LOCALAPPDATA 'Temp'), (Join-Path $env:USERPROFILE 'Downloads'), $env:PUBLIC, (Join-Path $env:SystemRoot 'Temp')) | Where-Object { $_ }
Get-Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique | ForEach-Object {
  $p = $_
  foreach ($d in $dirs) { if ($p.StartsWith($d + '\', [StringComparison]::OrdinalIgnoreCase)) {
    if ((Get-AuthenticodeSignature -LiteralPath $p).Status -ne 'Valid') { 'proc' + $T + $p }
    break
  } }
}`

func gatherHidden(ctx context.Context, home string) hiddenFacts {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	x := hiddenFacts{HostsPath: filepath.Join(root, "System32", "drivers", "etc", "hosts"), Getenv: os.Getenv}
	if b, err := os.ReadFile(x.HostsPath); err == nil {
		x.Hosts = string(b)
	}
	out, err := sysx.PowerShellScriptFor(ctx, 40*time.Second, winHiddenScript)
	if err != nil && out == "" {
		return x
	}
	x.Exclusions, x.ExclusionsRead, x.Running = parseHiddenScan(out)
	return x
}
