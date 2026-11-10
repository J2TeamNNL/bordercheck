package checks

import (
	"context"
	"os"
	"path/filepath"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winOutboundScript prints, without admin rights:
//   - profile=<Name>|<DefaultOutboundAction> from the effective policy
//     (ActiveStore), or from the local store when that can't be read;
//   - gpo=<Name>|<0 or 1> where Group Policy sets the default outbound action;
//   - active=<NetworkCategory> for each connected network;
//   - installed=<DisplayName> for each uninstall entry (matched in Go, never reported);
//   - service=<Name> for known outbound-firewall services that are running;
//   - process=<Name> when simplewall runs (it is often used portable).
const winOutboundScript = `$ErrorActionPreference = 'SilentlyContinue'
$p = Get-NetFirewallProfile -PolicyStore ActiveStore
if (-not $p) { $p = Get-NetFirewallProfile }
$p | ForEach-Object { 'profile={0}|{1}' -f $_.Name, $_.DefaultOutboundAction }
foreach ($n in 'Domain','Private','Public') {
  $v = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${n}Profile").DefaultOutboundAction
  if ($v -ne $null) { 'gpo={0}|{1}' -f $n, $v }
}
Get-NetConnectionProfile | ForEach-Object { 'active={0}' -f $_.NetworkCategory }
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object { $_.DisplayName } | ForEach-Object { 'installed=' + $_.DisplayName }
Get-Service FortFirewallSvc,PortmasterCore,TinyWall | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { 'service=' + $_.Name }
Get-Process simplewall | Select-Object -First 1 | ForEach-Object { 'process=' + $_.ProcessName }`

func outboundFirewalls(ctx context.Context) ([]string, outboundAdvice, bool) {
	out, err := sysx.PowerShellScript(ctx, winOutboundScript)
	if err != nil && out == "" {
		// Could not tell; don't suggest on a guess.
		return nil, outboundWin, false
	}
	f := parseWinOutbound(out)
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramData"} {
		root := os.Getenv(env)
		if root == "" {
			continue
		}
		for _, a := range winOutboundApps {
			for _, d := range a.folders {
				if st, err := os.Stat(filepath.Join(root, d)); err == nil && st.IsDir() {
					f.Folders = append(f.Folders, d)
				}
			}
		}
	}
	return evalWinOutbound(f), outboundWin, true
}
