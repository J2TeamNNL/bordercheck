package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winTrustScript lists the certificates in the current user's own Root store
// (the registry key behind it, so the machine-wide roots that
// Cert:\CurrentUser\Root also shows are left out) and the user's proxy
// settings. Windows asks the user to confirm every root added there.
const winTrustScript = `$ErrorActionPreference = 'SilentlyContinue'
$p = 'HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates'
if (Test-Path $p) {
  'roots=ok'
  Get-ChildItem $p | ForEach-Object {
    $b = (Get-ItemProperty $_.PSPath).Blob
    if ($b) { 'cert=' + $_.PSChildName + ':' + [Convert]::ToBase64String($b) }
  }
} else { 'roots=none' }
$k = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
'ProxyEnable=' + $k.ProxyEnable
'ProxyServer=' + $k.ProxyServer
'AutoConfigURL=' + $k.AutoConfigURL
`

func trustFactsOS(ctx context.Context, opts policy.TrustStore) trustFacts {
	out, err := sysx.PowerShellScript(ctx, winTrustScript)
	if err != nil {
		return trustFacts{CAErr: err.Error(), ProxyErr: err.Error()}
	}
	return winTrustFacts(out)
}
