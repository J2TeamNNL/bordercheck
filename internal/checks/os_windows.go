package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

func firewall(ctx context.Context, _ bool) check.Result {
	out, err := sysx.PowerShell(ctx, `Get-NetFirewallProfile | ForEach-Object { '{0}={1}' -f $_.Name, $_.Enabled }`)
	if err != nil {
		return check.Errored(err)
	}
	return evalWinFirewall(parseWinFirewall(out))
}

func diskEncryption(ctx context.Context) check.Result {
	out, err := sysx.PowerShell(ctx, `(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection')`)
	if err != nil {
		return check.Errored(err)
	}
	return evalBitLocker(out)
}

func listListeners(ctx context.Context) ([]listener, msg.Text, error) {
	out, err := sysx.PowerShell(ctx, `Get-NetTCPConnection -State Listen | ForEach-Object { '{0}|{1}|{2}' -f (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName, $_.LocalAddress, $_.LocalPort }`)
	if err != nil {
		return nil, nil, err
	}
	return parseWinListeners(out), nil, nil
}
