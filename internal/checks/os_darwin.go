package checks

import (
	"context"
	"os"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

func firewall(ctx context.Context, requireStealth bool) check.Result {
	global, err := sysx.Run(ctx, socketfilterfw, "--getglobalstate")
	if err != nil {
		return check.Errored(err)
	}
	stealth, _ := sysx.Run(ctx, socketfilterfw, "--getstealthmode")
	return evalMacFirewall(global, stealth, requireStealth)
}

func diskEncryption(ctx context.Context) check.Result {
	out, err := sysx.Run(ctx, "/usr/bin/fdesetup", "status")
	if err != nil {
		return check.Errored(err)
	}
	return evalFileVault(out)
}

func listListeners(ctx context.Context) ([]listener, string, error) {
	note := ""
	if os.Geteuid() != 0 {
		note = "Only your own processes are visible; run with sudo to include system services."
	}
	out, err := sysx.Run(ctx, "/usr/sbin/lsof", "+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN")
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, note, nil // lsof exits 1 when nothing listens
	}
	return parseLsof(out), note, nil
}
