package checks

// OS gathering for os-updates, screen-lock and remote-access on Windows. Every
// source here is readable by a standard user: registry keys, services, CIM and
// powercfg queries. Nothing goes online.

import (
	"context"
	"os"
	"path/filepath"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

func updateFactsOS(ctx context.Context) (updateFacts, error) {
	out, err := sysx.PowerShellScript(ctx, winUpdateScript)
	if err != nil {
		return updateFacts{}, err
	}
	return winUpdateFacts(kvLines(out)), nil
}

func browsersOS(context.Context) []browserInfo {
	pf, pf86, local := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")
	cands := []struct{ id, exe string }{
		{"chrome", filepath.Join(pf, `Google\Chrome\Application\chrome.exe`)},
		{"chrome", filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`)},
		{"chrome", filepath.Join(local, `Google\Chrome\Application\chrome.exe`)},
		{"edge", filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`)},
		{"edge", filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`)},
		{"firefox", filepath.Join(pf, `Mozilla Firefox\firefox.exe`)},
		{"firefox", filepath.Join(pf86, `Mozilla Firefox\firefox.exe`)},
		{"firefox", filepath.Join(local, `Mozilla Firefox\firefox.exe`)},
		{"brave", filepath.Join(pf, `BraveSoftware\Brave-Browser\Application\brave.exe`)},
		{"brave", filepath.Join(local, `BraveSoftware\Brave-Browser\Application\brave.exe`)},
	}
	var out []browserInfo
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.exe] || !filepath.IsAbs(c.exe) {
			continue // ProgramFiles(x86) is unset on 32-bit Windows
		}
		seen[c.exe] = true
		v := ""
		if c.id != "firefox" {
			v = chromiumVersion(filepath.Dir(c.exe))
		}
		if b, ok := browserAt(c.id, c.exe, v); ok {
			out = append(out, b)
		}
	}
	return out
}

func screenLockOS(ctx context.Context) (lockFacts, error) {
	out, err := sysx.PowerShellScript(ctx, winLockScript)
	if err != nil {
		return lockFacts{}, err
	}
	sleep, _ := sysx.Run(ctx, "powercfg.exe", "/q", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE")
	lock, _ := sysx.Run(ctx, "powercfg.exe", "/q", "SCHEME_CURRENT", "SUB_NONE", "CONSOLELOCK")
	return winLockFacts(kvLines(out), sleep, lock), nil
}

func remoteServicesOS(ctx context.Context) ([]remoteService, []string, error) {
	out, err := sysx.PowerShellScript(ctx, winRemoteScript)
	if err != nil {
		return nil, nil, err
	}
	return winRemoteServices(kvLines(out)), nil, nil
}
