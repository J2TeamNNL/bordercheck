package checks

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winKMSScript prints the KMS server Windows and Office activate against, if
// one is set.
const winKMSScript = `$ErrorActionPreference = 'SilentlyContinue'
"windows=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform').KeyManagementServiceName)"
"office=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform').KeyManagementServiceName)"`

// winCrackScanScript prints the enabled outbound block rules that name a
// program ("fw<TAB>rule<TAB>program") and the scheduled tasks' names
// ("task<TAB>path+name"). Both are readable without admin rights.
const winCrackScanScript = `$ErrorActionPreference = 'SilentlyContinue'
Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True | ForEach-Object {
  $p = ($_ | Get-NetFirewallApplicationFilter).Program
  if ($p -and $p -ne 'Any') { "fw` + "`t" + `$($_.DisplayName)` + "`t" + `$p" }
}
Get-ScheduledTask | ForEach-Object { "task` + "`t" + `$($_.TaskPath)$($_.TaskName)" }`

func crackFactsOS(ctx context.Context) crackFacts {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	f := crackFacts{HostsPath: filepath.Join(root, "System32", "drivers", "etc", "hosts"), KMS: map[string]string{}}
	if out, err := sysx.PowerShellScript(ctx, winKMSScript); err == nil {
		kv := kvLines(out)
		f.KMS["Windows"], f.KMS["Microsoft Office"] = kv["windows"], kv["office"]
	}
	pf := []string{}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		if p := os.Getenv(env); p != "" {
			pf = append(pf, p)
		}
	}
	// Where closed-source activators install themselves.
	dirs := []string{filepath.Join(root, "AutoKMS"), filepath.Join(os.Getenv("ProgramData"), "KMSAutoS"),
		filepath.Join(os.Getenv("ProgramData"), "KMSAuto")}
	for _, p := range pf {
		dirs = append(dirs, filepath.Join(p, "KMSpico"), filepath.Join(p, "KMSAuto Net"), filepath.Join(p, "AAct"))
	}
	for _, d := range dirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() && filepath.IsAbs(d) {
			f.Tools = append(f.Tools, filepath.Base(d)+" ("+d+")")
		}
	}
	// Ohook (open source, from Microsoft Activation Scripts) puts its own
	// sppc.dll into Office's private copy of System32, where genuine Office has none.
	for _, p := range pf {
		for _, sub := range []string{`Microsoft Office\root\vfs\System`, `Microsoft Office\root\vfs\SystemX86`} {
			if dll := filepath.Join(p, sub, "sppc.dll"); isRegularFile(dll) {
				f.Hooks = append(f.Hooks, "Ohook ("+dll+")")
			}
		}
	}
	if out, err := sysx.PowerShellScriptFor(ctx, 40*time.Second, winCrackScanScript); err == nil {
		rules, tasks := parseCrackScan(out)
		f.Firewall = rules
		for _, t := range tasks {
			f.Tools = append(f.Tools, "scheduled task "+t)
		}
	}
	return f
}

func isRegularFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
