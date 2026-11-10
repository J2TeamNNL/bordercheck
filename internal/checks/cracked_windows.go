package checks

import (
	"context"
	"os"
	"path/filepath"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// winKMSScript prints the KMS server Windows and Office activate against, if
// one is set.
const winKMSScript = `$ErrorActionPreference = 'SilentlyContinue'
"windows=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform').KeyManagementServiceName)"
"office=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform').KeyManagementServiceName)"`

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
	// Where the KMSpico installer puts itself and its AutoKMS scheduler.
	var dirs []string
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		if p := os.Getenv(env); p != "" {
			dirs = append(dirs, filepath.Join(p, "KMSpico"))
		}
	}
	dirs = append(dirs, filepath.Join(root, "AutoKMS"))
	for _, d := range dirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			f.Tools = append(f.Tools, filepath.Base(d)+" ("+d+")")
		}
	}
	return f
}
