package sysx

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os/exec"
	"path/filepath"
	"unicode/utf16"
)

// RunCombined runs name with args and returns stdout and stderr together, for
// tools such as sysadminctl that report on stderr.
func RunCombined(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return string(out), nil
}

// PowerShellScript runs a multi-line Windows PowerShell script passed with
// -EncodedCommand, so its quotes survive the Windows command line untouched.
func PowerShellScript(ctx context.Context, script string) (string, error) {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
}
