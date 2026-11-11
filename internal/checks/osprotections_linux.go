package checks

// OS gathering for os-protections on Linux: the SecureBoot EFI variable (or
// `mokutil --sb-state`), /sys/fs/selinux/enforce and AppArmor's module
// parameter. All are world-readable.

import (
	"context"
	"os"
	"strings"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

const efiSecureBootVar = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

func protFactsOS(ctx context.Context) (protFacts, error) {
	f := protFacts{Family: "linux"}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft") {
		f.WSL = true // Windows guards the boot; WSL kernels ship without AppArmor/SELinux enforcing
		return f, nil
	}
	if _, err := os.Stat("/sys/firmware/efi"); err != nil {
		f.NoUEFI = true
	} else if b, err := os.ReadFile(efiSecureBootVar); err == nil {
		f.SecureBoot = efiSecureBoot(b)
	}
	if f.SecureBoot == nil && !f.NoUEFI {
		if mok, ok := sysx.Find("mokutil", "/usr/bin/mokutil", "/bin/mokutil"); ok {
			out, _ := sysx.Run(ctx, mok, "--sb-state")
			f.SecureBoot = parseMokutilSB(out)
		}
	}
	enforce, err := os.ReadFile("/sys/fs/selinux/enforce")
	f.SELinux = selinuxMode(string(enforce), err == nil)
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		f.AppArmor = strings.TrimSpace(string(b)) == "Y"
	}
	return f, nil
}
