package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ptrinh/bordercheck/internal/notifier"
)

// On macOS the entry is a copy of the notification app in ~/Applications:
// Spotlight and Launchpad do not show apps under ~/Library, where the install
// folder is. Opened by a person, the app runs `bordercheck open` (see
// macos/notifier). The copy is only ever launched by the person, so nothing
// here trusts it: notifications still go through the app in the install
// folder, checked against its recorded digest before every use.

// opensReportKey is in the Info.plist of an app that opens the report page
// when a person launches it; an older app would just wait and quit.
const opensReportKey = "BCOpensReport"

func launcherPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Applications", LauncherName+".app"), nil
}

func ensureLauncher(env Env, cfg Config) error {
	dst, err := launcherPath()
	if err != nil {
		return err
	}
	return copyLauncher(notifier.Path(env.Dir), dst, cfg.NotifierDigest)
}

// copyLauncher makes dst a copy of the app at src, when src is the app that
// was installed (digest) and can open the report page. It never replaces
// something at dst that is not BorderCheck's app.
func copyLauncher(src, dst, digest string) error {
	if digest == "" {
		return nil
	}
	if d, err := notifier.Digest(src); err != nil || d != digest {
		return nil // not installed, or not as installed: the hourly run puts that right first
	}
	if !plistHas(src, opensReportKey) {
		return nil
	}
	if d, err := notifier.Digest(dst); err == nil && d == digest {
		return nil
	}
	if _, err := os.Lstat(dst); err == nil && !plistHas(dst, notifier.BundleID) {
		return fmt.Errorf("%s is not BorderCheck's app; leaving it alone", dst)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	_ = os.RemoveAll(tmp)
	// ditto keeps the code signature and the notarization ticket intact.
	if out, err := exec.Command("/usr/bin/ditto", src, tmp).CombinedOutput(); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("copying the app to %s: %s", filepath.Dir(dst), bytes.TrimSpace(out))
	}
	if err := os.RemoveAll(dst); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func removeLauncher() error {
	dst, err := launcherPath()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dst); errors.Is(err, os.ErrNotExist) || !plistHas(dst, notifier.BundleID) {
		return nil
	}
	return os.RemoveAll(dst)
}

// plistHas reports whether the app's Info.plist mentions s.
func plistHas(app, s string) bool {
	data, err := notifier.ReadCapped(filepath.Join(app, "Contents", "Info.plist"), 64<<10)
	return err == nil && bytes.Contains(data, []byte(s))
}
