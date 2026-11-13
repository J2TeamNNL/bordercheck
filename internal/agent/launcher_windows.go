package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// On Windows the entry is a shortcut in the user's Start menu. It runs
// `bordercheck open` through cmd so that, when there is no report page to
// open, the reason stays on screen until a key is pressed.

func launcherPath() (string, error) {
	base := os.Getenv("APPDATA")
	if base == "" {
		return "", errors.New("APPDATA is not set")
	}
	return filepath.Join(base, "Microsoft", "Windows", "Start Menu", "Programs", LauncherName+".lnk"), nil
}

// shortcutScript reads everything from the environment: no path is ever part
// of the script's text.
const shortcutScript = `$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:BC_LNK)
$s.TargetPath = $env:ComSpec
$s.Arguments = '/c ""' + $env:BC_BIN + '" open || pause"'
$s.IconLocation = $env:BC_BIN
$s.Description = "Open this computer's report page"
$s.Save()`

func ensureLauncher(env Env, _ Config) error {
	p, err := launcherPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", shortcutScript)
	cmd.Env = append(os.Environ(), "BC_LNK="+p, "BC_BIN="+filepath.Join(env.Dir, binName()))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("creating the Start menu shortcut: %s", bytes.TrimSpace(out))
	}
	return nil
}

func removeLauncher() error {
	p, err := launcherPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
