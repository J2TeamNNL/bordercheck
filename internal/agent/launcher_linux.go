package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// On Linux the entry is a desktop file in the user's applications folder.

func launcherPath() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "applications", "bordercheck.desktop"), nil
}

// desktopEntry is the desktop file that runs `bin open`. In Exec, a quoted
// argument escapes " ` $ and \ with a backslash, and % is written %%.
func desktopEntry(bin string) string {
	q := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`, `%`, `%%`).Replace(bin)
	return "[Desktop Entry]\nType=Application\nName=" + LauncherName +
		"\nComment=Open this computer's report page\nExec=\"" + q + "\" open\nTerminal=false\nCategories=Utility;Security;\n"
}

func ensureLauncher(env Env, _ Config) error {
	p, err := launcherPath()
	if err != nil {
		return err
	}
	bin := filepath.Join(env.Dir, binName())
	if strings.ContainsAny(bin, "\n\r") {
		return errors.New("the install folder's name has a line break in it")
	}
	want := []byte(desktopEntry(bin))
	if have, err := os.ReadFile(p); err == nil && bytes.Equal(have, want) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return writeFile(p, want, 0o644)
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
