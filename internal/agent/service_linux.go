package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// A systemd user timer: runs as the user, needs no root, and runs
// `bordercheck send` every hour while the user's systemd instance is up (as the
// macOS LaunchAgent runs while the user is logged in). Without a systemd user
// session (no systemd, or a login that did not start one) it falls back to the
// user's crontab.

func unitDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user"), nil
}

func systemctl(args ...string) ([]byte, error) {
	return exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
}

// hasSystemdUser reports whether this login can reach its systemd user manager.
func hasSystemdUser() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	_, err := systemctl("show-environment")
	return err == nil
}

func registerService(bin, dir string) error {
	if hasSystemdUser() {
		ud, err := unitDir()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(ud, 0o755); err != nil {
			return err
		}
		service, timer := systemdUnits(bin, dir)
		if err := os.WriteFile(filepath.Join(ud, unitName+".service"), []byte(service), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(ud, unitName+".timer"), []byte(timer), 0o644); err != nil {
			return err
		}
		if out, err := systemctl("daemon-reload"); err != nil {
			return fmt.Errorf("systemctl --user daemon-reload: %s", bytes.TrimSpace(out))
		}
		if out, err := systemctl("enable", "--now", unitName+".timer"); err != nil {
			return fmt.Errorf("systemctl --user enable --now %s.timer: %s", unitName, bytes.TrimSpace(out))
		}
		_ = setCron("") // drop a crontab line left by an earlier install without systemd
		return nil
	}
	if _, err := exec.LookPath("crontab"); err != nil {
		return errors.New("this login has no systemd user session (systemctl --user cannot reach it) and there is " +
			"no crontab command, so there is nothing to run BorderCheck every hour. Log in to a desktop session, " +
			"or install cron, and run bordercheck install again")
	}
	return setCron(cronLine(bin, time.Now().Minute()))
}

// canRegisterService checks that registerService should work: a systemd user
// session whose unit folder can be written, or a crontab command.
func canRegisterService() error {
	if hasSystemdUser() {
		ud, err := unitDir()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(ud, 0o755); err != nil {
			return err
		}
		return probeWrite(ud)
	}
	if _, err := exec.LookPath("crontab"); err != nil {
		return errors.New("this login has no systemd user session and no crontab command, so there is nothing " +
			"to run BorderCheck every hour. Log in to a desktop session, or install cron")
	}
	return nil
}

func unregisterService() error {
	var err error
	if hasSystemdUser() {
		_, _ = systemctl("disable", "--now", unitName+".timer")
	}
	if ud, e := unitDir(); e == nil {
		for _, ext := range []string{".service", ".timer"} {
			if e := os.Remove(filepath.Join(ud, unitName+ext)); e != nil && !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(err, e)
			}
		}
		if hasSystemdUser() {
			_, _ = systemctl("daemon-reload")
		}
	}
	if _, e := exec.LookPath("crontab"); e == nil {
		err = errors.Join(err, setCron(""))
	}
	return err
}

func serviceStatus() string {
	if hasSystemdUser() {
		if out, _ := systemctl("is-active", unitName+".timer"); strings.TrimSpace(string(out)) == "active" {
			return "active (systemd user timer " + unitName + ".timer, hourly)"
		}
	}
	if tab, err := readCrontab(); err == nil && strings.Contains(tab, cronMarker) {
		return "registered (crontab, hourly)"
	}
	if !hasSystemdUser() {
		return "not registered (no systemd user session in this login; checked crontab)"
	}
	return "not registered"
}

// readCrontab returns the user's crontab, "" when they have none.
func readCrontab() (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("crontab", "-l")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(strings.ToLower(stderr.String()), "no crontab") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %s", strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// setCron puts line in the user's crontab, replacing bordercheck's old line,
// or removes it when line is "". It never writes when reading failed, so an
// unreadable crontab is not replaced.
func setCron(line string) error {
	if _, err := exec.LookPath("crontab"); err != nil {
		return nil
	}
	old, err := readCrontab()
	if err != nil {
		return err
	}
	tab := withCronLine(old, line)
	if tab == old {
		return nil
	}
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(tab)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("crontab: %s", bytes.TrimSpace(out))
	}
	return nil
}
