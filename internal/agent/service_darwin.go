package agent

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// A per-user LaunchAgent: runs as the user (so it sees their home folder and
// processes), needs no admin rights, and runs `bordercheck send` every hour.
const label = "io.github.ptrinh.bordercheck"

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), err
}

func domain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

func registerService(bin, dir string) error {
	path, err := plistPath()
	if err != nil {
		return err
	}
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key><array><string>%s</string><string>send</string></array>
	<key>StartInterval</key><integer>3600</integer>
	<key>ProcessType</key><string>Background</string>
	<key>LowPriorityIO</key><true/>
	<key>Nice</key><integer>10</integer>
	<key>WorkingDirectory</key><string>%s</string>
</dict>
</plist>
`, label, esc(bin), esc(dir))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", domain()+"/"+label).Run() // a reinstall replaces the old one
	if out, err := exec.Command("launchctl", "bootstrap", domain(), path).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %s", bytes.TrimSpace(out))
	}
	return nil
}

// canRegisterService checks, without changing anything launchd sees, that
// registerService should work: launchctl is there and the LaunchAgents folder
// can be written.
func canRegisterService() error {
	if _, err := exec.LookPath("launchctl"); err != nil {
		return err
	}
	path, err := plistPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return probeWrite(filepath.Dir(path))
}

func unregisterService() error {
	_ = exec.Command("launchctl", "bootout", domain()+"/"+label).Run()
	path, err := plistPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func serviceStatus() string {
	if exec.Command("launchctl", "print", domain()+"/"+label).Run() != nil {
		return "not loaded"
	}
	return "loaded (launchd " + label + ", hourly)"
}
