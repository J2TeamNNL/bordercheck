package agent

import (
	"bytes"
	"fmt"
	"os/exec"
)

// A per-user scheduled task: runs as the user while they are logged on, needs
// no admin rights, and runs `bordercheck send` every hour.
const taskName = "bordercheck"

func registerService(bin, _ string) error {
	out, err := exec.Command("schtasks", "/Create", "/F", "/TN", taskName,
		"/SC", "HOURLY", "/MO", "1", "/TR", fmt.Sprintf(`"%s" send`, bin)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /Create: %s", bytes.TrimSpace(out))
	}
	return nil
}

func unregisterService() error {
	if out, err := exec.Command("schtasks", "/Delete", "/F", "/TN", taskName).CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks /Delete: %s", bytes.TrimSpace(out))
	}
	return nil
}

func serviceStatus() string {
	if exec.Command("schtasks", "/Query", "/TN", taskName).Run() != nil {
		return "not registered"
	}
	return "registered (Task Scheduler \"" + taskName + "\", hourly)"
}
