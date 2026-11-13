//go:build !darwin && !windows && !linux

package agent

func ensureLauncher(Env, Config) error { return nil }
func removeLauncher() error            { return nil }
