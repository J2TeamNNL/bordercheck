//go:build !darwin && !windows && !linux

package agent

func ensureCommand(Env, *State) error { return nil }
func removeCommand(Env) error         { return nil }
