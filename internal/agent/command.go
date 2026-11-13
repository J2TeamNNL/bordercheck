package agent

// command makes plain `bordercheck` work in a terminal: the install folder is
// not on PATH. ensure is called on every hourly run, like launcher.ensure, so
// an install made by an older version gets it too; what changes a person's own
// settings (a line in their shell profile, their PATH on Windows) is done once
// (State.CommandSetUp), so undoing it by hand sticks. Tests replace it.
var command = struct {
	ensure func(env Env, st *State) error
	remove func(env Env) error
}{ensureCommand, removeCommand}
