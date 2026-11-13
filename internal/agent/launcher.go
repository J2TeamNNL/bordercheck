package agent

// launcher puts BorderCheck where the OS's app search finds it (Spotlight and
// Launchpad on macOS, the Start menu on Windows, the application menu on
// Linux), so a person can open their report page without a terminal: the
// entry runs `bordercheck open`. ensure is called on every hourly run and
// does nothing when the entry is already as it should be, which is also how
// an install made by an older version gets one. Tests replace it so they
// never write outside their own folders.
var launcher = struct {
	ensure func(env Env, cfg Config) error
	remove func() error
}{ensureLauncher, removeLauncher}

// LauncherName is the entry's name in the OS's app search.
const LauncherName = "BorderCheck"
