package notify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// Linux: the freedesktop notification service on the user's session bus, which
// every desktop (GNOME, KDE, Xfce, …) runs. notify-send (libnotify) if it is
// installed, else gdbus (GLib, on nearly every desktop install). The text goes
// in as arguments, never through a shell.
//
// A systemd user service usually has DBUS_SESSION_BUS_ADDRESS; when it does
// not, the bus is at the standard per-user socket.
func show(ctx context.Context, m Message) error {
	var env []string
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		sock := fmt.Sprintf("/run/user/%d/bus", os.Getuid())
		if _, err := os.Stat(sock); err != nil {
			return errors.New("no desktop session bus to show a notification on")
		}
		env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+sock)
	}
	if p, err := exec.LookPath("notify-send"); err == nil {
		return run(ctx, env, p, "--app-name=bordercheck", "--urgency=normal", "--", m.Title, m.Body)
	}
	if p, err := exec.LookPath("gdbus"); err == nil {
		return run(ctx, env, p, "call", "--session",
			"--dest", "org.freedesktop.Notifications",
			"--object-path", "/org/freedesktop/Notifications",
			"--method", "org.freedesktop.Notifications.Notify",
			gvariantString("bordercheck"), "uint32 0", gvariantString(""),
			gvariantString(m.Title), gvariantString(m.Body),
			"@as []", "@a{sv} {}", "int32 -1")
	}
	return errors.New("neither notify-send nor gdbus is installed")
}
