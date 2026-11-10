package checks

// OS gathering for os-updates, screen-lock and remote-access on Linux. Every
// source here is readable by a normal user: /etc and /var files, /proc/net,
// `apt-config dump`, `systemctl is-enabled/is-active` and `gsettings get`.
// Nothing goes online and nothing asks for a password.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

func hasFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func newestModTime(paths ...string) time.Time {
	var t time.Time
	for _, p := range paths {
		if m := fileModTime(p); m.After(t) {
			t = m
		}
	}
	return t
}

func updateFactsOS(ctx context.Context) (updateFacts, error) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		if b, err = os.ReadFile("/usr/lib/os-release"); err != nil {
			return updateFacts{}, err
		}
	}
	osr := osReleaseFields(string(b))
	f := updateFacts{Family: linuxFamily(osr), Key: osr["ID"], Version: osr["VERSION_ID"], Name: osr["PRETTY_NAME"]}
	if f.Name == "" {
		f.Name = strings.TrimSpace(osr["NAME"] + " " + f.Version)
	}
	switch f.Family {
	case "debian":
		if dump, err := sysx.Run(ctx, "apt-config", "dump"); err == nil {
			on := aptAutoUpgrade(dump) && hasFile("/usr/bin/unattended-upgrade")
			f.AutoUpdate = &on
			if !on {
				f.AutoUpdateOff = msg.Of("updates.autoOff.apt")
			}
		}
		f.LastCheck = newestModTime("/var/lib/apt/periodic/update-success-stamp", "/var/cache/apt/pkgcache.bin")
		f.LastInstall = fileModTime("/var/lib/dpkg/status")
		if b, err := os.ReadFile("/var/lib/update-notifier/updates-available"); err == nil {
			if n, ok := parseUpdatesAvailable(string(b)); ok {
				f.PendingKnown, f.PendingCount = true, n
			}
		}
		f.RebootRequired = hasFile("/var/run/reboot-required")
	case "fedora":
		// is-enabled exits non-zero unless every unit is enabled, but still prints each state.
		out, _ := sysx.Run(ctx, "systemctl", "is-enabled", "dnf-automatic.timer", "dnf-automatic-install.timer",
			"dnf5-automatic.timer", "rpm-ostreed-automatic.timer")
		on := anyEnabled(out)
		if !on {
			if gs, err := sysx.Run(ctx, "gsettings", "get", "org.gnome.software", "download-updates"); err == nil && strings.TrimSpace(gs) == "true" {
				on = true
				f.Notes = append(f.Notes, msg.P("updates.note.gnomeSoftware"))
			}
		}
		f.AutoUpdate = &on
		if !on {
			f.AutoUpdateOff = msg.Of("updates.autoOff.dnf")
		}
		f.LastInstall = newestModTime("/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages")
	case "arch":
		f.LastInstall = fileModTime("/var/lib/pacman/local")
	}
	return f, nil
}

func browsersOS(context.Context) []browserInfo {
	cands := []struct{ id, exe string }{
		{"chrome", "/opt/google/chrome/chrome"},
		{"edge", "/opt/microsoft/msedge/msedge"},
		{"brave", "/opt/brave.com/brave/brave"},
		{"firefox", "/usr/lib/firefox/firefox"},
		{"firefox", "/usr/lib64/firefox/firefox"},
		{"firefox", "/opt/firefox/firefox"},
		{"firefox", "/snap/firefox/current/usr/lib/firefox/firefox"},
		{"firefox", "/var/lib/flatpak/app/org.mozilla.firefox/current/active/files/lib/firefox/firefox"},
	}
	var out []browserInfo
	for _, c := range cands {
		if b, ok := browserAt(c.id, c.exe, ""); ok {
			out = append(out, b)
		}
	}
	return out
}

func screenLockOS(ctx context.Context) (lockFacts, error) {
	desk := strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP")) // unset when run as a service
	kde := strings.Contains(desk, "kde") ||
		desk == "" && hasFile("/usr/bin/plasmashell") && !hasFile("/usr/bin/gnome-shell")
	if kde {
		cfg := os.Getenv("XDG_CONFIG_HOME")
		if cfg == "" {
			home, _ := os.UserHomeDir()
			cfg = filepath.Join(home, ".config")
		}
		rc, _ := os.ReadFile(filepath.Join(cfg, "kscreenlockerrc")) // missing: Plasma's defaults
		return kdeLockFacts(string(rc)), nil
	}
	gnome := strings.Contains(desk, "gnome") || strings.Contains(desk, "unity") || desk == "" && hasFile("/usr/bin/gnome-shell")
	if !gnome {
		return lockFacts{}, nil
	}
	ss, err := sysx.Run(ctx, "gsettings", "list-recursively", "org.gnome.desktop.screensaver")
	if err != nil {
		return lockFacts{}, err
	}
	idle, _ := sysx.Run(ctx, "gsettings", "get", "org.gnome.desktop.session", "idle-delay")
	return gnomeLockFacts(ss, idle), nil
}

var remoteUnits = []string{"ssh.service", "sshd.service", "ssh.socket", "sshd.socket", "xrdp.service", "gnome-remote-desktop.service"}

func remoteServicesOS(ctx context.Context) ([]remoteService, msg.Text, error) {
	var ls []listener
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if b, err := os.ReadFile(p); err == nil {
			ls = append(ls, procNetListen(string(b))...)
		}
	}
	var notes msg.Text
	active := map[string]string{}
	out, _ := sysx.Run(ctx, "systemctl", append([]string{"is-active"}, remoteUnits...)...)
	if states := strings.Fields(out); len(states) == len(remoteUnits) {
		for i, u := range remoteUnits {
			active[u] = states[i]
		}
	} else {
		notes = append(notes, msg.P("remote.note.noSystemd"))
	}
	var confs []string
	for _, pat := range []string{"/usr/share/lightdm/lightdm.conf.d/*.conf", "/usr/local/share/lightdm/lightdm.conf.d/*.conf",
		"/etc/xdg/lightdm/lightdm.conf.d/*.conf", "/etc/lightdm/lightdm.conf.d/*.conf", "/etc/lightdm/lightdm.conf"} {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			if b, err := os.ReadFile(f); err == nil {
				confs = append(confs, string(b))
			}
		}
	}
	guestScript := hasFile("/usr/sbin/lightdm") && (hasFile("/usr/sbin/guest-account") || hasFile("/usr/share/lightdm/guest-session/setup.sh"))
	return linuxRemoteServices(active, ls, lightdmGuest(confs, guestScript)), notes, nil
}
