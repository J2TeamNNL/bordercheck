package checks

// OS gathering for sharing on Linux: systemd unit states, /proc/net, and the
// world-readable smb.conf and /etc/exports. Nothing asks for a password.

import (
	"context"
	"os"
	"strings"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

var shareUnits = []string{"smbd.service", "smb.service", "nfs-server.service", "nfs-kernel-server.service"}

func shareServicesOS(ctx context.Context) ([]shareService, msg.Text, error) {
	f := linuxShareFacts{Active: map[string]string{}}
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if b, err := os.ReadFile(p); err == nil {
			f.Listeners = append(f.Listeners, procNetListen(string(b))...)
		}
	}
	var notes msg.Text
	out, _ := sysx.Run(ctx, "systemctl", append([]string{"is-active"}, shareUnits...)...)
	if states := strings.Fields(out); len(states) == len(shareUnits) {
		for i, u := range shareUnits {
			f.Active[u] = states[i]
		}
	} else {
		notes = append(notes, msg.P("sharing.note.noSystemd"))
	}
	if out, err := sysx.Run(ctx, "systemctl", "--user", "is-active", "gnome-user-share-webdav.service"); err == nil {
		f.GnomeShare = strings.TrimSpace(out) == "active"
	}
	if b, err := os.ReadFile("/etc/samba/smb.conf"); err == nil {
		f.SambaConf = string(b)
	}
	if b, err := os.ReadFile("/etc/exports"); err == nil {
		f.Exports = string(b)
	}
	if cupsctl, ok := sysx.Find("cupsctl", "/usr/sbin/cupsctl", "/usr/bin/cupsctl"); ok {
		f.Cups, _ = sysx.Run(ctx, cupsctl)
	}
	return linuxShareServices(f), notes, nil
}
