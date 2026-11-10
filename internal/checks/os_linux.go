package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// Without root, Linux shows the firewall's configuration and which services
// load it, but not the live rules. As root, the rules themselves are read.
func firewall(ctx context.Context, _ bool) check.Result {
	fw := linuxFirewall{Root: os.Geteuid() == 0, Services: map[string]string{}}
	if ufw, ok := sysx.Find("ufw", "/usr/sbin/ufw", "/sbin/ufw"); ok {
		fw.UFW = true
		if data, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil {
			fw.UFWConf = string(data)
		}
		if fw.Root {
			fw.UFWStatus, _ = sysx.Run(ctx, ufw, "status")
		}
	}
	if systemctl, ok := sysx.Find("systemctl", "/usr/bin/systemctl", "/bin/systemctl"); ok {
		for _, unit := range linuxFirewallServices {
			// is-active exits non-zero for anything but "active"; its output still says which.
			out, _ := sysx.Run(ctx, systemctl, "is-active", unit)
			fw.Services[unit] = strings.TrimSpace(out)
		}
	}
	if fw.Services["firewalld"] == "active" {
		if cmd, ok := sysx.Find("firewall-cmd", "/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd"); ok {
			out, _ := sysx.Run(ctx, cmd, "--get-default-zone")
			fw.FirewalldZone = strings.TrimSpace(out)
		}
	}
	if fw.Root {
		if nft, ok := sysx.Find("nft", "/usr/sbin/nft", "/sbin/nft"); ok {
			fw.Nft, _ = sysx.Run(ctx, nft, "list", "ruleset")
		}
		if ipt, ok := sysx.Find("iptables", "/usr/sbin/iptables", "/sbin/iptables"); ok {
			fw.Iptables, _ = sysx.Run(ctx, ipt, "-S", "INPUT")
		}
	}
	return evalLinuxFirewall(fw)
}

// diskEncryption follows / (and /home when it is a separate mount) down to
// its block devices in sysfs, which needs no root, looking for dm-crypt.
func diskEncryption(ctx context.Context) check.Result {
	mounts, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return check.Errored(err)
	}
	var vols []linuxVolume
	for _, mp := range []string{"/", "/home"} {
		src, fstype, ok := parseMounts(string(mounts), mp)
		if !ok {
			continue // /home is usually not a separate mount
		}
		v := linuxVolume{Mount: mp, Source: src, FSType: fstype}
		switch {
		case fstype == "zfs":
			if zfs, ok := sysx.Find("zfs", "/usr/sbin/zfs", "/sbin/zfs"); ok {
				out, _ := sysx.Run(ctx, zfs, "get", "-H", "-o", "value", "encryption", src)
				v.ZFSEncryption = strings.TrimSpace(out)
			}
		case strings.HasPrefix(src, "/dev/"):
			if dev, err := filepath.EvalSymlinks(src); err == nil {
				v.Chain = blockChain("/sys/class/block", filepath.Base(dev))
			}
		}
		vols = append(vols, v)
	}
	return evalLinuxDiskEncryption(vols)
}

func listListeners(ctx context.Context) ([]listener, msg.Text, error) {
	if ss, ok := sysx.Find("ss", "/usr/sbin/ss", "/usr/bin/ss", "/sbin/ss", "/bin/ss"); ok {
		var note msg.Text
		if os.Geteuid() != 0 {
			note = msg.Of("listeners.note.linux")
		}
		out, err := sysx.Run(ctx, ss, "-l", "-t", "-n", "-p")
		if err == nil {
			return parseSS(out), note, nil
		}
	}
	// No ss (or it failed): the kernel's own table has the sockets, without process names.
	var ls []listener
	var lastErr error
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			lastErr = err
			continue
		}
		ls = append(ls, parseProcNetTCP(string(data))...)
	}
	if ls == nil && lastErr != nil {
		return nil, nil, lastErr
	}
	return ls, msg.Of("listeners.note.linuxNoSS"), nil
}
