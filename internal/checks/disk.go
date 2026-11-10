package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
)

// evalFileVault judges `fdesetup status`.
func evalFileVault(out string) check.Result {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("disk.mac.on"))
	case strings.Contains(out, "FileVault is Off"):
		return check.Result{Status: check.Fail, Severity: check.High}.
			WithSummary(msg.Of("disk.mac.off")).WithFix(msg.Of("disk.mac.off.fix"))
	}
	return check.Result{Status: check.Warn, Severity: check.Medium}.
		WithSummary(msg.Of("disk.mac.partial", "status", firstLine(out)))
}

// evalBitLocker judges the System.Volume.BitLockerProtection value of the system
// drive, which Windows reports without admin rights: 1 = on, 2 = off, other values
// mean in progress, suspended or locked.
func evalBitLocker(code string) check.Result {
	fix := msg.Of("disk.win.fix")
	switch code = strings.TrimSpace(code); code {
	case "1":
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("disk.win.on"))
	case "2":
		return check.Result{Status: check.Fail, Severity: check.High}.WithSummary(msg.Of("disk.win.off")).WithFix(fix)
	case "":
		return check.SkippedMsg(msg.Of("disk.win.unknown"))
	}
	return check.Result{Status: check.Warn, Severity: check.Medium}.
		WithSummary(msg.Of("disk.win.partial", "code", code)).WithFix(fix)
}

// linuxVolume is one mount and what it sits on.
type linuxVolume struct {
	Mount, Source, FSType string
	Chain                 []string // block devices from Source down, as "name kind" (see blockChain)
	ZFSEncryption         string   // `zfs get encryption` for a ZFS dataset: "off" or a cipher
}

// Filesystems that live in memory or come from the host: a live system or a container.
var virtualFS = map[string]bool{"tmpfs": true, "overlay": true, "squashfs": true, "9p": true, "virtiofs": true, "ramfs": true}

// evalLinuxDiskEncryption judges / and /home (when it is separate): each must
// sit on dm-crypt (LUKS) or be an encrypted ZFS dataset.
func evalLinuxDiskEncryption(vols []linuxVolume) check.Result {
	var plain []string
	var unknown msg.Text
	for _, v := range vols {
		switch {
		case v.FSType == "zfs" && v.ZFSEncryption == "":
			unknown = append(unknown, msg.P("disk.linux.unknownZFS", "mount", v.Mount))
		case v.FSType == "zfs" && v.ZFSEncryption == "off":
			plain = append(plain, v.Mount)
		case v.FSType == "zfs":
		case virtualFS[v.FSType]:
			unknown = append(unknown, msg.P("disk.linux.unknownVirtual", "mount", v.Mount, "fstype", v.FSType))
		case len(v.Chain) == 0:
			unknown = append(unknown, msg.P("disk.linux.unknownDevice", "mount", v.Mount, "source", v.Source))
		case !slices.ContainsFunc(v.Chain, func(d string) bool { return strings.HasSuffix(d, " crypt") }):
			plain = append(plain, v.Mount)
		}
	}
	switch {
	case len(vols) == 0:
		return check.SkippedMsg(msg.Of("disk.linux.noRoot"))
	case len(plain) > 0:
		s := msg.Of("disk.linux.plain", "mount", plain[0])
		if len(plain) > 1 {
			s = msg.Of("disk.linux.plainBoth", "mount", strings.Join(plain[:len(plain)-1], ", "), "other", plain[len(plain)-1])
		}
		return check.Result{Status: check.Fail, Severity: check.High, Evidence: chainEvidence(vols)}.
			WithSummary(s).WithFix(msg.Of("disk.linux.plain.fix"))
	case len(unknown) > 0:
		return check.SkippedMsg(append(msg.Of("disk.linux.unknown"), unknown...))
	}
	return check.Result{Status: check.Pass, Evidence: chainEvidence(vols)}.WithSummary(msg.Of(encryptedHow(vols)))
}

// encryptedHow is the message key that says how the disk is encrypted.
func encryptedHow(vols []linuxVolume) string {
	for _, v := range vols {
		if v.FSType == "zfs" {
			return "disk.linux.onZFS"
		}
	}
	return "disk.linux.onLUKS"
}

func chainEvidence(vols []linuxVolume) []string {
	var ev []string
	for _, v := range vols {
		if len(v.Chain) > 0 {
			ev = append(ev, v.Mount+": "+strings.Join(v.Chain, " ← "))
		}
	}
	return ev
}

// parseMounts finds the source and type of the filesystem mounted at mp in
// /proc/self/mounts. The last entry wins, as later mounts hide earlier ones.
func parseMounts(mounts, mp string) (source, fstype string, ok bool) {
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && unescape.Replace(f[1]) == mp {
			source, fstype, ok = unescape.Replace(f[0]), f[2], true
		}
	}
	return source, fstype, ok
}

// blockChain walks from the block device name down through what it is built
// on, using sysfs (sys is /sys/class/block), which needs no root. Each entry is
// "name kind", kind being crypt (dm-crypt, LUKS included), lvm, dm, part or disk.
func blockChain(sys, name string) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(n string)
	walk = func(n string) {
		if seen[n] || len(seen) > 32 {
			return
		}
		seen[n] = true
		kind := "disk"
		if _, err := os.Stat(filepath.Join(sys, n, "partition")); err == nil {
			kind = "part"
		}
		if uuid, err := os.ReadFile(filepath.Join(sys, n, "dm", "uuid")); err == nil {
			switch u := strings.TrimSpace(string(uuid)); {
			case strings.HasPrefix(u, "CRYPT-"):
				kind = "crypt"
			case strings.HasPrefix(u, "LVM-"):
				kind = "lvm"
			default:
				kind = "dm"
			}
		}
		out = append(out, n+" "+kind)
		slaves, _ := os.ReadDir(filepath.Join(sys, n, "slaves"))
		for _, s := range slaves {
			walk(s.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(sys, name)); err == nil {
		walk(name)
	}
	return out
}
