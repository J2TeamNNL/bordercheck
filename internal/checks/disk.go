package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
)

// evalFileVault judges `fdesetup status`.
func evalFileVault(out string) check.Result {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return check.Result{Status: check.Pass, Summary: "FileVault is on."}
	case strings.Contains(out, "FileVault is Off"):
		return check.Result{Status: check.Fail, Severity: check.High,
			Summary: "FileVault is off: anyone who takes this Mac can read its disk.",
			Fix:     "System Settings → Privacy & Security → FileVault → Turn On."}
	}
	return check.Result{Status: check.Warn, Severity: check.Medium,
		Summary: "FileVault is not fully on: " + firstLine(out)}
}

// evalBitLocker judges the System.Volume.BitLockerProtection value of the system
// drive, which Windows reports without admin rights: 1 = on, 2 = off, other values
// mean in progress, suspended or locked.
func evalBitLocker(code string) check.Result {
	fix := "Settings → Privacy & security → Device encryption, or Control Panel → BitLocker Drive Encryption → turn on."
	switch code = strings.TrimSpace(code); code {
	case "1":
		return check.Result{Status: check.Pass, Summary: "BitLocker is on for the system drive."}
	case "2":
		return check.Result{Status: check.Fail, Severity: check.High,
			Summary: "BitLocker is off: anyone who takes this PC can read its disk.", Fix: fix}
	case "":
		return check.Skipped("Windows did not report BitLocker status for the system drive.")
	}
	return check.Result{Status: check.Warn, Severity: check.Medium,
		Summary: "BitLocker is not fully on for the system drive (status " + code + ").", Fix: fix}
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
	var plain, unknown []string
	for _, v := range vols {
		switch {
		case v.FSType == "zfs" && v.ZFSEncryption == "":
			unknown = append(unknown, v.Mount+" (ZFS, encryption unknown)")
		case v.FSType == "zfs" && v.ZFSEncryption == "off":
			plain = append(plain, v.Mount)
		case v.FSType == "zfs":
		case virtualFS[v.FSType]:
			unknown = append(unknown, v.Mount+" ("+v.FSType+": a live system or container)")
		case len(v.Chain) == 0:
			unknown = append(unknown, v.Mount+" (could not find the device under "+v.Source+")")
		case !slices.ContainsFunc(v.Chain, func(d string) bool { return strings.HasSuffix(d, " crypt") }):
			plain = append(plain, v.Mount)
		}
	}
	switch {
	case len(vols) == 0:
		return check.Skipped("Could not find the root filesystem in /proc/self/mounts.")
	case len(plain) > 0:
		return check.Result{Status: check.Fail, Severity: check.High,
			Summary:  strings.Join(plain, " and ") + " is not on an encrypted disk: anyone who takes this machine can read it.",
			Evidence: chainEvidence(vols),
			Fix: "Linux cannot easily encrypt a disk in use: back up, reinstall and choose \"Encrypt the new installation\" " +
				"(LUKS), then restore. Experts: cryptsetup reencrypt --encrypt from a live USB."}
	case len(unknown) > 0:
		return check.Skipped("Could not tell whether the disk is encrypted: " + strings.Join(unknown, "; ") + ".")
	}
	return check.Result{Status: check.Pass, Summary: "The disk is encrypted (" + encryptedHow(vols) + ").",
		Evidence: chainEvidence(vols)}
}

func encryptedHow(vols []linuxVolume) string {
	for _, v := range vols {
		if v.FSType == "zfs" {
			return "ZFS native encryption"
		}
	}
	return "LUKS / dm-crypt"
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
