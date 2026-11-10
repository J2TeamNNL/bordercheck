package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
)

// Sample output in the shape of the real tools (Ubuntu 24.04, Fedora 41).

func TestParseSS(t *testing.T) {
	out := `State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
LISTEN 0      511                *:3000             *:*    users:(("node",pid=4242,fd=21))
LISTEN 0      4096           [::1]:631             [::]:*
LISTEN 0      128             [::]:22             [::]:*
LISTEN 0      50    [::ffff:127.0.0.1]:6463          *:*    users:(("Discord",pid=77,fd=60),("Discord",pid=77,fd=61))
LISTEN 0      4096   100.101.102.103:41641     0.0.0.0:*    users:(("tailscaled",pid=900,fd=3))
`
	ls := parseSS(out)
	want := []listener{
		{"", "127.0.0.53", "53"}, {"", "0.0.0.0", "22"}, {"node", "*", "3000"}, {"", "::1", "631"},
		{"", "::", "22"}, {"Discord", "::ffff:127.0.0.1", "6463"}, {"tailscaled", "100.101.102.103", "41641"},
	}
	if !slices.Equal(ls, want) {
		t.Fatalf("parseSS:\n got %+v\nwant %+v", ls, want)
	}
	r := evalListeners(ls, "", nil)
	wantEv := []string{
		"node: port 3000 on all interfaces",
		"tailscaled: port 41641 on 100.101.102.103",
		"unknown process: port 22 on all interfaces",
	}
	if r.Status != check.Warn || !slices.Equal(r.Evidence, wantEv) {
		t.Errorf("got %s %q, want %q", r.Status, r.Evidence, wantEv)
	}
}

func TestParseProcNetTCP(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 20494 1 0000000000000000 100 0 0 10 5
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22370 1 0000000000000000 100 0 0 10 0
   2: 0F02000A:A1B2 5DB8D822:01BB 01 00000000:00000000 02:00000A3C 00000000  1000        0 99999 2 0000000000000000 20 4 30 10 -1
`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41000 1 0000000000000000 100 0 0 10 0
`
	got := append(parseProcNetTCP(tcp), parseProcNetTCP(tcp6)...)
	want := []listener{{"", "127.0.0.53", "53"}, {"", "0.0.0.0", "22"}, {"", "::1", "631"}, {"", "::", "3000"}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestEvalLinuxFirewall(t *testing.T) {
	svc := func(active ...string) map[string]string {
		m := map[string]string{"firewalld": "inactive", "nftables": "inactive", "netfilter-persistent": "inactive", "iptables": "inactive"}
		for _, a := range active {
			m[a] = "active"
		}
		return m
	}
	ufwOn := "# /etc/ufw/ufw.conf\n#\n\n# Set to yes to start on boot.\nENABLED=yes\nLOGLEVEL=low\n"
	ufwOff := strings.Replace(ufwOn, "ENABLED=yes", "ENABLED=no", 1)
	for name, tc := range map[string]struct {
		fw   linuxFirewall
		want check.Status
		says string
	}{
		"ufw on":             {linuxFirewall{UFW: true, UFWConf: ufwOn, Services: svc()}, check.Pass, "ufw is on"},
		"ufw off":            {linuxFirewall{UFW: true, UFWConf: ufwOff, Services: svc()}, check.Fail, "ufw is installed but off"},
		"nothing":            {linuxFirewall{Services: svc()}, check.Fail, "ufw is not installed"},
		"firewalld public":   {linuxFirewall{Services: svc("firewalld"), FirewalldZone: "public"}, check.Pass, "zone public"},
		"fedora zone":        {linuxFirewall{Services: svc("firewalld"), FirewalldZone: "FedoraWorkstation"}, check.Warn, "1025 to 65535"},
		"nftables, no root":  {linuxFirewall{UFW: true, UFWConf: ufwOff, Services: svc("nftables")}, check.Skip, "only be read as root"},
		"no systemd, no ufw": {linuxFirewall{Services: map[string]string{}}, check.Skip, "Could not tell"},
		"root: ufw active":   {linuxFirewall{Root: true, UFW: true, UFWConf: ufwOff, UFWStatus: "Status: active\n", Services: svc()}, check.Pass, "ufw is on."},
		"root: nft drop": {linuxFirewall{Root: true, Services: svc("nftables"), Nft: "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t}\n}\n"},
			check.Pass, "drops incoming"},
		"root: nft accept": {linuxFirewall{Root: true, Services: svc("nftables"), Nft: "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"},
			check.Fail, "No firewall drops"},
		"root: iptables reject": {linuxFirewall{Root: true, Services: svc("iptables"),
			Iptables: "-P INPUT ACCEPT\n-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT --reject-with icmp-host-prohibited\n"},
			check.Pass, "drops incoming"},
		"root: iptables accept": {linuxFirewall{Root: true, Services: svc(), Iptables: "-P INPUT ACCEPT\n-A INPUT -p tcp -j DROP\n"}, check.Fail, "No firewall drops"},
	} {
		r := evalLinuxFirewall(tc.fw)
		if r.Status != tc.want || !strings.Contains(r.Summary, tc.says) {
			t.Errorf("%s: got %s %q, want %s containing %q", name, r.Status, r.Summary, tc.want, tc.says)
		}
	}
}

func TestParseMounts(t *testing.T) {
	mounts := `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/mapper/ubuntu--vg-ubuntu--lv / ext4 rw,relatime 0 0
/dev/nvme0n1p2 /boot ext4 rw,relatime 0 0
/dev/mapper/luks-1234 /home btrfs rw,relatime,subvol=/home 0 0
/dev/sdb1 /media/me/My\040Disk vfat rw 0 0
`
	for mp, want := range map[string][2]string{
		"/":                 {"/dev/mapper/ubuntu--vg-ubuntu--lv", "ext4"},
		"/home":             {"/dev/mapper/luks-1234", "btrfs"},
		"/media/me/My Disk": {"/dev/sdb1", "vfat"},
	} {
		src, fs, ok := parseMounts(mounts, mp)
		if !ok || src != want[0] || fs != want[1] {
			t.Errorf("parseMounts(%q) = %q %q %v", mp, src, fs, ok)
		}
	}
	if _, _, ok := parseMounts(mounts, "/var"); ok {
		t.Error("/var is not a mount")
	}
}

// fakeSysfs builds /sys/class/block for Ubuntu's default encrypted install:
// LVM (dm-1) on LUKS (dm-0) on nvme0n1p3, plus a plain partition.
func fakeSysfs(t *testing.T) string {
	t.Helper()
	sys := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(sys, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("dm-1/dm/uuid", "LVM-abcDEF\n")
	write("dm-1/slaves/dm-0/x", "") // sysfs has symlinks; a folder of the same name will do
	write("dm-0/dm/uuid", "CRYPT-LUKS2-0f1e2d3c-luks-0f1e\n")
	write("dm-0/slaves/nvme0n1p3/x", "")
	write("nvme0n1p3/partition", "3\n")
	write("nvme0n1p2/partition", "2\n")
	return sys
}

func TestBlockChain(t *testing.T) {
	sys := fakeSysfs(t)
	if got, want := blockChain(sys, "dm-1"), []string{"dm-1 lvm", "dm-0 crypt", "nvme0n1p3 part"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := blockChain(sys, "nvme0n1p2"); !slices.Equal(got, []string{"nvme0n1p2 part"}) {
		t.Errorf("plain: got %q", got)
	}
	if got := blockChain(sys, "sda9"); got != nil {
		t.Errorf("missing: got %q", got)
	}
}

func TestEvalLinuxDiskEncryption(t *testing.T) {
	luks := []string{"dm-1 lvm", "dm-0 crypt", "nvme0n1p3 part"}
	plain := []string{"nvme0n1p2 part"}
	for name, tc := range map[string]struct {
		vols []linuxVolume
		want check.Status
	}{
		"luks root":        {[]linuxVolume{{Mount: "/", FSType: "ext4", Chain: luks}}, check.Pass},
		"plain root":       {[]linuxVolume{{Mount: "/", FSType: "ext4", Chain: plain}}, check.Fail},
		"plain home":       {[]linuxVolume{{Mount: "/", FSType: "ext4", Chain: luks}, {Mount: "/home", FSType: "ext4", Chain: plain}}, check.Fail},
		"zfs encrypted":    {[]linuxVolume{{Mount: "/", FSType: "zfs", Source: "rpool/ROOT/ubuntu", ZFSEncryption: "aes-256-gcm"}}, check.Pass},
		"zfs plain":        {[]linuxVolume{{Mount: "/", FSType: "zfs", Source: "rpool/ROOT/ubuntu", ZFSEncryption: "off"}}, check.Fail},
		"container":        {[]linuxVolume{{Mount: "/", FSType: "overlay", Source: "overlay"}}, check.Skip},
		"device not found": {[]linuxVolume{{Mount: "/", FSType: "ext4", Source: "/dev/root"}}, check.Skip},
		"no mounts":        {nil, check.Skip},
	} {
		if r := evalLinuxDiskEncryption(tc.vols); r.Status != tc.want {
			t.Errorf("%s: got %s %q", name, r.Status, r.Summary)
		}
	}
}
