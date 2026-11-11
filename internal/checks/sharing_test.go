package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
)

// The cupsctl sample was captured on macOS 27; the rest are written from the
// documented formats of each file and tool.

const cupsctlSample = "_debug_logging=0\n_remote_admin=0\n_remote_any=0\n_share_printers=0\n_user_cancel_any=0\nBrowseLocalProtocols=dnssd\n"

func TestMacShareServices(t *testing.T) {
	svcs := macShareServices(map[string]string{"airdrop": "Contacts Only", "cups": cupsctlSample, "nat": "0",
		"media_home": "0", "media_public": "0", "assetcache": "false"}, `"com.apple.smbd" => disabled`, "")
	r := evalSharing(svcs, nil, nil)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "AirDrop (Everyone), File Sharing") {
		t.Errorf("all off: %s %q", r.Status, r.Summary)
	}

	on := strings.Replace(cupsctlSample, "_share_printers=0", "_share_printers=1", 1)
	svcs = macShareServices(map[string]string{"airdrop": "Everyone", "cups": on, "nat": "1", "media_public": "1",
		"bluetooth": "1", "assetcache": "true"}, `"com.apple.smbd" => enabled`, "tcp4 0 0 *.445 *.* LISTEN\n")
	got := map[string]bool{}
	for _, s := range svcs {
		got[s.ID] = s.On
	}
	for _, id := range []string{"airdrop", "file-sharing", "printer-sharing", "internet-sharing", "media-sharing", "bluetooth-sharing", "content-caching"} {
		if !got[id] {
			t.Errorf("%s not on", id)
		}
	}
	r = evalSharing(svcs, nil, nil)
	if r.Status != check.Fail || r.Severity != check.High || !strings.Contains(r.Summary, "Internet Sharing is on") {
		t.Errorf("got %s/%s %q", r.Status, r.Severity, r.Summary)
	}
	r = evalSharing(svcs, nil, []string{"internet-sharing", "airdrop", "file-sharing", "printer-sharing", "media-sharing", "bluetooth-sharing"})
	if r.Status != check.Warn || r.Severity != check.Low || !strings.Contains(r.Summary, "allowed by policy") {
		t.Errorf("allowed: %s/%s %q", r.Status, r.Severity, r.Summary)
	}
}

func TestWinShareServices(t *testing.T) {
	r := evalSharing(winShareServices(kvLines("fps_public=0\ndiscovery_public=0\nshares=\nprinters=0\nnearby=1\n")), nil, nil)
	if r.Status != check.Pass {
		t.Errorf("off: %s %q", r.Status, r.Summary)
	}
	r = evalSharing(winShareServices(kvLines("fps_public=3\ndiscovery_public=0\nshares=Projects|Scans\nprinters=1\nnearby=2\n")), nil, nil)
	if r.Status != check.Fail || r.Severity != check.High || !strings.Contains(strings.Join(r.Evidence, "\n"), "Projects, Scans") ||
		!strings.Contains(r.Summary, "Nearby sharing") {
		t.Errorf("on: %s/%s %q %v", r.Status, r.Severity, r.Summary, r.Evidence)
	}
	r = evalSharing(winShareServices(kvLines("fps_public=0\ndiscovery_public=2\nshares=Projects\n")), nil, nil)
	if r.Status != check.Warn || r.Severity != check.Medium {
		t.Errorf("private only: %s/%s %q", r.Status, r.Severity, r.Summary)
	}
}

func TestLinuxShareParsers(t *testing.T) {
	conf := `[global]
   map to guest = bad user
   guest ok = yes
[printers]
   guest ok = yes
[homes]
   guest ok = no
; [old]
;   guest ok = yes
[Public Files]
   Public = Yes
[team]
   guest  ok = yes
`
	if g := sambaGuestShares(conf); strings.Join(g, ",") != "Public Files,team" {
		t.Errorf("samba: %v", g)
	}
	exports := "# /srv *(ro)\n/srv/nfs4 192.168.1.0/24(rw,sync)\n/srv/pub *(ro,all_squash)\n/srv/all\n/srv/x host1(ro) (rw)\n"
	if g := nfsOpenExports(exports); strings.Join(g, ",") != "/srv/pub,/srv/all,/srv/x" {
		t.Errorf("exports: %v", g)
	}
	if hasExports("# nothing\n\n") || !hasExports(exports) {
		t.Error("hasExports")
	}
}

func TestLinuxShareServices(t *testing.T) {
	r := evalSharing(linuxShareServices(linuxShareFacts{Active: map[string]string{"smbd.service": "inactive"}}), nil, nil)
	if r.Status != check.Pass {
		t.Errorf("off: %s %q", r.Status, r.Summary)
	}
	f := linuxShareFacts{Active: map[string]string{"smbd.service": "active"}, SambaConf: "[pub]\nguest ok = yes\n",
		Cups: "_share_printers=1\n", GnomeShare: true}
	r = evalSharing(linuxShareServices(f), nil, nil)
	if r.Status != check.Fail || r.Severity != check.High || !strings.Contains(r.Summary, "without a password") ||
		!strings.Contains(r.Summary, "GNOME File Sharing is on") {
		t.Errorf("on: %s/%s %q", r.Status, r.Severity, r.Summary)
	}
	f = linuxShareFacts{Listeners: []listener{{"", "0.0.0.0", "2049"}}, Exports: "/srv 10.0.0.0/8(ro)\n"}
	r = evalSharing(linuxShareServices(f), nil, nil)
	if r.Status != check.Warn || r.Severity != check.Medium || !strings.Contains(r.Summary, "NFS server is on") {
		t.Errorf("nfs: %s/%s %q", r.Status, r.Severity, r.Summary)
	}
	if r = evalSharing(linuxShareServices(f), nil, []string{"nfs"}); r.Status != check.Pass {
		t.Errorf("nfs allowed: %s %q", r.Status, r.Summary)
	}
}
