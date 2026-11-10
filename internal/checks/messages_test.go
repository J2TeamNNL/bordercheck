package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/report"
)

// sampleResults runs every check's judging on made-up inputs, on all three
// OSes, so each check has a failing and a warning (or skipped) variant. It
// reads nothing from this machine. Keyed by a made-up machine.
func sampleResults(t *testing.T) map[string][]check.Result {
	t.Helper()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	def := policy.Default().Checks
	on, off := true, false
	titles := map[string]string{}
	for _, c := range All(policy.Default()) {
		titles[c.ID] = c.Title
	}
	id := func(id string, r check.Result) check.Result { r.ID, r.Title = id, titles[id]; return r }

	mac := []check.Result{
		id("firewall", withOutbound(evalMacFirewall("Firewall is enabled. (State = 1)", "Stealth mode disabled", true), nil, outboundMac)),
		id("disk-encryption", evalFileVault("FileVault is Off.")),
		id("listeners", evalListeners([]listener{{"node", "*", "3000"}, {"postgres", "0.0.0.0", "5432"}, {"ControlCenter", "*", "7000"},
			{"rapportd", "*", "49152"}}, msg.Of("listeners.note.mac"), []policy.ListenerRule{{Process: "rapportd"}})),
		id("tailscale", evalTailscalePrefs(`{"ShieldsUp": false}`)),
		id("docker", evalDocker(`[{"Name":"/db","HostConfig":{"NetworkMode":"bridge","Privileged":true},
			"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"5432"}]}},
			"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock"}]}]`, "/Users/demo", def.Docker)),
		id("secrets", evalSecrets([]secretFinding{{path: "~/.zshrc", line: 12, kind: "OpenAI API key", name: "OPENAI_API_KEY"},
			{path: "~/work/app/.env.production", line: 3, kind: "Stripe live key", name: "STRIPE_KEY", prod: true, severe: true}},
			[]string{"~/certs/demo.p12"}, true, msg.Text{msg.P("secrets.fix.mac"), msg.P("secrets.fix.rotate")})),
		id("os-updates", evalOSUpdates(updateFacts{Family: "macos", Key: "macos", Name: "macOS 26.1", Version: "26.1",
			AutoUpdate: &off, AutoUpdateOff: msg.Of("updates.autoOff.mac", "settings", "Check for updates, Install Security Responses and system files"),
			LastCheck: now.AddDate(0, 0, -40), PendingKnown: true,
			Pending: []pendingUpdate{{Name: "macOS Tahoe 26.1.1", Since: now.AddDate(0, 0, -30)}, {Name: "Safari 26.2", Since: now.AddDate(0, 0, -2)}}},
			[]browserInfo{{ID: "chrome", Name: "Google Chrome", Version: "141.0.7390.54", Modified: now.AddDate(0, 0, -70)}},
			policy.OSUpdates{MinOSVersions: map[string]string{"macos": "26.2"}, MaxCheckAgeDays: 14, MaxPendingDays: 14, MaxBrowserAgeDays: 45}, now)),
		id("screen-lock", evalScreenLock(lockFacts{Family: "macos", PasswordOnWake: &on, LockKnown: true, LockAfter: 30 * time.Minute}, def.ScreenLock)),
		id("remote-access", evalRemoteAccess(macRemoteServices(`"com.openssh.sshd" => enabled`, "tcp4 0 0 *.5900 *.* LISTEN\n", false, "true"), nil, nil)),
		id("ssh-keys", evalSSHKeys([]sshKey{{path: "~/.ssh/id_ed25519", format: "OpenSSH", keyType: "ssh-ed25519", mode: 0o644},
			{path: "~/.ssh/id_rsa", format: "OpenSSH", keyType: "ssh-rsa", mode: 0o600}, {path: "~/.ssh/id_sk", hardware: true}},
			[]authorizedKey{{path: "~/.ssh/authorized_keys", line: 1, keyType: "ssh-ed25519", fingerprint: "SHA256:demo"}}, def.SSHKeys)),
		id("tunnels", evalTunnels([]exposure{{tool: "tailscale-funnel", what: "Tailscale Funnel: public HTTPS", port: "3000", sev: check.High, public: true},
			{tool: "ngrok", what: "ngrok tunnel", port: "8080", sev: check.Medium, public: true}}, def.Tunnels, msg.Of("tunnels.noServe"))),
		id("ai-agents", evalAIAgents([]aiFinding{{path: "~/.cursor/mcp.json", where: "mcpServers.github.env", what: "GitHub token in plain text", sev: check.Medium},
			{path: "~/.claude/settings.json", where: "permissions.defaultMode = bypassPermissions", what: "every tool runs without asking", sev: check.High}}, 4)),
		id("cracked-software", evalCracked(crackFacts{HostsPath: "/etc/hosts", Hosts: "127.0.0.1 lmlicensing.adobe.com\n0.0.0.0 genuine.autodesk.com\n"},
			def.CrackedSoftware)),
	}

	winAuto := winUpdateFacts(kvLines("build=19045\nubr=6093\ndisplay_version=22H2\nno_auto_update=1\nwuauserv_start=Disabled\n" +
		"pause_until=2026-12-01T10:00:00Z\nreboot_required=True\nlast_search=2026-08-01T07:00:00Z\nlast_hotfix=2026-07-09\n"))
	win := []check.Result{
		id("firewall", withOutbound(evalWinFirewall(map[string]bool{"Domain": true, "Private": true, "Public": true}), nil, outboundWin)),
		id("disk-encryption", evalBitLocker("3")),
		id("listeners", evalListeners([]listener{{"System", "0.0.0.0", "445"}, {"node", "::", "5173"}}, nil, nil)),
		id("tailscale", evalTailscalePrefs(`{"ShieldsUp": true}`)),
		id("docker", evalDocker(`[{"Name":"/web","HostConfig":{"NetworkMode":"bridge"},
			"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"","HostPort":"8080"}]}},"Mounts":[]}]`, `C:\Users\demo`, def.Docker)),
		id("secrets", evalSecrets([]secretFinding{{path: `~\Documents\notes.txt`, line: 4, kind: "Password in URL"}}, nil, false,
			msg.Text{msg.P("secrets.fix.win"), msg.P("secrets.fix.rotate")})),
		id("os-updates", evalOSUpdates(winAuto, nil, def.OSUpdates, now)),
		id("screen-lock", evalScreenLock(lockFacts{Family: "windows", PasswordOnWake: &off, LockKnown: true, Never: true}, def.ScreenLock)),
		id("remote-access", evalRemoteAccess(winRemoteServices(kvLines("rdp_deny=0\nlisten=3389,5985\nsshd=Stopped/Manual\nguest_disabled=False\n")), nil, []string{"winrm"})),
		id("ssh-keys", evalSSHKeys([]sshKey{{path: `~\.ssh\id_ed25519`, format: "OpenSSH", keyType: "ssh-ed25519"}}, nil, def.SSHKeys)),
		id("tunnels", evalTunnels([]exposure{{tool: "cloudflared", what: "Cloudflare quick tunnel (trycloudflare.com)", port: "3000", sev: check.Medium, public: true}},
			def.Tunnels, nil)),
		id("ai-agents", evalAIAgents([]aiFinding{{path: `~\AppData\Roaming\Code\User\mcp.json`, what: "Token in an HTTP header in plain text", sev: check.Medium}}, 2)),
		id("cracked-software", evalCracked(crackFacts{HostsPath: `C:\Windows\System32\drivers\etc\hosts`,
			KMS: map[string]string{"Windows": "127.0.0.2:1688"}, Tools: []string{`KMSpico (C:\Program Files\KMSpico)`}}, def.CrackedSoftware)),
	}

	linux := []check.Result{
		id("firewall", evalLinuxFirewall(linuxFirewall{UFW: true, UFWConf: "ENABLED=no\n",
			Services: map[string]string{"firewalld": "inactive", "nftables": "inactive", "netfilter-persistent": "inactive", "iptables": "inactive"}})),
		id("disk-encryption", evalLinuxDiskEncryption([]linuxVolume{{Mount: "/", Source: "/dev/nvme0n1p2", FSType: "ext4", Chain: []string{"nvme0n1p2 part", "nvme0n1 disk"}},
			{Mount: "/home", Source: "/dev/nvme0n1p3", FSType: "ext4", Chain: []string{"nvme0n1p3 part", "nvme0n1 disk"}}})),
		id("listeners", evalListeners([]listener{{"", "0.0.0.0", "8000"}}, msg.Of("listeners.note.linux"), nil)),
		id("tailscale", check.SkippedMsg(msg.Of("tailscale.denied", "err", "exit status 1: Access denied: prefs read access denied"))),
		id("docker", check.SkippedMsg(msg.Of("docker.noPermission"))),
		id("secrets", evalSecrets(nil, nil, false, nil)),
		id("os-updates", evalOSUpdates(updateFacts{Family: "debian", Name: "Ubuntu 24.04.1 LTS", Key: "ubuntu", Version: "24.04",
			AutoUpdate: &off, AutoUpdateOff: msg.Of("updates.autoOff.apt"), LastCheck: now.AddDate(0, 0, -1), PendingKnown: true, PendingCount: 1,
			LastInstall: now.AddDate(0, 0, -20), RebootRequired: true}, nil, def.OSUpdates, now)),
		id("screen-lock", evalScreenLock(lockFacts{Family: "gnome", PasswordOnWake: &on, LockKnown: true, LockAfter: 15 * time.Minute}, def.ScreenLock)),
		id("remote-access", evalRemoteAccess(linuxRemoteServices(map[string]string{"ssh.service": "active"}, nil, true), msg.Of("remote.note.noSystemd"), nil)),
		id("ssh-keys", evalSSHKeys(nil, nil, def.SSHKeys)),
		id("tunnels", evalTunnels(nil, def.Tunnels, nil)),
		id("ai-agents", evalAIAgents(nil, 3)),
		id("cracked-software", evalCracked(crackFacts{HostsPath: "/etc/hosts"}, def.CrackedSoftware)),
	}
	return map[string][]check.Result{"mac": mac, "windows": win, "linux": linux}
}

// TestPartsMatchText: the English summary and fix every check returns are
// exactly what their parts render to, and every part's key is in the table.
func TestPartsMatchText(t *testing.T) {
	used := map[string]bool{}
	for machine, rs := range sampleResults(t) {
		for _, r := range rs {
			if r.Summary != "" && r.SummaryParts == nil {
				t.Errorf("%s/%s: summary without parts: %q", machine, r.ID, r.Summary)
			}
			if r.Fix != "" && r.FixParts == nil {
				t.Errorf("%s/%s: fix without parts: %q", machine, r.ID, r.Fix)
			}
			if c := r.Consistent(); !reflect.DeepEqual(c, r) {
				t.Errorf("%s/%s: parts and text disagree:\n%q\n%q", machine, r.ID, r.Summary, r.SummaryParts.English())
			}
			for _, p := range append(append(msg.Text{}, r.SummaryParts...), r.FixParts...) {
				used[p.Key] = true
				if _, ok := msg.Catalog[p.Key]; !ok {
					t.Errorf("%s/%s: unknown key %s", machine, r.ID, p.Key)
				}
			}
		}
	}
	var missing []string
	for k := range msg.Catalog {
		if !used[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	t.Logf("%d of %d keys appear in the sample reports; not shown: %s", len(msg.Catalog)-len(missing), len(msg.Catalog), strings.Join(missing, " "))

	// A summary changed without its parts loses them rather than being misread.
	r := evalFileVault("FileVault is On.")
	r.Summary += " (edited)"
	if r.Consistent().SummaryParts != nil {
		t.Error("Consistent kept parts that no longer match the summary")
	}
}

// TestNoFreeText: checks set summaries and fixes only through messages, so
// none is left untranslatable by accident. (Errors from the OS stay free text.)
func TestNoFreeText(t *testing.T) {
	bad := regexp.MustCompile(`\bSummary\s*(:|\+?=)|\bFix\s*(:\s*"|\+?=)|check\.Skipped\(|\.Summary\s*\+`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if bad.MatchString(line) {
				t.Errorf("%s:%d sets text without a message: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestWriteSampleReports writes the sample results as reports when
// BORDERCHECK_SAMPLE_DIR is set, for looking at the portal with made-up data:
// BORDERCHECK_SAMPLE_DIR=/tmp/x go test ./internal/checks -run SampleReports
func TestWriteSampleReports(t *testing.T) {
	dir := os.Getenv("BORDERCHECK_SAMPLE_DIR")
	if dir == "" {
		t.Skip("BORDERCHECK_SAMPLE_DIR not set")
	}
	hosts := map[string]report.Host{
		"mac":     {OS: "darwin", Arch: "arm64", Hostname: "demo-macbook"},
		"windows": {OS: "windows", Arch: "amd64", Hostname: "DEMO-LAPTOP"},
		"linux":   {OS: "linux", Arch: "amd64", Hostname: "demo-thinkpad"},
	}
	for machine, rs := range sampleResults(t) {
		rep := report.New("0.4.0-dev", "default", rs)
		rep.Host = hosts[machine]
		rep.Time = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
		f, err := os.Create(dir + "/" + machine + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(f).Encode(rep); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
}
