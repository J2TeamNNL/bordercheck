package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Samples in the shape Cloudflare's documentation shows (warp-settings.txt is
// the output of `warp-cli settings`); to be checked against a real client.
const (
	warpStatusConnected    = "Status update: Connected\nNetwork: healthy\n"
	warpStatusDisconnected = "Status update: Disconnected\nReason: Manual Disconnection\n"
	warpStatusNoReg        = "Status update: Unable\nReason: Registration Missing\n"
	warpRegTeam            = "Account type: Team\nDevice ID: 0000\nPublic key: abcd\nAccount ID: 1111\nOrganization: senprints\n"
	warpRegFree            = "Account type: Free\nDevice ID: 0000\nPublic key: abcd\nAccount ID: 1111\n"
	warpSettingsPosture    = "Merged configuration:\n(derived)\tAlways On: true\n(network policy)\tSwitch Locked: false\n" +
		"(network policy)\tMode: PostureOnly\n(user set)\tOrganization: senprints\n"
	warpSettingsTraffic = "Merged configuration:\n(network policy)    Mode: WarpWithDnsOverHttps # The device's WARP mode\n" +
		"(user set)  Organization: Other-Team\n"
	warpNoDaemon = "\nwarp-cli: Error communicating with daemon: Unable to connect to the CloudflareWARP daemon"
)

// Real output of warp-cli 2026.8.2115.0 on macOS, signed in to a team and
// switched off, IDs removed.
const (
	warpRealStatus   = "Status update: Disconnected\nReason: Manual Disconnection\n"
	warpRealReg      = "Account type: Team\nID: x\nDevice ID: x\nPublic key: x\nAccount ID: x\nOrganization: senprints\n"
	warpRealSettings = "Merged configuration:\n(not set)\tCompliance Environment: Normal\n(derived)\tAlways On: false\n" +
		"(override)\tSwitch Locked: false\n(network policy)\tMode: WarpWithDnsOverHttps\n" +
		"(network policy)\tWARP tunnel protocol: WireGuard\n(not set)\tMASQUE Protocol Settings: \n" +
		"  HTTP Version: MASQUE (HTTP/3 with HTTP/2 fallback)\n(network policy)\tExclude mode, with hosts/ips:\n" +
		"  10.0.0.0/8\n(user set)\tOrganization: senprints\n(network policy)\tProfile ID: default\n"
)

func TestParseWarpReal(t *testing.T) {
	// Posture only, connected.
	posture := strings.Replace(warpRealSettings, "Mode: WarpWithDnsOverHttps", "Mode: PostureOnly", 1)
	if f := parseWarp("Status update: Connected\nNetwork: healthy\n", warpRealReg, posture); !f.Connected || f.Mode != "PostureOnly" ||
		evalWarp(f, policy.Warp{Team: "senprints", PostureOnly: true}, "darwin").Status != check.Pass {
		t.Errorf("posture only, connected: %+v", f)
	}
	// Posture only before the zone's client certificates were turned on.
	if f := parseWarp("Status update: Unable\nReason: Failed to set mTLS Identity\n", warpRealReg, warpRealSettings); f.Status != "Unable" ||
		f.Reason != "Failed to set mTLS Identity" || f.Connected {
		t.Errorf("unable: %+v", f)
	}
	f := parseWarp(warpRealStatus, warpRealReg, warpRealSettings)
	want := warpFacts{Installed: true, Running: true, Registered: true, Account: "Team", Org: "senprints",
		Status: "Disconnected", Reason: "Manual Disconnection", Mode: "WarpWithDnsOverHttps"}
	if f != want {
		t.Errorf("got %+v\nwant %+v", f, want)
	}
}

func TestParseWarp(t *testing.T) {
	f := parseWarp(warpStatusConnected, warpRegTeam, warpSettingsPosture)
	if !f.Running || !f.Registered || !f.Connected || f.Account != "Team" || f.Org != "senprints" || f.Mode != "PostureOnly" {
		t.Errorf("team, posture only: %+v", f)
	}
	f = parseWarp(warpStatusConnected, warpRegTeam, warpSettingsTraffic)
	if f.Org != "senprints" || f.Mode != "WarpWithDnsOverHttps" {
		t.Errorf("registration's organization comes first, mode without its comment: %+v", f)
	}
	f = parseWarp(warpStatusDisconnected, warpRegFree, "Merged configuration:\n(default)\tMode: WarpWithDnsOverHttps\n")
	if !f.Registered || f.Connected || f.Account != "Free" || f.Org != "" {
		t.Errorf("free, disconnected: %+v", f)
	}
	f = parseWarp(warpStatusNoReg, "Error: Missing registration. Try running: \"warp-cli registration new\"", "")
	if !f.Running || f.Registered {
		t.Errorf("no registration: %+v", f)
	}
	f = parseWarp(warpNoDaemon, warpNoDaemon, warpNoDaemon)
	if !f.Installed || f.Running {
		t.Errorf("no daemon: %+v", f)
	}
	// A client never set up for this user asks for its terms; BorderCheck never accepts them.
	f = parseWarp("Terms of Service: https://www.cloudflare.com/application/terms/\nAccept Terms of Service? [y/N]", "", "")
	if f.Registered {
		t.Errorf("terms prompt: %+v", f)
	}
}

func TestEvalWarp(t *testing.T) {
	p := policy.Warp{Team: "SenPrints", PostureOnly: true}
	ok := warpFacts{Installed: true, Running: true, Registered: true, Account: "Team", Org: "senprints",
		Connected: true, Status: "Connected", Mode: "PostureOnly"}
	cases := []struct {
		name string
		f    func(*warpFacts)
		p    func(*policy.Warp)
		st   check.Status
		sev  check.Severity
		has  string
	}{
		{"ok", nil, nil, check.Pass, "", "signed in to SenPrints and connected"},
		{"missing", func(f *warpFacts) { *f = warpFacts{} }, nil, check.Warn, check.Medium, "not installed"},
		{"no service", func(f *warpFacts) { f.Running = false }, nil, check.Warn, check.Medium, "did not answer"},
		{"not enrolled", func(f *warpFacts) { f.Registered = false }, nil, check.Warn, check.Medium, "not signed in"},
		{"consumer", func(f *warpFacts) { f.Account = "Free"; f.Org = "" }, nil, check.Warn, check.Medium, "free consumer"},
		{"other team", func(f *warpFacts) { f.Org = "acme" }, nil, check.Warn, check.Medium, "team acme, not SenPrints"},
		{"disconnected", func(f *warpFacts) { f.Connected = false; f.Status = "Disconnected" }, nil, check.Warn, check.Low, "disconnected"},
		{"cannot connect", func(f *warpFacts) { f.Connected = false; f.Status = "Unable"; f.Reason = "Failed to set mTLS Identity" }, nil,
			check.Warn, check.Low, "on but not connected (status Unable: Failed to set mTLS Identity)"},
		{"traffic mode", func(f *warpFacts) { f.Mode = "WarpWithDnsOverHttps" }, nil, check.Warn, check.Low, "WarpWithDnsOverHttps mode"},
		{"traffic mode allowed", func(f *warpFacts) { f.Mode = "WarpWithDnsOverHttps" }, func(p *policy.Warp) { p.PostureOnly = false },
			check.Pass, "", "connected"},
		{"team unknown", func(f *warpFacts) { f.Org = "" }, nil, check.Pass, "", "did not say which team"},
		{"mode unknown", func(f *warpFacts) { f.Mode = "" }, nil, check.Pass, "", "did not say which mode"},
	}
	for _, c := range cases {
		f, pp := ok, p
		if c.f != nil {
			c.f(&f)
		}
		if c.p != nil {
			c.p(&pp)
		}
		for _, goos := range []string{"darwin", "windows", "linux"} {
			r := evalWarp(f, pp, goos)
			if r.Status != c.st || r.Severity != c.sev || !strings.Contains(r.Summary, c.has) {
				t.Errorf("%s on %s: %s %s %q", c.name, goos, r.Status, r.Severity, r.Summary)
			}
			if r.Status == check.Warn && !strings.Contains(r.Fix, "docs/warp.md") {
				t.Errorf("%s on %s: the fix does not point to the guide: %q", c.name, goos, r.Fix)
			}
			if r.Status == check.Warn && r.Fix == "" {
				t.Errorf("%s on %s: no fix", c.name, goos)
			}
		}
	}
	if r := evalWarp(warpFacts{Installed: true, Running: true}, p, "darwin"); !strings.Contains(r.Fix, "warp-cli registration new SenPrints") {
		t.Errorf("enroll fix names the team: %q", r.Fix)
	}
}
