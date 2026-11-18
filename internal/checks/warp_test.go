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
			if r.Status == check.Warn && r.Fix == "" {
				t.Errorf("%s on %s: no fix", c.name, goos)
			}
		}
	}
	if r := evalWarp(warpFacts{Installed: true, Running: true}, p, "darwin"); !strings.Contains(r.Fix, "warp-cli registration new SenPrints") {
		t.Errorf("enroll fix names the team: %q", r.Fix)
	}
}
