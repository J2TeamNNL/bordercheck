package checks

// Remote-control apps of other vendors, judged in remote-access beside the
// OS's own services: TeamViewer, AnyDesk and the like. Whoever has the ID and
// password, or takes over the vendor account, controls the whole machine.
//
// What counts, per tool, from what a normal user can read without launching
// anything:
//   - installed only: not a finding (listed in the evidence);
//   - running now, or set to start by itself (a LaunchAgent/LaunchDaemon that
//     runs at load or is kept alive, a Windows service that is running or
//     starts automatically, an enabled or active systemd unit): warn, medium;
//   - unattended access on (someone can connect without anyone at the
//     computer approving), where the tool's own files say so: fail, high.
//     Only the presence of a password hash is tested, never its value.

import (
	"bufio"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/msg"
)

// rcTool says how to recognise one remote-control app. Names are matched
// case-insensitively; a trailing * in Launchd, Services and Units is a prefix.
type rcTool struct {
	ID, Name  string   // ID is its name in policy.RemoteControlTools
	Procs     []string // process names, as procName gives them (base name, no .exe)
	ProcPaths []string // parts of an executable's path, e.g. an app bundle
	Launchd   []string // launchd labels
	Services  []string // Windows service names
	Units     []string // systemd units
	// UnknownNote: unattended access exists but cannot be read reliably, so
	// a running copy gets a "could not tell" note.
	UnknownNote bool
	FixKey      string // fix key; "" = remote.fix.tool
}

// rcTools are the tools recognised. Left out because they could not be told
// apart reliably from a viewer, or their names could not be verified: Parsec,
// LogMeIn, NoMachine, Zoho Assist, GoToMyPC, Jump Desktop Connect.
var rcTools = []rcTool{
	{ID: "teamviewer", Name: "TeamViewer",
		Procs:       []string{"TeamViewer", "TeamViewer_Service", "TeamViewer_Desktop", "TeamViewerHost", "teamviewerd"},
		Launchd:     []string{"com.teamviewer.*"},
		Services:    []string{"TeamViewer"},
		Units:       []string{"teamviewerd.service"},
		UnknownNote: true},
	{ID: "anydesk", Name: "AnyDesk",
		Procs:    []string{"AnyDesk"},
		Launchd:  []string{"com.philandro.anydesk*"},
		Services: []string{"AnyDesk*"},
		Units:    []string{"anydesk.service"}},
	{ID: "rustdesk", Name: "RustDesk",
		Procs:       []string{"RustDesk"},
		Launchd:     []string{"com.carriez.*"},
		Services:    []string{"RustDesk"},
		Units:       []string{"rustdesk.service"},
		UnknownNote: true},
	// Chrome Remote Desktop's host: its LaunchAgent is installed with the host
	// but starts it only once remote access is turned on, so the switch file
	// is what counts on macOS, not the LaunchAgent.
	{ID: "chrome-remote-desktop", Name: "Chrome Remote Desktop",
		Procs:    []string{"remoting_me2me_host", "remoting_host", "chrome-remote-desktop-host"},
		Services: []string{"chromoting"},
		Units:    []string{"chrome-remote-desktop*"},
		FixKey:   "remote.fix.crd"},
	{ID: "splashtop", Name: "Splashtop Streamer",
		Procs:       []string{"SRService", "SRAgent"},
		ProcPaths:   []string{"/Splashtop Streamer.app/"},
		Services:    []string{"SplashtopRemoteService"},
		UnknownNote: true},
	{ID: "screenconnect", Name: "ConnectWise ScreenConnect",
		Procs:     []string{"ScreenConnect.ClientService", "ScreenConnect.WindowsClient"},
		ProcPaths: []string{"/connectwisecontrol-", "/screenconnect-"},
		Launchd:   []string{"screenconnect-*", "connectwisecontrol-*"},
		Services:  []string{"ScreenConnect Client*"},
		Units:     []string{"connectwisecontrol-*", "screenconnect-*"}},
	{ID: "vnc", Name: "VNC server",
		Procs: []string{"vncserver", "vncserver-x11", "vncserver-x11-serviced", "vncserver-virtuald", "Xvnc", "x0vncserver",
			"x11vnc", "Xtigervnc", "Xtightvnc", "tvnserver", "winvnc"},
		Launchd:  []string{"com.realvnc.vncserver*"},
		Services: []string{"vncserver", "tvnserver", "uvnc_service"},
		Units:    []string{"vncserver-x11-serviced.service", "vncserver-virtuald.service", "x11vnc.service", "vncserver@*"}},
}

// rcLaunchd is one LaunchAgent or LaunchDaemon: Auto when it runs at load or
// is kept alive (a helper started on demand is not).
type rcLaunchd struct {
	Label string
	Auto  bool
}

// rcRaw is what the per-OS gatherers read.
type rcRaw struct {
	Procs     []proc
	Launchd   []rcLaunchd
	Services  map[string]string // Windows: name → "Running|Automatic" (status|start type)
	Units     map[string]string // systemd: unit → "enabled", "active" or "enabled,active"
	Installed map[string]string // tool ID → where it was found
	// Unattended: tool ID → what shows unattended access is on, e.g.
	// "unattended-access password set in /etc/anydesk/system.conf".
	Unattended map[string]string
}

func nameMatch(name string, patterns []string) bool {
	n := strings.ToLower(name)
	for _, p := range patterns {
		p = strings.ToLower(p)
		if pre, ok := strings.CutSuffix(p, "*"); ok && strings.HasPrefix(n, pre) || n == p {
			return true
		}
	}
	return false
}

// remoteTools turns what was read into remote-access services, one per tool
// found, and lists the tools only installed.
func remoteTools(raw rcRaw) (svcs []remoteService, installedOnly []string, notes msg.Text) {
	for _, t := range rcTools {
		var how []string
		if slices.ContainsFunc(raw.Procs, func(p proc) bool {
			if nameMatch(procName(p.exe), t.Procs) {
				return true
			}
			exe := strings.ReplaceAll(p.exe, `\`, "/")
			return slices.ContainsFunc(t.ProcPaths, func(s string) bool { return strings.Contains(exe, s) })
		}) {
			how = append(how, "running")
		}
		for _, l := range raw.Launchd {
			if l.Auto && nameMatch(l.Label, t.Launchd) {
				how = append(how, "starts by itself ("+l.Label+")")
				break
			}
		}
		for name, st := range raw.Services {
			if !nameMatch(name, t.Services) {
				continue
			}
			status, start, _ := strings.Cut(st, "|")
			switch {
			case strings.EqualFold(status, "Running"):
				how = append(how, "service "+name+" running")
			case strings.HasPrefix(strings.ToLower(start), "automatic"):
				how = append(how, "service "+name+" starts automatically")
			}
		}
		for unit, st := range raw.Units {
			if nameMatch(unit, t.Units) {
				how = append(how, unit+" "+st)
			}
		}
		how = uniqKeepOrder(how)
		unattended := raw.Unattended[t.ID]
		where, installed := raw.Installed[t.ID]
		fix := t.FixKey
		if fix == "" {
			fix = "remote.fix.tool"
		}
		s := remoteService{ID: t.ID, Name: t.Name, Fix: msg.P(fix, "tool", t.Name)}
		switch {
		case unattended != "" && (installed || len(how) > 0):
			s.On, s.High = true, true
			s.How = strings.Join(append([]string{unattended}, how...), ", ")
			s.Text = msg.Of("remote.tool.unattended", "tool", t.Name)
		case len(how) > 0:
			s.On, s.How = true, strings.Join(how, ", ")
			s.Text = msg.Of("remote.tool.running", "tool", t.Name)
			if t.UnknownNote {
				notes = append(notes, msg.P("remote.tool.unattendedUnknown", "tool", t.Name))
			}
		case installed:
			installedOnly = append(installedOnly, fmt.Sprintf("%s: installed (%s), not running", t.Name, where))
			continue
		default:
			continue
		}
		s.Medium = !s.High
		svcs = append(svcs, s)
	}
	return svcs, installedOnly, notes
}

// anyDeskUnattended reads an AnyDesk system.conf or service.conf ("key=value"
// lines) and reports whether a permission profile has a password
// (ad.security.permission_profiles.<profile>.pwd, AnyDesk 7 and later; an
// empty one is off) or the older ad.anynet.pwd_hash is set. Values are only
// tested for being non-empty, never kept.
func anyDeskUnattended(conf string) bool {
	sc := bufio.NewScanner(strings.NewReader(conf))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "ad.anynet.pwd_hash" ||
			strings.HasPrefix(k, "ad.security.permission_profiles.") && strings.HasSuffix(k, ".pwd") {
			return true
		}
	}
	return false
}

// anyDeskUnattendedIn looks for an unattended-access password in AnyDesk's
// system.conf and service.conf in each folder, and says where it is set.
func anyDeskUnattendedIn(dirs ...string) string {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		for _, f := range []string{"system.conf", "service.conf"} {
			p := filepath.Join(d, f)
			if b, err := readCapped(p); err == nil && anyDeskUnattended(string(b)) {
				return "unattended-access password set in " + p
			}
		}
	}
	return ""
}

// installedAt returns the first path that exists, by glob.
func installedAt(globs ...string) (string, bool) {
	for _, g := range globs {
		if g == "" {
			continue
		}
		if m, _ := filepath.Glob(g); len(m) > 0 {
			return m[0], true
		}
	}
	return "", false
}

// rcInstalled maps each tool ID to the first of its paths that exists.
func rcInstalled(paths map[string][]string) map[string]string {
	out := map[string]string{}
	for id, ps := range paths {
		if p, ok := installedAt(ps...); ok {
			out[id] = p
		}
	}
	return out
}

// rcLaunchdPatterns are every tool's launchd label patterns.
func rcLaunchdPatterns() []string {
	var out []string
	for _, t := range rcTools {
		out = append(out, t.Launchd...)
	}
	return out
}

// launchdAuto reads a launchd property list (XML) and says whether it runs
// at load or is kept alive.
func launchdAuto(doc string) (label string, auto bool, ok bool) {
	d, err := plistDict(doc)
	if err != nil {
		return "", false, false
	}
	label, _ = d["Label"].(string)
	if dis, _ := d["Disabled"].(bool); dis {
		return label, false, true
	}
	run, _ := d["RunAtLoad"].(bool)
	switch k := d["KeepAlive"].(type) {
	case bool:
		run = run || k
	case map[string]any:
		run = run || len(k) > 0
	}
	return label, run, true
}

// parseServiceLines reads "name|status|start type" lines (Windows services).
func parseServiceLines(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) == 3 && f[0] != "" {
			m[f[0]] = f[1] + "|" + f[2]
		}
	}
	return m
}

// systemdUnitStates joins `systemctl list-unit-files --no-legend --plain`
// (unit, state, …) and `systemctl list-units --state=active --no-legend
// --plain` (unit, load, active, …), keeping only units some tool knows.
func systemdUnitStates(files, active string) map[string]string {
	var known []string
	for _, t := range rcTools {
		known = append(known, t.Units...)
	}
	m := map[string]string{}
	for _, line := range strings.Split(files, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "enabled" && nameMatch(f[0], known) && !strings.HasSuffix(f[0], "@.service") {
			m[f[0]] = "enabled"
		}
	}
	for _, line := range strings.Split(active, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == "active" && nameMatch(f[0], known) {
			if m[f[0]] != "" {
				m[f[0]] += ","
			}
			m[f[0]] += "active"
		}
	}
	return m
}
