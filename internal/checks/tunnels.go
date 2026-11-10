package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// proc is a running process: its executable's base name and its arguments.
// Arguments can carry auth tokens, so they are only read here, never shown.
type proc struct {
	exe  string
	args []string
}

// exposure is one thing published beyond this machine.
type exposure struct {
	tool   string // a policy.TunnelTools name
	what   string // human description, never a raw argument
	port   string // local port, "" if it can't be told
	sev    check.Severity
	public bool // reachable by anyone on the internet without signing in
}

func (e exposure) String() string {
	s := e.tool + ": " + e.what
	if e.port != "" {
		s += " → local port " + e.port
	}
	return s
}

func tunnels(p policy.Tunnels) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		var found []exposure
		var notes []string
		if p.Processes {
			ps, err := listProcs(ctx)
			if err != nil {
				notes = append(notes, "Could not list processes ("+err.Error()+").")
			}
			for _, pr := range ps {
				if e, ok := classifyProc(pr); ok {
					found = append(found, e)
				}
			}
		}
		if p.TailscaleFunnel || p.TailscaleServe {
			if out, ok := tailscaleServeStatus(ctx); ok {
				es, err := parseServeStatus(out)
				if err != nil {
					notes = append(notes, "Could not read `tailscale serve status`.")
				}
				for _, e := range es {
					if (e.tool == "tailscale-funnel" && p.TailscaleFunnel) || (e.tool == "tailscale-serve" && p.TailscaleServe) {
						found = append(found, e)
					}
				}
			}
		}
		return evalTunnels(found, p, strings.Join(notes, " "))
	}
}

func tailscaleServeStatus(ctx context.Context) (string, bool) {
	var fallbacks []string
	switch runtime.GOOS {
	case "darwin":
		fallbacks = []string{"/Applications/Tailscale.app/Contents/MacOS/Tailscale"}
	case "windows":
		fallbacks = []string{`C:\Program Files\Tailscale\tailscale.exe`}
	}
	bin, ok := sysx.Find("tailscale", fallbacks...)
	if !ok {
		return "", false
	}
	// `tailscale funnel status --json` prints the same ServeConfig; one call covers both.
	out, err := sysx.Run(ctx, bin, "serve", "status", "--json")
	if err != nil {
		return "", false // not running or logged out: nothing is served
	}
	return out, true
}

// serveConfig is the part of Tailscale's ipn.ServeConfig that says what is exposed.
type serveConfig struct {
	TCP map[string]struct {
		HTTPS        bool
		HTTP         bool
		TCPForward   string
		TerminateTLS string
	}
	Web map[string]struct {
		Handlers map[string]struct {
			Proxy string
			Path  string
			Text  string
		}
	}
	AllowFunnel map[string]bool
	Foreground  map[string]serveConfig
	Services    map[string]serveConfig
}

// parseServeStatus reads `tailscale serve status --json`. A port in AllowFunnel
// is on the public internet; anything else served is on the tailnet.
func parseServeStatus(out string) ([]exposure, error) {
	out = strings.TrimSpace(out)
	if out == "" || out == "{}" || out == "null" {
		return nil, nil
	}
	var sc serveConfig
	if err := json.Unmarshal([]byte(out), &sc); err != nil {
		return nil, err
	}
	var es []exposure
	var walk func(c serveConfig)
	walk = func(c serveConfig) {
		funnel := map[string]bool{}
		for hp, on := range c.AllowFunnel {
			if on {
				_, port, _ := net.SplitHostPort(hp)
				funnel[port] = true
			}
		}
		add := func(tsPort, target string) {
			e := exposure{tool: "tailscale-serve", what: "shared on the tailnet on port " + tsPort, port: target, sev: check.Medium}
			if funnel[tsPort] {
				e = exposure{tool: "tailscale-funnel", what: "public on the internet on port " + tsPort, port: target,
					sev: check.High, public: true}
			}
			if target == "folder" {
				e.what, e.port = e.what+" (files from a folder)", ""
			}
			es = append(es, e)
		}
		for hp, w := range c.Web {
			_, tsPort, _ := net.SplitHostPort(hp)
			for _, h := range w.Handlers {
				switch {
				case h.Proxy != "":
					add(tsPort, proxyPort(h.Proxy))
				case h.Path != "":
					add(tsPort, "folder")
				default:
					add(tsPort, "")
				}
			}
		}
		for port, t := range c.TCP {
			if t.TCPForward != "" {
				add(port, proxyPort(t.TCPForward))
			}
		}
		for _, f := range c.Foreground {
			walk(f)
		}
		for _, f := range c.Services {
			walk(f)
		}
	}
	walk(sc)
	return es, nil
}

// proxyPort returns the port of a proxy target: "3000", "http://127.0.0.1:3000", "localhost:3000".
func proxyPort(t string) string {
	if _, err := strconv.Atoi(t); err == nil {
		return t
	}
	if u, err := url.Parse(t); err == nil && u.Port() != "" {
		return u.Port()
	}
	if _, port, err := net.SplitHostPort(t); err == nil {
		return port
	}
	return ""
}

var (
	interpreters = map[string]bool{"node": true, "python": true, "python3": true, "bun": true, "deno": true}
	launchers    = map[string]bool{"npx": true, "npm": true, "exec": true, "pnpm": true, "dlx": true, "yarn": true,
		"bunx": true, "run": true, "-y": true, "--yes": true}
	// Public SSH relays that turn `ssh -R` into a public URL.
	sshRelays = []string{"serveo.net", "localhost.run", "pinggy.io", "srv.us"}
)

// procName is the base name of an executable, lower case, without .exe.
func procName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	return strings.TrimSuffix(strings.ToLower(path.Base(p)), ".exe")
}

// classifyProc says whether a process publishes something, and what.
func classifyProc(p proc) (exposure, bool) {
	name, args := procName(p.exe), p.args
	if interpreters[name] { // node /usr/local/bin/lt --port 3000, npx localtunnel …
		for len(args) > 0 && (strings.HasPrefix(args[0], "-") || launchers[procName(args[0])]) {
			args = args[1:]
		}
		if len(args) == 0 {
			return exposure{}, false
		}
		name, args = strings.TrimSuffix(procName(args[0]), ".js"), args[1:]
	}
	sub := firstPositional(args)
	switch name {
	case "ngrok":
		switch sub {
		case "http", "tcp", "tls", "start", "service", "":
			port := ""
			if sub == "http" || sub == "tcp" || sub == "tls" {
				port = portAfter(args, sub)
			}
			return exposure{tool: "ngrok", what: "public ngrok tunnel", port: port, sev: check.High, public: true}, true
		}
	case "cloudflared":
		switch sub {
		case "access", "proxy-dns", "update", "login", "version", "help", "tail", "service":
			return exposure{}, false
		}
		if v := flagValue(args, "--url"); v != "" && !hasArg(args, "run") && flagValue(args, "--token") == "" {
			return exposure{tool: "cloudflared", what: "Cloudflare quick tunnel (public trycloudflare.com URL, no access control)",
				port: targetPort(v), sev: check.High, public: true}, true
		}
		return exposure{tool: "cloudflared", what: "Cloudflare named tunnel", port: targetPort(flagValue(args, "--url")),
			sev: check.High}, true
	case "lt", "localtunnel":
		return exposure{tool: "localtunnel", what: "public localtunnel URL", port: targetPort(flagValue(args, "--port", "-p")),
			sev: check.High, public: true}, true
	case "bore":
		if sub == "local" {
			return exposure{tool: "bore", what: "public bore tunnel", port: targetPort(positionalAfter(args, "local")),
				sev: check.High, public: true}, true
		}
	case "frpc":
		return exposure{tool: "frp", what: "frp client (ports are in its config file)", sev: check.High, public: true}, true
	case "zrok":
		if sub == "share" {
			mode := positionalAfter(args, "share")
			target := portAfter(args, mode)
			if mode == "public" {
				return exposure{tool: "zrok", what: "public zrok share", port: target, sev: check.High, public: true}, true
			}
			return exposure{tool: "zrok", what: "zrok " + safeWord(mode) + " share", port: target, sev: check.Medium}, true
		}
	case "code", "code-insiders", "code-tunnel", "code-tunnel-insiders":
		if sub == "tunnel" {
			switch positionalAfter(args, "tunnel") {
			case "status", "kill", "rename", "unregister", "user", "prune", "restart", "help":
			default:
				return exposure{tool: "vscode-tunnel", what: "VS Code Remote Tunnel (this machine reachable from vscode.dev, " +
					"plus any ports forwarded through it)", sev: check.Medium}, true
			}
		}
	case "devtunnel":
		if sub == "host" {
			e := exposure{tool: "devtunnel", what: "Microsoft dev tunnel", port: targetPort(flagValue(args, "-p", "--port-numbers")),
				sev: check.Medium}
			if hasArg(args, "--allow-anonymous") || hasArg(args, "-a") {
				e.what, e.sev, e.public = "Microsoft dev tunnel open to anyone (--allow-anonymous)", check.High, true
			}
			return e, true
		}
	case "ssh", "autossh":
		if spec, ok := sshRemoteForward(args); ok {
			e := exposure{tool: "ssh", what: "ssh -R reverse forward to a remote server", port: spec, sev: check.Medium}
			if spec == "SOCKS" {
				e.what, e.port = "ssh -R reverse SOCKS proxy: the remote server can reach this machine's network", ""
			}
			for _, a := range args {
				for _, relay := range sshRelays {
					if strings.Contains(strings.ToLower(a), relay) {
						e.what, e.sev, e.public = "ssh -R to a public tunnel service", check.High, true
					}
				}
			}
			return e, true
		}
	}
	return exposure{}, false
}

// safeWord returns s when it is a plain word, so no argument that could be a token is ever shown.
func safeWord(s string) string {
	switch s {
	case "private", "reserved", "public":
		return s
	}
	return ""
}

func firstPositional(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return a
		}
		if !strings.Contains(a, "=") && flagTakesValue(a) && i+1 < len(args) {
			i++
		}
	}
	return ""
}

// flagTakesValue lists global flags of the tools above that take a separate value,
// so their value isn't mistaken for a subcommand.
func flagTakesValue(f string) bool {
	switch f {
	case "--config", "--loglevel", "--log", "--logfile", "--log-level", "--origincert", "--metrics", "--cli-data-dir",
		"--user-data-dir", "--extensions-dir":
		return true
	}
	return false
}

func positionalAfter(args []string, word string) string {
	i := slices.Index(args, word)
	if i < 0 {
		return ""
	}
	for _, a := range args[i+1:] {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// portAfter returns the first port among the positional arguments after word,
// skipping values like a domain that hold no port.
func portAfter(args []string, word string) string {
	i := slices.Index(args, word)
	if i < 0 {
		return ""
	}
	for _, a := range args[i+1:] {
		if p := targetPort(a); p != "" && !strings.HasPrefix(a, "-") {
			return p
		}
	}
	return ""
}

func hasArg(args []string, a string) bool { return slices.Contains(args, a) }

// flagValue returns the value of the first of names found, as --name value or --name=value.
func flagValue(args []string, names ...string) string {
	for i, a := range args {
		for _, n := range names {
			if a == n && i+1 < len(args) {
				return args[i+1]
			}
			if v, ok := strings.CutPrefix(a, n+"="); ok {
				return v
			}
		}
	}
	return ""
}

// targetPort reduces a target ("3000", "localhost:8080", "http://127.0.0.1:5173") to its port,
// so no hostname or credential from the command line is shown.
func targetPort(t string) string {
	if t == "" {
		return ""
	}
	if p := proxyPort(t); p != "" {
		if _, err := strconv.Atoi(p); err == nil {
			return p
		}
	}
	if u, err := url.Parse(t); err == nil && u.Scheme != "" {
		switch u.Scheme {
		case "http":
			return "80"
		case "https":
			return "443"
		}
	}
	return ""
}

// sshRemoteForward finds -R in ssh's arguments (alone, combined like -fNR, or
// -o RemoteForward=) and returns the local port it exposes.
func sshRemoteForward(args []string) (string, bool) {
	for i, a := range args {
		var spec string
		switch {
		case strings.HasPrefix(a, "-o") && strings.Contains(strings.ToLower(a+" "+next(args, i)), "remoteforward"):
			v := a[2:]
			if v == "" {
				v = next(args, i)
			}
			_, spec, _ = strings.Cut(v, "=")
			if spec == "" {
				f := strings.Fields(v)
				if len(f) > 1 {
					spec = strings.Join(f[1:], " ")
				}
			}
			return sshForwardPort(spec), true
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "R"):
			// -R must be the last of combined flags when its value follows, e.g. -fNR 8080:localhost:3000
			j := strings.IndexByte(a, 'R')
			if strings.ContainsAny(a[1:j], "bcDEeFIiJLlmOopQSWw") { // R is inside another flag's value
				continue
			}
			spec = a[j+1:]
			if spec == "" {
				spec = next(args, i)
			}
			return sshForwardPort(spec), true
		}
	}
	return "", false
}

func next(args []string, i int) string {
	if i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

// sshForwardPort reads [bind:]port:host:hostport (or a bare port: a reverse SOCKS proxy).
func sshForwardPort(spec string) string {
	f := strings.Split(strings.Fields(spec + " ")[0], ":")
	switch {
	case len(f) >= 3:
		return targetPort(f[len(f)-1])
	case len(f) == 1 && targetPort(f[0]) != "":
		return "SOCKS"
	}
	return ""
}

func evalTunnels(found []exposure, p policy.Tunnels, note string) check.Result {
	var shown []exposure
	allowed := 0
	for _, e := range found {
		if slices.Contains(p.Allow, e.tool) {
			allowed++
			continue
		}
		if slices.Contains(p.LowerSeverity, e.tool) {
			e.sev = check.Low
			if e.public {
				e.sev = check.Medium
			}
		}
		shown = append(shown, e)
	}
	rank := map[check.Severity]int{check.High: 0, check.Medium: 1, check.Low: 2}
	sort.SliceStable(shown, func(i, j int) bool { return rank[shown[i].sev] < rank[shown[j].sev] })
	var ev []string
	worst := check.Low
	for _, e := range shown {
		ev = append(ev, e.String()+"  ["+string(e.sev)+"]")
		if rank[e.sev] < rank[worst] {
			worst = e.sev
		}
	}
	ev = uniqKeepOrder(ev)
	if allowed > 0 {
		note = strings.TrimSpace(fmt.Sprintf("%d more allowed by policy. %s", allowed, note))
	}
	if note != "" {
		note = " " + note
	}
	if len(ev) == 0 {
		return check.Result{Status: check.Pass, Summary: "No tunnels publish this machine to the internet or the tailnet." + note}
	}
	r := check.Result{Status: check.Warn, Severity: worst, Evidence: ev,
		Summary: fmt.Sprintf("%d tunnel(s) publish this machine beyond the local network.%s", len(ev), note),
		Fix: "Stop tunnels you aren't using (tailscale funnel reset, tailscale serve reset; quit ngrok, ssh -R…). " +
			"If you must share something, use a named Cloudflare Tunnel behind Cloudflare Access, not a public URL."}
	if worst == check.High {
		r.Status = check.Fail
	}
	return r
}

func uniqKeepOrder(ss []string) []string {
	seen := map[string]bool{}
	out := ss[:0]
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
