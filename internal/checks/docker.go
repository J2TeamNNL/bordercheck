package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// The docker check looks at the containers of every local engine: each local
// context of the docker CLI (Docker Desktop, OrbStack, Colima, Rancher
// Desktop…, each named by its socket) and Podman through its own CLI.

// containerEngine is one place containers run, and how to ask it.
type containerEngine struct {
	Name    string   // as people know it: "OrbStack", "Docker Desktop", "Podman"…
	Cli     string   // docker or podman
	Args    []string // before the command: --context <name>
	Current bool     // the docker CLI's current context
}

// cliPaths are where the docker and podman CLIs live when the hourly service's
// PATH does not have them (it has only the system folders).
func cliPaths(goos, home, name string) []string {
	switch goos {
	case "darwin":
		out := []string{"/usr/local/bin/" + name, "/opt/homebrew/bin/" + name}
		if name == "docker" {
			out = append(out, filepath.Join(home, ".orbstack/bin/docker"), filepath.Join(home, ".rd/bin/docker"),
				filepath.Join(home, ".docker/bin/docker"), "/Applications/Docker.app/Contents/Resources/bin/docker",
				"/Applications/OrbStack.app/Contents/MacOS/xbin/docker")
		} else {
			out = append(out, "/opt/podman/bin/podman")
		}
		return out
	case "windows":
		if name == "docker" {
			return []string{`C:\Program Files\Docker\Docker\resources\bin\docker.exe`,
				filepath.Join(home, `AppData\Local\Programs\Rancher Desktop\resources\resources\win32\bin\docker.exe`),
				`C:\Program Files\Rancher Desktop\resources\resources\win32\bin\docker.exe`}
		}
		return []string{`C:\Program Files\RedHat\Podman\podman.exe`}
	default:
		out := []string{"/usr/bin/" + name, "/usr/local/bin/" + name}
		if name == "docker" {
			out = append(out, "/snap/bin/docker", filepath.Join(home, ".rd/bin/docker"))
		}
		return out
	}
}

// engineName names an engine by its context and the socket it talks to.
func engineName(ctxName, endpoint string) string {
	e := strings.ToLower(endpoint)
	switch {
	case strings.Contains(e, ".orbstack"):
		return "OrbStack"
	case strings.Contains(e, ".colima"):
		return "Colima"
	case strings.Contains(e, "/.rd/") || strings.Contains(e, "rancher-desktop") || strings.Contains(e, "rancher_desktop"):
		return "Rancher Desktop"
	case strings.Contains(e, "podman"):
		return "Podman"
	case strings.Contains(e, "/.lima/"):
		return "Lima"
	case ctxName == "desktop-linux" || ctxName == "desktop-windows" || strings.Contains(e, ".docker/run/docker.sock") ||
		strings.Contains(e, "docker_engine") || strings.Contains(e, "dockerdesktop"):
		return "Docker Desktop"
	case ctxName == "default" || ctxName == "":
		return "Docker"
	}
	return "Docker (" + ctxName + ")"
}

type dockerContext struct {
	Name           string
	DockerEndpoint string
	Current        bool
}

// parseDockerContexts reads `docker context ls --format '{{json .}}'`: one JSON
// object a line (Current is a bool in newer CLIs, a string in some older ones).
func parseDockerContexts(out string) []dockerContext {
	var cs []dockerContext
	for _, line := range strings.Split(out, "\n") {
		var raw map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &raw) != nil {
			continue
		}
		c := dockerContext{}
		c.Name, _ = raw["Name"].(string)
		c.DockerEndpoint, _ = raw["DockerEndpoint"].(string)
		switch v := raw["Current"].(type) {
		case bool:
			c.Current = v
		case string:
			c.Current = v == "true" || v == "*"
		}
		if c.Name != "" {
			cs = append(cs, c)
		}
	}
	return cs
}

// localEngines picks the contexts to ask: local ones (unix socket or Windows
// named pipe), one per socket, and of those whose socket file is missing only
// the current one (to say it is not running). exists is os.Stat in the check.
func localEngines(cli string, cs []dockerContext, exists func(string) (string, bool)) []containerEngine {
	var out []containerEngine
	seen := map[string]bool{}
	for _, c := range cs {
		ep := c.DockerEndpoint
		key := ep
		switch {
		case strings.HasPrefix(ep, "unix://"):
			sock := strings.TrimPrefix(ep, "unix://")
			real, ok := exists(sock)
			if !ok && !c.Current {
				continue
			}
			if ok {
				key = real
			}
			name := engineName(c.Name, real)
			if name == "Docker" || name == "Docker ("+c.Name+")" {
				name = engineName(c.Name, ep)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, containerEngine{Name: name, Cli: cli, Args: []string{"--context", c.Name}, Current: c.Current})
		case strings.HasPrefix(ep, "npipe://"):
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, containerEngine{Name: engineName(c.Name, ep), Cli: cli, Args: []string{"--context", c.Name}, Current: c.Current})
		}
	}
	return out
}

// engineResult is what one engine answered.
type engineResult struct {
	Engine  string
	Running bool
	Denied  bool   // Linux: this user may not use the socket
	Inspect string // `inspect` of its running containers; "" with none
	Err     error  // inspect failed
}

func docker(ctx context.Context, opts policy.Docker) check.Result {
	home, _ := os.UserHomeDir()
	var engines []containerEngine
	dockerCli, haveDocker := sysx.Find("docker", cliPaths(runtime.GOOS, home, "docker")...)
	podmanSeen := false
	if haveDocker {
		out, err := sysx.Run(ctx, dockerCli, "context", "ls", "--format", "{{json .}}")
		if err == nil {
			engines = localEngines(dockerCli, parseDockerContexts(out), func(sock string) (string, bool) {
				if _, err := os.Stat(sock); err != nil {
					return "", false
				}
				if real, err := filepath.EvalSymlinks(sock); err == nil {
					return real, true
				}
				return sock, true
			})
		}
		if len(engines) == 0 { // an old CLI without contexts: its default
			engines = []containerEngine{{Name: "Docker", Cli: dockerCli, Current: true}}
		}
		for _, e := range engines {
			podmanSeen = podmanSeen || e.Name == "Podman"
		}
	}
	if podman, ok := sysx.Find("podman", cliPaths(runtime.GOOS, home, "podman")...); ok && !podmanSeen {
		engines = append(engines, containerEngine{Name: "Podman", Cli: podman})
	}
	if len(engines) == 0 {
		return check.SkippedMsg(msg.Of("docker.notInstalled"))
	}
	var results []engineResult
	for _, e := range engines {
		r := engineResult{Engine: e.Name}
		ids, err := sysx.Run(ctx, e.Cli, append(slices.Clone(e.Args), "ps", "-q")...)
		switch {
		case err != nil && strings.Contains(strings.ToLower(err.Error()), "permission denied"):
			r.Denied = true // Linux: the socket belongs to root and the docker group
		case err != nil:
		default:
			r.Running = true
			if f := strings.Fields(ids); len(f) > 0 {
				r.Inspect, r.Err = sysx.Run(ctx, e.Cli, append(append(slices.Clone(e.Args), "inspect"), f...)...)
			}
		}
		results = append(results, r)
	}
	return evalEngines(results, home, opts)
}

// evalEngines judges what every engine answered.
func evalEngines(rs []engineResult, home string, opts policy.Docker) check.Result {
	var running, stopped, denied []string
	var all []namedContainer
	for _, r := range rs {
		switch {
		case r.Denied:
			denied = append(denied, r.Engine)
		case !r.Running:
			stopped = append(stopped, r.Engine)
		case r.Err != nil:
			return check.Errored(fmt.Errorf("%s: %w", r.Engine, r.Err))
		default:
			running = append(running, r.Engine)
			if r.Inspect == "" {
				continue
			}
			var cs []dockerContainer
			if err := json.Unmarshal([]byte(r.Inspect), &cs); err != nil {
				return check.Errored(fmt.Errorf("reading %s inspect: %w", r.Engine, err))
			}
			for _, c := range cs {
				all = append(all, namedContainer{Engine: r.Engine, dockerContainer: c})
			}
		}
	}
	if len(running) == 0 {
		if len(denied) > 0 && len(stopped) == 0 {
			return check.SkippedMsg(msg.Of("docker.noPermission"))
		}
		if len(stopped) == 1 && stopped[0] == "Docker" {
			return check.SkippedMsg(msg.Of("docker.notRunning"))
		}
		return check.SkippedMsg(msg.Of("docker.notRunningEngines", "engines", strings.Join(stopped, ", ")))
	}
	r := judgeContainers(all, len(running) > 1, home, opts)
	notes := msg.Text{}
	if len(running) > 1 || running[0] != "Docker" {
		notes = append(notes, msg.P("docker.checked", "engines", strings.Join(running, ", ")))
	}
	if len(stopped) > 0 {
		notes = append(notes, msg.P("docker.alsoStopped", "engines", strings.Join(stopped, ", ")))
	}
	if len(notes) > 0 {
		r = r.WithSummary(append(slices.Clone(r.SummaryParts), notes...))
	}
	return r
}

type namedContainer struct {
	Engine string
	dockerContainer
}

type dockerContainer struct {
	Name       string
	HostConfig struct {
		NetworkMode string
		Privileged  bool
	}
	NetworkSettings struct {
		Ports map[string][]struct{ HostIp, HostPort string }
	}
	Mounts []struct{ Type, Source string }
}

// evalDocker judges `docker inspect` output for one engine's running containers.
func evalDocker(out, home string, opts policy.Docker) check.Result {
	var cs []dockerContainer
	if err := json.Unmarshal([]byte(out), &cs); err != nil {
		return check.Errored(fmt.Errorf("reading docker inspect: %w", err))
	}
	all := make([]namedContainer, len(cs))
	for i, c := range cs {
		all[i] = namedContainer{Engine: "Docker", dockerContainer: c}
	}
	return judgeContainers(all, false, home, opts)
}

// judgeContainers judges the running containers of every engine; with several
// engines, evidence names each container's engine.
func judgeContainers(cs []namedContainer, several bool, home string, opts policy.Docker) check.Result {
	if len(cs) == 0 {
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("docker.noContainers"))
	}
	var high, medium []string
	allowedMounts := make([]string, len(opts.AllowMounts))
	for i, m := range opts.AllowMounts {
		allowedMounts[i] = normPath(expandHome(m, home))
	}
	for _, c := range cs {
		name := strings.TrimPrefix(c.Name, "/")
		if slices.Contains(opts.AllowContainers, name) {
			continue
		}
		if several {
			name = c.Engine + ": " + name
		}
		if c.HostConfig.NetworkMode == "host" {
			high = append(high, name+": uses the host network")
		}
		if c.HostConfig.Privileged {
			high = append(high, name+": runs privileged")
		}
		for port, binds := range c.NetworkSettings.Ports {
			for _, b := range binds {
				if !isLoopback(b.HostIp) {
					ip := b.HostIp
					if ip == "" {
						ip = "0.0.0.0"
					}
					medium = append(medium, fmt.Sprintf("%s: %s published on %s:%s", name, port, ip, b.HostPort))
				}
			}
		}
		for _, m := range c.Mounts {
			if m.Type != "bind" || mountAllowed(m.Source, allowedMounts) {
				continue
			}
			if why := riskyMount(m.Source, home); why != "" {
				high = append(high, fmt.Sprintf("%s: mounts %s (%s)", name, m.Source, why))
			}
		}
	}
	high, medium = uniqSorted(high), uniqSorted(medium)
	if len(high)+len(medium) == 0 {
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("docker.pass", "n", len(cs)))
	}
	r := check.Result{Status: check.Warn, Severity: check.Medium, Evidence: append(high, medium...)}.
		WithSummary(msg.Of("docker.problems", "n", len(high)+len(medium), "containers", len(cs))).
		WithFix(msg.Of("docker.fix"))
	if len(high) > 0 {
		r.Status, r.Severity = check.Fail, check.High
	}
	return r
}

func mountAllowed(src string, allowed []string) bool {
	s := normPath(src)
	for _, a := range allowed {
		if s == a || strings.HasPrefix(s, a+"/") {
			return true
		}
	}
	return false
}

// riskyMount says why mounting src into a container is dangerous, or "" if it isn't.
func riskyMount(src, home string) string {
	s, h := normPath(src), normPath(home)
	switch {
	case strings.HasSuffix(s, "docker.sock") || strings.Contains(s, "docker_engine"):
		return "the Docker socket: full control of the host"
	case s == "/" || (len(s) == 2 && s[1] == ':'):
		return "the whole disk"
	case s == h:
		return "your whole home folder"
	case s == path.Dir(h) || s == "/users" || s == "/home":
		return "every user's home folder"
	}
	for _, d := range []string{".ssh", ".aws", ".kube", ".gnupg", ".docker", ".config"} {
		if dir := h + "/" + d; s == dir || strings.HasPrefix(s, dir+"/") {
			return "credentials folder ~/" + d
		}
	}
	return ""
}

// normPath makes Mac, Windows and Docker Desktop paths comparable:
// `C:\Users\me`, `/run/desktop/mnt/host/c/Users/me` and `/c/Users/me` all become "c:/users/me".
func normPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimPrefix(p, "/run/desktop/mnt/host")
	if len(p) >= 2 && p[0] == '/' && isLetter(p[1]) && (len(p) == 2 || p[2] == '/') {
		p = p[1:2] + ":" + p[2:]
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return strings.ToLower(p)
}

func isLetter(b byte) bool { return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' }
