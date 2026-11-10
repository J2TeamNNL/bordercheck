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

func docker(ctx context.Context, opts policy.Docker) check.Result {
	home, _ := os.UserHomeDir()
	var fallbacks []string
	switch runtime.GOOS {
	case "darwin":
		fallbacks = []string{"/usr/local/bin/docker", filepath.Join(home, ".docker/bin/docker"),
			"/Applications/Docker.app/Contents/Resources/bin/docker"}
	case "windows":
		fallbacks = []string{`C:\Program Files\Docker\Docker\resources\bin\docker.exe`}
	case "linux":
		fallbacks = []string{"/usr/bin/docker", "/usr/local/bin/docker", "/snap/bin/docker"}
	}
	bin, ok := sysx.Find("docker", fallbacks...)
	if !ok {
		return check.SkippedMsg(msg.Of("docker.notInstalled"))
	}
	ids, err := sysx.Run(ctx, bin, "ps", "-q")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			// Linux: the socket belongs to root and the docker group.
			return check.SkippedMsg(msg.Of("docker.noPermission"))
		}
		return check.SkippedMsg(msg.Of("docker.notRunning"))
	}
	if len(strings.Fields(ids)) == 0 {
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("docker.noContainers"))
	}
	out, err := sysx.Run(ctx, bin, append([]string{"inspect"}, strings.Fields(ids)...)...)
	if err != nil {
		return check.Errored(err)
	}
	return evalDocker(out, home, opts)
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

// evalDocker judges `docker inspect` output for the running containers.
func evalDocker(out, home string, opts policy.Docker) check.Result {
	var cs []dockerContainer
	if err := json.Unmarshal([]byte(out), &cs); err != nil {
		return check.Errored(fmt.Errorf("reading docker inspect: %w", err))
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
