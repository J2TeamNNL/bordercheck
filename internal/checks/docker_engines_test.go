package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// docker context ls --format '{{json .}}' on a Mac with OrbStack and Docker Desktop.
const contextsJSON = `{"Current":false,"Description":"Current DOCKER_HOST based configuration","DockerEndpoint":"unix:///var/run/docker.sock","Error":"","Name":"default"}
{"Current":false,"Description":"Docker Desktop","DockerEndpoint":"unix:///Users/me/.docker/run/docker.sock","Error":"","Name":"desktop-linux"}
{"Current":true,"Description":"OrbStack","DockerEndpoint":"unix:///Users/me/.orbstack/run/docker.sock","Error":"","Name":"orbstack"}
{"Current":false,"Description":"","DockerEndpoint":"ssh://me@server","Error":"","Name":"remote"}
{"Current":"false","DockerEndpoint":"unix:///Users/me/.colima/default/docker.sock","Name":"colima"}`

func TestDockerEngines(t *testing.T) {
	cs := parseDockerContexts(contextsJSON)
	if len(cs) != 5 || !cs[2].Current || cs[4].Current {
		t.Fatalf("contexts: %+v", cs)
	}
	// /var/run/docker.sock is a link to Docker Desktop's socket; Colima is stopped (no socket).
	sockets := map[string]string{
		"/var/run/docker.sock":                "/Users/me/.docker/run/docker.sock",
		"/Users/me/.docker/run/docker.sock":   "/Users/me/.docker/run/docker.sock",
		"/Users/me/.orbstack/run/docker.sock": "/Users/me/.orbstack/run/docker.sock",
	}
	exists := func(s string) (string, bool) { r, ok := sockets[s]; return r, ok }
	es := localEngines("docker", cs, exists)
	var names []string
	for _, e := range es {
		names = append(names, e.Name+" "+strings.Join(e.Args, " "))
	}
	if got := strings.Join(names, " | "); got != "Docker Desktop --context default | OrbStack --context orbstack" {
		t.Errorf("engines: %s", got)
	}
	// The current context is kept even when its socket is missing, to say it is not running.
	delete(sockets, "/Users/me/.orbstack/run/docker.sock")
	if es := localEngines("docker", cs, exists); len(es) != 2 || es[1].Name != "OrbStack" {
		t.Errorf("stopped current context: %+v", es)
	}
	for ep, want := range map[string]string{
		"unix:///Users/me/.rd/docker.sock":                                    "Rancher Desktop",
		"unix:///Users/me/.local/share/containers/podman/machine/podman.sock": "Podman",
		"npipe:////./pipe/dockerDesktopLinuxEngine":                           "Docker Desktop",
		"unix:///Users/me/.lima/docker/sock/docker.sock":                      "Lima",
	} {
		if got := engineName("x", ep); got != want {
			t.Errorf("%s: %s, want %s", ep, got, want)
		}
	}
	if engineName("default", "unix:///var/run/docker.sock") != "Docker" || engineName("work", "unix:///run/work.sock") != "Docker (work)" {
		t.Error("plain names")
	}
}

func TestEvalEngines(t *testing.T) {
	var opts policy.Docker
	web := `[{"Name":"/web","HostConfig":{"NetworkMode":"host"}}]`
	podman := `[{"Name":"db","HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"5432"}]}}}]`
	cases := []struct {
		name string
		rs   []engineResult
		st   check.Status
		has  []string
	}{
		{"stopped OrbStack", []engineResult{{Engine: "OrbStack"}}, check.Skip, []string{"Not running: OrbStack."}},
		{"plain Docker stopped", []engineResult{{Engine: "Docker"}}, check.Skip, []string{"Docker is not running."}},
		{"denied", []engineResult{{Engine: "Docker", Denied: true}}, check.Skip, []string{"docker group"}},
		{"no containers", []engineResult{{Engine: "OrbStack", Running: true}}, check.Pass, []string{"No running containers.", "Checked: OrbStack."}},
		{"two engines", []engineResult{{Engine: "OrbStack", Running: true, Inspect: web}, {Engine: "Podman", Running: true, Inspect: podman}, {Engine: "Colima"}},
			check.Fail, []string{"OrbStack: web: uses the host network", "Podman: db: 5432/tcp published on 0.0.0.0:5432", "Checked: OrbStack, Podman.", "Not running, so not checked: Colima."}},
	}
	for _, c := range cases {
		r := evalEngines(c.rs, "/Users/me", opts)
		all := r.Summary + " " + strings.Join(r.Evidence, " ")
		if r.Status != c.st {
			t.Errorf("%s: %s %q", c.name, r.Status, all)
		}
		for _, h := range c.has {
			if !strings.Contains(all, h) {
				t.Errorf("%s: no %q in %q", c.name, h, all)
			}
		}
	}
}
