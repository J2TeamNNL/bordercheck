// Package report renders check results as text for people or JSON for machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
)

type Host struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
}

type Counts struct {
	Fail  int `json:"fail"`
	Error int `json:"error"`
	Warn  int `json:"warn"`
	Pass  int `json:"pass"`
	Skip  int `json:"skip"`
}

type Report struct {
	Tool    string    `json:"tool"`
	Version string    `json:"version"`
	Policy  string    `json:"policy"`
	Time    time.Time `json:"time"`
	Host    Host      `json:"host"`
	// Set when an installed bordercheck sends the report.
	Email     string         `json:"email,omitempty"`
	InstallID string         `json:"install_id,omitempty"`
	Counts    Counts         `json:"counts"`
	Results   []check.Result `json:"results"`
}

func New(version, policy string, results []check.Result) Report {
	hostname, _ := os.Hostname()
	r := Report{Tool: "bordercheck", Version: version, Policy: policy, Time: time.Now().UTC().Truncate(time.Second),
		Host: Host{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: hostname}, Results: results}
	for _, res := range results {
		switch res.Status {
		case check.Fail:
			r.Counts.Fail++
		case check.Error:
			r.Counts.Error++
		case check.Warn:
			r.Counts.Warn++
		case check.Pass:
			r.Counts.Pass++
		case check.Skip:
			r.Counts.Skip++
		}
	}
	return r
}

func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

var styles = map[check.Status]struct {
	label, color string
	rank         int
}{
	check.Fail:  {"FAIL", "\x1b[31m", 0},
	check.Error: {"ERR ", "\x1b[35m", 1},
	check.Warn:  {"WARN", "\x1b[33m", 2},
	check.Pass:  {"PASS", "\x1b[32m", 3},
	check.Skip:  {"SKIP", "\x1b[90m", 4},
}

// WriteText prints the worst results first.
func (r Report) WriteText(w io.Writer, color bool) {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + "\x1b[0m"
	}
	fmt.Fprintf(w, "%s %s · %s/%s · %s · policy: %s\n\n", paint("\x1b[1m", r.Tool), r.Version, r.Host.OS, r.Host.Arch, r.Host.Hostname, r.Policy)
	results := append([]check.Result(nil), r.Results...)
	sort.SliceStable(results, func(i, j int) bool { return styles[results[i].Status].rank < styles[results[j].Status].rank })
	for _, res := range results {
		st := styles[res.Status]
		line := paint(st.color, st.label) + "  " + res.Title
		if res.Severity != "" && (res.Status == check.Fail || res.Status == check.Warn) {
			line += paint("\x1b[90m", " ["+string(res.Severity)+"]")
		}
		fmt.Fprintln(w, line)
		if res.Summary != "" {
			fmt.Fprintln(w, "      "+res.Summary)
		}
		for _, e := range res.Evidence {
			fmt.Fprintln(w, "        · "+e)
		}
		if res.Fix != "" {
			fmt.Fprintln(w, "      "+paint("\x1b[1m", "Fix:")+" "+res.Fix)
		}
		fmt.Fprintln(w)
	}
	c := r.Counts
	var parts []string
	for _, p := range []struct {
		n    int
		name string
	}{{c.Fail, "fail"}, {c.Error, "error"}, {c.Warn, "warn"}, {c.Pass, "pass"}, {c.Skip, "skip"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.name))
		}
	}
	fmt.Fprintln(w, strings.Join(parts, " · "))
}
