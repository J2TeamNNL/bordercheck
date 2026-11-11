package checks

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func listenerAllowed(l listener, allow []policy.ListenerRule) bool {
	for _, r := range allow {
		if strings.EqualFold(r.Process, l.Proc) && (r.Port == "" || r.Port == l.Port) {
			return true
		}
	}
	return false
}

type listener struct{ Proc, Addr, Port string }

// What common listeners are and where to turn them off, so people know what they're looking at.
var listenerHints = map[string]string{
	"ControlCenter":       "AirPlay Receiver; turn off in System Settings → General → AirDrop & Handoff if unused",
	"rapportd":            "Apple Handoff/Continuity",
	"DropboxFileProvider": "Dropbox LAN sync; turn off in Dropbox → Preferences → Network",
	"spotify":             "Spotify Connect discovery",
	"Spotify":             "Spotify Connect discovery",
	"System":              "Windows file sharing (SMB) and other system services",
	"svchost":             "Windows system service",
	"sshd":                "SSH server; turn it off if unused (Linux: sudo systemctl disable --now ssh; Mac: Remote Login)",
	"kdeconnectd":         "KDE Connect",
}

func listeners(ctx context.Context, opts policy.Listeners) check.Result {
	ls, note, err := listListeners(ctx)
	if errors.Is(err, errUnsupported) {
		return unsupported()
	}
	if err != nil {
		return check.Errored(err)
	}
	return evalListenersWith(ls, note, opts.Allow, opts.LowerSeverity)
}

func isLoopback(addr string) bool {
	addr = strings.Trim(addr, "[]")
	if addr == "localhost" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

func isAnyAddr(addr string) bool {
	switch strings.Trim(addr, "[]") {
	case "", "*", "0.0.0.0", "::":
		return true
	}
	return false
}

// parseLsof reads `lsof -nP -iTCP -sTCP:LISTEN`, whose last two columns are
// NAME (addr:port) and "(LISTEN)".
func parseLsof(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[len(f)-1] != "(LISTEN)" {
			continue
		}
		name := f[len(f)-2]
		i := strings.LastIndex(name, ":")
		if i < 0 {
			continue
		}
		ls = append(ls, listener{Proc: strings.ReplaceAll(f[0], `\x20`, " "), Addr: name[:i], Port: name[i+1:]})
	}
	return ls
}

// parseWinListeners reads lines of "process|address|port".
func parseWinListeners(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) == 3 {
			ls = append(ls, listener{Proc: f[0], Addr: f[1], Port: f[2]})
		}
	}
	return ls
}

var ssProcRe = regexp.MustCompile(`users:\(\("([^"]+)"`)

// parseSS reads `ss -l -t -n -p`: State Recv-Q Send-Q Local:Port Peer:Port
// [users:(("name",pid=…,fd=…))]. Without root, only the user's own sockets
// carry a process name.
func parseSS(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "LISTEN" {
			continue
		}
		local := f[3]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		addr, _, _ := strings.Cut(local[:i], "%") // 127.0.0.53%lo: the interface the socket is bound to
		l := listener{Addr: strings.Trim(addr, "[]"), Port: local[i+1:]}
		if m := ssProcRe.FindStringSubmatch(line); m != nil {
			l.Proc = m[1]
		}
		ls = append(ls, l)
	}
	return ls
}

// parseProcNetTCP reads /proc/net/tcp or tcp6, keeping sockets in state 0A
// (LISTEN). Addresses are hex, each 32-bit word in host (little-endian) order.
func parseProcNetTCP(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		hexAddr, hexPort, ok := strings.Cut(f[1], ":")
		b, err := hex.DecodeString(hexAddr)
		port, perr := strconv.ParseUint(hexPort, 16, 16)
		if !ok || err != nil || perr != nil || (len(b) != 4 && len(b) != 16) {
			continue
		}
		ip := make(net.IP, len(b))
		for i := 0; i < len(b); i += 4 {
			ip[i], ip[i+1], ip[i+2], ip[i+3] = b[i+3], b[i+2], b[i+1], b[i]
		}
		ls = append(ls, listener{Addr: ip.String(), Port: strconv.FormatUint(port, 10)})
	}
	return ls
}

func evalListeners(ls []listener, note msg.Text, allow []policy.ListenerRule) check.Result {
	return evalListenersWith(ls, note, allow, nil)
}

// evalListenersWith is evalListeners with the policy's lower_severity list:
// when every exposed port belongs to one of those processes (AirPlay Receiver,
// Dropbox LAN sync and the like), the warning is low instead of medium.
func evalListenersWith(ls []listener, note msg.Text, allow []policy.ListenerRule, lower []string) check.Result {
	var exposed []string
	allowed := 0
	onlyLower := true
	for _, l := range ls {
		if isLoopback(l.Addr) {
			continue
		}
		if listenerAllowed(l, allow) {
			allowed++
			continue
		}
		proc, where := l.Proc, l.Addr
		if proc == "" {
			proc = "unknown process"
		}
		if isAnyAddr(where) {
			where = "all interfaces"
		}
		if !slices.ContainsFunc(lower, func(p string) bool { return strings.EqualFold(p, l.Proc) }) {
			onlyLower = false
		}
		line := fmt.Sprintf("%s: port %s on %s", proc, l.Port, where)
		if hint := listenerHints[proc]; hint != "" {
			line += " (" + hint + ")"
		}
		exposed = append(exposed, line)
	}
	exposed = uniqSorted(exposed) // IPv4 and IPv6 sockets of one server collapse
	if allowed > 0 {
		note = append(msg.Of("check.moreAllowed", "n", allowed), note...)
	}
	if len(exposed) == 0 {
		return check.Result{Status: check.Pass}.
			WithSummary(append(msg.Of("listeners.pass", "n", len(ls)), note...))
	}
	if onlyLower {
		return check.Result{Status: check.Warn, Severity: check.Low, Evidence: exposed}.
			WithSummary(slices.Concat(msg.Of("listeners.exposed", "n", len(exposed)), msg.Of("listeners.lower"), note)).
			WithFix(msg.Of("listeners.fix.lower"))
	}
	return check.Result{Status: check.Warn, Severity: check.Medium, Evidence: exposed}.
		WithSummary(append(msg.Of("listeners.exposed", "n", len(exposed)), note...)).
		WithFix(msg.Of("listeners.fix"))
}
