package checks

import (
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func TestListenersInfoOnly(t *testing.T) {
	lower := policy.Default().Checks.Listeners.InfoOnly
	airplay := []listener{{Proc: "ControlCenter", Addr: "*", Port: "5000"}, {Proc: "ControlCenter", Addr: "*", Port: "7000"},
		{Proc: "dropboxfileprovider", Addr: "*", Port: "17500"}}
	// Only well-known services: a pass that lists them, with nothing to fix.
	r := evalListenersWith(airplay, nil, nil, lower)
	if r.Status != check.Pass || r.Severity != "" || !strings.Contains(r.Summary, "3 ports") ||
		!strings.Contains(r.Summary, "listed for information") || r.Fix != "" || len(r.Evidence) != 3 {
		t.Errorf("known services only: %s %s %q %q", r.Status, r.Severity, r.Summary, r.Fix)
	}
	// One other open port makes it medium again, with the ordinary fix.
	r = evalListenersWith(append(airplay, listener{Proc: "node", Addr: "*", Port: "3000"}), nil, nil, lower)
	if r.Severity != check.Medium || strings.Contains(r.Summary, "well-known") || !strings.Contains(r.Fix, "127.0.0.1") {
		t.Errorf("with a dev server: %s %q %q", r.Severity, r.Summary, r.Fix)
	}
	// An empty list makes them findings again.
	if r := evalListenersWith(airplay, nil, nil, nil); r.Status != check.Warn || r.Severity != check.Medium {
		t.Errorf("no info_only list: %s", r.Severity)
	}
}

func TestWindowsSystemListeners(t *testing.T) {
	old := listenersOS
	defer func() { listenersOS = old }()
	lower := policy.Default().Checks.Listeners.InfoOnly
	// What a stock Windows 11 PC with Tailscale has open.
	stock := []listener{
		{Proc: "svchost", Addr: "0.0.0.0", Port: "135"}, {Proc: "System", Addr: "0.0.0.0", Port: "445"},
		{Proc: "System", Addr: "192.168.1.20", Port: "139"}, {Proc: "svchost", Addr: "0.0.0.0", Port: "5040"},
		{Proc: "svchost", Addr: "0.0.0.0", Port: "7680"}, {Proc: "lsass", Addr: "0.0.0.0", Port: "49664"},
		{Proc: "wininit", Addr: "0.0.0.0", Port: "49665"}, {Proc: "svchost", Addr: "0.0.0.0", Port: "49666"},
		{Proc: "services", Addr: "0.0.0.0", Port: "49670"}, {Proc: "spoolsv", Addr: "0.0.0.0", Port: "49668"},
		{Proc: "tailscaled", Addr: "100.101.102.103", Port: "52301"},
	}
	listenersOS = "windows"
	r := evalListenersWith(stock, nil, nil, lower)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "11 ports") || !strings.Contains(r.Summary, "Windows' own system services") || len(r.Evidence) != 11 {
		t.Errorf("stock Windows: %s %q %d", r.Status, r.Summary, len(r.Evidence))
	}
	// Remote desktop, WinRM, a dev server, or a system process on an unexpected port still warn.
	for _, extra := range []listener{
		{Proc: "svchost", Addr: "0.0.0.0", Port: "3389"}, {Proc: "System", Addr: "0.0.0.0", Port: "5985"},
		{Proc: "node", Addr: "0.0.0.0", Port: "3000"}, {Proc: "lsass", Addr: "0.0.0.0", Port: "4444"},
		{Proc: "System", Addr: "0.0.0.0", Port: "80"},
	} {
		if r := evalListenersWith(append(stock[:len(stock):len(stock)], extra), nil, nil, lower); r.Status != check.Warn || r.Severity != check.Medium {
			t.Errorf("%s:%s should warn, got %s", extra.Proc, extra.Port, r.Status)
		}
	}
	// The same names on another OS are not Windows services.
	listenersOS = "linux"
	if r := evalListenersWith(stock[:3], nil, nil, lower); r.Status != check.Warn {
		t.Errorf("not Windows: %s", r.Status)
	}
}
