package agent

import (
	"strings"
	"testing"
)

func TestSystemdUnits(t *testing.T) {
	service, timer := systemdUnits(`/home/an o"k/.local/share/bordercheck/bordercheck`, "/home/an 100%/.local/share/bordercheck")
	for _, want := range []string{
		`ExecStart="/home/an o\"k/.local/share/bordercheck/bordercheck" send` + "\n",
		"WorkingDirectory=/home/an 100%%/.local/share/bordercheck\n",
		"Type=oneshot\n",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("service lacks %q:\n%s", want, service)
		}
	}
	for _, want := range []string{"OnCalendar=hourly\n", "Persistent=true\n", "WantedBy=timers.target\n"} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer lacks %q:\n%s", want, timer)
		}
	}
}

func TestCronLine(t *testing.T) {
	got := cronLine("/home/o'brien/50%/bordercheck", 75)
	want := `15 * * * * env PATH=` + cronSafePATH + ` '/home/o'\''brien/50\%/bordercheck' send >/dev/null 2>&1 ` + cronMarker
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestWithCronLine(t *testing.T) {
	line := cronLine("/b", 5)
	old := cronLine("/old", 9)
	for _, tc := range []struct{ tab, line, want string }{
		{"", line, line + "\n"},
		{"", "", ""},
		{"MAILTO=me\n0 3 * * * backup\n", line, "MAILTO=me\n0 3 * * * backup\n" + line + "\n"},
		{"0 3 * * * backup\n" + old + "\n", line, "0 3 * * * backup\n" + line + "\n"},
		{"0 3 * * * backup\n" + old + "\n\n", "", "0 3 * * * backup\n"},
		{old + "\n", "", ""},
	} {
		if got := withCronLine(tc.tab, tc.line); got != tc.want {
			t.Errorf("withCronLine(%q, %q) = %q, want %q", tc.tab, tc.line, got, tc.want)
		}
	}
}
