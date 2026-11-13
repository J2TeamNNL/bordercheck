package agent

import (
	"strings"
	"testing"
)

func TestDesktopEntry(t *testing.T) {
	e := desktopEntry(`/home/an/.local/share/bordercheck/bordercheck`)
	if !strings.Contains(e, "\nExec=\"/home/an/.local/share/bordercheck/bordercheck\" open\n") || !strings.Contains(e, "\nName=BorderCheck\n") {
		t.Errorf("entry:\n%s", e)
	}
	// Characters the Exec key treats specially stay part of the one path.
	e = desktopEntry("/home/a\"b`c$d\\e%f/bordercheck")
	if !strings.Contains(e, "\nExec=\"/home/a\\\"b\\`c\\$d\\\\e%%f/bordercheck\" open\n") {
		t.Errorf("entry:\n%s", e)
	}
}
