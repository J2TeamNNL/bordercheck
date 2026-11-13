package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The real script, against a registry key of the test's own: the user's PATH
// is never touched.
func TestSetPathKeepsWhatIsThere(t *testing.T) {
	key := fmt.Sprintf(`Software\BorderCheckTest-%d`, os.Getpid())
	full := `HKCU\` + key
	reg := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("reg", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("reg %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	path := func() string {
		for _, l := range strings.Split(reg("query", full, "/v", "Path"), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "Path" {
				return strings.Join(f[1:], " ")
			}
		}
		return ""
	}
	t.Cleanup(func() { _ = exec.Command("reg", "delete", full, "/f").Run() })
	const before = `%USERPROFILE%\bin;C:\Tools`
	const dir = `C:\Users\An Example\AppData\Local\bordercheck`
	reg("add", full, "/v", "Path", "/t", "REG_EXPAND_SZ", "/d", before, "/f")

	for range 2 { // adding twice leaves one entry
		if err := setPathIn(key, dir, true); err != nil {
			t.Fatal(err)
		}
		if got, want := path(), "REG_EXPAND_SZ "+before+";"+dir; got != want {
			t.Fatalf("after add:\n got %q\nwant %q", got, want)
		}
	}
	if err := setPathIn(key, dir, false); err != nil {
		t.Fatal(err)
	}
	if got, want := path(), "REG_EXPAND_SZ "+before; got != want {
		t.Fatalf("after remove:\n got %q\nwant %q", got, want)
	}

	// A user with no Path of their own gets one holding just the folder.
	reg("delete", full, "/v", "Path", "/f")
	if err := setPathIn(key, dir, true); err != nil {
		t.Fatal(err)
	}
	if got, want := path(), "REG_EXPAND_SZ "+dir; got != want {
		t.Fatalf("new Path: got %q want %q", got, want)
	}
	// A missing key is an error, not a new key somewhere.
	if err := setPathIn(key+`\missing`, dir, true); err == nil {
		t.Error("no error for a key that does not exist")
	}
}
