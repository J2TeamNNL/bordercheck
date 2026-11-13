package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ptrinh/bordercheck/internal/notifier"
)

func fakeLauncherApp(t *testing.T, dir, plist string) string {
	t.Helper()
	app := filepath.Join(dir, notifier.AppName)
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"Contents/Info.plist": plist, "Contents/MacOS/bordercheck-notifier": "program"} {
		if err := os.WriteFile(filepath.Join(app, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return app
}

func TestCopyLauncher(t *testing.T) {
	plist := "<key>CFBundleIdentifier</key><string>" + notifier.BundleID + "</string><key>" + opensReportKey + "</key><true/>"
	src := fakeLauncherApp(t, t.TempDir(), plist)
	digest, err := notifier.Digest(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "Applications", LauncherName+".app")

	// Not the app that was installed: nothing is copied.
	if err := copyLauncher(src, dst, "0000"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("copied an app that does not match the recorded digest")
	}
	// An app from before it could open the report page: not copied either.
	old := fakeLauncherApp(t, t.TempDir(), "<string>"+notifier.BundleID+"</string>")
	oldDigest, _ := notifier.Digest(old)
	if err := copyLauncher(old, dst, oldDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("copied an app that cannot open the report page")
	}

	if err := copyLauncher(src, dst, digest); err != nil {
		t.Fatal(err)
	}
	if d, err := notifier.Digest(dst); err != nil || d != digest {
		t.Fatalf("copy differs: %v", err)
	}
	// Already there: left as it is.
	before, _ := os.Stat(dst)
	if err := copyLauncher(src, dst, digest); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(dst); !os.SameFile(before, after) {
		t.Error("an up-to-date copy was replaced")
	}
	// Changed: put right.
	if err := os.WriteFile(filepath.Join(dst, "Contents", "MacOS", "bordercheck-notifier"), []byte("other"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyLauncher(src, dst, digest); err != nil {
		t.Fatal(err)
	}
	if d, _ := notifier.Digest(dst); d != digest {
		t.Error("a changed copy was not replaced")
	}

	// Somebody else's app under that name is never replaced.
	other := filepath.Join(t.TempDir(), LauncherName+".app")
	if err := os.MkdirAll(filepath.Join(other, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "Contents", "Info.plist"), []byte("<string>com.example.other</string>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyLauncher(src, other, digest); err == nil {
		t.Error("replaced an app that is not BorderCheck's")
	}
	if !plistHas(other, "com.example.other") {
		t.Error("the other app was touched")
	}
}
