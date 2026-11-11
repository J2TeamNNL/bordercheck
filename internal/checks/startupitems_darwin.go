package checks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/msg"
)

// bordercheck's own LaunchAgent (internal/agent/service_darwin.go).
const ownLaunchdLabel = "io.github.ptrinh.bordercheck"

// gatherStartup reads the LaunchAgents and LaunchDaemons folders. They need
// no admin rights or privacy permission to read. Login Items (the Background
// Task Management database) can only be listed as root, so they are left out.
func gatherStartup(ctx context.Context, home string) ([]startupItem, msg.Text, error) {
	var items []startupItem
	for _, d := range []struct{ dir, source string }{
		{filepath.Join(home, "Library", "LaunchAgents"), "LaunchAgent"},
		{"/Library/LaunchAgents", "LaunchAgent"},
		{"/Library/LaunchDaemons", "LaunchDaemon"},
	} {
		entries, err := os.ReadDir(d.dir)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".plist") && !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if ctx.Err() != nil || len(items) >= startupMaxItems {
				return items, nil, nil
			}
			p := filepath.Join(d.dir, n)
			doc, err := plistXML(ctx, p)
			if err != nil || doc == "" {
				continue
			}
			if it, ok := launchdItem(doc, d.source, tildePath(home, p)); ok {
				it.Own = it.Label == ownLaunchdLabel
				items = append(items, it)
			}
		}
	}
	return items, nil, nil
}
