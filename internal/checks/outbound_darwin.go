package checks

import (
	"context"
	"os"
	"path/filepath"
)

// outboundFirewalls returns the outbound firewalls installed on this Mac.
func outboundFirewalls(context.Context) ([]string, outboundAdvice, bool) {
	dirs := []string{"/Applications"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	var found []string
	for _, app := range outboundApps {
		for _, d := range dirs {
			if st, err := os.Stat(filepath.Join(d, app+".app")); err == nil && st.IsDir() {
				found = append(found, app)
				break
			}
		}
	}
	return found, outboundMac, true
}
