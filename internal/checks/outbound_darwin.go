package checks

import (
	"os"
	"path/filepath"
)

// outboundFirewalls returns the outbound firewalls installed on this Mac, and
// true because the suggestion applies here.
func outboundFirewalls() ([]string, bool) {
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
	return found, true
}
