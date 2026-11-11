package checks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// bordercheck's own systemd user unit (internal/agent/systemd.go).
const ownSystemdUnit = "bordercheck"

// gatherStartup reads XDG autostart entries, the systemd user units enabled
// in ~/.config/systemd/user, and the user's crontab. All are the user's own
// files; nothing needs root.
func gatherStartup(ctx context.Context, home string) ([]startupItem, msg.Text, error) {
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" || !filepath.IsAbs(cfg) {
		cfg = filepath.Join(home, ".config")
	}
	var items []startupItem
	auto, _ := filepath.Glob(filepath.Join(cfg, "autostart", "*.desktop"))
	sort.Strings(auto)
	for _, p := range auto {
		if b, err := readSmall(p); err == nil {
			if it, ok := desktopItem(string(b), tildePath(home, p)); ok {
				items = append(items, it)
			}
		}
	}
	unitDir := filepath.Join(cfg, "systemd", "user")
	wants, _ := filepath.Glob(filepath.Join(unitDir, "*.wants", "*"))
	sort.Strings(wants)
	seen := map[string]bool{}
	for _, w := range wants {
		name := filepath.Base(w)
		unit := strings.TrimSuffix(strings.TrimSuffix(name, ".service"), ".timer")
		if seen[unit] || (!strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer")) {
			continue
		}
		seen[unit] = true
		svc := w
		if strings.HasSuffix(name, ".timer") {
			svc = filepath.Join(unitDir, unit+".service")
		}
		b, err := readSmall(svc)
		if err != nil {
			continue
		}
		if exec := systemdExec(string(b)); exec != "" {
			it := commandItem("systemd user unit", tildePath(home, svc), unit, exec)
			it.Own = unit == ownSystemdUnit
			items = append(items, it)
		}
	}
	if _, ok := sysx.Find("crontab"); ok && ctx.Err() == nil {
		if tab, err := sysx.Run(ctx, "crontab", "-l"); err == nil {
			items = append(items, cronItems(tab)...)
		}
	}
	if len(items) > startupMaxItems {
		items = items[:startupMaxItems]
	}
	return items, nil, nil
}

func readSmall(p string) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 256<<10 {
		return nil, os.ErrInvalid
	}
	return os.ReadFile(p)
}
