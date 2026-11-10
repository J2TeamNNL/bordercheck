package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/notify"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// showNotification is notify.Show; tests replace it.
var showNotification = notify.Show

// notifyUser tells the person at the machine about problems that are new since
// the last check, or due a reminder, and records what was announced in st.
//
// A forced send (`bordercheck send -force`, and the first report at install) is
// run by someone at a terminal, so the problems are printed there instead of
// popping up, and count as announced: the next hourly run does not repeat them.
//
// A notification that cannot be shown is logged and tried again next time.
func notifyUser(ctx context.Context, env Env, n policy.Notify, results []check.Result, st *State, now time.Time, force bool) {
	due, next := notify.Plan(results, n, st.Notified, now)
	st.Notified = next
	if len(due) == 0 {
		return
	}
	msg := notify.Compose(due)
	if force {
		fmt.Fprintf(env.Out, "\n%s\n%s\n\n", msg.Title, indent(msg.Body))
		return
	}
	if err := showNotification(ctx, msg); err != nil {
		for _, r := range due {
			delete(st.Notified, notify.Key(r))
		}
		fmt.Fprintf(env.Out, "%s notification not shown: %v\n", now.Format(time.RFC3339), err)
		return
	}
	fmt.Fprintf(env.Out, "%s notified: %d problem(s)\n", now.Format(time.RFC3339), len(due))
}

func indent(s string) string { return "  " + strings.ReplaceAll(s, "\n", "\n  ") }

// identity is who this machine is for waivers.
func identity(cfg Config) policy.Identity {
	host, _ := os.Hostname()
	return policy.Identity{Email: cfg.Email, InstallID: cfg.InstallID, Hostname: host}
}

// Identity is who this machine is for waivers when bordercheck runs by hand:
// the email and install ID from this user's install in dir, if there is one,
// and the hostname. It only reads. Without an install, only waivers that name
// nothing but a hostname can match.
func Identity(dir string) policy.Identity {
	var cfg Config
	_ = readJSON(filepath.Join(dir, "config.json"), &cfg)
	return identity(cfg)
}
