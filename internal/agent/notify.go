package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
//
// When the receiver gave this machine a report page (st.ReportPage, on the host
// reports go to, reportURL) and an announced problem is high severity, the page
// opens in the browser too, unless the policy turns notify.open_report off;
// when it is off or the page cannot be opened, the notification only adds a
// hint to run bordercheck status for the link. A forced send prints the link
// on the terminal (env.Term), never in the log. The link is a secret: it is
// never written to env.Out.
func notifyUser(ctx context.Context, env Env, n policy.Notify, results []check.Result, st *State, now time.Time, force bool, reportURL string) {
	due, next := notify.Plan(results, n, st.Notified, now)
	st.Notified = next
	if len(due) == 0 {
		return
	}
	msg := notify.Compose(due)
	link := reportPage(st.ReportPage, reportURL)
	high := link != "" && slices.ContainsFunc(due, func(r check.Result) bool { return r.Severity == check.High })
	if force {
		fmt.Fprintf(env.Out, "\n%s\n%s\n\n", msg.Title, indent(msg.Body))
		if high && env.Term != nil {
			fmt.Fprintf(env.Term, "Your report page: %s\n\n", link)
		}
		return
	}
	opened := false
	if high && n.OpenReport {
		if err := openURL(ctx, link); err == nil {
			opened = true
			fmt.Fprintf(env.Out, "%s opened the report page\n", now.Format(time.RFC3339))
		} else if !errors.Is(err, errNoDesktop) {
			fmt.Fprintf(env.Out, "%s report page not opened: %v\n", now.Format(time.RFC3339), err)
		}
	}
	if high && !opened {
		msg.Body += "\nRun bordercheck status for the link to your report page."
	}
	if err := showNotification(ctx, msg); err != nil {
		if !opened { // the open page told them; don't open it again next hour
			for _, r := range due {
				delete(st.Notified, notify.Key(r))
			}
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
