// Package notify tells the person at the machine, with a native desktop
// notification, about problems a scheduled run found. Deciding what to
// announce is portable and tested here; showing it is per OS (notify_*.go) and
// uses only what the OS ships with: osascript on macOS, a PowerShell toast on
// Windows, notify-send or gdbus on Linux.
//
// A notification carries only check IDs and summaries, never evidence, so no
// file path, port, variable name or secret ever reaches the screen.
package notify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Key names one problem in state.json: a check and its status, so a warn that
// turns into a fail is announced again, and whether it shows signs of
// compromise, so a fail that turns into one is announced again too.
func Key(r check.Result) string {
	k := r.ID + ":" + string(r.Status)
	if len(r.Compromise) > 0 {
		k += ":compromised"
	}
	return k
}

// Plan decides what to announce. seen maps the Key of each problem announced
// earlier, and still present in the previous run, to when it was last
// announced. A problem is due when it is new or was last announced at least
// n.Remind() ago. next is the state to keep if the due problems are shown:
// problems gone from this run are dropped, so they count as new if they come
// back.
func Plan(results []check.Result, n policy.Notify, seen map[string]time.Time, now time.Time) (due []check.Result, next map[string]time.Time) {
	next = map[string]time.Time{}
	for _, r := range results {
		if !n.Wants(r) {
			continue
		}
		k := Key(r)
		last, ok := seen[k]
		if !ok || (n.Remind() > 0 && now.Sub(last) >= n.Remind()) {
			due = append(due, r)
			last = now
		}
		next[k] = last
	}
	return due, next
}

// Message is one notification.
type Message struct {
	Title string
	Body  string
}

const (
	maxLines   = 3   // problems listed by name; the rest are counted
	maxSummary = 110 // characters per problem
)

// Compose writes the notification for due problems: which checks, their
// summaries, and how to see the fix. It never includes evidence.
//
// When a problem shows signs of compromise, the notification says so first,
// with what the signs are (never which item), and to stop and tell IT.
func Compose(due []check.Result) Message {
	title := "bordercheck: 1 problem on this computer"
	if len(due) != 1 {
		title = fmt.Sprintf("bordercheck: %d problems on this computer", len(due))
	}
	var lines []string
	for _, r := range due {
		for _, ind := range r.Compromise {
			if len(lines) == 0 {
				title = "bordercheck: this computer may be compromised"
			}
			if len(lines) < maxLines {
				lines = append(lines, clean(r.ID)+": "+clip(clean(ind.What.English()), maxSummary))
			}
		}
	}
	if len(lines) > 0 {
		lines = append(lines, "Stop using it for work and tell your IT team now. Do not delete the item yourself.")
		return Message{Title: title, Body: strings.Join(lines, "\n")}
	}
	for i, r := range due {
		if i == maxLines {
			lines = append(lines, fmt.Sprintf("… and %d more", len(due)-maxLines))
			break
		}
		text := r.Summary
		if text == "" {
			text = r.Title
		}
		lines = append(lines, clean(r.ID)+": "+clip(clean(text), maxSummary))
	}
	lines = append(lines, "Run bordercheck in a terminal to see how to fix it.")
	return Message{Title: title, Body: strings.Join(lines, "\n")}
}

// Clean puts text from elsewhere on one line without control characters, and
// Clip shortens it to n characters, for showing it to the person.
func Clean(s string) string { return clean(s) }

func Clip(s string, n int) string { return clip(s, n) }

// clean puts text on one line and drops control characters.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}

// Show displays m as a desktop notification. It gives up after a few seconds;
// callers log the error and carry on, since a notification is never worth a
// failed report.
func Show(ctx context.Context, m Message) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return show(ctx, m)
}

// gvariantString quotes s as a GVariant text-format string, for gdbus.
func gvariantString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`)
	return "'" + r.Replace(s) + "'"
}

// run runs a command with extra environment variables, returning stderr's
// first line on failure.
func run(ctx context.Context, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if msg, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n"); msg != "" {
			return fmt.Errorf("%s: %s", name, msg)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
