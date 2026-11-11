package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/agent"
	"github.com/ptrinh/bordercheck/internal/checks"
	"github.com/ptrinh/bordercheck/internal/ignore"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// `bordercheck ignore` and `unignore`: the person at the machine marks a
// finding of secrets, ai-agents or ssh-keys as not sensitive (package ignore).

// ignoreEnv is what the commands need from outside, so tests can run them on
// a temporary folder and made-up findings.
type ignoreEnv struct {
	dir  string // install folder, where ignored.json lives
	pol  policy.Policy
	out  io.Writer
	scan func() ([]checks.Item, string, error) // the findings of the three checks, and the home folder
	now  time.Time
}

func runIgnoreCommand(cmd string, args []string) int {
	fs := flag.NewFlagSet("bordercheck "+cmd, flag.ContinueOnError)
	checkID := fs.String("check", "", "which check: "+strings.Join(ignore.Checks, ", ")+" (found from the path when left out)")
	name := fs.String("name", "", "only the finding with this name (variable, setting) or kind, as the report shows it")
	reason := fs.String("reason", "", "ignore: why this is not sensitive (required; IT sees it)")
	list := fs.Bool("list", false, "ignore: show what is ignored on this computer")
	policyPath := fs.String("policy", "", "policy JSON file")
	var positional []string
	for { // flags may come before or after the path
		if err := fs.Parse(args); err != nil {
			return 2
		}
		if args = fs.Args(); len(args) == 0 {
			break
		}
		positional, args = append(positional, args[0]), args[1:]
	}
	if *checkID != "" && !slices.Contains(ignore.Checks, *checkID) {
		return fail(fmt.Errorf("-check must be one of %s", strings.Join(ignore.Checks, ", ")))
	}
	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return fail(err)
	}
	dir, err := agent.Dir()
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	env := ignoreEnv{dir: dir, pol: pol, out: os.Stdout, now: time.Now(),
		scan: func() ([]checks.Item, string, error) { return checks.IgnorableItems(ctx, pol) }}
	switch {
	case cmd == "ignore" && *list:
		if len(positional) > 0 || *name != "" || *reason != "" || *checkID != "" {
			return fail(errors.New("ignore -list takes nothing else"))
		}
		err = ignoreList(env)
	case len(positional) != 1 && cmd == "ignore":
		return fail(errors.New(`usage: bordercheck ignore [-check ID] <path> [-name NAME] -reason "why", or bordercheck ignore -list`))
	case len(positional) != 1:
		return fail(errors.New("usage: bordercheck unignore [-check ID] <path> [-name NAME]"))
	case cmd == "ignore":
		err = ignoreAdd(env, *checkID, positional[0], *name, *reason)
	default:
		if *reason != "" {
			return fail(errors.New("unignore takes no -reason"))
		}
		err = ignoreRemove(env, *checkID, positional[0], *name)
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

// userIgnoreAllowed is the policy switch of each check that takes the list.
func userIgnoreAllowed(pol policy.Policy, id string) (allowed, enabled bool) {
	c := pol.Checks
	switch id {
	case "secrets":
		return c.Secrets.UserIgnore, c.Secrets.IsEnabled()
	case "ai-agents":
		return c.AIAgents.UserIgnore, c.AIAgents.IsEnabled()
	case "ssh-keys":
		return c.SSHKeys.UserIgnore, c.SSHKeys.IsEnabled()
	}
	return false, false
}

// describe names a finding the way the report does: kind, and its name if any.
func describe(it checks.Item) string {
	if len(it.Names) > 0 && it.Names[0] != it.Kind {
		return it.Kind + " (" + it.Names[0] + ")"
	}
	return it.Kind
}

// blockedWhy says why a finding cannot be ignored here, and what to do instead.
func blockedWhy(it checks.Item) string {
	what := it.Path + "  " + describe(it)
	switch it.Blocked {
	case checks.BlockedProduction:
		return what + " is marked [production], so it cannot be ignored here: ask IT to waive it, or to change " +
			"checks.secrets.production_keywords or ignore_paths if it is not production"
	case checks.BlockedGuardrail:
		return what + " is an AI agent guardrail (approvals or the sandbox), not a secret, so it cannot be ignored: " +
			"turn the setting back, or ask IT for a waiver"
	case checks.BlockedPerms:
		return what + ": other users can read this key file, and that cannot be ignored; it is a one-line fix: chmod 600 " + quoteArg(it.Path)
	case checks.BlockedAuthorized:
		return what + ": who can log in to this computer is for IT to decide, so it cannot be ignored here; " +
			"remove the line, or ask IT to allow it (checks.ssh-keys.allow_keys or a waiver)"
	case checks.BlockedSSHConfig:
		return what + ": an SSH client setting cannot be ignored; change it in that file, or ask IT for a waiver"
	}
	return what + " cannot be ignored here"
}

func ignoreAdd(env ignoreEnv, checkID, path, name, reason string) error {
	if err := ignore.CheckReason(reason); err != nil {
		return err
	}
	reason = ignore.OneLine(reason)
	name = strings.TrimSpace(name)
	entries, err := ignore.Load(env.dir)
	if err != nil {
		return fmt.Errorf("your list of ignored findings cannot be read (%v); delete %s and add the entries again", err, ignore.FileName)
	}
	items, home, err := env.scan()
	if err != nil {
		return fmt.Errorf("could not run the checks: %w", err)
	}
	shown, err := ignore.Shown(path, home)
	if err != nil {
		return err
	}
	// Which check: the one given, else the one with findings in that file.
	var inFile []checks.Item
	var found []string
	for _, it := range items {
		if ignore.SamePath(it.Path, shown, home) && (checkID == "" || it.Check == checkID) {
			inFile = append(inFile, it)
			if !slices.Contains(found, it.Check) {
				found = append(found, it.Check)
			}
		}
	}
	switch {
	case len(inFile) == 0 && checkID != "":
		return fmt.Errorf("the %s check finds nothing in %s right now, so there is nothing to ignore; run: bordercheck -only %s", checkID, shown, checkID)
	case len(inFile) == 0:
		return fmt.Errorf("bordercheck finds nothing in %s right now that can be ignored (%s are the checks that take it); run: bordercheck -only %s",
			shown, strings.Join(ignore.Checks, ", "), strings.Join(ignore.Checks, ","))
	case len(found) > 1:
		return fmt.Errorf("both %s find something in %s; say which with -check", strings.Join(found, " and "), shown)
	}
	checkID = found[0]
	switch allowed, enabled := userIgnoreAllowed(env.pol, checkID); {
	case !enabled:
		return fmt.Errorf("the %s check is turned off by this computer's policy, so there is nothing to ignore", checkID)
	case !allowed:
		return fmt.Errorf("this computer's policy does not allow ignoring findings of the %s check (checks.%s.user_ignore); ask IT for a waiver instead", checkID, checkID)
	}
	entry := ignore.Entry{Check: checkID, Path: inFile[0].Path, Name: name, Reason: reason, Since: env.now.Format("2006-01-02")}
	var covered, blocked []checks.Item
	for _, it := range inFile {
		if entry.Covers(it.Check, it.Path, it.Names, it.Kind, home) {
			if it.Blocked != "" {
				blocked = append(blocked, it)
			} else {
				covered = append(covered, it)
			}
		}
	}
	switch {
	case len(covered)+len(blocked) == 0:
		var names []string
		for _, it := range inFile {
			names = append(names, describe(it))
		}
		return fmt.Errorf("nothing called %q in %s; what the %s check finds there: %s", name, entry.Path, checkID, strings.Join(uniq(names), ", "))
	case len(covered) == 0:
		return errors.New(blockedWhy(blocked[0]))
	}
	replaced := false
	for i, e := range entries {
		if e.Check == entry.Check && ignore.SamePath(e.Path, entry.Path, home) && e.Name == entry.Name {
			entries[i], replaced = entry, true
		}
	}
	if !replaced {
		if len(entries) >= ignore.MaxEntries {
			return fmt.Errorf("at most %d entries; remove some with bordercheck unignore", ignore.MaxEntries)
		}
		entries = append(entries, entry)
	}
	if err := ignore.Save(env.dir, entries); err != nil {
		return err
	}
	what := entry.Path
	if name != "" {
		what += " (" + name + ")"
	}
	fmt.Fprintf(env.out, "Ignored %s for the %s check: %s on this computer.\n", what, checkID, plural(len(covered), "1 finding no longer counts", "%d findings no longer count"))
	fmt.Fprintf(env.out, "IT will see %s in the report, with your reason: %s\n", plural(len(covered), "it", "them"), reason)
	if len(blocked) > 0 {
		fmt.Fprintf(env.out, "%s; for example: %s.\n", plural(len(blocked), "1 finding there still counts", "%d findings there still count"), blockedWhy(blocked[0]))
	}
	undo := "bordercheck unignore -check " + checkID + " " + quoteArg(entry.Path)
	if name != "" {
		undo += " -name " + quoteArg(name)
	}
	fmt.Fprintln(env.out, "To undo: "+undo)
	return nil
}

func ignoreRemove(env ignoreEnv, checkID, path, name string) error {
	entries, err := ignore.Load(env.dir)
	if err != nil {
		return fmt.Errorf("your list of ignored findings cannot be read (%v); delete %s to start again", err, ignore.FileName)
	}
	home, _ := os.UserHomeDir()
	shown, err := ignore.Shown(path, home)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	var kept []ignore.Entry
	removed := 0
	for _, e := range entries {
		if ignore.SamePath(e.Path, shown, home) && (name == "" || e.Name == name) && (checkID == "" || e.Check == checkID) {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	if removed == 0 {
		if name != "" {
			shown += " (" + name + ")"
		}
		return fmt.Errorf("nothing is ignored for %s; see: bordercheck ignore -list", shown)
	}
	if err := ignore.Save(env.dir, kept); err != nil {
		return err
	}
	fmt.Fprintf(env.out, "Removed %s: %s counts again from the next check.\n", plural(removed, "1 entry", "%d entries"), shown)
	return nil
}

func ignoreList(env ignoreEnv) error {
	entries, err := ignore.Load(env.dir)
	if err != nil {
		fmt.Fprintf(env.out, "Your list of ignored findings cannot be read (%v), so nothing is ignored.\nDelete %s and add the entries again.\n",
			err, ignore.FileName)
		return nil
	}
	if len(entries) == 0 {
		fmt.Fprintln(env.out, "Nothing is ignored on this computer.")
		return nil
	}
	items, home, err := env.scan()
	if err != nil {
		return fmt.Errorf("could not run the checks: %w", err)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Check != entries[j].Check {
			return slices.Index(ignore.Checks, entries[i].Check) < slices.Index(ignore.Checks, entries[j].Check)
		}
		return entries[i].Path < entries[j].Path
	})
	stale := 0
	for _, e := range entries {
		n := 0
		for _, it := range items {
			if it.Blocked == "" && e.Covers(it.Check, it.Path, it.Names, it.Kind, home) {
				n++
			}
		}
		line := fmt.Sprintf("[%s] %s", e.Check, e.Path)
		if e.Name != "" {
			line += " (" + e.Name + ")"
		}
		line += ": " + e.Reason
		if e.Since != "" {
			line += " (since " + e.Since + ")"
		}
		switch allowed, _ := userIgnoreAllowed(env.pol, e.Check); {
		case !allowed:
			line += "  [not applied: the policy does not allow it]"
		case n == 0:
			line += "  [stale: matches nothing now]"
			stale++
		default:
			line += "  [" + plural(n, "1 finding", "%d findings") + "]"
		}
		fmt.Fprintln(env.out, "  "+line)
	}
	fmt.Fprintln(env.out, "These do not count on this computer; every report lists them with your reasons for IT.")
	if stale > 0 {
		fmt.Fprintf(env.out, "%s nothing now (kept in case the finding comes back); remove with bordercheck unignore <path>.\n",
			plural(stale, "1 stale entry matches", "%d stale entries match"))
	}
	return nil
}

// plural picks one when n is 1, else other with n in place of %d.
func plural(n int, one, other string) string {
	if n == 1 {
		return one
	}
	return fmt.Sprintf(other, n)
}

func uniq(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// quoteArg quotes a path for a shell when it needs it.
func quoteArg(s string) string {
	if !strings.ContainsAny(s, " \t'\"$`\\()&;|<>*?!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
