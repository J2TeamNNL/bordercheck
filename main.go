// Command bordercheck checks a work laptop for open doors: firewall, disk
// encryption, exposed ports, Tailscale, Docker and plain-text secrets. A plain
// run only reads and prints; `bordercheck install` sets it up to report to the
// organisation's endpoint on a schedule.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/agent"
	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/checks"
	"github.com/ptrinh/bordercheck/internal/guard"
	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/report"
)

var version = "dev" // set by -ldflags "-X main.version=..."

const usage = `Usage:
  bordercheck [-policy file] [-json] [-only id,id]   check this machine and print a report
  bordercheck install [policies-url] [-email you@work]
                                                     report to your organisation every hour as a service;
                                                     without a URL, uses policies.json beside the binary
  bordercheck install https://<portal>/i/<code> [-update-repo owner/name -update-key base64]
                                                     enroll with an invite link from IT (no email question);
                                                     run again without the link to finish an interrupted install
  bordercheck status                                 show the install and the last report sent
  bordercheck notifications                          macOS: let macOS ask whether BorderCheck may show its own
                                                     notifications (install asks when run in a terminal)
  bordercheck send [-force]                          what the service runs; -force sends a report now
  bordercheck update                                 refresh the policy and install a newer signed release now
  bordercheck uninstall
  bordercheck ignore [-check ID] <path> [-name NAME] -reason "why"
                                                     mark a finding of secrets, ai-agents (tokens) or ssh-keys
                                                     (no passphrase) as not sensitive: it no longer counts here,
                                                     and every report lists it with the reason
  bordercheck ignore -list                           what is ignored, and entries that no longer match anything
  bordercheck unignore [-check ID] <path> [-name NAME]
                                                     make it count again
  bordercheck fix                                    what to fix, with rules for an AI coding assistant
  bordercheck waiver request -check ID -until YYYY-MM-DD -reason "why" -accept-risk
                                                     enrolled installs: ask IT to exempt this machine from one
                                                     check until that day (at most a year)
  bordercheck waiver list                            those requests and IT's decisions
  bordercheck verify SHA256SUMS SHA256SUMS.sig [file...]
                                                     check downloaded release files against the signed checksums
  bordercheck -list | -print-policy | -version
  bordercheck help                                   the commands in plain words

The policy is read from -policy, then $BORDERCHECK_POLICY, then policies.json beside the binary,
else the built-in one. Exit status: 0 no failures, 1 at least one failure, 2 error.
`

func main() { os.Exit(run(os.Args[1:])) }

// help is what a person at the machine can run, in plain words; usage (-h)
// lists every option.
const help = `BorderCheck %s: checks this computer for open doors and says how to close each one.

Everyday
  bordercheck                    check this computer now and show what to fix (sends nothing)
  bordercheck status             is it installed, when it last reported, the link to your report page
  bordercheck open               open your report page in the browser (also: "BorderCheck" in Spotlight,
                                 the Start menu or your desktop's application menu)
  bordercheck fix                what to fix and how, written for an AI coding assistant to follow with you
  bordercheck full-scan          secrets left where the hourly check looks only in part: all AI chat history
                                 (Claude Code, Codex, Gemini CLI, Copilot, Cursor, Cline, Aider, opencode, Goose),
                                 Alfred's clipboard, logs, and the history of your git repositories;
                                 -verify asks each provider whether the tokens found still work
  bordercheck guard install      keep secrets out of Claude Code: stop prompts that hold one, refuse commands
                                 that print them, hide them in commands' output (bordercheck guard: status)
  bordercheck send -force        check now and send a fresh report to your organisation
  bordercheck update             get the newest policy and the newest version now
  bordercheck notifications      macOS: let BorderCheck show notifications under its own name
  bordercheck uninstall          remove BorderCheck from this computer (stops the reports too)

Secrets that are not sensitive
  bordercheck ignore ~/proj/.env -reason "local test database"
                                 stop counting what was found in that file (add -name VAR for one only);
                                 works for plain-text secrets, tokens in AI agent configs and SSH keys
                                 without a passphrase; IT still sees each one, with your reason, in every report
  bordercheck ignore -list       what you ignored, and what no longer matches anything
  bordercheck unignore ~/proj/.env
                                 count it again

Exceptions from IT
  bordercheck waiver request -check listeners -until 2026-12-31 -reason "Postgres for the billing project" -accept-risk
                                 ask IT to exempt this computer from one check until that day (at most a year);
                                 it counts as before until IT approves it in the portal
  bordercheck waiver list        your requests and IT's decisions

Looking closer
  bordercheck -only firewall,secrets    run only these checks
  bordercheck -list                     the checks and their IDs
  bordercheck -json                     the report as JSON
  bordercheck -print-policy             the rules in force on this computer

Setting up
  bordercheck install <invite link from IT, or a policies.json URL>
  bordercheck verify SHA256SUMS SHA256SUMS.sig [file...]

  bordercheck help               this list
  bordercheck -h                 every option

This copy: %s
%s
`

func runHelp() int {
	exe, err := os.Executable()
	if err != nil {
		exe = "bordercheck"
	}
	fmt.Printf(help, version, exe, report.Credit)
	return 0
}

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "help", "--help":
			return runHelp()
		case "install", "uninstall", "status", "open", "send", "setup", "update", "notifications":
			return runAgent(args[0], args[1:])
		case "fix":
			return runFix(args[1:])
		case "full-scan":
			return runFullScan(args[1:])
		case "chats":
			return runChats(args[1:])
		case "guard":
			return runGuard(args[1:])
		case "ignore", "unignore":
			return runIgnoreCommand(args[0], args[1:])
		case "verify":
			return runVerify(args[1:])
		case "waiver":
			return runWaiver(args[1:])
		}
	}
	// A word that is not a command or an option: say so, rather than running the checks.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		fmt.Fprintf(os.Stderr, "bordercheck: unknown command %q; run: bordercheck help\n", args[0])
		return 2
	}
	return runCheck(args)
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "bordercheck:", err)
	return 2
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("bordercheck", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage+"\nFlags:\n"); fs.PrintDefaults() }
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	only := fs.String("only", "", "run only these checks (comma-separated IDs, see -list)")
	list := fs.Bool("list", false, "list the checks and exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	policyPath := fs.String("policy", "", "policy JSON file")
	printPolicy := fs.Bool("print-policy", false, "print the policy in effect as JSON and exit; a starting point for your own")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion { // before the policy: self-update runs this to see that a new binary works
		fmt.Println("bordercheck", version)
		return 0
	}

	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return fail(err)
	}
	all := checks.AllWith(pol, localSettings())
	switch {
	case *printPolicy:
		if err := pol.WriteJSON(os.Stdout); err != nil {
			return fail(err)
		}
		return 0
	case *list:
		for _, c := range all {
			fmt.Printf("%-16s %s\n", c.ID, c.Title)
		}
		return 0
	}

	selected := all
	if *only != "" {
		byID := map[string]check.Check{}
		for _, c := range all {
			byID[c.ID] = c
		}
		selected = nil
		for _, id := range strings.Split(*only, ",") {
			id = strings.TrimSpace(id)
			if id == "tailscale" { // up to v0.4 Tailscale had a check of its own
				fmt.Fprintln(os.Stderr, "bordercheck: the tailscale check is now part of mesh-vpn; running mesh-vpn")
				id = "mesh-vpn"
			}
			c, ok := byID[id]
			if !ok {
				return fail(fmt.Errorf("unknown or disabled check %q (see -list)", id))
			}
			if slices.ContainsFunc(selected, func(s check.Check) bool { return s.ID == c.ID }) {
				continue
			}
			selected = append(selected, c)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// The first Ctrl-C asks the run to wind up; a second one ends the process,
	// whatever it is stuck on.
	go func() { <-ctx.Done(); stop() }()
	var progress check.Progress
	if isTerminal(os.Stderr) {
		progress = report.Progress(os.Stderr)
	}
	rep := report.New(version, pol.Name, pol.Waive(check.RunAllProgress(ctx, selected, progress), waiverIdentity(), time.Now()))
	if !pol.Report.CompromiseAlert {
		rep.DropCompromise()
	}
	if *jsonOut {
		if err := rep.WriteJSON(os.Stdout); err != nil {
			return fail(err)
		}
	} else {
		rep.WriteText(os.Stdout, useColor())
	}
	if rep.Counts.Fail > 0 {
		return 1
	}
	return 0
}

// runFix runs every check and prints the problems with instructions for an
// AI coding assistant to fix them together with the person at the machine. It
// only reads, like a plain run; the prompt on the portal's report page is
// "Run `bordercheck fix` and follow what it prints."
func runFix(args []string) int {
	fs := flag.NewFlagSet("bordercheck fix", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy JSON file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		return fail(fmt.Errorf("fix: unexpected argument %q", fs.Arg(0)))
	}
	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return fail(err)
	}
	if !pol.Report.FixPrompt {
		return fail(errors.New("fix is turned off by this computer's policy (report.fix_prompt); run bordercheck to see what to fix"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() { <-ctx.Done(); stop() }()
	var progress check.Progress
	if isTerminal(os.Stderr) {
		progress = report.Progress(os.Stderr)
	}
	rep := report.New(version, pol.Name, pol.Waive(check.RunAllProgress(ctx, checks.AllWith(pol, localSettings()), progress), waiverIdentity(), time.Now()))
	if !pol.Report.CompromiseAlert {
		rep.DropCompromise()
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "bordercheck"
	}
	installed := false
	if dir, err := agent.Dir(); err == nil {
		_, err := os.Stat(filepath.Join(dir, "config.json"))
		installed = err == nil
	}
	rep.WriteFix(os.Stdout, exe, installed)
	return 0
}

// loadPolicy finds the policy: the flag, then $BORDERCHECK_POLICY, then
// policies.json beside the binary, else the built-in one.
// runChats lists the secrets in AI assistants' chat history, all of it unless
// -hours says otherwise, by file and line, never the values. The secrets
// check reads only the last ai_chat_hours of it and points here. It only reads.
// Exit status 1 when something is found.
func runChats(args []string) int { return runFullScan(args) } // the name before v0.5.15

// runFullScan is `bordercheck full-scan`: every place a secret may have been
// left that the hourly check reads only in part or not at all: all of the AI
// assistants' chat history and the databases of tools that keep chats or a
// clipboard, log files, and the history of every git repository the secrets
// walk reaches. By file and line or commit, never the values. It only reads.
// Exit status 1 when something is found.
func runFullScan(args []string) int {
	fs := flag.NewFlagSet("bordercheck full-scan", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy JSON file")
	hours := fs.Int("hours", 0, "only chats and logs changed in this many hours (0: all); git history is read in full")
	jsonOut := fs.Bool("json", false, "print the findings as JSON (never the values)")
	noGit := fs.Bool("no-git", false, "leave git history out")
	verify := fs.Bool("verify", false, "ask each provider whether the tokens found still work: "+checks.VerifiableKinds()+
		" (each token goes only to the provider that issued it, with a read-only request; nothing is sent elsewhere)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		return fail(fmt.Errorf("full-scan: unexpected argument %q", fs.Arg(0)))
	}
	if *hours < 0 {
		return fail(errors.New("full-scan: -hours must not be negative"))
	}
	pol, err := loadPolicy(*policyPath)
	if err != nil {
		return fail(err)
	}
	var since time.Time
	what := "all of the AI chat history, chat and clipboard databases, and logs"
	if *hours > 0 {
		since = time.Now().Add(-time.Duration(*hours) * time.Hour)
		what = fmt.Sprintf("AI chats, chat and clipboard databases, and logs changed in the last %d hours", *hours)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	say := func(s string) {
		if isTerminal(os.Stderr) && !*jsonOut {
			fmt.Fprintln(os.Stderr, s)
		}
	}
	say("Reading " + what + "…")
	var tokens *checks.Tokens
	if *verify {
		tokens = checks.NewTokens()
		ctx = checks.WithTokens(ctx, tokens)
	}
	found, err := checks.ScanChatsAndLogs(ctx, pol.Checks.Secrets, since, true)
	if err != nil {
		return fail(err)
	}
	var git []checks.GitFinding
	repos, partial := 0, []string(nil)
	if !*noGit {
		say("Reading the history of the git repositories in your home folder…")
		if git, repos, partial, err = checks.ScanGitHistory(ctx, pol.Checks.Secrets); err != nil {
			return fail(err)
		}
	}
	if tokens != nil && tokens.Len() > 0 && ctx.Err() == nil {
		say(fmt.Sprintf("Asking the providers about %d token(s)…", tokens.Len()))
		checks.Annotate(tokens.Verify(ctx, nil), found, git)
	}
	if dir, err := agent.Dir(); err == nil && *hours == 0 && !*noGit && ctx.Err() == nil {
		_ = agent.RecordFullScan(dir, time.Now()) // only the date, so the hourly check stops suggesting it
	}
	home, _ := os.UserHomeDir()
	if *jsonOut {
		return writeFullScanJSON(os.Stdout, found, git, repos, partial, *hours, home, !*noGit)
	}
	code := writeChats(os.Stdout, found, *hours, what, home, false)
	if !*noGit {
		code = max(code, writeGit(os.Stdout, git, repos, partial))
	}
	settings := guard.SettingsPath(home)
	if _, err := os.Stat(filepath.Dir(settings)); code == 1 && err == nil && len(guard.Installed(settings)) < len(guard.Hooks) {
		fmt.Println("\nTo keep secrets out of Claude Code from now on (stop prompts that hold one, refuse commands that print them,\n" +
			"hide them in commands' output), run: bordercheck guard install")
	}
	return code
}

// writeGit prints the secrets found in git history; 1 when there are any.
func writeGit(w io.Writer, found []checks.GitFinding, repos int, partial []string) int {
	fmt.Fprintf(w, "\n== Git history (%d repositories)\n", repos)
	if len(partial) > 0 {
		fmt.Fprintf(w, "Read only in part (too large or too slow): %s\n", strings.Join(partial, ", "))
	}
	if len(found) == 0 {
		fmt.Fprintln(w, "No secrets found in git history.")
		return 0
	}
	fmt.Fprintf(w, "%d secret(s) in git history. Values are not shown.\n", len(found))
	for i, f := range found {
		fmt.Fprintf(w, "\n%3d. %s\n     Where: %s\n     State: %s\n", i+1, f.Item(), f.Where(), f.State())
		if f.Verified != "" {
			fmt.Fprintf(w, "     Key:   %s\n", checks.VerifiedText(f.Verified))
		}
	}
	fmt.Fprintf(w, "\n%s\n", checks.GitFix())
	return 1
}

// writeFullScanJSON prints both parts as JSON; the exit status is 1 when either found something.
func writeFullScanJSON(w io.Writer, chats []checks.ChatFinding, git []checks.GitFinding, repos int, partial []string, hours int, home string, withGit bool) int {
	type item struct {
		checks.ChatFinding
		App     string `json:"app"`
		Explain string `json:"explain"`
	}
	type gitPart struct {
		Repos    int                 `json:"repos"`
		Partial  []string            `json:"partial,omitempty"`
		Findings []checks.GitFinding `json:"findings"`
		Fix      string              `json:"fix,omitempty"`
	}
	out := struct {
		Hours    int      `json:"hours"` // 0: all; git history is always read in full
		Findings []item   `json:"findings"`
		Fix      string   `json:"fix,omitempty"`
		Git      *gitPart `json:"git,omitempty"`
	}{Hours: hours, Findings: []item{}}
	for _, f := range chats {
		out.Findings = append(out.Findings, item{f, f.App(), f.Explain(home)})
	}
	if len(chats) > 0 {
		out.Fix = checks.ChatFix()
	}
	if withGit {
		out.Git = &gitPart{Repos: repos, Partial: partial, Findings: append([]checks.GitFinding{}, git...)}
		if len(git) > 0 {
			out.Git.Fix = checks.GitFix()
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fail(err)
	}
	if len(chats)+len(git) > 0 {
		return 1
	}
	return 0
}

// runGuard is `bordercheck guard`: install, uninstall or show the Claude Code
// hooks (guard.Hooks); `guard prompt`, `guard command` and `guard output`
// are the hooks themselves.
func runGuard(args []string) int {
	home, err := os.UserHomeDir()
	if err != nil {
		return fail(err)
	}
	path := guard.SettingsPath(home)
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "prompt":
		return guardPrompt(os.Stdin, os.Stderr)
	case "command":
		return guardCommand(os.Stdin, os.Stderr)
	case "output":
		return guardOutput(os.Stdin, os.Stdout)
	case "install":
		bin, err := guardBinary()
		if err != nil {
			return fail(err)
		}
		changed, err := guard.Install(path, bin)
		if err != nil {
			return fail(err)
		}
		if changed {
			fmt.Printf("Added BorderCheck's hooks to %s. In Claude Code sessions started from now on:\n", tildePath(home, path))
		} else {
			fmt.Printf("BorderCheck's hooks are already in %s. In Claude Code:\n", tildePath(home, path))
		}
		fmt.Println("  - a prompt that holds a secret is stopped before it is sent, and you are told which (#allow-secret lets it through)\n" +
			"  - a command that prints secrets wholesale (env, cat .env, touchenv get…) is refused, with what to do instead\n" +
			"  - secrets in a command's output are replaced with ***REDACTED*** before the model sees them\n" +
			"Not covered: files the assistant reads or edits with its own tools (they must reach it as they are), and\n" +
			"what is already on disk: Claude Code's history keeps a stopped prompt and a command's original output;\n" +
			"bordercheck chats finds those. /hooks in Claude Code lists the hooks; bordercheck guard uninstall removes them.")
		return 0
	case "uninstall":
		changed, err := guard.Uninstall(path, "")
		if err != nil {
			return fail(err)
		}
		if changed {
			fmt.Printf("Removed BorderCheck's hooks from %s.\n", tildePath(home, path))
		} else {
			fmt.Println("BorderCheck's hooks are not set up; nothing to remove.")
		}
		return 0
	case "", "status":
		on := guard.Installed(path)
		if len(on) == 0 {
			fmt.Println("Off. bordercheck guard install makes Claude Code stop prompts that hold a secret, refuse commands\n" +
				"that print secrets, and hide secrets in commands' output.")
			return 0
		}
		fmt.Printf("In %s:\n", tildePath(home, path))
		for _, h := range guard.Hooks {
			state := "off"
			if on[h.Sub] {
				state = "on"
			}
			fmt.Printf("  %-8s %s (%s)\n", h.Sub, state, map[string]string{
				"prompt": "stops a prompt that holds a secret", "command": "refuses commands that print secrets",
				"output": "hides secrets in commands' output"}[h.Sub])
		}
		if len(on) < len(guard.Hooks) {
			fmt.Println("bordercheck guard install sets up the rest.")
		}
		return 0
	}
	return fail(fmt.Errorf("guard: unknown command %q; use install, uninstall or status", sub))
}

// guardBinary is the program the hook runs: the installed copy when there is
// one (it updates itself and stays where it is), else this one.
func guardBinary() (string, error) {
	if dir, err := agent.Dir(); err == nil {
		bin := filepath.Join(dir, map[bool]string{true: "bordercheck.exe", false: "bordercheck"}[runtime.GOOS == "windows"])
		if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
			if _, err := os.Stat(bin); err == nil {
				return bin, nil
			}
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// guardPrompt is the hook: Claude Code passes the prompt as JSON on stdin; a
// prompt holding a secret is refused with exit status 2 and the reason on
// stderr, which Claude Code shows. Anything going wrong lets the prompt
// through (status 0): a broken guard must not stop anyone from working.
func guardPrompt(in io.Reader, errOut io.Writer) int {
	var ev struct {
		Prompt string `json:"prompt"`
	}
	data, err := io.ReadAll(io.LimitReader(in, 8<<20))
	if err != nil || json.Unmarshal(data, &ev) != nil || ev.Prompt == "" || strings.Contains(ev.Prompt, guard.Allow) {
		return 0
	}
	pol, err := loadPolicy("")
	if err != nil {
		pol = policy.Default()
	}
	items, err := checks.SecretsInText(pol.Checks.Secrets, []byte(ev.Prompt))
	if err != nil || len(items) == 0 {
		return 0
	}
	fmt.Fprintln(errOut, guard.Reason(items))
	return 2
}

// guardCommand is the PreToolUse hook on Bash: a command that would print
// secrets wholesale (guard.Risky) is refused with exit status 2 and the
// reason on stderr, which Claude Code gives the assistant. Anything it cannot
// read goes ahead.
func guardCommand(in io.Reader, errOut io.Writer) int {
	var ev struct {
		ToolInput struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}
	data, err := io.ReadAll(io.LimitReader(in, 8<<20))
	if err != nil || json.Unmarshal(data, &ev) != nil {
		return 0
	}
	if why, bad := guard.Risky(ev.ToolInput.Command); bad {
		fmt.Fprintln(errOut, why)
		return 2
	}
	return 0
}

// guardOutput is the PostToolUse hook on Bash: secrets in the command's
// stdout and stderr are replaced with ***REDACTED*** in what the model sees
// (updatedToolOutput, the same object with those two fields changed). The
// other fields are passed on as they are. Anything it cannot read, or a
// command whose output holds no secret, is left alone (no output).
func guardOutput(in io.Reader, out io.Writer) int {
	var ev struct {
		ToolResponse json.RawMessage `json:"tool_response"`
	}
	data, err := io.ReadAll(io.LimitReader(in, 64<<20))
	if err != nil || json.Unmarshal(data, &ev) != nil || len(ev.ToolResponse) == 0 {
		return 0
	}
	pol, err := loadPolicy("")
	if err != nil {
		pol = policy.Default()
	}
	var items []string
	redact := func(s string) string {
		r, found, err := checks.Redact(pol.Checks.Secrets, s)
		if err != nil {
			return s
		}
		items = append(items, found...)
		return r
	}
	var updated any
	var asString string
	if json.Unmarshal(ev.ToolResponse, &asString) == nil {
		updated = redact(asString)
	} else {
		var obj map[string]json.RawMessage
		if json.Unmarshal(ev.ToolResponse, &obj) != nil {
			return 0
		}
		for _, k := range []string{"stdout", "stderr"} {
			var v string
			if raw, ok := obj[k]; ok && json.Unmarshal(raw, &v) == nil {
				if r := redact(v); r != v {
					obj[k], _ = json.Marshal(r)
				}
			}
		}
		updated = obj
	}
	if len(items) == 0 {
		return 0
	}
	reply := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":     "PostToolUse",
		"updatedToolOutput": updated,
		"additionalContext": "BorderCheck replaced " + strconv.Itoa(len(items)) + " secret(s) in this output with ***REDACTED*** (" +
			strings.Join(items, "; ") + "). The real values are unchanged wherever they came from; do not write ***REDACTED*** back anywhere.",
	}}
	if err := json.NewEncoder(out).Encode(reply); err != nil {
		return 0
	}
	return 0
}

func tildePath(home, p string) string {
	if rest, ok := strings.CutPrefix(p, home); ok && home != "" {
		return "~" + rest
	}
	return p
}

// writeChats prints what bordercheck chats found, as text or JSON, and
// returns the exit status: 1 when anything was found.
func writeChats(w io.Writer, found []checks.ChatFinding, hours int, what, home string, asJSON bool) int {
	if asJSON {
		type item struct {
			checks.ChatFinding
			App     string `json:"app"`
			Explain string `json:"explain"`
		}
		out := struct {
			Hours    int    `json:"hours"` // 0: all of the history
			Findings []item `json:"findings"`
			Fix      string `json:"fix,omitempty"`
		}{Hours: hours, Findings: []item{}}
		for _, f := range found {
			out.Findings = append(out.Findings, item{f, f.App(), f.Explain(home)})
		}
		if len(found) > 0 {
			out.Fix = checks.ChatFix()
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fail(err)
		}
		return min(len(found), 1)
	}
	if len(found) == 0 {
		fmt.Fprintf(w, "No secrets found in %s.\n", what)
		return 0
	}
	files := map[string]bool{}
	for _, f := range found {
		files[f.Path] = true
	}
	fmt.Fprintf(w, "%d secret(s) in %d conversation(s), in %s, newest first. Values are not shown.\n", len(found), len(files), what)
	for i, f := range found {
		fmt.Fprintf(w, "\n%3d. %s\n     Where: %s\n     What:  %s\n", i+1, f.Item(), f.Where(), f.Explain(home))
		if f.Verified != "" {
			fmt.Fprintf(w, "     Key:   %s\n", checks.VerifiedText(f.Verified))
		}
	}
	fmt.Fprintf(w, "\n%s\n", checks.ChatFix())
	return 1
}

func loadPolicy(path string) (policy.Policy, error) {
	for _, p := range []string{path, os.Getenv("BORDERCHECK_POLICY"), policy.NextToBinary()} {
		if p != "" {
			pol, err := policy.Load(p)
			if err != nil {
				return pol, fmt.Errorf("policy: %w", err)
			}
			return pol, nil
		}
	}
	return policy.Default(), nil
}

// waiverIdentity is who this machine is for the policy's waivers: the email and
// install ID of this user's install, if bordercheck is installed (read, never
// written), and the hostname. Uninstalled, no waiver applies: each names an
// email or install ID.
func waiverIdentity() policy.Identity {
	dir, err := agent.Dir()
	if err != nil {
		host, _ := os.Hostname()
		return policy.Identity{Hostname: host}
	}
	return agent.Identity(dir)
}

// localSettings is what the person at this computer has set in the install
// folder (the findings they ignored), read whether or not bordercheck is
// installed, so a plain run shows what the service reports.
func localSettings() checks.Local {
	dir, err := agent.Dir()
	if err != nil {
		return checks.Local{}
	}
	return agent.Local(dir)
}

func runAgent(cmd string, args []string) int {
	fs := flag.NewFlagSet("bordercheck "+cmd, flag.ContinueOnError)
	email := fs.String("email", "", "install: your work email (asked for when omitted); not with an invite link")
	updateRepo := fs.String("update-repo", "", "install with an invite link: take self-updates from this GitHub owner/name instead of the official one")
	updateKey := fs.String("update-key", "", "install with an invite link: the base64 ed25519 key those releases are signed with")
	force := fs.Bool("force", false, "send: send a report now even if one is not due")
	notifierZip := fs.String("notifier-zip", "", "install, notifications (macOS): install the notification app from this zip instead of the release's (for testing a build)")
	// Flags may come before or after the policies URL.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return 2
		}
		if args = fs.Args(); len(args) == 0 {
			break
		}
		positional, args = append(positional, args[0]), args[1:]
	}
	if max := map[bool]int{true: 1, false: 0}[cmd == "install"]; len(positional) > max {
		return fail(fmt.Errorf("%s: unexpected argument %q; see bordercheck -h", cmd, positional[max]))
	}
	policySrc := ""
	if len(positional) == 1 {
		policySrc = positional[0]
	}
	dir, err := agent.Dir()
	if err != nil {
		return fail(err)
	}
	env := agent.Env{Dir: dir, Version: version, Client: &http.Client{Timeout: time.Minute}, Out: os.Stdout}
	if isTerminal(os.Stdout) { // the report page link goes to a person, never to the log
		env.Term = os.Stdout
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// The first Ctrl-C asks the run to wind up; a second one ends the process,
	// whatever it is stuck on.
	go func() { <-ctx.Done(); stop() }()

	switch cmd {
	case "install":
		err = agent.Install(ctx, env, agent.InstallOptions{
			Policy: policySrc, Email: *email, In: os.Stdin, Ask: isTerminal(os.Stdin),
			UpdateRepo: *updateRepo, UpdateKey: *updateKey, NotifierZip: *notifierZip})
	case "uninstall":
		if err = agent.Uninstall(env); err == nil {
			fmt.Println("Uninstalled.")
		}
	case "status":
		var s string
		if s, err = agent.Status(env); err == nil {
			fmt.Print(s)
		}
	case "open":
		err = agent.Open(ctx, env)
	case "setup":
		err = agent.SetUp(ctx, env)
	case "send":
		// The service has no terminal: keep a log beside the install, trimmed when it grows.
		logPath := filepath.Join(dir, "bordercheck.log")
		if st, e := os.Stat(logPath); e == nil && st.Size() > 1<<20 {
			_ = os.Remove(logPath)
		}
		if f, e := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); e == nil {
			defer f.Close()
			env.Out = io.MultiWriter(os.Stdout, f)
		}
		err = agent.Send(ctx, env, *force)
	case "update":
		err = agent.Update(ctx, env)
	case "notifications":
		err = agent.Notifications(ctx, env, *notifierZip)
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stdout) {
		return false
	}
	return runtime.GOOS != "windows" || os.Getenv("WT_SESSION") != "" // legacy console has no ANSI
}
