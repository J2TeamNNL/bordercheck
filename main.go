// Command bordercheck checks a work laptop for open doors: firewall, disk
// encryption, exposed ports, Tailscale, Docker and plain-text secrets. A plain
// run only reads and prints; `bordercheck install` sets it up to report to the
// organisation's endpoint on a schedule.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/agent"
	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/checks"
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
  bordercheck send [-force]                          what the service runs; -force sends a report now
  bordercheck update                                 refresh the policy and install a newer signed release now
  bordercheck uninstall
  bordercheck verify SHA256SUMS SHA256SUMS.sig [file...]
                                                     check downloaded release files against the signed checksums
  bordercheck -list | -print-policy | -version

The policy is read from -policy, then $BORDERCHECK_POLICY, then policies.json beside the binary,
else the built-in one. Exit status: 0 no failures, 1 at least one failure, 2 error.
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "install", "uninstall", "status", "send", "update":
			return runAgent(args[0], args[1:])
		case "verify":
			return runVerify(args[1:])
		}
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
	all := checks.All(pol)
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
			c, ok := byID[strings.TrimSpace(id)]
			if !ok {
				return fail(fmt.Errorf("unknown or disabled check %q (see -list)", id))
			}
			selected = append(selected, c)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep := report.New(version, pol.Name, pol.Waive(check.RunAll(ctx, selected), waiverIdentity(), time.Now()))
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

// loadPolicy finds the policy: the flag, then $BORDERCHECK_POLICY, then
// policies.json beside the binary, else the built-in one.
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

func runAgent(cmd string, args []string) int {
	fs := flag.NewFlagSet("bordercheck "+cmd, flag.ContinueOnError)
	email := fs.String("email", "", "install: your work email (asked for when omitted); not with an invite link")
	updateRepo := fs.String("update-repo", "", "install with an invite link: take self-updates from this GitHub owner/name instead of the official one")
	updateKey := fs.String("update-key", "", "install with an invite link: the base64 ed25519 key those releases are signed with")
	force := fs.Bool("force", false, "send: send a report now even if one is not due")
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

	switch cmd {
	case "install":
		err = agent.Install(ctx, env, agent.InstallOptions{
			Policy: policySrc, Email: *email, In: os.Stdin, Ask: isTerminal(os.Stdin),
			UpdateRepo: *updateRepo, UpdateKey: *updateKey})
	case "uninstall":
		if err = agent.Uninstall(env); err == nil {
			fmt.Println("Uninstalled.")
		}
	case "status":
		var s string
		if s, err = agent.Status(env); err == nil {
			fmt.Print(s)
		}
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
