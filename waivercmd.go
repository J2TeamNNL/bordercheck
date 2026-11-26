package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/ptrinh/bordercheck/internal/agent"
)

const waiverUsage = `Usage:
  bordercheck waiver request -check ID -until YYYY-MM-DD -reason "why" -accept-risk
                         ask IT to exempt this machine from one check until that day (at most a year);
                         IT approves or rejects it in the portal
  bordercheck waiver list
                         this machine's requests and IT's decisions
`

// runWaiver: `bordercheck waiver request|list`, for an install enrolled with
// an invite link (the requests go to that portal, with the install's token).
func runWaiver(args []string) int {
	if len(args) == 0 || (args[0] != "request" && args[0] != "list") {
		fmt.Fprint(os.Stderr, waiverUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("bordercheck waiver "+sub, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, waiverUsage+"\nFlags:\n"); fs.PrintDefaults() }
	var w agent.WaiverRequest
	if sub == "request" {
		fs.StringVar(&w.Check, "check", "", "the check's ID (see bordercheck -list)")
		fs.StringVar(&w.Until, "until", "", "the last day of the waiver, YYYY-MM-DD")
		fs.StringVar(&w.Reason, "reason", "", "why this machine needs the exception (IT sees it)")
		fs.BoolVar(&w.AcceptRisk, "accept-risk", false, "you accept the risk of this check being exempted until then (required)")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		return fail(fmt.Errorf("waiver %s: unexpected argument %q; see bordercheck waiver", sub, fs.Arg(0)))
	}
	dir, err := agent.Dir()
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	env := agent.Env{Dir: dir, Version: version, Client: &http.Client{Timeout: time.Minute}, Out: os.Stdout}
	if sub == "request" {
		err = agent.RequestWaiver(ctx, env, w)
	} else {
		var s string
		if s, err = agent.WaiverRequests(ctx, env); err == nil {
			fmt.Print(s)
		}
	}
	if err != nil {
		return fail(err)
	}
	return 0
}
