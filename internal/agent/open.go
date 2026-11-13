package agent

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// openURL opens a link in the default browser; tests replace it.
var openURL = openBrowser

// errNoDesktop means there is no graphical session to open a browser in.
var errNoDesktop = errors.New("no graphical session")

// openBrowser hands link to the OS's opener as a single argument, never
// through a shell. Errors never include the link, which is a secret.
func openBrowser(ctx context.Context, link string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/bin/open", link)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", link)
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return errNoDesktop
		}
		p, err := exec.LookPath("xdg-open")
		if err != nil {
			return errNoDesktop
		}
		cmd = exec.CommandContext(ctx, p, link)
	default:
		return errNoDesktop
	}
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return errors.New("the browser opener exited with " + exit.ProcessState.String())
		}
		return errors.New("the browser opener did not run")
	}
	return nil
}

// reportPage returns link when it may be used as this machine's report page:
// https (or http to localhost when reports go there over http) on exactly the
// host reports are posted to. Otherwise "".
func reportPage(link, reportURL string) string {
	if link == "" || reportURL == "" {
		return ""
	}
	l, err := url.Parse(link)
	r, err2 := url.Parse(reportURL)
	if err != nil || err2 != nil || l.Host == "" || l.User != nil || !strings.EqualFold(l.Host, r.Host) {
		return ""
	}
	local := l.Hostname() == "localhost" || l.Hostname() == "127.0.0.1"
	if l.Scheme != "https" && !(l.Scheme == "http" && r.Scheme == "http" && local) {
		return ""
	}
	return l.String()
}

// Open opens this machine's report page in the default browser: `bordercheck
// open`, and what the entry in the OS's app search runs (see launcher). The
// link is the one the last report was answered with, checked as in reportPage.
func Open(ctx context.Context, env Env) error {
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		return fmt.Errorf("BorderCheck is not installed (%w); run: bordercheck install", err)
	}
	var st State
	_ = readJSON(filepath.Join(env.Dir, "state.json"), &st)
	pol, err := policy.Load(filepath.Join(env.Dir, policy.FileName))
	if err != nil {
		return err
	}
	bin := filepath.Join(env.Dir, binName())
	link := reportPage(st.ReportPage, pol.Report.URL)
	if link == "" {
		if st.LastSent.IsZero() {
			return fmt.Errorf("no report has been sent from this computer yet, so there is no report page. To see what BorderCheck finds, run: \"%s\"", bin)
		}
		return fmt.Errorf("%s gives this computer no report page. To see what BorderCheck finds, run: \"%s\"", hostOf(pol.Report.URL), bin)
	}
	if err := openURL(ctx, link); err != nil {
		if errors.Is(err, errNoDesktop) && env.Term != nil { // to a person, never to a log
			fmt.Fprintf(env.Term, "No browser to open here. Report page: %s (anyone with this link can see this machine's results)\n", link)
			return nil
		}
		return fmt.Errorf("opening the report page: %w", err)
	}
	fmt.Fprintln(env.Out, "Opened your report page in the browser.")
	return nil
}
