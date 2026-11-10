package agent

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
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
