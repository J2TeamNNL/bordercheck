package agent

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPortalEndToEnd enrolls against a real receiver and sends a report. It is
// skipped unless BORDERCHECK_E2E_INVITE holds an unused invite link from a
// receiver started with
//
//	npx wrangler dev --local-protocol https
//
// (its certificate is self-signed, so this test alone skips verification). The
// service, the browser and notifications are the fakes from TestMain; the
// checks are real, so give the invite a role whose policy turns off the checks
// you do not want to run here.
func TestPortalEndToEnd(t *testing.T) {
	link := os.Getenv("BORDERCHECK_E2E_INVITE")
	if link == "" {
		t.Skip("set BORDERCHECK_E2E_INVITE to an unused invite link")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	origin := u.Scheme + "://" + u.Host
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	out := &strings.Builder{}
	env := Env{Dir: filepath.Join(t.TempDir(), "bordercheck"), Version: "v0.0.0-e2e", Client: client, Out: out}

	if err := Install(t.Context(), env, InstallOptions{Policy: link}); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	cfg := readCfg(t, env)
	e := cfg.Enrollment
	if e == nil || e.Pending || e.Portal != origin || e.PolicyURL != origin+"/policy" || cfg.Email == "" || len(cfg.InstallID) != 32 {
		t.Fatalf("config %+v %+v", cfg, e)
	}
	token, err := os.ReadFile(filepath.Join(env.Dir, TokenFile))
	if err != nil || len(strings.TrimSpace(string(token))) < 32 {
		t.Fatalf("token file: %v", err)
	}
	tok := strings.TrimSpace(string(token))
	t.Logf("enrolled as %s, role %s", cfg.Email, e.Role)

	// The first report went with the install, and the receiver answered with
	// this machine's report page.
	st := readState(t, env)
	if st.LastSent.IsZero() || !strings.HasPrefix(st.ReportPage, origin+"/r/") {
		t.Fatalf("state %+v\n%s", st, out)
	}

	// Running install again finishes from what is saved; the spent code is not sent again.
	if err := Install(t.Context(), env, InstallOptions{Policy: link}); err != nil {
		t.Fatalf("second install: %v\n%s", err, out)
	}
	if again := readCfg(t, env); again.InstallID != cfg.InstallID {
		t.Fatalf("install ID changed from %s to %s", cfg.InstallID, again.InstallID)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatalf("send: %v\n%s", err, out)
	}

	// The report page needs no login and shows this machine, not the token.
	res, err := client.Get(readState(t, env).ReportPage)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	page, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(page), cfg.Email) {
		t.Fatalf("report page: %d\n%.600s", res.StatusCode, page)
	}
	status, err := Status(env)
	if err != nil {
		t.Fatal(err)
	}
	noToken(t, env, tok, out.String(), string(page), status)
	t.Logf("status:\n%s", strings.ReplaceAll(status, readState(t, env).ReportPage, origin+"/r/<id>"))

	// The same invite cannot enroll a second machine.
	other := Env{Dir: filepath.Join(t.TempDir(), "bordercheck"), Version: "v0.0.0-e2e", Client: client, Out: io.Discard}
	if err := Install(t.Context(), other, InstallOptions{Policy: link}); err == nil {
		t.Fatal("a used invite enrolled a second machine")
	} else {
		t.Logf("second machine refused: %v", err)
	}
}
