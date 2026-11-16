package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
)

// The tests never run the touchenv installed on this machine.
func init() {
	touchenvRun = func(context.Context, ...string) (string, bool) { return "", false }
}

// fakeTouchenv answers by the arguments joined with spaces; a command not
// listed fails, as an older touchenv's "unknown" does.
func fakeTouchenv(t *testing.T, answers map[string]string) {
	t.Helper()
	old := touchenvRun
	t.Cleanup(func() { touchenvRun = old })
	touchenvRun = func(_ context.Context, args ...string) (string, bool) {
		out, ok := answers[strings.Join(args, " ")]
		return out, ok
	}
}

func TestLooksSensitive(t *testing.T) {
	for name, want := range map[string]bool{
		"STRIPE_LIVE_KEY": true, "DB_PROD_PASSWORD": true, "BORDERCHECK_SIGNING_KEY": true, "ASC_KEY_P8": true,
		"KIKI_KEYSTORE_PASSWORD": true, "AWS_ROOT_SECRET": true, "DEPLOY_TOKEN": true, "prod_api": true,
		"OPENAI_API_KEY": false, "MCP_TRINH_AUTH": false, "PRODUCT_ID": false, "STRIPE_TEST_KEY": false,
		"DB_STAGING_PASSWORD": false, "SIGNAL_TOKEN": false, "DEV_DEPLOY_TOKEN": false, "LIVELY": false,
	} {
		if got := looksSensitive(name, false); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	if !looksSensitive("GITHUB", true) {
		t.Error("an SSH private key is sensitive whatever its name")
	}
	if looksSensitive("SSH_TEST_KEY", true) {
		t.Error("a key named as a test key")
	}
}

func TestTouchenvInfoOnAMac(t *testing.T) {
	fakeTouchenv(t, map[string]string{
		"totp status": "codes: on since 16 Nov 2026 at 18:00\na code approves: a timed grant of synced secrets, at most 8 hours and 20 times\nlast used: never\n",
		"ls --synced": "OPENAI_API_KEY\nSTRIPE_LIVE_KEY\nSSH_ID_ED25519\nbad name\n",
		"ssh ls": "SSH_AUR         ED25519 256  SHA256:rjTQ  this Mac\n" +
			"SSH_ID_ED25519  ED25519 256  SHA256:3jaB  iCloud\n",
	})
	st := readTouchenv(context.Background(), "darwin")
	if st == nil || !st.codesOn || strings.Join(st.reach, ",") != "OPENAI_API_KEY,SSH_ID_ED25519,STRIPE_LIVE_KEY" || !st.ssh["SSH_ID_ED25519"] || st.ssh["SSH_AUR"] {
		t.Fatalf("%+v", st)
	}
	text, ev := touchenvInfo(st, "darwin")
	if len(text) != 2 || text[0].Key != "secrets.touchenvSensitive" || text[1].Key != "secrets.touchenvCodes" {
		t.Fatalf("%+v", text)
	}
	english := text.English()
	for _, want := range []string{"2 keys in touchenv that look highly sensitive", "touchenv unsync SSH_ID_ED25519 STRIPE_LIVE_KEY", "3 keys are within a code's reach"} {
		if !strings.Contains(english, want) {
			t.Errorf("no %q in %q", want, english)
		}
	}
	if len(ev) != 3 || ev[0] != "touchenv: OPENAI_API_KEY  [synced through iCloud, information]" ||
		ev[1] != "touchenv: SSH_ID_ED25519  [SSH private key, synced through iCloud, looks highly sensitive, information]" {
		t.Errorf("%q", ev)
	}
	// It is information: the status, the severity and the fix don't change.
	pass := check.Result{Status: check.Pass}.WithSummary(msg.Of("secrets.pass"))
	got := withTouchenvInfo(pass, text, ev)
	if got.Status != check.Pass || got.Severity != pass.Severity || len(got.Info) != 2 || len(got.Evidence) != 3 ||
		!strings.Contains(got.Summary, "touchenv unsync") || len(got.SummaryParts) != 3 || got.Fix != "" {
		t.Errorf("%+v", got)
	}
	fail := check.Result{Status: check.Fail, Severity: check.High, Evidence: []string{"~/.env  AWS key"}}.
		WithSummary(msg.Of("secrets.found", "n", 1, "files", 1)).WithFix(msg.Of("secrets.fix.keystore"))
	got = withTouchenvInfo(fail, text, ev)
	if got.Status != check.Fail || got.Severity != check.High || got.Fix != fail.Fix || got.Evidence[0] != "~/.env  AWS key" || len(got.Evidence) != 4 {
		t.Errorf("%+v", got)
	}
	if errored := withTouchenvInfo(check.Result{Status: check.Error, Summary: "boom"}, text, ev); errored.Summary != "boom" || errored.Info != nil {
		t.Errorf("%+v", errored)
	}
}

func TestTouchenvInfoQuietCases(t *testing.T) {
	// Not installed, or an older touchenv that knows none of the commands.
	if st := readTouchenv(context.Background(), "darwin"); st != nil {
		t.Fatalf("%+v", st)
	}
	if text, ev := touchenvInfo(nil, "darwin"); text != nil || ev != nil {
		t.Error("information without touchenv")
	}
	// Synced keys that don't look sensitive, codes off: nothing worth a line.
	fakeTouchenv(t, map[string]string{"totp status": "codes: off (touchenv totp setup turns them on: see docs/grants.md)\n",
		"ls --synced": "OPENAI_API_KEY\nMCP_TRINH_AUTH\n", "ssh ls": "no SSH keys in touchenv; add one: touchenv ssh add ~/.ssh/id_ed25519\n"})
	if text, _ := touchenvInfo(readTouchenv(context.Background(), "darwin"), "darwin"); text != nil {
		t.Errorf("%+v", text)
	}
	// touchenv 1.9.0 has no ls --synced: SSH keys are still seen.
	fakeTouchenv(t, map[string]string{"totp status": "codes: off\n", "ssh ls": "DEPLOY  RSA 4096  SHA256:x  iCloud\n"})
	text, ev := touchenvInfo(readTouchenv(context.Background(), "darwin"), "darwin")
	if len(text) != 1 || !strings.Contains(text.English(), "1 key in touchenv that looks highly sensitive") || len(ev) != 1 {
		t.Errorf("%+v %q", text, ev)
	}
	// Codes on with nothing in reach is still said.
	fakeTouchenv(t, map[string]string{"totp status": "codes: on since today\n"})
	if text, _ := touchenvInfo(readTouchenv(context.Background(), "darwin"), "darwin"); len(text) != 1 || text[0].Key != "secrets.touchenvCodes" {
		t.Errorf("%+v", text)
	}
}

func TestTouchenvInfoOnWindows(t *testing.T) {
	fakeTouchenv(t, map[string]string{"totp status": "codes: on since 16 Nov 2026 18:00\r\na code approves: a timed grant of the secrets below, at most 8 hours and 20 times\r\n" +
		"allowed from afar: DB_PROD_PASSWORD, OPENAI_API_KEY\r\nlast used: never\r\n",
		"ls --synced": "SHOULD_NOT_BE_ASKED\n"})
	st := readTouchenv(context.Background(), "windows")
	if st == nil || strings.Join(st.reach, ",") != "DB_PROD_PASSWORD,OPENAI_API_KEY" {
		t.Fatalf("%+v", st)
	}
	text, ev := touchenvInfo(st, "windows")
	if len(text) != 2 || text[0].Key != "secrets.touchenvSensitiveWin" || !strings.Contains(text.English(), "touchenv totp deny DB_PROD_PASSWORD") ||
		ev[0] != "touchenv: DB_PROD_PASSWORD  [allowed from afar, looks highly sensitive, information]" {
		t.Errorf("%+v %q", text, ev)
	}
	fakeTouchenv(t, map[string]string{"totp status": "codes: on since x\nallowed from afar: none yet (touchenv totp allow NAME ...)\n"})
	if st := readTouchenv(context.Background(), "windows"); st == nil || len(st.reach) != 0 {
		t.Fatalf("%+v", st)
	}
}
