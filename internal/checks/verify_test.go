package checks

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// withVerifiers points the verifiers at a test server for the test's length.
func withVerifiers(t *testing.T, url string) {
	t.Helper()
	saved := verifiers
	t.Cleanup(func() { verifiers = saved })
	verifiers = map[string]verifier{}
	for k, v := range saved {
		v.url = url + "/" + strings.ReplaceAll(k, " ", "-")
		verifiers[k] = v
	}
}

func TestVerifyTokensFound(t *testing.T) {
	home := isolatedHome(t)
	liveTok := "sk_" + "live_" + strings.Repeat("a1B2", 8)
	deadTok := "npm_" + strings.Repeat("Ab1", 12)
	// Goose's database (a raw store) and a log, as in TestRawStoresAndLogs.
	writeTestFile(t, filepath.Join(home, ".local", "share", "goose", "sessions", "sessions.db"), "SQLite format 3\x00\x00binary "+liveTok+" \x00more")
	logDir := filepath.Join(t.TempDir(), "logs")
	t.Setenv("TMPDIR", logDir)
	t.Setenv("TEMP", logDir)
	t.Setenv("TMP", logDir)
	writeTestFile(t, filepath.Join(logDir, "app", "run.log"), "npm token "+deadTok+"\nagain "+deadTok+"\n")

	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		switch r.Header.Get("Authorization") {
		case "Bearer " + liveTok:
			w.WriteHeader(200)
		case "Bearer " + deadTok:
			w.WriteHeader(401)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	withVerifiers(t, srv.URL)

	tokens := NewTokens()
	ctx := WithTokens(t.Context(), tokens)
	chats, err := ScanChatsAndLogs(ctx, policy.Default().Checks.Secrets, time.Time{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.Len() != 2 {
		t.Fatalf("kept %d tokens, want 2 (the same token twice is asked about once)", tokens.Len())
	}
	Annotate(tokens.Verify(ctx, srv.Client()), chats, nil)
	got := map[string]string{}
	for _, f := range chats {
		got[f.Kind] = f.Verified
	}
	if got["Stripe live key"] != KeyLive || got["npm token"] != KeyInvalid {
		t.Errorf("verdicts %v", got)
	}
	if len(asked) != 2 || tokens.Len() != 0 {
		t.Errorf("asked %v; %d tokens still kept", asked, tokens.Len())
	}
}

func TestVerifyNotAskedFor(t *testing.T) {
	home := isolatedHome(t)
	writeTestFile(t, filepath.Join(home, ".local", "share", "goose", "sessions", "sessions.db"), "SQLite format 3\x00 sk_"+"live_"+strings.Repeat("a1B2", 8))
	chats, err := ScanChatsAndLogs(t.Context(), policy.Default().Checks.Secrets, time.Time{}, false)
	if err != nil || len(chats) != 1 || chats[0].tokenKey != "" || chats[0].Verified != "" {
		t.Errorf("without -verify: %+v %v", chats, err)
	}
}

func TestVerdicts(t *testing.T) {
	for status, want := range map[int]string{200: KeyLive, 204: KeyLive, 403: KeyLive, 429: KeyLive, 401: KeyInvalid, 404: KeyUnknown, 500: KeyUnknown} {
		if got := byStatus(status, nil); got != want {
			t.Errorf("byStatus(%d) = %s, want %s", status, got, want)
		}
	}
	slack := verifiers["Slack token"].verdict
	for body, want := range map[string]string{
		`{"ok":true}`: KeyLive, `{"ok":false,"error":"invalid_auth"}`: KeyInvalid,
		`{"ok":false,"error":"ratelimited"}`: KeyUnknown, `not json`: KeyUnknown,
	} {
		if got := slack(200, []byte(body)); got != want {
			t.Errorf("slack %s = %s, want %s", body, got, want)
		}
	}
	// Kinds with no way to verify (an AWS key needs its secret too) are not kept.
	if k := NewTokens().keep("AWS access key", "AKIA"+strings.Repeat("A", 16)); k != "" {
		t.Errorf("an AWS key was kept")
	}
	var none *Tokens
	if none.keep("GitHub token", "x") != "" {
		t.Error("a nil Tokens kept something")
	}
}
