package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Key verification, for `bordercheck full-scan -verify` only: each provider
// token found is sent to the provider that issued it, with a read-only request
// that costs nothing (list models, who am I), to learn whether it still works.
// The hourly check never does this. Values are kept in memory for the length
// of the scan, keyed by a hash; findings carry only that hash.

// Verdicts of a verification.
const (
	KeyLive    = "live"    // the provider accepted it: it works now
	KeyInvalid = "invalid" // the provider refused it: revoked, expired or made up
	KeyUnknown = "unknown" // no clear answer (network, rate limit, an unexpected reply)
)

// Tokens collects the provider tokens a scan finds, when verification was asked for.
type Tokens struct {
	mu sync.Mutex
	m  map[string]token // by tokenKey
}

type token struct{ kind, value string }

// NewTokens is an empty collection.
func NewTokens() *Tokens { return &Tokens{m: map[string]token{}} }

type tokensKey struct{}

// WithTokens makes the scans run with ctx keep the provider tokens they find in t.
func WithTokens(ctx context.Context, t *Tokens) context.Context {
	return context.WithValue(ctx, tokensKey{}, t)
}

func tokensFrom(ctx context.Context) *Tokens {
	t, _ := ctx.Value(tokensKey{}).(*Tokens)
	return t
}

// tokenKey is how a finding refers to its token without holding it.
func tokenKey(kind, value string) string {
	h := sha256.Sum256([]byte(kind + "\x00" + value))
	return hex.EncodeToString(h[:12])
}

// keep remembers a token of a kind that can be verified; "" when it is not kept.
func (t *Tokens) keep(kind, value string) string {
	if t == nil || verifiers[kind].url == "" {
		return ""
	}
	k := tokenKey(kind, value)
	t.mu.Lock()
	t.m[k] = token{kind, value}
	t.mu.Unlock()
	return k
}

// Len is how many different tokens were kept.
func (t *Tokens) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// verifier asks a provider whether a token works.
type verifier struct {
	method, url string
	auth        func(r *http.Request, v string)
	// verdict reads the status (and, where the status says nothing, the body).
	verdict func(status int, body []byte) string
}

func bearer(r *http.Request, v string) { r.Header.Set("Authorization", "Bearer "+v) }

// byStatus: 2xx works; 401 does not. 403 (allowed in, not to this) and 429
// (rate limit, no quota left) mean the provider knows the key.
func byStatus(status int, _ []byte) string {
	switch {
	case status >= 200 && status < 300, status == 403, status == 429:
		return KeyLive
	case status == 401:
		return KeyInvalid
	}
	return KeyUnknown
}

var verifiers = map[string]verifier{
	"GitHub token":   {"GET", "https://api.github.com/user", bearer, byStatus},
	"OpenAI API key": {"GET", "https://api.openai.com/v1/models", bearer, byStatus},
	"Anthropic API key": {"GET", "https://api.anthropic.com/v1/models", func(r *http.Request, v string) {
		r.Header.Set("x-api-key", v)
		r.Header.Set("anthropic-version", "2023-06-01")
	}, byStatus},
	// A restricted key may not read the balance (403), but Stripe knows it.
	"Stripe live key": {"GET", "https://api.stripe.com/v1/balance", bearer, byStatus},
	"npm token":       {"GET", "https://registry.npmjs.org/-/whoami", bearer, byStatus},
	// Slack answers 200 either way; the body says.
	"Slack token": {"POST", "https://slack.com/api/auth.test", bearer, func(status int, body []byte) string {
		var r struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if status != 200 || json.Unmarshal(body, &r) != nil {
			return KeyUnknown
		}
		switch {
		case r.OK:
			return KeyLive
		case r.Error == "invalid_auth" || r.Error == "token_revoked" || r.Error == "account_inactive" || r.Error == "token_expired" || r.Error == "not_authed":
			return KeyInvalid
		}
		return KeyUnknown
	}},
}

// VerifiableKinds names the kinds -verify can check, for help text.
func VerifiableKinds() string {
	return "GitHub, OpenAI, Anthropic, Stripe, Slack and npm tokens"
}

// Verify asks each provider about each token kept, a few at a time, and
// returns the verdict by token key. The values are forgotten afterwards.
func (t *Tokens) Verify(ctx context.Context, client *http.Client) map[string]string {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	t.mu.Lock()
	todo := t.m
	t.m = map[string]token{}
	t.mu.Unlock()
	out := make(map[string]string, len(todo))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for k, tok := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			v := verifyOne(ctx, client, tok)
			mu.Lock()
			out[k] = v
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func verifyOne(ctx context.Context, client *http.Client, tok token) string {
	vf := verifiers[tok.kind]
	if vf.url == "" || strings.ContainsAny(tok.value, " \r\n\t") {
		return KeyUnknown
	}
	req, err := http.NewRequestWithContext(ctx, vf.method, vf.url, nil)
	if err != nil {
		return KeyUnknown
	}
	req.Header.Set("User-Agent", "bordercheck-verify")
	vf.auth(req, tok.value)
	resp, err := client.Do(req)
	if err != nil {
		return KeyUnknown
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return vf.verdict(resp.StatusCode, body)
}

// Annotate sets Verified on the findings whose token has a verdict.
func Annotate(verdicts map[string]string, chats []ChatFinding, git []GitFinding) {
	for i := range chats {
		if v, ok := verdicts[chats[i].tokenKey]; ok {
			chats[i].Verified = v
		}
	}
	for i := range git {
		if v, ok := verdicts[git[i].tokenKey]; ok {
			git[i].Verified = v
		}
	}
}

// VerifiedText is how a verdict is shown next to a finding.
func VerifiedText(v string) string {
	switch v {
	case KeyLive:
		return "LIVE: the provider accepted it just now. Delete the copies; replace it at the provider only if it was pushed, shared or sent somewhere"
	case KeyInvalid:
		return "dead: the provider refused it (revoked, expired or not real); deleting the copies is enough"
	case KeyUnknown:
		return "unknown: the provider gave no clear answer"
	}
	return ""
}
