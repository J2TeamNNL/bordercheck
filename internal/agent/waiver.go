package agent

// Waiver requests: `bordercheck waiver request` asks the portal this install
// is enrolled with to exempt this machine from one check until a date, and
// `bordercheck waiver list` shows what IT decided. Both go to the portal with
// the install's token, the way reports do: to that portal only, over https,
// without following redirects.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ptrinh/bordercheck/internal/notify"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// MaxWaiverReason is the longest reason the portal keeps.
const MaxWaiverReason = 300

// WaiverRequest is what the person asks IT for.
type WaiverRequest struct {
	Check      string `json:"check"`
	Until      string `json:"until"`
	Reason     string `json:"reason"`
	AcceptRisk bool   `json:"accept_risk"`
}

// Validate checks a request the way the portal will, against the local date,
// so a mistake is caught before anything is sent.
func (w WaiverRequest) Validate(now time.Time) error {
	if !policy.IsCheckID(w.Check) {
		return fmt.Errorf("-check %q is not a check ID; see bordercheck -list", w.Check)
	}
	if strings.TrimSpace(w.Reason) == "" {
		return errors.New(`-reason is required: say why this machine needs the exception (IT sees it)`)
	}
	if utf8.RuneCountInString(strings.TrimSpace(w.Reason)) > MaxWaiverReason {
		return fmt.Errorf("-reason is longer than %d characters", MaxWaiverReason)
	}
	until, err := time.Parse(policy.DateFormat, w.Until)
	if err != nil {
		return fmt.Errorf(`-until must be the last day of the waiver, like "2026-12-01", not %q`, w.Until)
	}
	today, _ := time.Parse(policy.DateFormat, now.Format(policy.DateFormat))
	maxDays := int(policy.MaxWaiver.Hours() / 24)
	switch {
	case until.Before(today):
		return fmt.Errorf("-until %s is in the past", w.Until)
	case until.After(today.AddDate(0, 0, maxDays)):
		return fmt.Errorf("-until %s is more than %d days ahead; waivers are temporary", w.Until, maxDays)
	case !w.AcceptRisk:
		return errors.New("add -accept-risk to state that you accept the risk of this check being exempted on this machine until then")
	}
	return nil
}

// RequestWaiver sends the request to the portal and says what happens next.
func RequestWaiver(ctx context.Context, env Env, w WaiverRequest) error {
	if err := w.Validate(time.Now()); err != nil {
		return err
	}
	w.Reason = strings.TrimSpace(w.Reason)
	var answer struct {
		RequestID int64 `json:"request_id"`
	}
	host, err := portalCall(ctx, env, http.MethodPost, w, &answer)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Out, "Asked %s for a waiver of %s until %s (request #%d).\n"+
		"Until IT approves it the check counts as before. See the decision with: bordercheck waiver list\n",
		host, w.Check, w.Until, answer.RequestID)
	return nil
}

// WaiverRequests lists this machine's requests, newest first.
func WaiverRequests(ctx context.Context, env Env) (string, error) {
	var answer struct {
		Data []struct {
			ID           int64  `json:"request_id"`
			Check        string `json:"check"`
			Until        string `json:"until"`
			Reason       string `json:"reason"`
			Status       string `json:"status"`
			RequestedAt  string `json:"requested_at"`
			DecisionNote string `json:"decision_note"`
		} `json:"data"`
	}
	host, err := portalCall(ctx, env, http.MethodGet, nil, &answer)
	if err != nil {
		return "", err
	}
	if len(answer.Data) == 0 {
		return fmt.Sprintf("No waiver requests from this machine on %s.\n", host), nil
	}
	var b strings.Builder
	for _, r := range answer.Data {
		status := map[string]string{"pending": "waiting for IT", "approved": "approved", "rejected": "rejected"}[r.Status]
		if status == "" {
			status = "unknown"
		}
		fmt.Fprintf(&b, "#%d %s until %s: %s (asked %s)\n", r.ID, notify.Clip(notify.Clean(r.Check), 64),
			day(r.Until), status, day(r.RequestedAt))
		fmt.Fprintf(&b, "    why: %s\n", notify.Clip(notify.Clean(r.Reason), MaxWaiverReason))
		if n := notify.Clean(r.DecisionNote); n != "" {
			fmt.Fprintf(&b, "    IT: %s\n", notify.Clip(n, MaxWaiverReason))
		}
	}
	return b.String(), nil
}

// day is the YYYY-MM-DD at the start of a date the portal sent.
func day(s string) string {
	s = notify.Clean(s)
	if len(s) > 10 {
		s = s[:10]
	}
	return s
}

// portalCall sends body (nil for GET) to the enrolled portal's
// /waiver-requests with the install's token and decodes the answer into out.
// It returns the portal's host, for messages.
func portalCall(ctx context.Context, env Env, method string, body, out any) (string, error) {
	var cfg Config
	if err := readJSON(filepath.Join(env.Dir, "config.json"), &cfg); err != nil {
		return "", fmt.Errorf("BorderCheck is not installed (%w); run: bordercheck install", err)
	}
	if cfg.Enrollment == nil {
		return "", errors.New("waiver requests go to the portal a machine is enrolled with, and this one was installed from a policies.json; ask IT for the waiver instead")
	}
	tok, err := credentials(env, cfg)
	if err != nil {
		return "", err
	}
	target := tok.portal + "/waiver-requests"
	host := hostOf(target)
	if err := tok.allows(target); err != nil {
		return host, err
	}
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return host, err
		}
		rd = bytes.NewReader(data)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return host, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "bordercheck/"+env.Version)
	req.Header.Set("Authorization", "Bearer "+tok.token)
	resp, err := noRedirects(env.Client).Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return host, fmt.Errorf("could not reach %s: %v", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return host, authError(resp, host)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return host, fmt.Errorf("reading the answer from %s: %v", host, err)
	}
	if resp.StatusCode/100 != 2 {
		var e struct{ Message string }
		_ = json.Unmarshal(data, &e)
		if m := notify.Clean(e.Message); m != "" {
			return host, fmt.Errorf("%s refused the request: %s", host, notify.Clip(m, 300))
		}
		if resp.StatusCode == http.StatusNotFound {
			return host, fmt.Errorf("%s does not take waiver requests yet; ask IT for the waiver instead", host)
		}
		return host, fmt.Errorf("%s answered %s", host, resp.Status)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return host, fmt.Errorf("%s answered with something BorderCheck cannot read", host)
	}
	return host, nil
}
