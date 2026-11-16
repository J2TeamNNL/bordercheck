package checks

// What touchenv (github.com/ptrinh/touch-env) holds outside the fingerprint
// lock, as information on the secrets check: keys synced through iCloud (a
// Mac) or allowed from afar (Windows) are guarded by touchenv's own check, and
// can be granted with a code from an authenticator app when codes are on. A
// key that looks highly sensitive (an SSH key, a production or signing key) is
// safest kept on this computer only, so those are named with how to move
// them. It never counts against the computer.
//
// Only commands that never ask for Touch ID or Windows Hello are run:
// "touchenv totp status" (1.9.0+), "touchenv ssh ls" and, on a Mac,
// "touchenv ls --synced". An older touchenv answers "unknown" to the ones it
// lacks, before any prompt.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
)

// touchenvState is what touchenv said. reach: the names outside the
// fingerprint lock; ssh: which of them are SSH private keys.
type touchenvState struct {
	codesOn bool
	reach   []string
	ssh     map[string]bool
}

// touchenvRun runs touchenv with args and returns what it printed; ok is
// false when it isn't installed or the command failed.
var touchenvRun = func(ctx context.Context, args ...string) (string, bool) {
	bin := touchenvPath()
	if bin == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = nil
	out, err := cmd.Output()
	return string(out), err == nil
}

// touchenvPath finds touchenv where its installers put it, then on PATH.
func touchenvPath() string {
	home, _ := os.UserHomeDir()
	var places []string
	if runtime.GOOS == "windows" {
		places = []string{filepath.Join(os.Getenv("ProgramFiles"), "touchenv", "touchenv.exe")}
	} else {
		places = []string{"/Applications/touchenv.app/Contents/MacOS/touchenv",
			filepath.Join(home, "Applications/touchenv.app/Contents/MacOS/touchenv")}
	}
	for _, p := range places {
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			return p
		}
	}
	if p, err := exec.LookPath("touchenv"); err == nil {
		return p
	}
	return ""
}

func validSecretName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i, c := range name {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// readTouchenv asks touchenv; nil when it isn't installed or says nothing
// to report.
func readTouchenv(ctx context.Context, goos string) *touchenvState {
	st := &touchenvState{ssh: map[string]bool{}}
	seen := map[string]bool{}
	add := func(name string) {
		if validSecretName(name) && !seen[name] {
			seen[name] = true
			st.reach = append(st.reach, name)
		}
	}
	if out, ok := touchenvRun(ctx, "totp", "status"); ok {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "codes: on") {
				st.codesOn = true
			}
			// Windows: the keys a code may grant, kept by the service outside Windows Hello.
			if names, ok := strings.CutPrefix(line, "allowed from afar: "); ok && goos == "windows" && !strings.HasPrefix(names, "none") {
				for _, n := range strings.Split(names, ",") {
					add(strings.TrimSpace(n))
				}
			}
		}
	}
	if goos == "darwin" {
		if out, ok := touchenvRun(ctx, "ls", "--synced"); ok {
			for _, line := range strings.Split(out, "\n") {
				add(strings.TrimSpace(line))
			}
		}
		// SSH keys: "NAME  ED25519 256  SHA256:…  iCloud" (or "this Mac").
		if out, ok := touchenvRun(ctx, "ssh", "ls"); ok {
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(line)
				if len(f) >= 5 && f[len(f)-1] == "iCloud" && strings.HasPrefix(f[len(f)-2], "SHA256:") {
					add(f[0])
					st.ssh[f[0]] = true
				}
			}
		}
	}
	if !st.codesOn && len(st.reach) == 0 {
		return nil
	}
	sort.Strings(st.reach)
	return st
}

// Words in a key's name that mark it as one to keep behind the fingerprint
// lock, and words that say it is not the real thing.
var (
	sensitiveWords = map[string]bool{"PROD": true, "PRODUCTION": true, "LIVE": true, "SIGNING": true, "SIGN": true,
		"PRIVATE": true, "ROOT": true, "ADMIN": true, "MASTER": true, "DEPLOY": true, "RELEASE": true, "KEYSTORE": true,
		"SSH": true, "P8": true, "PEM": true, "PAYMENT": true, "PAYMENTS": true, "STRIPE": true, "BANK": true, "WALLET": true,
		"MNEMONIC": true, "SEED": true}
	harmlessWords = map[string]bool{"TEST": true, "TESTING": true, "DEV": true, "DEVELOPMENT": true, "STAGING": true,
		"STAGE": true, "SANDBOX": true, "DEMO": true, "EXAMPLE": true, "LOCAL": true}
)

// looksSensitive: an SSH private key, or a name that says production,
// signing, admin or payments and doesn't say test.
func looksSensitive(name string, sshKey bool) bool {
	words := strings.FieldsFunc(strings.ToUpper(name), func(r rune) bool { return r == '_' })
	hit := sshKey
	for _, w := range words {
		if harmlessWords[w] {
			return false
		}
		hit = hit || sensitiveWords[w]
	}
	return hit
}

// touchenvInfo is the information for the secrets check: the headline and
// the evidence lines, nil when there is nothing to say.
func touchenvInfo(st *touchenvState, goos string) (msg.Text, []string) {
	if st == nil {
		return nil, nil
	}
	how, where := "touchenv unsync", "synced through iCloud"
	if goos == "windows" {
		how, where = "touchenv totp deny", "allowed from afar"
	}
	var sensitive, ev []string
	for _, name := range st.reach {
		label := where
		if st.ssh[name] {
			label = "SSH private key, " + where
		}
		if looksSensitive(name, st.ssh[name]) {
			sensitive = append(sensitive, name)
			label += ", looks highly sensitive"
		}
		ev = append(ev, "touchenv: "+name+"  ["+label+", information]")
	}
	var text msg.Text
	switch {
	case len(sensitive) > 0 && goos == "windows":
		text = msg.Of("secrets.touchenvSensitiveWin", "n", len(sensitive), "cmd", how+" "+strings.Join(sensitive, " "))
	case len(sensitive) > 0:
		text = msg.Of("secrets.touchenvSensitive", "n", len(sensitive), "cmd", how+" "+strings.Join(sensitive, " "))
	}
	if st.codesOn {
		text = append(text, msg.P("secrets.touchenvCodes", "n", len(st.reach)))
	}
	if len(text) == 0 {
		return nil, nil // synced keys that don't look sensitive, codes off: nothing worth a line
	}
	return text, ev
}

// withTouchenvInfo adds touchenv's information to the secrets result. The
// status, the severity and the fix stay as they are.
func withTouchenvInfo(r check.Result, text msg.Text, ev []string) check.Result {
	if len(text) == 0 || r.Status == check.Error {
		return r
	}
	r.Info = append(r.Info, text...)
	r.Evidence = capEvidence(append(r.Evidence, ev...))
	if r.SummaryParts == nil && r.Summary != "" { // a summary without parts stays as it is: Info still carries this
		return r
	}
	return r.WithSummary(append(r.SummaryParts[:len(r.SummaryParts):len(r.SummaryParts)], text...))
}
