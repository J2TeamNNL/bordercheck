package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// install.sh --dry-run against a local, signed fake release: it verifies the
// download and prints the bordercheck command it would run, which shows how an
// invite link and the options are passed through.
func TestInstallScriptDryRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is for macOS and Linux")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	// A stand-in binary: reports its version and accepts `verify` (used where
	// OpenSSL 3 is missing; the signature below is real either way).
	bin := []byte("#!/bin/sh\ncase $1 in -version) echo 'bordercheck v9.9.9' ;; verify) exit 0 ;; *) exit 3 ;; esac\n")
	sum := sha256.Sum256(bin)
	var sums strings.Builder
	for _, arch := range []string{"amd64", "arm64"} {
		sums.WriteString(hex.EncodeToString(sum[:]) + "  bordercheck-v9.9.9-" + runtime.GOOS + "-" + arch + "\n")
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sums.String())))
	key := base64.StdEncoding.EncodeToString(pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case strings.HasSuffix(p, "/releases/latest/download/SHA256SUMS"):
			w.Write([]byte(sums.String()))
		case strings.HasSuffix(p, "/releases/latest/download/SHA256SUMS.sig"):
			w.Write([]byte(sig + "\n"))
		case strings.Contains(p, "/releases/download/v9.9.9/bordercheck-v9.9.9-"):
			w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	run := func(args ...string) (string, error) {
		cmd := exec.Command("sh", append([]string{"install.sh"}, args...)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir(),
			"BORDERCHECK_GITHUB=" + srv.URL}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	const invite = "https://portal.example.com/i/abc123"

	for _, c := range []struct {
		args          []string
		want, notWant string
	}{
		{[]string{invite, "--dry-run", "--repo", "o/r", "--key", key},
			"would now run: bordercheck install " + invite + " -update-repo o/r -update-key " + key, "-email"},
		{[]string{"--dry-run", "--key", key, invite},
			"would now run: bordercheck install " + invite + " -update-key " + key, "-update-repo"},
		{[]string{"https://portal.example.com/policies.json", "--dry-run", "--repo", "o/r", "--key", key, "--email", "an@example.com"},
			"would now run: bordercheck install https://portal.example.com/policies.json -email an@example.com", "-update-"},
	} {
		out, err := run(c.args...)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, c.notWant) {
			t.Errorf("install.sh %v: %v\n%s", c.args, err, out)
		}
	}

	out, err := run(invite, "--email", "an@example.com", "--dry-run", "--key", key)
	if err == nil || !strings.Contains(out, "cannot be used with an invite link") {
		t.Errorf("--email with an invite: %v\n%s", err, out)
	}
	out, err = run("http://portal.example.com/i/abc123", "--dry-run")
	if err == nil || !strings.Contains(out, "https://") {
		t.Errorf("http invite: %v\n%s", err, out)
	}
}
