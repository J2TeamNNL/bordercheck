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
	"path/filepath"
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
	srv, key := signedInstallerRelease(t, runtime.GOOS, []byte("#!/bin/sh\nexit 97\n"))

	runWithPath := func(path string, args ...string) (string, error) {
		cmd := exec.Command("sh", append([]string{"install.sh"}, args...)...)
		cmd.Env = []string{"PATH=" + path, "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir(),
			"BORDERCHECK_GITHUB=" + srv.URL}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	run := func(args ...string) (string, error) { return runWithPath(os.Getenv("PATH"), args...) }
	const invite = "https://portal.example.com/i/abc123"

	// Remove OpenSSL from PATH without changing the machine's installation.
	noVerifier := t.TempDir()
	for _, name := range []string{"uname", "mktemp", "rm", "sysctl", "grep"} {
		if src, err := exec.LookPath(name); err == nil {
			if err := os.Symlink(src, filepath.Join(noVerifier, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if out, err := runWithPath(noVerifier, invite, "--dry-run"); err == nil || !strings.Contains(out, "OpenSSL with Ed25519 support is required") {
		t.Fatalf("missing verifier: %v\n%s", err, out)
	}
	out, err := run(invite, "--dry-run", "--key", key)
	if err != nil && strings.Contains(out, "OpenSSL with Ed25519 support is required") {
		t.Skip("trusted OpenSSL with Ed25519 support is needed for the signed release cases")
	}
	otherKey, _, _ := ed25519.GenerateKey(nil)
	if out, err := run(invite, "--dry-run", "--key", base64.StdEncoding.EncodeToString(otherKey)); err == nil ||
		!strings.Contains(out, "NOT signed") || strings.Contains(out, "Downloading bordercheck") {
		t.Fatalf("wrong signing key: %v\n%s", err, out)
	}

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

	out, err = run(invite, "--email", "an@example.com", "--dry-run", "--key", key)
	if err == nil || !strings.Contains(out, "cannot be used with an invite link") {
		t.Errorf("--email with an invite: %v\n%s", err, out)
	}
	out, err = run("http://portal.example.com/i/abc123", "--dry-run")
	if err == nil || !strings.Contains(out, "https://") {
		t.Errorf("http invite: %v\n%s", err, out)
	}
}

func TestWindowsInstallScriptDryRun(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is unavailable")
	}
	srv, key := signedInstallerRelease(t, "windows", []byte("This signed fixture is not executable."))
	run := func(path, key string) (string, error) {
		cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "install.ps1",
			"-PolicyUrl", "https://portal.example.com/i/abc123", "-Key", key, "-DryRun")
		cmd.Env = append(os.Environ(), "PATH="+path, "BORDERCHECK_GITHUB="+srv.URL)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(t.TempDir(), key); err == nil || !strings.Contains(out, "OpenSSL with Ed25519 support is required") {
		t.Fatalf("missing verifier: %v\n%s", err, out)
	}
	if _, err := exec.LookPath("openssl.exe"); err != nil {
		t.Skip("trusted openssl.exe is needed for the signed release cases")
	}
	if out, err := run(os.Getenv("PATH"), key); err != nil || !strings.Contains(out, "Verified v9.9.9. Dry run") {
		t.Fatalf("valid signature: %v\n%s", err, out)
	}
	otherKey, _, _ := ed25519.GenerateKey(nil)
	if out, err := run(os.Getenv("PATH"), base64.StdEncoding.EncodeToString(otherKey)); err == nil ||
		!strings.Contains(out, "could not verify SHA256SUMS") || strings.Contains(out, "Downloading bordercheck") {
		t.Fatalf("wrong signing key: %v\n%s", err, out)
	}
}

func signedInstallerRelease(t *testing.T, goos string, bin []byte) (*httptest.Server, string) {
	t.Helper()
	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}
	sum := sha256.Sum256(bin)
	var sums strings.Builder
	for _, arch := range []string{"amd64", "arm64"} {
		sums.WriteString(hex.EncodeToString(sum[:]) + "  bordercheck-v9.9.9-" + goos + "-" + arch + ext + "\n")
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
	t.Cleanup(srv.Close)
	return srv, key
}
