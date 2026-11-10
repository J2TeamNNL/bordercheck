package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/update"
)

func TestVerifyRelease(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	bin := write("bordercheck-v1.2.3-linux-amd64", "binary")
	h := sha256.Sum256([]byte("binary"))
	sums := hex.EncodeToString(h[:]) + "  bordercheck-v1.2.3-linux-amd64\n"
	sumsPath := write("SHA256SUMS", sums)
	sigPath := write("SHA256SUMS.sig", base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sums)))+"\n")
	key := base64.StdEncoding.EncodeToString(pub)

	if err := verifyRelease(key, sumsPath, sigPath, []string{bin}); err != nil {
		t.Fatalf("good release: %v", err)
	}
	if err := verifyRelease(base64.StdEncoding.EncodeToString(otherPub), sumsPath, sigPath, nil); err == nil {
		t.Error("another key: want an error")
	}
	if err := verifyRelease("", sumsPath, sigPath, nil); err == nil {
		t.Error("the official key did not sign this: want an error")
	}
	write("bordercheck-v1.2.3-linux-amd64", "tampered")
	if err := verifyRelease(key, sumsPath, sigPath, []string{bin}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("tampered binary: got %v", err)
	}
	if err := verifyRelease(key, sumsPath, sigPath, []string{write("other", "x")}); err == nil {
		t.Error("unlisted file: want an error")
	}
}

// The install scripts pin the release key; they must pin the one this binary trusts.
func TestInstallScriptsPinOfficialKey(t *testing.T) {
	for file, re := range map[string]*regexp.Regexp{
		"install.sh":  regexp.MustCompile(`(?m)^OFFICIAL_KEY='([^']+)'`),
		"install.ps1": regexp.MustCompile(`(?m)^\$OfficialKey = '([^']+)'`),
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindSubmatch(data)
		if m == nil || string(m[1]) != update.OfficialKey {
			t.Errorf("%s pins %q, want update.OfficialKey %q", file, m, update.OfficialKey)
		}
	}
}
