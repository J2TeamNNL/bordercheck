package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type release struct {
	version string
	binary  []byte
	sums    []byte
	sig     []byte
}

func newRelease(t *testing.T, priv ed25519.PrivateKey, version string, binary []byte) release {
	t.Helper()
	h := sha256.Sum256(binary)
	sums := fmt.Sprintf("%s  bordercheck-%s-plan9-mips\n%s  bordercheck-%s%s\n",
		strings.Repeat("0", 64), version, hex.EncodeToString(h[:]), version, AssetSuffix())
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sums)))
	return release{version, binary, []byte(sums), []byte(sig)}
}

func serve(t *testing.T, r release) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/o/r/releases/latest/download/SHA256SUMS":
			w.Write(r.sums)
		case "/o/r/releases/latest/download/SHA256SUMS.sig":
			w.Write(r.sig)
		case "/o/r/releases/download/" + r.version + "/bordercheck-" + r.version + AssetSuffix():
			w.Write(r.binary)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func keys(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub), priv
}

func installed(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "bordercheck")
	if err := os.WriteFile(bin, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestRunUpdates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake binary is a shell script")
	}
	pub, priv := keys(t)
	srv := serve(t, newRelease(t, priv, "v0.3.0", []byte("#!/bin/sh\necho bordercheck v0.3.0\n")))
	bin := installed(t)
	res, err := Run(t.Context(), srv.Client(), Source{srv.URL, "o/r", pub}, "v0.2.1", bin)
	if err != nil || !res.Updated || res.Latest != "v0.3.0" {
		t.Fatalf("got %+v, %v", res, err)
	}
	if data, _ := os.ReadFile(bin); !strings.Contains(string(data), "v0.3.0") {
		t.Errorf("binary not replaced: %q", data)
	}
}

func TestRunRefuses(t *testing.T) {
	pub, priv := keys(t)
	otherPub, _ := keys(t)
	good := newRelease(t, priv, "v0.3.0", []byte("#!/bin/sh\necho bordercheck v0.3.0\n"))
	tampered := good
	tampered.binary = []byte("#!/bin/sh\necho evil\n")
	broken := newRelease(t, priv, "v0.3.0", []byte("#!/bin/sh\nexit 1\n"))

	for name, tc := range map[string]struct {
		r       release
		key     string
		current string
		wantErr string
	}{
		"wrong signing key":  {good, otherPub, "v0.2.0", "not signed"},
		"tampered binary":    {tampered, pub, "v0.2.0", "does not match"},
		"binary doesn't run": {broken, pub, "v0.2.0", "did not run"},
		"dev build":          {good, pub, "dev", "not a release"},
		"same version":       {good, pub, "v0.3.0", ""},
		"newer installed":    {good, pub, "v0.4.0", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS == "windows" && tc.wantErr == "did not run" {
				t.Skip("the fake binary is a shell script")
			}
			bin := installed(t)
			srv := serve(t, tc.r)
			res, err := Run(t.Context(), srv.Client(), Source{srv.URL, "o/r", tc.key}, tc.current, bin)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantErr)
			}
			if data, _ := os.ReadFile(bin); string(data) != "old" || res.Updated {
				t.Errorf("binary replaced: %q, %+v", data, res)
			}
		})
	}
}

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"v0.3.0", "v0.2.9", true},
		{"v0.10.0", "v0.9.0", true},
		{"v1.0.0", "v1.0.0-rc.1", true},
		{"v1.0.0-rc.2", "v1.0.0-rc.1", true},
		{"v1.0.0-rc.1", "v1.0.0", false},
		{"v0.2.0", "v0.2.0", false},
		{"v0.1.0", "v0.2.0", false},
		{"v1.0.0", "dev", false},
		{"garbage", "v0.1.0", false},
	} {
		if got := newer(tc.a, tc.b); got != tc.want {
			t.Errorf("newer(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}
