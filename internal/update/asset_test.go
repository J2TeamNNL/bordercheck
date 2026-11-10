package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FetchAsset (the macOS notification app) is held to the rules of a binary
// update: signed SHA256SUMS, matching hash, and the release asked for.
func TestFetchAsset(t *testing.T) {
	pub, priv := keys(t)
	otherPub, _ := keys(t)
	asset := []byte("PK zip bytes")
	h := sha256.Sum256(asset)
	name := "bordercheck-notifier-v0.4.0-darwin-universal.zip"
	sums := hex.EncodeToString(h[:]) + "  " + name + "\n"
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sums)))
	served := asset
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/o/r/releases/download/v0.4.0/SHA256SUMS":
			w.Write([]byte(sums))
		case "/o/r/releases/download/v0.4.0/SHA256SUMS.sig":
			w.Write([]byte(sig))
		case "/o/r/releases/download/v0.4.0/" + name:
			w.Write(served)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	src := Source{srv.URL, "o/r", pub}

	got, err := FetchAsset(t.Context(), srv.Client(), src, "v0.4.0", name, 1<<20)
	if err != nil || string(got) != string(asset) {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := FetchAsset(t.Context(), srv.Client(), Source{srv.URL, "o/r", otherPub}, "v0.4.0", name, 1<<20); err == nil ||
		!strings.Contains(err.Error(), "not signed") {
		t.Errorf("another key: %v", err)
	}
	if _, err := FetchAsset(t.Context(), srv.Client(), src, "v0.4.0", "bordercheck-notifier-v0.4.0-other.zip", 1<<20); err == nil ||
		!strings.Contains(err.Error(), "not listed") {
		t.Errorf("unlisted: %v", err)
	}
	if _, err := FetchAsset(t.Context(), srv.Client(), src, "dev", name, 1<<20); err == nil {
		t.Error("a dev version was fetched")
	}
	if _, err := FetchAsset(t.Context(), srv.Client(), src, "v0.4.0", name, 4); err == nil {
		t.Error("over the size limit")
	}
	served = []byte("swapped")
	if _, err := FetchAsset(t.Context(), srv.Client(), src, "v0.4.0", name, 1<<20); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Errorf("swapped asset: %v", err)
	}
}

// The notification app's zip in SHA256SUMS is never taken for a binary.
func TestFindAssetSkipsTheNotifierZip(t *testing.T) {
	sums := strings.Repeat("1", 64) + "  bordercheck-notifier-v0.4.0-darwin-universal.zip\n" +
		strings.Repeat("2", 64) + "  bordercheck-v0.4.0" + AssetSuffix() + "\n"
	name, version, _, err := findAsset([]byte(sums))
	if err != nil || name != "bordercheck-v0.4.0"+AssetSuffix() || version != "v0.4.0" {
		t.Errorf("got %q %q %v", name, version, err)
	}
}
