// Package update replaces an installed bordercheck with the latest GitHub
// release of its repo, but only a binary whose hash is listed in a SHA256SUMS
// signed by a key this binary trusts. Taking over the GitHub account is not
// enough to push code to installed machines; the signing key is also needed.
//
// It reads releases/latest/download/SHA256SUMS (served by GitHub's CDN, not the
// rate-limited API) and takes the version from the asset name,
// bordercheck-<version>-<os>-<arch>[.exe].
package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// OfficialKey is the base64 ed25519 public key that signs the SHA256SUMS of
// github.com/ptrinh/bordercheck releases. A policy may name another key for a fork.
const OfficialKey = "Q5Mw8yJQUgKSEtPNBVNnEP7HiSvhwT2y9Te4mEPOlcs="

// Source is where releases come from.
type Source struct {
	GitHub    string // "https://github.com"; tests point it elsewhere
	Repo      string // owner/name
	PublicKey string // base64 ed25519; "" = OfficialKey
}

type Result struct {
	Current, Latest string
	Updated         bool
}

// Run installs the latest release over bin when it is newer than current.
func Run(ctx context.Context, client *http.Client, src Source, current, bin string) (Result, error) {
	res := Result{Current: current}
	if _, _, ok := parseVersion(current); !ok {
		return res, fmt.Errorf("this is a %q build, not a release; it does not update itself", current)
	}
	key, err := publicKey(src.PublicKey)
	if err != nil {
		return res, err
	}
	latest := src.GitHub + "/" + src.Repo + "/releases/latest/download/"
	sums, err := get(ctx, client, latest+"SHA256SUMS", 64<<10)
	if err != nil {
		return res, err
	}
	sig, err := get(ctx, client, latest+"SHA256SUMS.sig", 1<<10)
	if err != nil {
		return res, err
	}
	rawSig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(key, sums, rawSig) {
		return res, errors.New("SHA256SUMS of the latest release is not signed by the trusted key; not updating")
	}
	name, version, want, err := findAsset(sums)
	if err != nil {
		return res, err
	}
	res.Latest = version
	if !newer(version, current) {
		return res, nil
	}
	data, err := get(ctx, client, src.GitHub+"/"+src.Repo+"/releases/download/"+version+"/"+name, 200<<20)
	if err != nil {
		return res, err
	}
	if got := sha256.Sum256(data); !bytes.Equal(got[:], want) {
		return res, fmt.Errorf("%s does not match its SHA256SUMS entry; not updating", name)
	}
	if err := replace(ctx, bin, data, version); err != nil {
		return res, err
	}
	res.Updated = true
	return res, nil
}

func publicKey(b64 string) (ed25519.PublicKey, error) {
	if b64 == "" {
		b64 = OfficialKey
	}
	if b64 == "" {
		return nil, errors.New("no update signing key: this build has none and the policy sets no update.public_key")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("update.public_key is not a base64 ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// AssetSuffix is how release assets for this OS and architecture end.
func AssetSuffix() string {
	s := "-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		s += ".exe"
	}
	return s
}

// findAsset finds this platform's binary in SHA256SUMS ("<hex>  <name>" lines).
func findAsset(sums []byte) (name, version string, hash []byte, err error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		n := strings.TrimPrefix(f[1], "*")
		v, ok := strings.CutPrefix(n, "bordercheck-")
		if !ok || !strings.HasSuffix(v, AssetSuffix()) {
			continue
		}
		h, err := hex.DecodeString(f[0])
		if err != nil || len(h) != sha256.Size {
			return "", "", nil, fmt.Errorf("bad SHA256SUMS line for %s", n)
		}
		return n, strings.TrimSuffix(v, AssetSuffix()), h, nil
	}
	return "", "", nil, fmt.Errorf("the latest release has no binary for %s/%s", runtime.GOOS, runtime.GOARCH)
}

func get(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return data, err
}

// replace puts data at bin once it has shown it runs and reports version.
// Windows cannot overwrite a running .exe but can rename it, so the old one is
// moved aside to bin.old and removed on the next update.
func replace(ctx context.Context, bin string, data []byte, version string) error {
	tmp := bin + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tmp, "-version").Output()
	if err != nil || !strings.Contains(string(out), version) {
		os.Remove(tmp)
		return fmt.Errorf("the new binary did not run as %s; keeping the current one", version)
	}
	if runtime.GOOS == "windows" {
		old := bin + ".old"
		_ = os.Remove(old)
		if err := os.Rename(bin, old); err != nil && !errors.Is(err, os.ErrNotExist) {
			os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, bin)
}

// parseVersion reads vMAJOR.MINOR.PATCH[-pre].
func parseVersion(v string) (nums [3]int, pre string, ok bool) {
	core, pre, _ := strings.Cut(strings.TrimPrefix(v, "v"), "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return nums, "", false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nums, "", false
		}
		nums[i] = n
	}
	return nums, pre, true
}

// newer reports whether version a is later than b. Unparsable versions are never newer.
func newer(a, b string) bool {
	na, pa, okA := parseVersion(a)
	nb, pb, okB := parseVersion(b)
	if !okA || !okB {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return na[i] > nb[i]
		}
	}
	switch {
	case pa == pb:
		return false
	case pa == "":
		return true // a release beats its pre-releases
	case pb == "":
		return false
	}
	return pa > pb
}
