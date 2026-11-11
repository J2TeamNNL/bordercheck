package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

const (
	sshMaxKeyFile    = 64 << 10
	sshMaxConfigFile = 256 << 10
	sshMaxIncludes   = 16
)

// sshKey is what bordercheck learns about one private key file. It never
// holds key material.
type sshKey struct {
	path      string // as shown, ~ for the home folder
	format    string // "OpenSSH", "PEM", "PKCS#8", "PuTTY"
	keyType   string // e.g. "ssh-ed25519", "RSA"; "" if unknown
	encrypted bool
	hardware  bool        // a FIDO/Secure Enclave stub: useless without the token
	mode      fs.FileMode // permission bits; 0 when not known (Windows)
}

// authorizedKey is one line of authorized_keys: type, fingerprint and comment, never the key.
type authorizedKey struct {
	path        string
	line        int
	keyType     string
	fingerprint string
	comment     string
}

func sshKeys(p policy.SSHKeys) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		home, err := os.UserHomeDir()
		if err != nil {
			return check.Errored(err)
		}
		keys, auth := gatherSSH(home, runtime.GOOS != "windows")
		return sshClientConfigResult(evalSSHKeys(keys, auth, p), home, p) // client config: sshconfig.go
	}
}

// gatherSSH reads every private key file directly in ~/.ssh, the keys named
// by IdentityFile in ~/.ssh/config (and files it Includes), and authorized_keys.
func gatherSSH(home string, modes bool) ([]sshKey, []authorizedKey) {
	dir := filepath.Join(home, ".ssh")
	candidates := map[string]bool{}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() {
				candidates[filepath.Join(dir, e.Name())] = true
			}
		}
	}
	for _, p := range sshIdentityFiles(home, filepath.Join(dir, "config")) {
		candidates[p] = true
	}
	paths := make([]string, 0, len(candidates))
	for p := range candidates {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var keys []sshKey
	var auth []authorizedKey
	for _, p := range paths {
		base := filepath.Base(p)
		if base == "authorized_keys" || base == "authorized_keys2" {
			if filepath.Dir(p) == dir {
				auth = append(auth, readAuthorizedKeys(p, tildePath(home, p))...)
			}
			continue
		}
		if strings.HasSuffix(base, ".pub") || base == "known_hosts" || base == "config" {
			continue
		}
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() > sshMaxKeyFile {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		k, ok := parsePrivateKey(data)
		if !ok {
			continue
		}
		k.path = tildePath(home, p)
		if modes {
			k.mode = st.Mode().Perm()
		}
		keys = append(keys, k)
	}
	return keys, auth
}

var sshConfigLineRe = regexp.MustCompile(`(?i)^\s*(identityfile|include)\s*(?:=\s*|\s+)(.+?)\s*$`)

// sshIdentityFiles returns the IdentityFile paths in an ssh config file and
// the files it Includes. Tokens other than %d (home) can't be resolved
// without a host, so those lines are skipped.
func sshIdentityFiles(home, config string) []string {
	var out []string
	seen := map[string]bool{}
	var read func(p string, depth int)
	read = func(p string, depth int) {
		if depth > 3 || seen[p] || len(seen) >= sshMaxIncludes {
			return
		}
		seen[p] = true
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() > sshMaxConfigFile {
			return
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			m := sshConfigLineRe.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			for _, arg := range sshConfigArgs(m[2]) {
				arg = strings.ReplaceAll(arg, "%d", home)
				if strings.Contains(arg, "%") || strings.Contains(arg, "${") || strings.EqualFold(arg, "none") {
					continue
				}
				arg = expandHome(arg, home)
				if strings.EqualFold(m[1], "include") {
					if !filepath.IsAbs(arg) {
						arg = filepath.Join(home, ".ssh", arg)
					}
					matches, _ := filepath.Glob(arg)
					for _, inc := range matches {
						if !sshPathAvoided(home, inc) {
							read(inc, depth+1)
						}
					}
					continue
				}
				if !filepath.IsAbs(arg) {
					arg = filepath.Join(home, arg)
				}
				if !sshPathAvoided(home, arg) {
					out = append(out, filepath.Clean(arg))
				}
			}
		}
	}
	read(config, 0)
	return out
}

// sshConfigArgs splits an ssh config value, honouring double quotes.
func sshConfigArgs(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		if s[0] == '"' {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				return append(out, s[1:])
			}
			out = append(out, s[1:end+1])
			s = s[end+2:]
			continue
		}
		f, rest, _ := strings.Cut(s, " ")
		out = append(out, f)
		s = rest
	}
	return out
}

// sshPathAvoided keeps the check away from folders macOS guards with a privacy
// prompt, so a scheduled run never pops a dialog.
func sshPathAvoided(home, p string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	rel, err := filepath.Rel(home, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	first, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
	switch first {
	case "Desktop", "Documents", "Downloads", "Library", "Pictures", "Movies", "Music":
		return true
	}
	return false
}

// parsePrivateKey recognises a private key file and whether it is encrypted,
// by reading its format: never by running ssh-keygen.
func parsePrivateKey(data []byte) (sshKey, bool) {
	if bytes.HasPrefix(data, []byte("PuTTY-User-Key-File-")) {
		return parsePuTTY(data)
	}
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return sshKey{}, false
		}
		rest = r
		switch {
		case block.Type == "OPENSSH PRIVATE KEY":
			return parseOpenSSHKey(block.Bytes)
		case block.Type == "ENCRYPTED PRIVATE KEY":
			return sshKey{format: "PKCS#8", encrypted: true}, true
		case block.Type == "PRIVATE KEY":
			return sshKey{format: "PKCS#8"}, true
		case strings.HasSuffix(block.Type, " PRIVATE KEY"): // RSA, EC, DSA
			return sshKey{format: "PEM", keyType: strings.TrimSuffix(block.Type, " PRIVATE KEY"),
				encrypted: strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")}, true
		}
	}
}

// parseOpenSSHKey reads the header of an "openssh-key-v1" key: the cipher name
// ("none" = no passphrase) and the type of the first public key.
func parseOpenSSHKey(b []byte) (sshKey, bool) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return sshKey{}, false
	}
	b = b[len(magic):]
	cipher, b, ok := sshString(b)
	if !ok {
		return sshKey{}, false
	}
	k := sshKey{format: "OpenSSH", encrypted: string(cipher) != "none"}
	if _, b, ok = sshString(b); !ok { // kdf name
		return k, true
	}
	if _, b, ok = sshString(b); !ok { // kdf options
		return k, true
	}
	if len(b) < 4 || binary.BigEndian.Uint32(b) == 0 {
		return k, true
	}
	pub, _, ok := sshString(b[4:])
	if !ok {
		return k, true
	}
	if t, _, ok := sshString(pub); ok {
		k.keyType = string(t)
		k.hardware = strings.HasPrefix(k.keyType, "sk-")
	}
	return k, true
}

func sshString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, b, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, b, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func parsePuTTY(data []byte) (sshKey, bool) {
	k := sshKey{format: "PuTTY"}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for i := 0; sc.Scan() && i < 4; i++ {
		name, value, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(name, "PuTTY-User-Key-File-"):
			k.keyType = value
			k.hardware = strings.HasPrefix(value, "sk-")
		case name == "Encryption":
			k.encrypted = value != "none"
			return k, true
		}
	}
	return sshKey{}, false
}

var authBlobRe = regexp.MustCompile(`^AAAA[A-Za-z0-9+/]{12,}={0,2}$`)

var authKeyTypeRe = regexp.MustCompile(`^(?:ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9.@-]+|[a-z0-9-]+-cert-v01@openssh\.com)$`)

func readAuthorizedKeys(p, shown string) []authorizedKey {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > sshMaxConfigFile {
		return nil
	}
	return parseAuthorizedKeys(f, shown)
}

// parseAuthorizedKeys lists the keys in an authorized_keys file. The options
// before the key type may hold quoted spaces, so the key type is found by shape.
func parseAuthorizedKeys(r io.Reader, shown string) []authorizedKey {
	var out []authorizedKey
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if !authKeyTypeRe.MatchString(f[i]) {
				continue
			}
			if !authBlobRe.MatchString(f[i+1]) { // e.g. "ssh-rsa" inside a quoted command= option
				continue
			}
			k := authorizedKey{path: shown, line: n, keyType: f[i], comment: strings.Join(f[i+2:], " ")}
			// sshd still reads a key that doesn't decode cleanly as a line, so it is counted without a fingerprint.
			if blob, err := base64.StdEncoding.DecodeString(f[i+1]); err == nil {
				sum := sha256.Sum256(blob)
				k.fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
			}
			out = append(out, k)
			break
		}
	}
	return out
}

func sshKeyAllowed(path string, allow []string) bool {
	for _, g := range allow {
		if re, err := policy.Glob(g); err == nil && re.MatchString(filepath.ToSlash(path)) {
			return true
		}
	}
	return false
}

func evalSSHKeys(keys []sshKey, auth []authorizedKey, p policy.SSHKeys) check.Result {
	var high, medium []string
	plain, loose, authN, hw := 0, 0, 0, 0
	for _, k := range keys {
		if sshKeyAllowed(k.path, p.AllowKeys) {
			continue
		}
		if k.hardware {
			hw++
			continue
		}
		desc := k.format
		if k.keyType != "" {
			desc += " " + k.keyType
		}
		noPass := p.NoPassphrase && !k.encrypted
		open := p.LoosePermissions && k.mode&0o077 != 0
		switch {
		case noPass && open:
			high = append(high, fmt.Sprintf("%s  no passphrase and readable by other users (mode %04o, %s)", k.path, k.mode, desc))
		case noPass:
			medium = append(medium, fmt.Sprintf("%s  no passphrase (%s)", k.path, desc))
		case open:
			medium = append(medium, fmt.Sprintf("%s  readable by other users (mode %04o, %s)", k.path, k.mode, desc))
		}
		if noPass {
			plain++
		}
		if open {
			loose++
		}
	}
	if p.AuthorizedKeys {
		for _, a := range auth {
			if sshKeyAllowed(a.path, p.AllowKeys) {
				continue
			}
			authN++
			comment := a.comment
			if comment == "" {
				comment = "(no comment)"
			}
			key := strings.TrimSpace(a.keyType + " " + a.fingerprint)
			medium = append(medium, fmt.Sprintf("%s:%d  can log in here: %s %s", a.path, a.line, key, comment))
		}
	}
	var note msg.Text
	if hw > 0 {
		note = msg.Of("sshkeys.hardware", "n", hw)
	}
	if len(high)+len(medium) == 0 {
		return check.Result{Status: check.Pass}.WithSummary(append(msg.Of("sshkeys.pass", "n", len(keys)), note...))
	}
	var parts msg.Text
	if plain > 0 {
		parts = append(parts, msg.P("sshkeys.noPassphrase", "n", plain))
	}
	if loose > 0 {
		parts = append(parts, msg.P("sshkeys.readable", "n", loose))
	}
	if authN > 0 {
		parts = append(parts, msg.P("sshkeys.authorized", "n", authN))
	}
	r := check.Result{Status: check.Warn, Severity: check.Medium, Evidence: append(high, medium...)}.
		WithSummary(append(parts, note...)).WithFix(sshFix())
	if len(high) > 0 {
		r.Status, r.Severity = check.Fail, check.High
	}
	return r
}

func sshFix() msg.Text {
	t := msg.Of("sshkeys.fix.passphrase")
	switch runtime.GOOS {
	case "darwin":
		t = append(t, msg.P("sshkeys.fix.mac"))
	case "windows":
		t = append(t, msg.P("sshkeys.fix.win"))
	}
	return append(t, msg.P("sshkeys.fix.rest"))
}
