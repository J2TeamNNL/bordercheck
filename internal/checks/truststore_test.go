package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// testCA makes a self-signed root with a common name, generated on the spot.
func testCA(t *testing.T, cn string) (der []byte, fp string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn, Organization: []string{"Demo"}},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return der, strings.ToUpper(hex.EncodeToString(sum[:]))
}

// Shaped like `security dump-trust-settings` output on macOS 26 (names
// changed): a root trusted for everything, one trusted as root for SSL
// only, a remote desktop's certificate trusted for its host name only, and
// one marked Never Trust.
const macTrustSample = `Number of trusted certs = 4
Cert 0: mkcert demo@demo-mac.local (Demo User)
   Number of trust settings : 0
Cert 1: Sample Corp TLS Inspection CA
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : SSL
      Allowed Error         : CSSMERR_TP_CERT_EXPIRED
      Result Type           : kSecTrustSettingsResultTrustRoot
Cert 2: DEMO-PC
   Number of trust settings : 2
   Trust Setting 0:
      Policy OID            : SSL
      Policy String         : demo-pc.example.ts.net
      Allowed Error         : Host name mismatch
      Result Type           : kSecTrustSettingsResultTrustRoot
   Trust Setting 1:
      Policy OID            : Apple X509 Basic
      Policy String         : demo-pc.example.ts.net
      Allowed Error         : CSSMERR_TP_CERT_EXPIRED
      Result Type           : kSecTrustSettingsResultTrustRoot
Cert 3: Distrusted Thing
   Number of trust settings : 1
   Trust Setting 0:
      Policy OID            : SSL
      Result Type           : kSecTrustSettingsResultDeny
`

func TestParseMacTrustSettings(t *testing.T) {
	got := parseMacTrustSettings(macTrustSample)
	want := []macTrustEntry{
		{Name: "mkcert demo@demo-mac.local (Demo User)", Trusted: true},
		{Name: "Sample Corp TLS Inspection CA", Trusted: true},
		{Name: "DEMO-PC", Trusted: true, HostOnly: true},
		{Name: "Distrusted Thing"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	if got := parseMacTrustSettings("SecTrustSettingsCopyCertificates: No Trust Settings were found.\n"); len(got) != 0 {
		t.Errorf("none: %+v", got)
	}
}

func TestParseScutilProxy(t *testing.T) {
	// Shaped like `scutil --proxy` with a manual proxy and a PAC file set.
	out := `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 3128
  HTTPProxy : proxy.sample.example
  HTTPSEnable : 0
  HTTPSPort : 8443
  HTTPSProxy : other.example
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://user:pw@wpad.sample.example/proxy.pac?token=abc#x
  SOCKSEnable : 1
  SOCKSPort : 7890
  SOCKSProxy : 127.0.0.1
  __SCOPED__ : <dictionary> {
    en0 : <dictionary> {
      HTTPEnable : 1
      HTTPProxy : scoped.example
    }
  }
}`
	got := parseScutilProxy(out)
	var shown []string
	for _, p := range got {
		shown = append(shown, p.String())
	}
	want := "HTTP proxy proxy.sample.example:3128 (system settings)|SOCKS proxy 127.0.0.1:7890 (system settings)|" +
		"PAC file http://wpad.sample.example/proxy.pac (system settings)"
	if strings.Join(shown, "|") != want {
		t.Errorf("got %s", strings.Join(shown, "|"))
	}
	if got := parseScutilProxy("<dictionary> {\n  HTTPEnable : 0\n  SOCKSEnable : 0\n}\n"); len(got) != 0 {
		t.Errorf("none: %+v", got)
	}
}

func TestProxyParsing(t *testing.T) {
	got := parseWinProxyServer("http=proxy.sample.example:8080;https=proxy.sample.example:8443;socks=127.0.0.1:1080")
	if len(got) != 3 || got[0].Shown != "proxy.sample.example:8080" || got[0].Kind != "HTTP proxy" || got[2].Host != "127.0.0.1" {
		t.Errorf("per protocol: %+v", got)
	}
	if got := parseWinProxyServer("10.0.0.1:3128"); len(got) != 1 || got[0].Shown != "10.0.0.1:3128" {
		t.Errorf("one for all: %+v", got)
	}
	env := map[string]string{"https_proxy": "http://bob:hunter2@proxy.sample.example:3128", "HTTPS_PROXY": "http://bob:hunter2@proxy.sample.example:3128",
		"http_proxy": "localhost:8888", "no_proxy": "localhost"}
	ps := envProxies(func(k string) string { return env[k] })
	all := ""
	for _, p := range ps {
		all += p.String() + "\n"
	}
	if len(ps) != 2 || strings.Contains(all, "bob") || strings.Contains(all, "hunter2") ||
		!strings.Contains(all, "https_proxy proxy.sample.example:3128 (environment)") || !strings.Contains(all, "http_proxy localhost:8888") {
		t.Errorf("env: %s", all)
	}
	gs := map[string]string{
		"org.gnome.system.proxy mode": "'manual'\n", "org.gnome.system.proxy.http host": "'proxy.sample.example'\n",
		"org.gnome.system.proxy.http port": "3128\n", "org.gnome.system.proxy.https host": "''\n",
		"org.gnome.system.proxy.socks host": "'127.0.0.1'\n", "org.gnome.system.proxy.socks port": "1080\n",
	}
	got = gnomeProxies(func(s, k string) string { return gs[s+" "+k] })
	if len(got) != 2 || got[0].Shown != "proxy.sample.example:3128" || got[1].Shown != "127.0.0.1:1080" {
		t.Errorf("gnome manual: %+v", got)
	}
	gs = map[string]string{"org.gnome.system.proxy mode": "'auto'\n", "org.gnome.system.proxy autoconfig-url": "'https://wpad.sample.example/p.pac'\n"}
	if got := gnomeProxies(func(s, k string) string { return gs[s+" "+k] }); len(got) != 1 || got[0].Host != "wpad.sample.example" {
		t.Errorf("gnome auto: %+v", got)
	}
	if got := gnomeProxies(func(s, k string) string { return "'none'\n" }); len(got) != 0 {
		t.Errorf("gnome none: %+v", got)
	}
}

func TestTrustCerts(t *testing.T) {
	der, fp := testCA(t, "Sample Corp TLS Inspection CA")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cs := certsFromFile(pemData, "sample.crt", "/usr/local/share/ca-certificates/sample.crt")
	if len(cs) != 1 || cs[0].CN != "Sample Corp TLS Inspection CA" || cs[0].SHA256 != fp || cs[0].NotAfter.Year() != 2036 {
		t.Fatalf("pem: %+v", cs)
	}
	if cs := certsFromFile(der, "sample.der", "x"); len(cs) != 1 || cs[0].SHA256 != fp {
		t.Errorf("der: %+v", cs)
	}
	if cs := certsFromFile([]byte("garbage"), "bad.crt", "x"); len(cs) != 1 || cs[0].Name != "bad.crt" || cs[0].SHA256 != "" {
		t.Errorf("unreadable: %+v", cs)
	}

	// A registry Blob: a property before the certificate, then CERT_CERT_PROP_ID (32).
	prop := func(id uint32, data []byte) []byte {
		h := make([]byte, 12)
		binary.LittleEndian.PutUint32(h, id)
		binary.LittleEndian.PutUint32(h[4:], 1)
		binary.LittleEndian.PutUint32(h[8:], uint32(len(data)))
		return append(h, data...)
	}
	blob := append(prop(3, make([]byte, 20)), prop(32, der)...)
	if c, ok := winCertFromBlob(blob, "w"); !ok || c.SHA256 != fp {
		t.Errorf("blob: %+v %v", c, ok)
	}
	if _, ok := winCertFromBlob(prop(3, []byte{1, 2})[:10], "w"); ok {
		t.Error("truncated blob parsed")
	}

	out := "roots=ok\ncert=ABCDEF0123:" + base64.StdEncoding.EncodeToString(blob) + "\ncert=99FF:!!!\n" +
		"ProxyEnable=1\nProxyServer=proxy.sample.example:8080\nAutoConfigURL=http://wpad/proxy.pac\n"
	f := winTrustFacts(out)
	if len(f.Certs) != 2 || f.Certs[0].CN != "Sample Corp TLS Inspection CA" || f.Certs[1].Name != "99FF" || f.CAErr != "" ||
		len(f.Proxies) != 2 || f.Proxies[1].Kind != "PAC file" {
		t.Errorf("windows: %+v", f)
	}
	if f := winTrustFacts("roots=none\nProxyEnable=0\nProxyServer=proxy:1\n"); len(f.Certs) != 0 || len(f.Proxies) != 0 || f.CAErr != "" {
		t.Errorf("windows clean: %+v", f)
	}

	dir := t.TempDir()
	putFile(t, filepath.Join(dir, "deb", "corp", "sample.crt"), string(pemData))
	putFile(t, filepath.Join(dir, "deb", "README"), "not a cert")
	putFile(t, filepath.Join(dir, "rh", "sample.pem"), string(pemData))
	if cs := linuxAnchors([]string{filepath.Join(dir, "deb"), filepath.Join(dir, "rh"), filepath.Join(dir, "missing")}); len(cs) != 3 {
		// README counts as an unreadable anchor in a folder that is not Debian's.
		t.Errorf("linux anchors: %+v", cs)
	}
}

func TestEvalTrustStore(t *testing.T) {
	def := policy.Default().Checks.TrustStore
	_, fp := testCA(t, "x")
	mk := trustCert{Name: "mkcert demo@demo-mac.local (Demo User)", CN: "mkcert demo@demo-mac.local (Demo User)",
		SHA256: "AA11", NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC), Where: "user trust settings"}
	corp := trustCert{Name: "Sample Corp TLS Inspection CA", CN: "Sample Corp TLS Inspection CA", SHA256: fp, Where: "admin trust settings"}
	corpProxy := trustProxy{Kind: "HTTP proxy", Host: "proxy.sample.example", Shown: "proxy.sample.example:3128", Where: "system settings"}
	envProxy := trustProxy{Kind: "https_proxy", Host: "proxy.sample.example", Shown: "proxy.sample.example:3128", Where: "environment"}
	local := trustProxy{Kind: "SOCKS proxy", Host: "127.0.0.1", Shown: "127.0.0.1:7890", Where: "system settings"}

	r := evalTrustStore(trustFacts{OS: "darwin", HostOnly: 9, Proxies: []trustProxy{local}}, def)
	if r.Status != check.Pass || !strings.Contains(r.Summary, "127.0.0.1:7890") || !strings.Contains(r.Summary, "9 certificates are trusted for one host name only") {
		t.Errorf("pass: %+v", r)
	}

	r = evalTrustStore(trustFacts{OS: "darwin", Certs: []trustCert{mk, corp}}, def)
	if r.Status != check.Warn || r.Severity != check.Medium || !strings.Contains(r.Summary, "2 root certificates") ||
		!strings.Contains(r.Summary, "(mkcert)") || !strings.Contains(r.Fix, "Keychain Access") ||
		!strings.Contains(r.Evidence[0], "expires 2036-01-01") {
		t.Errorf("cas: %+v", r)
	}

	p := def
	p.AllowCAs = []string{strings.ToLower(fp[:2]) + ":" + fp[2:], "mkcert *"}
	if r := evalTrustStore(trustFacts{OS: "darwin", Certs: []trustCert{mk, corp}}, p); r.Status != check.Pass {
		t.Errorf("allowed cas: %+v", r)
	}

	p = def
	p.CASeverity = check.High
	if r := evalTrustStore(trustFacts{OS: "windows", Certs: []trustCert{corp}}, p); r.Status != check.Fail || r.Severity != check.High ||
		!strings.Contains(r.Fix, "certmgr.msc") {
		t.Errorf("high: %+v", r)
	}

	r = evalTrustStore(trustFacts{OS: "linux", Proxies: []trustProxy{corpProxy, envProxy, local}}, def)
	if r.Status != check.Warn || r.Severity != check.Medium || !strings.Contains(r.Summary, "through a proxy: proxy.sample.example:3128.") ||
		!strings.Contains(r.Fix, "Network Proxy") || !strings.Contains(r.Fix, "https_proxy") || len(r.Evidence) != 3 {
		t.Errorf("proxies: %+v", r)
	}
	p = def
	p.AllowProxies = []string{"*.sample.example"}
	if r := evalTrustStore(trustFacts{OS: "linux", Proxies: []trustProxy{corpProxy}}, p); r.Status != check.Pass {
		t.Errorf("allowed proxy: %+v", r)
	}
	p = def
	p.Proxies, p.CAs = false, true
	if r := evalTrustStore(trustFacts{OS: "linux", Proxies: []trustProxy{corpProxy}, Certs: []trustCert{corp}}, p); !strings.Contains(r.Summary, "1 root certificate was") ||
		strings.Contains(r.Summary, "proxy") {
		t.Errorf("proxies off: %+v", r)
	}

	if r := evalTrustStore(trustFacts{OS: "darwin", CAErr: "security: boom", ProxyErr: "scutil: boom"}, def); r.Status != check.Error {
		t.Errorf("both unreadable: %+v", r)
	}
	if r := evalTrustStore(trustFacts{OS: "darwin", CAErr: "security: boom"}, def); r.Status != check.Pass ||
		r.Summary != "No proxy is set. The trust store could not be read: security: boom" {
		t.Errorf("ca unreadable: %+v", r)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{"127.0.0.1": true, "localhost": true, "[::1]": true, "::1": true, "127.0.0.53": true,
		"proxy.local": false, "10.0.0.1": false, "": false} {
		if isLoopbackHost(h) != want {
			t.Errorf("isLoopbackHost(%q) != %v", h, want)
		}
	}
}
