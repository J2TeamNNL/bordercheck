package checks

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The trust-store check looks for root certificates someone added to the
// trust store, and for a system proxy or PAC file. Together they are how
// traffic gets intercepted: whoever holds an added root's key can read this
// machine's HTTPS traffic when it passes through them. Both have honest uses
// (company TLS inspection, mkcert and debugging proxies), so the default is
// a warning that says so. Only commands that never show a dialog are run:
// on macOS `security dump-trust-settings` (user and admin domains), `security
// find-certificate` (certificates are not access-controlled) and `scutil
// --proxy`; on Windows the current user's own Root store and Internet
// Settings in the registry; on Linux the local anchor folders and GNOME's
// proxy settings. Proxy environment variables are read on every OS.

// trustCert is one added, trusted certificate.
type trustCert struct {
	Name     string // as the trust store names it (macOS label, file name)
	CN       string // subject common name, "" if the certificate could not be read
	SHA256   string // hex, upper case; "" if unknown
	NotAfter time.Time
	Where    string // "user trust settings", "~/…/x.crt"
}

func (c trustCert) String() string {
	name := c.CN
	if name == "" {
		name = c.Name
	}
	s := name + " (" + c.Where
	if c.SHA256 != "" {
		s += ", SHA-256 " + c.SHA256
	}
	if !c.NotAfter.IsZero() {
		s += ", expires " + c.NotAfter.UTC().Format("2006-01-02")
	}
	return s + ")"
}

// trustProxy is one configured proxy or PAC file.
type trustProxy struct {
	Kind  string // "HTTP proxy", "PAC file", "https_proxy"
	Host  string // host only, for allow globs and the loopback test
	Shown string // host:port or the PAC URL, without user:pass, query or fragment
	Where string // "system settings", "environment"
}

func (p trustProxy) String() string { return p.Kind + " " + p.Shown + " (" + p.Where + ")" }

// trustFacts is what the per-OS code gathers.
type trustFacts struct {
	OS       string // runtime.GOOS, picks the fix
	Certs    []trustCert
	HostOnly int    // macOS: certificates trusted for one host name only (e.g. a remote desktop's), not counted
	CAErr    string // why the trust store could not be read; "" if it was
	Proxies  []trustProxy
	ProxyErr string
}

// devCAs are the subject names of local development and debugging tools'
// root certificates.
var devCAs = []struct{ prefix, tool string }{
	{"mkcert ", "mkcert"},
	{"mitmproxy", "mitmproxy"},
	{"Charles Proxy CA", "Charles Proxy"},
	{"DO_NOT_TRUST_FiddlerRoot", "Fiddler"},
	{"PortSwigger CA", "Burp Suite"},
}

func devCATool(cn string) string {
	for _, d := range devCAs {
		if strings.HasPrefix(cn, d.prefix) {
			return d.tool
		}
	}
	return ""
}

func normFingerprint(s string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(s))
}

func isLoopbackHost(h string) bool {
	h = strings.Trim(strings.ToLower(h), "[]")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func evalTrustStore(f trustFacts, opts policy.TrustStore) check.Result {
	allowCN := globList(opts.AllowCAs)
	var allowFP []string
	for _, a := range opts.AllowCAs {
		allowFP = append(allowFP, normFingerprint(a))
	}
	allowHost := globList(opts.AllowProxies)

	var certs []trustCert
	var tools []string
	if opts.CAs {
		for _, c := range f.Certs {
			if (c.SHA256 != "" && slices.Contains(allowFP, c.SHA256)) || matchAny(allowCN, c.CN) || matchAny(allowCN, c.Name) {
				continue
			}
			certs = append(certs, c)
			if t := devCATool(c.CN + c.Name); t != "" && !slices.Contains(tools, t) {
				tools = append(tools, t)
			}
		}
	}
	var remote, local []trustProxy
	if opts.Proxies {
		for _, p := range f.Proxies {
			switch {
			case matchAny(allowHost, p.Host):
			case isLoopbackHost(p.Host):
				local = append(local, p)
			default:
				remote = append(remote, p)
			}
		}
	}
	caErr := opts.CAs && f.CAErr != ""
	proxyErr := opts.Proxies && f.ProxyErr != ""
	if (caErr || !opts.CAs) && (proxyErr || !opts.Proxies) && (caErr || proxyErr) {
		return check.Errored(msg.Err("trust.unknown", "err", strings.Trim(f.CAErr+"; "+f.ProxyErr, "; ")))
	}

	var summary, fix msg.Text
	var ev []string
	status, sev := check.Pass, check.Severity("")
	if len(certs) > 0 {
		status, sev = check.Warn, opts.CASeverity
		var names []string
		for _, c := range certs {
			n := c.CN
			if n == "" {
				n = c.Name
			}
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
			ev = append(ev, "trusted root certificate: "+c.String())
		}
		summary = append(summary, msg.P("trust.ca.found", "n", len(certs), "names", shortList(names)))
		if len(tools) > 0 {
			summary = append(summary, msg.P("trust.ca.devTool", "tools", strings.Join(tools, ", ")))
		}
		fix = append(fix, msg.P(trustFixes[fixOS(f.OS)][0]))
	}
	if len(remote) > 0 {
		if status == check.Pass {
			status, sev = check.Warn, check.Medium
		}
		var shown []string
		env, system := false, false
		for _, p := range remote {
			shown = append(shown, p.Shown)
			ev = append(ev, p.String())
			if p.Where == "environment" {
				env = true
			} else {
				system = true
			}
		}
		summary = append(summary, msg.P("trust.proxy.found", "proxies", shortList(uniqSorted(shown))))
		if system {
			fix = append(fix, msg.P(trustFixes[fixOS(f.OS)][1]))
		}
		if env {
			fix = append(fix, msg.P("trust.fix.proxy.env"))
		}
	}
	if sev == check.High {
		status = check.Fail
	}
	if status == check.Pass {
		caOK, proxyOK := opts.CAs && !caErr, opts.Proxies && !proxyErr
		switch {
		case caOK && proxyOK:
			summary = msg.Of("trust.pass")
		case caOK:
			summary = msg.Of("trust.pass.ca")
		default:
			summary = msg.Of("trust.pass.proxy")
		}
	} else {
		fix = append(fix, msg.P("trust.fix.allow"))
	}
	if len(local) > 0 {
		var shown []string
		for _, p := range local {
			shown = append(shown, p.Shown)
			ev = append(ev, p.String())
		}
		summary = append(summary, msg.P("trust.proxy.local", "proxies", shortList(uniqSorted(shown))))
	}
	if opts.CAs && f.HostOnly > 0 {
		summary = append(summary, msg.P("trust.ca.hostOnly", "n", f.HostOnly))
	}
	if caErr {
		summary = append(summary, msg.P("trust.ca.unknown", "err", f.CAErr))
	}
	if proxyErr {
		summary = append(summary, msg.P("trust.proxy.unknown", "err", f.ProxyErr))
	}
	r := check.Result{Status: status, Severity: sev, Evidence: ev}.WithSummary(summary)
	if status != check.Pass {
		r = r.WithFix(fix)
	}
	return r
}

// trustFixes are the fixes for an added root and for a system proxy, per OS.
var trustFixes = map[string][2]string{
	"mac":   {"trust.fix.ca.mac", "trust.fix.proxy.mac"},
	"win":   {"trust.fix.ca.win", "trust.fix.proxy.win"},
	"linux": {"trust.fix.ca.linux", "trust.fix.proxy.linux"},
}

func fixOS(goos string) string {
	switch goos {
	case "darwin":
		return "mac"
	case "windows":
		return "win"
	}
	return "linux"
}

func trustStore(opts policy.TrustStore) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		f := trustFactsOS(ctx, opts)
		f.OS = runtime.GOOS
		if opts.Proxies {
			f.Proxies = append(f.Proxies, envProxies(os.Getenv)...)
		}
		return evalTrustStore(f, opts)
	}
}

// ---- parsing, shared by the per-OS code ----

// certFromDER reads a certificate's name, fingerprint and expiry.
func certFromDER(der []byte, name, where string) (trustCert, bool) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return trustCert{}, false
	}
	sum := sha256.Sum256(der)
	if name == "" {
		name = c.Subject.CommonName
	}
	return trustCert{Name: name, CN: c.Subject.CommonName, SHA256: strings.ToUpper(hex.EncodeToString(sum[:])),
		NotAfter: c.NotAfter, Where: where}, true
}

// certsFromFile reads the certificates of a PEM or DER file.
func certsFromFile(data []byte, name, where string) []trustCert {
	var out []trustCert
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" || b.Type == "TRUSTED CERTIFICATE" {
			if c, ok := certFromDER(b.Bytes, "", where); ok {
				out = append(out, c)
			}
		}
	}
	if len(out) == 0 {
		if c, ok := certFromDER(data, "", where); ok {
			out = append(out, c)
		}
	}
	if len(out) == 0 && name != "" {
		out = append(out, trustCert{Name: name, Where: where}) // unreadable, still trusted
	}
	return out
}

// macTrustEntry is one certificate in `security dump-trust-settings` output.
type macTrustEntry struct {
	Name     string
	HostOnly bool // every trusting setting is limited to a host name (Policy String)
	Trusted  bool // trusted as a root for at least one use
}

// parseMacTrustSettings reads `security dump-trust-settings [-d]`. A
// certificate with no settings is trusted as a root for everything; a
// setting without a Result Type means kSecTrustSettingsResultTrustRoot.
func parseMacTrustSettings(out string) []macTrustEntry {
	var res []macTrustEntry
	type setting struct {
		result string
		policy bool
	}
	var cur *macTrustEntry
	var sets []setting
	flush := func() {
		if cur == nil {
			return
		}
		if len(sets) == 0 {
			cur.Trusted = true
		}
		anyOpen := false
		for _, s := range sets {
			if s.result == "" || s.result == "kSecTrustSettingsResultTrustRoot" || s.result == "kSecTrustSettingsResultTrustAsRoot" {
				cur.Trusted = true
				if !s.policy {
					anyOpen = true
				}
			}
		}
		cur.HostOnly = cur.Trusted && len(sets) > 0 && !anyOpen
		res = append(res, *cur)
		cur, sets = nil, nil
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Cert ") && strings.Contains(t, ":"):
			flush()
			_, name, _ := strings.Cut(t, ":")
			cur = &macTrustEntry{Name: strings.TrimSpace(name)}
		case cur == nil:
		case strings.HasPrefix(t, "Trust Setting "):
			sets = append(sets, setting{})
		case len(sets) > 0:
			k, v, _ := strings.Cut(t, ":")
			switch strings.TrimSpace(k) {
			case "Result Type":
				sets[len(sets)-1].result = strings.TrimSpace(v)
			case "Policy String":
				sets[len(sets)-1].policy = strings.TrimSpace(v) != ""
			}
		}
	}
	flush()
	return res
}

// parseScutilProxy reads the top level of `scutil --proxy`.
func parseScutilProxy(out string) []trustProxy {
	kv := map[string]string{}
	depth := 0
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if depth == 1 {
			if k, v, ok := strings.Cut(t, " : "); ok && !strings.HasSuffix(v, "{") {
				kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		depth += strings.Count(t, "{") - strings.Count(t, "}")
	}
	var out2 []trustProxy
	for _, k := range []struct{ key, kind string }{{"HTTP", "HTTP proxy"}, {"HTTPS", "HTTPS proxy"}, {"SOCKS", "SOCKS proxy"}} {
		if kv[k.key+"Enable"] == "1" && kv[k.key+"Proxy"] != "" {
			out2 = append(out2, hostPortProxy(k.kind, kv[k.key+"Proxy"], kv[k.key+"Port"], "system settings"))
		}
	}
	if kv["ProxyAutoConfigEnable"] == "1" && kv["ProxyAutoConfigURLString"] != "" {
		if p, ok := pacProxy(kv["ProxyAutoConfigURLString"], "system settings"); ok {
			out2 = append(out2, p)
		}
	}
	return out2
}

func hostPortProxy(kind, host, port, where string) trustProxy {
	if _, h, ok := strings.Cut(host, "@"); ok {
		host = h // never show user:pass
	}
	shown := host
	if port != "" && port != "0" {
		shown = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	return trustProxy{Kind: kind, Host: strings.Trim(host, "[]"), Shown: shown, Where: where}
}

// pacProxy describes a PAC URL without user info, query or fragment.
func pacProxy(raw, where string) (trustProxy, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" && u.Scheme != "file" {
		return trustProxy{}, false
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment = nil, "", "", ""
	return trustProxy{Kind: "PAC file", Host: u.Hostname(), Shown: u.String(), Where: where}, true
}

// urlProxy reads a proxy given as a URL or host:port (environment
// variables, Windows ProxyServer entries).
func urlProxy(kind, raw, where string) (trustProxy, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return trustProxy{}, false
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return trustProxy{}, false
	}
	return hostPortProxy(kind, u.Hostname(), u.Port(), where), true
}

// envProxies reads the proxy environment variables bordercheck runs with.
func envProxies(getenv func(string) string) []trustProxy {
	var out []trustProxy
	seen := map[string]bool{}
	for _, k := range []string{"https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"} {
		v := getenv(k)
		if v == "" || seen[strings.ToLower(k)+"="+v] {
			continue
		}
		seen[strings.ToLower(k)+"="+v] = true
		if p, ok := urlProxy(k, v, "environment"); ok {
			out = append(out, p)
		}
	}
	return out
}

// parseWinProxyServer reads Internet Settings' ProxyServer: "host:port" for
// every protocol, or "http=host:port;https=host:port;socks=host:port".
func parseWinProxyServer(v string) []trustProxy {
	var out []trustProxy
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kind := "proxy"
		if k, rest, ok := strings.Cut(part, "="); ok {
			kind, part = strings.ToUpper(k)+" proxy", rest
		}
		if p, ok := urlProxy(kind, part, "system settings"); ok {
			out = append(out, p)
		}
	}
	return out
}

// winCertFromBlob reads the certificate in a registry certificate Blob: a
// list of properties (ID, reserved, length, data, all little-endian uint32
// headers); property 32 (CERT_CERT_PROP_ID) holds the DER certificate.
func winCertFromBlob(b []byte, where string) (trustCert, bool) {
	for len(b) >= 12 {
		id, n := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[8:])
		if uint64(n) > uint64(len(b)-12) {
			break
		}
		if id == 32 {
			return certFromDER(b[12:12+n], "", where)
		}
		b = b[12+n:]
	}
	return trustCert{}, false
}

// gsettingsValue unquotes a `gsettings get` string value.
func gsettingsValue(s string) string {
	return strings.Trim(strings.TrimSpace(s), "'")
}

// winTrustFacts reads winTrustScript's output.
func winTrustFacts(out string) trustFacts {
	var f trustFacts
	kv := map[string]string{}
	rootsRead := false
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "roots":
			rootsRead = true
		case "cert":
			thumb, b64, _ := strings.Cut(v, ":")
			blob, err := base64.StdEncoding.DecodeString(b64)
			c, ok := winCertFromBlob(blob, "current user's Root store")
			if err != nil || !ok {
				c = trustCert{Name: thumb, Where: "current user's Root store"}
			}
			f.Certs = append(f.Certs, c)
		default:
			kv[k] = v
		}
	}
	if !rootsRead {
		f.CAErr = "the current user's Root store could not be read"
	}
	if kv["ProxyEnable"] == "1" {
		f.Proxies = append(f.Proxies, parseWinProxyServer(kv["ProxyServer"])...)
	}
	if u := kv["AutoConfigURL"]; u != "" {
		if p, ok := pacProxy(u, "system settings"); ok {
			f.Proxies = append(f.Proxies, p)
		}
	}
	return f
}

// linuxAnchors reads the certificates in the local anchor folders. Debian's
// update-ca-certificates only takes *.crt files there.
func linuxAnchors(dirs []string) []trustCert {
	var out []trustCert
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || !e.Type().IsRegular() {
				return nil
			}
			if strings.HasPrefix(d, "/usr/local/share/ca-certificates") && !strings.HasSuffix(p, ".crt") {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			out = append(out, certsFromFile(data, filepath.Base(p), p)...)
			return nil
		})
	}
	return out
}

// gnomeProxies reads GNOME's proxy settings through get(schema, key), which
// returns `gsettings get` output ("" if unknown).
func gnomeProxies(get func(schema, key string) string) []trustProxy {
	var out []trustProxy
	switch gsettingsValue(get("org.gnome.system.proxy", "mode")) {
	case "manual":
		for _, k := range []struct{ schema, kind string }{{"http", "HTTP proxy"}, {"https", "HTTPS proxy"}, {"socks", "SOCKS proxy"}} {
			host := gsettingsValue(get("org.gnome.system.proxy."+k.schema, "host"))
			if host == "" {
				continue
			}
			out = append(out, hostPortProxy(k.kind, host, strings.TrimSpace(get("org.gnome.system.proxy."+k.schema, "port")), "system settings"))
		}
	case "auto":
		if p, ok := pacProxy(gsettingsValue(get("org.gnome.system.proxy", "autoconfig-url")), "system settings"); ok {
			out = append(out, p)
		}
	}
	return out
}
