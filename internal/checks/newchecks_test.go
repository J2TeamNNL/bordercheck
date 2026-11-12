package checks

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// Every fake credential below is assembled at run time so secret scanners
// (GitHub push protection) never see a token-shaped literal in this file.
var (
	fakeGitHub  = "gh" + "p_" + strings.Repeat("Ab3", 12) + "WXYZ"
	fakeOpenAI  = "sk-" + "proj-" + strings.Repeat("q7", 12) + "TAIL"
	fakeSecret  = "zq" + "Vr8" + "Lm2" + "Nx5" + "Kp9"
	fakeBearer  = "eyJ" + strings.Repeat("hb", 10) + "QQ"
	fakeTunnel  = "tun" + "nel" + strings.Repeat("Tk", 12)
	fakeLeakset = []string{fakeGitHub[:20], fakeOpenAI[:20], fakeSecret, fakeBearer[:12], fakeTunnel}
)

func assertNoLeak(t *testing.T, where string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		for _, v := range fakeLeakset {
			if strings.Contains(l, v) {
				t.Errorf("%s leaks a secret value: %q", where, l)
			}
		}
	}
}

func writeFile(t *testing.T, home, rel, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // umask may have narrowed it
		t.Fatal(err)
	}
	return p
}

// --- ssh-keys ---------------------------------------------------------------

func sshStr(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// openSSHKey serialises a throwaway key in the "openssh-key-v1" format. The
// private section is random bytes: the checker only reads the header.
func openSSHKey(t *testing.T, keyType, cipher string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBlob := append(sshStr([]byte(keyType)), sshStr(pub)...)
	if strings.HasPrefix(keyType, "sk-") {
		pubBlob = append(pubBlob, sshStr([]byte("ssh:"))...)
	}
	kdf, kdfOpts := "none", []byte{}
	if cipher != "none" {
		kdf, kdfOpts = "bcrypt", append(sshStr(make([]byte, 16)), 0, 0, 0, 16)
	}
	priv := make([]byte, 64)
	_, _ = rand.Read(priv)
	b := []byte("openssh-key-v1\x00")
	b = append(b, sshStr([]byte(cipher))...)
	b = append(b, sshStr([]byte(kdf))...)
	b = append(b, sshStr(kdfOpts)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, sshStr(pubBlob)...)
	b = append(b, sshStr(priv)...)
	return string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: b}))
}

func pkcs8Key(t *testing.T) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func randomPEM(typ string, headers map[string]string) string {
	b := make([]byte, 48)
	_, _ = rand.Read(b)
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Headers: headers, Bytes: b}))
}

func authorizedLine(t *testing.T, prefix, comment string) (string, string) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	blob := base64.StdEncoding.EncodeToString(append(sshStr([]byte("ssh-ed25519")), sshStr(pub)...))
	return strings.TrimSpace(prefix + " ssh-ed25519 " + blob + " " + comment), blob
}

func TestParsePrivateKey(t *testing.T) {
	for _, tc := range []struct {
		name               string
		data               string
		ok, enc, hw        bool
		format, keyTypeHas string
	}{
		{"openssh plain", openSSHKey(t, "ssh-ed25519", "none"), true, false, false, "OpenSSH", "ed25519"},
		{"openssh encrypted", openSSHKey(t, "ssh-ed25519", "aes256-ctr"), true, true, false, "OpenSSH", "ed25519"},
		{"fido stub", openSSHKey(t, "sk-ssh-ed25519@openssh.com", "none"), true, false, true, "OpenSSH", "sk-"},
		{"pkcs8 plain", pkcs8Key(t), true, false, false, "PKCS#8", ""},
		{"pkcs8 encrypted", randomPEM("ENCRYPTED PRIVATE KEY", nil), true, true, false, "PKCS#8", ""},
		{"pem rsa plain", randomPEM("RSA PRIVATE KEY", nil), true, false, false, "PEM", "RSA"},
		{"pem rsa encrypted", randomPEM("RSA PRIVATE KEY", map[string]string{"Proc-Type": "4,ENCRYPTED",
			"DEK-Info": "AES-128-CBC,00112233445566778899AABBCCDDEEFF"}), true, true, false, "PEM", "RSA"},
		{"putty plain", "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: a\n", true, false, false, "PuTTY", "ed25519"},
		{"putty encrypted", "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc\n", true, true, false, "PuTTY", "rsa"},
		{"public key", "ssh-ed25519 AAAAC3Nza me@domain.com\n", false, false, false, "", ""},
		{"certificate", randomPEM("CERTIFICATE", nil), false, false, false, "", ""},
		{"garbage", "-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64!!\n-----END OPENSSH PRIVATE KEY-----\n", false, false, false, "", ""},
	} {
		k, ok := parsePrivateKey([]byte(tc.data))
		if ok != tc.ok || (ok && (k.encrypted != tc.enc || k.hardware != tc.hw || k.format != tc.format ||
			!strings.Contains(k.keyType, tc.keyTypeHas))) {
			t.Errorf("%s: got %+v ok=%v", tc.name, k, ok)
		}
	}
}

func TestGatherAndEvalSSH(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".ssh/id_ed25519", openSSHKey(t, "ssh-ed25519", "none"), 0o600)
	writeFile(t, home, ".ssh/id_ed25519.pub", "ssh-ed25519 AAAA me@domain.com\n", 0o644)
	writeFile(t, home, ".ssh/id_locked", openSSHKey(t, "ssh-ed25519", "aes256-ctr"), 0o600)
	writeFile(t, home, ".ssh/id_open", openSSHKey(t, "ssh-ed25519", "none"), 0o644)
	writeFile(t, home, ".ssh/id_sk", openSSHKey(t, "sk-ssh-ed25519@openssh.com", "none"), 0o600)
	writeFile(t, home, ".ssh/known_hosts", "github.com ssh-ed25519 AAAA\n", 0o644)
	writeFile(t, home, "keys/work_rsa", randomPEM("RSA PRIVATE KEY", nil), 0o600)
	writeFile(t, home, "keys/deploy", pkcs8Key(t), 0o600)
	writeFile(t, home, ".ssh/config", "Host *\n  IdentityFile ~/keys/work_rsa\n  IdentityFile %d/missing\n  IdentityFile ~/.ssh/%h\nInclude conf.d/*\n", 0o600)
	writeFile(t, home, ".ssh/conf.d/extra", "Host deploy\n  IdentityFile=\"~/keys/deploy\"\n", 0o600)
	line1, blob1 := authorizedLine(t, `command="echo hi",no-pty`, "alice@domain.com")
	line2, blob2 := authorizedLine(t, "", "")
	writeFile(t, home, ".ssh/authorized_keys", "# managed\n"+line1+"\n\n"+line2+"\n"+
		`command="ssh-rsa not-a-key",restrict`+"\n", 0o600)
	if a := parseAuthorizedKeys(strings.NewReader("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBadBase64x bob@domain.com\n"), "~/a"); len(a) != 1 || a[0].fingerprint != "" {
		t.Errorf("undecodable key should still count: %+v", a)
	}

	keys, auth := gatherSSH(home, runtime.GOOS != "windows")
	var paths []string
	for _, k := range keys {
		paths = append(paths, filepath.ToSlash(k.path))
	}
	want := []string{"~/.ssh/id_ed25519", "~/.ssh/id_locked", "~/.ssh/id_open", "~/.ssh/id_sk", "~/keys/deploy", "~/keys/work_rsa"}
	slices.Sort(paths)
	if !slices.Equal(paths, want) {
		t.Fatalf("keys: got %q, want %q", paths, want)
	}
	if len(auth) != 2 || auth[0].comment != "alice@domain.com" || auth[0].line != 2 || auth[1].comment != "" {
		t.Fatalf("authorized keys: %+v", auth)
	}

	p := policy.Default().Checks.SSHKeys
	r := evalSSHKeys(keys, auth, p)
	for _, l := range append(r.Evidence, r.Summary) {
		if strings.Contains(l, blob1[:20]) || strings.Contains(l, blob2[:20]) {
			t.Errorf("evidence shows key material: %q", l)
		}
	}
	if strings.Contains(strings.Join(r.Evidence, "\n"), "id_sk") || strings.Contains(strings.Join(r.Evidence, "\n"), "id_locked:") {
		t.Errorf("hardware or encrypted key flagged: %q", r.Evidence)
	}
	if runtime.GOOS != "windows" {
		if r.Status != check.Fail || !strings.Contains(r.Evidence[0], "id_open") {
			t.Errorf("world-readable unencrypted key should fail first: %s %q", r.Status, r.Evidence)
		}
	}
	if !strings.Contains(r.Summary, "4 private keys have no passphrase") || !strings.Contains(r.Summary, "2 keys in authorized_keys") {
		t.Errorf("summary: %q", r.Summary)
	}

	// Toggles and the allow-list.
	p.AuthorizedKeys, p.LoosePermissions = false, false
	p.AllowKeys = []string{"~/keys/*", "~/.ssh/id_open"}
	r = evalSSHKeys(keys, auth, p)
	if r.Status != check.Warn || len(r.Evidence) != 1 || !strings.Contains(filepath.ToSlash(r.Evidence[0]), "~/.ssh/id_ed25519") {
		t.Errorf("allow + toggles: %s %q", r.Status, r.Evidence)
	}
	p.NoPassphrase = false
	if r := evalSSHKeys(keys, auth, p); r.Status != check.Pass {
		t.Errorf("all off: %s %q", r.Status, r.Evidence)
	}
	if r := evalSSHKeys(nil, nil, policy.Default().Checks.SSHKeys); r.Status != check.Pass {
		t.Errorf("no keys: %s", r.Status)
	}
}

func TestSSHConfigArgs(t *testing.T) {
	if got := sshConfigArgs(`"~/My Keys/id" ~/b`); !slices.Equal(got, []string{"~/My Keys/id", "~/b"}) {
		t.Errorf("got %q", got)
	}
}

// --- tunnels ----------------------------------------------------------------

func TestClassifyProc(t *testing.T) {
	for _, tc := range []struct {
		exe  string
		args string
		tool string // "" = not a tunnel
		port string
		sev  check.Severity
	}{
		{"/opt/homebrew/bin/ngrok", "http 3000", "ngrok", "3000", check.High},
		{"ngrok.exe", "http --url my.ngrok.app http://localhost:8080 --authtoken " + fakeTunnel, "ngrok", "8080", check.High},
		{"ngrok", "config add-authtoken " + fakeTunnel, "", "", ""},
		{"cloudflared", "tunnel --url http://localhost:8080", "cloudflared", "8080", check.High},
		{"cloudflared", "--no-autoupdate tunnel run --token " + fakeTunnel, "cloudflared", "", check.High},
		{"cloudflared", "--config /etc/cf.yml tunnel run", "cloudflared", "", check.High},
		{"cloudflared", "access tcp --hostname db.domain.com --url localhost:5432", "", "", ""},
		{"cloudflared", "proxy-dns", "", "", ""},
		{"/usr/local/bin/node", "/usr/local/bin/lt --port 3000 --subdomain acme", "localtunnel", "3000", check.High},
		{"node", "/Users/me/.npm/_npx/1/node_modules/.bin/npx -y localtunnel -p 4000", "localtunnel", "4000", check.High},
		{"node", "server.js --port 3000", "", "", ""},
		{"bore", "local 5000 --to bore.pub --secret " + fakeTunnel, "bore", "5000", check.High},
		{"bore", "server", "", "", ""},
		{"frpc", "-c ./frpc.toml", "frp", "", check.High},
		{"frps", "-c ./frps.toml", "", "", ""},
		{"zrok", "share public localhost:8080", "zrok", "8080", check.High},
		{"zrok", "share private 3000", "zrok", "3000", check.Medium},
		{"zrok", "enable " + fakeTunnel, "", "", ""},
		{"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code-tunnel", "tunnel --accept-server-license-terms", "vscode-tunnel", "", check.Medium},
		{"code", "tunnel status", "", "", ""},
		{"code", "--wait file.txt", "", "", ""},
		{"devtunnel.exe", "host -p 3000", "devtunnel", "3000", check.Medium},
		{"devtunnel", "host -p 3000 --allow-anonymous", "devtunnel", "3000", check.High},
		{"/usr/bin/ssh", "-R 8080:localhost:3000 me@vps.domain.com", "ssh", "3000", check.Medium},
		{"ssh", "-fNR 80:localhost:5173 serveo.net", "ssh", "5173", check.High},
		{"autossh", "-M 0 -R 9000 bastion", "ssh", "", check.Medium},
		{"ssh", "-o RemoteForward=8080:127.0.0.1:3000 host", "ssh", "3000", check.Medium},
		{"ssh", "-i ~/.ssh/id_Rsa -L 5432:db:5432 host", "", "", ""},
		{"ssh", "-l Rob -oRequestTTY=no host", "", "", ""},
		{"ssh", "-p 2222 host", "", "", ""},
	} {
		e, ok := classifyProc(proc{exe: tc.exe, args: strings.Fields(tc.args)})
		if ok != (tc.tool != "") || e.tool != tc.tool || e.port != tc.port || e.sev != tc.sev {
			t.Errorf("%s %s: got %+v ok=%v, want tool %q port %q sev %q", filepath.Base(tc.exe), tc.args, e, ok, tc.tool, tc.port, tc.sev)
		}
		assertNoLeak(t, "exposure", e.String())
		for _, host := range []string{"domain.com", "serveo", "bore.pub", "ngrok.app", "frpc.toml"} {
			if strings.Contains(e.String(), host) {
				t.Errorf("exposure shows a command-line argument: %q", e)
			}
		}
	}
}

func TestParseProcs(t *testing.T) {
	comm := "  101 /Applications/Visual Studio Code.app/Contents/Resources/app/bin/code-tunnel\n  202 /opt/homebrew/bin/ngrok\n 303 -zsh\n"
	args := "  101 /Applications/Visual Studio Code.app/Contents/Resources/app/bin/code-tunnel tunnel --name x\n  202 ngrok http 3000\n 303 -zsh\n 404 orphan\n"
	ps := parsePs(comm, args)
	if len(ps) != 3 || !slices.Equal(ps[0].args, []string{"tunnel", "--name", "x"}) || !slices.Equal(ps[1].args, []string{"http", "3000"}) {
		t.Errorf("parsePs: %+v", ps)
	}
	win := parseWinProcs("ngrok.exe|\"C:\\Program Files\\ngrok\\ngrok.exe\" http 3000\r\nSystem|\r\nssh.exe|ssh -R 80:localhost:3000 \"my host\"\r\n")
	if len(win) != 3 || !slices.Equal(win[0].args, []string{"http", "3000"}) || len(win[1].args) != 0 || win[2].args[2] != "my host" {
		t.Errorf("parseWinProcs: %+v", win)
	}
}

func TestParseServeStatus(t *testing.T) {
	out := `{
  "TCP": {"443": {"HTTPS": true}, "8443": {"HTTPS": true}, "5432": {"TCPForward": "127.0.0.1:5432"}},
  "Web": {
    "mbp.tail1234.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}}},
    "mbp.tail1234.ts.net:8443": {"Handlers": {"/files": {"Path": "/Users/me/share"}}}
  },
  "AllowFunnel": {"mbp.tail1234.ts.net:443": true},
  "Foreground": {"abc": {"Web": {"mbp.tail1234.ts.net:10000": {"Handlers": {"/": {"Text": "hi"}}}}}}
}`
	es, err := parseServeStatus(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range es {
		got = append(got, e.tool+"|"+e.port)
	}
	slices.Sort(got)
	want := []string{"tailscale-funnel|3000", "tailscale-serve|", "tailscale-serve|", "tailscale-serve|5432"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, empty := range []string{"", "{}", "null"} {
		if es, err := parseServeStatus(empty); err != nil || len(es) != 0 {
			t.Errorf("%q: %v %v", empty, es, err)
		}
	}
	if _, err := parseServeStatus("not json"); err == nil {
		t.Error("bad json: no error")
	}
}

func TestEvalTunnels(t *testing.T) {
	p := policy.Default().Checks.Tunnels
	named := exposure{tool: "cloudflared", what: "Cloudflare named tunnel", sev: check.High}
	quick := exposure{tool: "cloudflared", what: "quick", port: "8080", sev: check.High, public: true}
	if r := evalTunnels([]exposure{named}, p, nil); r.Status != check.Warn || r.Severity != check.Low {
		t.Errorf("named cloudflared: %s %s", r.Status, r.Severity)
	}
	if r := evalTunnels([]exposure{named, quick}, p, nil); r.Status != check.Warn || r.Severity != check.Medium {
		t.Errorf("quick cloudflared: %s %s", r.Status, r.Severity)
	}
	funnel := exposure{tool: "tailscale-funnel", what: "public", port: "3000", sev: check.High, public: true}
	r := evalTunnels([]exposure{named, funnel}, p, nil)
	if r.Status != check.Fail || r.Severity != check.High || !strings.HasPrefix(r.Evidence[0], "tailscale-funnel") {
		t.Errorf("funnel: %s %s %q", r.Status, r.Severity, r.Evidence)
	}
	p.Allow = []string{"tailscale-funnel", "cloudflared"}
	if r := evalTunnels([]exposure{named, funnel}, p, nil); r.Status != check.Pass || !strings.Contains(r.Summary, "2 more allowed") {
		t.Errorf("allowed: %s %q", r.Status, r.Summary)
	}
	p = policy.Default().Checks.Tunnels
	p.LowerSeverity = nil
	if r := evalTunnels([]exposure{named}, p, nil); r.Status != check.Fail {
		t.Errorf("cloudflared without lower_severity: %s", r.Status)
	}
	if r := evalTunnels(nil, p, nil); r.Status != check.Pass {
		t.Errorf("none: %s", r.Status)
	}
}

// --- secrets: credential stores ---------------------------------------------

func TestCredentialReaders(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("me:" + fakeSecret))
	for _, tc := range []struct {
		name  string
		read  func([]byte) []credHit
		data  string
		names []string // the name of each hit, in order
	}{
		{"docker inline", readDockerConfig, `{"auths":{"ghcr.io":{"auth":"` + b64 + `"},"registry.domain.com":{"identitytoken":"` + fakeBearer + `"}}}`,
			[]string{"ghcr.io", "registry.domain.com"}},
		{"docker creds store", readDockerConfig, `{"auths":{"https://index.docker.io/v1/":{}},"credsStore":"osxkeychain","credHelpers":{"gcr.io":"gcloud"}}`, nil},
		{"kube inline", readKubeConfig, "apiVersion: v1\nclusters:\n- name: prod\n  cluster:\n    certificate-authority-data: " + b64 +
			"\nusers:\n- name: prod-admin\n  user:\n    client-certificate-data: " + b64 + "\n    client-key-data: " + b64 +
			"\n- name: ci\n  user:\n    token: " + fakeBearer + "\n", []string{"prod-admin", "ci"}},
		{"kube exec plugin", readKubeConfig, "users:\n- name: eks\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n" +
			"      command: aws\n      args: [\"eks\", \"get-token\"]\n- name: file\n  user:\n    tokenFile: /var/run/token\n    client-key: /Users/me/.kube/key.pem\n", nil},
		{"netrc multi-line", readNetrc, "machine api.domain.com\n  login me\n  password " + fakeSecret + "\nmachine x login y password $PASS\ndefault login a password b2\n",
			[]string{"api.domain.com", "default"}},
		{"git credentials", readGitCredentials, "https://me:" + fakeGitHub + "@github.com\nhttps://github.com\n", []string{"github.com"}},
		{"git helper store", readGitConfigHelper, "[user]\n  name = Me\n[credential]\n\thelper = store\n", []string{"credential.helper"}},
		{"git helper keychain", readGitConfigHelper, "[credential]\n  helper = osxkeychain\n[alias]\n  helper = store\n", nil},
		{"gcloud user", readGCloudADC, `{"type":"authorized_user","client_id":"x.apps.googleusercontent.com","refresh_token":"1//` + fakeSecret + `"}`, []string{""}},
		{"gcloud service account", readGCloudADC, `{"type":"service_account","client_email":"ci@acme.iam.gserviceaccount.com","private_key":"` +
			strings.ReplaceAll(randomPEM("PRIVATE KEY", nil), "\n", `\n`) + `"}`, []string{"ci@acme.iam.gserviceaccount.com"}},
		{"gcloud external account", readGCloudADC, `{"type":"external_account","audience":"//iam","credential_source":{"file":"/tmp/t"}}`, nil},
		{"azure msal", readAzureTokenCache, `{"AccessToken":{},"RefreshToken":{"k":{"secret":"` + fakeSecret + `"}}}`, []string{""}},
		{"azure empty", readAzureTokenCache, `{"AccessToken":{},"RefreshToken":{},"Account":{}}`, nil},
		{"azure sp", readAzureServicePrincipals, `[{"client_id":"app-1","client_secret":"` + fakeSecret + `"},{"client_id":"app-2","certificate":"/x.pem"}]`, []string{"app-1"}},
		{"pypirc", iniPasswords("PyPI password", "password"), "[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\npassword = pypi-" + fakeSecret + "\n[test]\npassword = <your token>\n", []string{"pypi"}},
		{"gh token", readGHHosts, "github.com:\n    users:\n        me:\n            oauth_token: gh" + "o_" + fakeSecret + "\n    git_protocol: https\n    oauth_token: gh" + "o_" + fakeSecret + "\n", []string{"github.com", "github.com"}},
		{"gh keychain", readGHHosts, "github.com:\n    users:\n        me:\n    git_protocol: https\n    user: me\n", nil},
		{"terraform", readTerraformCreds, `{"credentials":{"app.terraform.io":{"token":"` + fakeSecret + `.atlasv1.` + fakeSecret + `"}}}`, []string{"app.terraform.io"}},
		{"pgpass", readPgPass, "# host:port:db:user:pw\ndb.domain.com:5432:*:app:" + fakeSecret + "\nlocal\\:sock:*:*:me:\nweird:1:d:u:pa\\:ss\n", []string{"db.domain.com", "weird"}},
		{"my.cnf", iniPasswords("MySQL password", "password"), "[client]\nuser=me\npassword=\"" + fakeSecret + "\"\n[mysqldump]\npassword\n", []string{"client"}},
	} {
		hs := tc.read([]byte(tc.data))
		var names []string
		for _, h := range hs {
			names = append(names, h.name)
		}
		if !slices.Equal(names, tc.names) {
			t.Errorf("%s: got %q, want %q (%+v)", tc.name, names, tc.names, hs)
		}
	}
}

func TestScanLocations(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".docker/config.json", `{"auths":{"ghcr.io":{"auth":"`+base64.StdEncoding.EncodeToString([]byte("me:"+fakeSecret))+`"}}}`, 0o600)
	writeFile(t, home, ".kube/config", "users:\n- name: prod-admin\n  user:\n    token: "+fakeBearer+"\n", 0o600)
	writeFile(t, home, ".netrc", "machine api.domain.com login me password "+fakeSecret+"\n", 0o600)
	writeFile(t, home, ".git-credentials", "https://me:"+fakeGitHub+"@github.com\n", 0o600)
	writeFile(t, home, ".config/gcloud/credentials.db", "SQLite format 3\x00", 0o600)
	writeFile(t, home, ".config/gcloud/legacy_credentials/me@domain.com/adc.json", `{"type":"authorized_user","refresh_token":"1//`+fakeSecret+`"}`, 0o600)
	writeFile(t, home, "AppData/Roaming/gcloud/credentials.db", "SQLite format 3\x00", 0o600)
	writeFile(t, home, ".pgpass", "db:5432:*:app:"+fakeSecret+"\n", 0o600)

	p := policy.Default().Checks.Secrets
	s := testScanner(t, p)
	found := s.scanLocations(home, "darwin", p.Locations)
	var got []string
	for _, f := range found {
		got = append(got, filepath.ToSlash(tildePath(home, f.path))+"|"+f.kind+"|"+f.name+"|"+f.tail)
		assertNoLeak(t, "finding", f.String())
	}
	want := []string{
		"~/.docker/config.json|Docker registry login|ghcr.io|",
		"~/.kube/config|Kubernetes token|prod-admin|",
		"~/.netrc|netrc password|api.domain.com|",
		"~/.git-credentials|Git credential (plain text)|github.com|WXYZ",
		"~/.config/gcloud/legacy_credentials/me@domain.com/adc.json|gcloud application default credentials (refresh token)||",
		"~/.config/gcloud/credentials.db|gcloud credential store (tokens in a plain SQLite file)||",
		"~/.pgpass|PostgreSQL password|db|",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, f := range found {
		if f.name == "prod-admin" && !f.prod {
			t.Error("prod-admin not marked production")
		}
	}

	// Each location switches off on its own; ignore_paths still apply.
	p.Locations.Kube, p.Locations.GitCredentials = false, false
	p.IgnorePaths = []string{"~/.config/gcloud/**"}
	s = testScanner(t, p)
	s.ignore = nil
	for _, g := range p.IgnorePaths {
		re, _ := policy.Glob(g)
		s.ignore = append(s.ignore, re)
	}
	found = s.scanLocations(home, "darwin", p.Locations)
	if len(found) != 3 {
		t.Errorf("toggles: got %d findings: %v", len(found), found)
	}
	// Windows keeps gcloud under %APPDATA%.
	found = testScanner(t, policy.Default().Checks.Secrets).scanLocations(home, "windows", policy.Default().Checks.Secrets.Locations)
	if !slices.ContainsFunc(found, func(f secretFinding) bool { return strings.Contains(f.path, "AppData") }) {
		t.Errorf("windows gcloud path not read: %v", found)
	}
}

func TestSecretsMovedFilesStillCovered(t *testing.T) {
	for _, rel := range []string{".netrc", ".pypirc", ".git-credentials", ".docker/config.json"} {
		if slices.Contains(secretFiles, rel) {
			t.Errorf("%s is read by both the generic scan and its location reader", rel)
		}
	}
}

// --- ai-agents --------------------------------------------------------------

func testAIScanner(t *testing.T, p policy.AIAgents) *aiScanner {
	t.Helper()
	s, err := newAIScanner(p, policy.Default().Checks.Secrets, "/home/me")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func aiConfigFor(t *testing.T, agent, format string) aiConfig {
	t.Helper()
	for _, c := range aiConfigs {
		if c.agent == agent && c.format == format {
			return c
		}
	}
	t.Fatalf("no config for %s %s", agent, format)
	return aiConfig{}
}

func TestScanAIConfigs(t *testing.T) {
	s := testAIScanner(t, policy.Default().Checks.AIAgents)
	claudeJSON := `{"numStartups": 12, "oauthAccount": {"accessToken": "` + fakeSecret + `"},
  "mcpServers": {"github": {"command": "npx", "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "` + fakeGitHub + `"}}},
  "projects": {"/Users/me/app": {"mcpServers": {
     "db": {"command": "pg-mcp", "args": ["--password", "` + fakeSecret + `"]},
     "safe": {"command": "x", "env": {"API_KEY": "${API_KEY}", "TOKEN": "${env:TOKEN}"}},
     "remote": {"type": "http", "url": "https://mcp.domain.com/mcp", "headers": {"Authorization": "Bearer ` + fakeBearer + `"}}}}}}`
	settings := `{"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(npm test)"]}, "skipDangerousModePermissionPrompt": true}`
	vscode := `{
  // my settings
  "editor.fontSize": 14,
  "chat.tools.global.autoApprove": true, /* yolo */
  "chat.permissions.default": "ask",
  "github.copilot.chat.claudeAgent.allowDangerouslySkipPermissions": false,
}`
	codex := `model = "gpt-5"
approval_policy = "never"
sandbox_mode = "workspace-write"

[profiles.yolo]
sandbox_mode = "danger-full-access"

[model_providers.acme]
name = "not an mcp server"

[mcp_servers.search]
command = "npx"
env = { "SEARCH_API_KEY" = "` + fakeSecret + `" }

[mcp_servers."remote".http_headers]
Authorization = "Bearer ` + fakeBearer + `"

[mcp_servers.safe]
bearer_token_env_var = "SAFE_TOKEN"
env_vars = ["SAFE_API_KEY", "OTHER_TOKEN"]

[mcp_servers.safe.env_http_headers]
Authorization = "SAFE_AUTH_TOKEN"
`
	zed := `{
  "agent": {"tool_permissions": {"default": "allow"}},
  "context_servers": {"linear": {"url": "https://mcp.linear.app", "headers": {"Authorization": "Bearer ` + fakeBearer + `"}}},
}`
	gemini := `{"mcpServers": {"fs": {"command": "x", "trust": true}, "web": {"command": "y", "trust": false}}, "general": {"defaultApprovalMode": "default"}}`
	continueYAML := "models:\n  - name: gpt\n    provider: openai\n    apiKey: " + fakeOpenAI + "\n  - name: local\n    apiKey: ${{ secrets.OPENAI_KEY }}\n"

	for _, tc := range []struct {
		name   string
		cfg    aiConfig
		data   string
		wheres []string
	}{
		{"claude.json", aiConfigFor(t, "Claude Code", "json"), claudeJSON, []string{
			"mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN", "projects./Users/me/app.mcpServers.db.args",
			"projects./Users/me/app.mcpServers.remote.headers.Authorization"}},
		{"claude settings", aiConfigs[1], settings, []string{
			"permissions.defaultMode = bypassPermissions", "skipDangerousModePermissionPrompt = true"}},
		{"vscode", aiConfigFor(t, "VS Code", "jsonc"), vscode, []string{"chat.tools.global.autoApprove = true"}},
		{"codex", aiConfigFor(t, "Codex", "toml"), codex, []string{
			`profiles.yolo.sandbox_mode = "danger-full-access"`, `approval_policy = "never"`,
			"line 13 (SEARCH_API_KEY)", "line 16 (Authorization)"}},
		{"zed", aiConfigFor(t, "Zed", "jsonc"), zed, []string{
			"agent.tool_permissions.default = allow", "context_servers.linear.headers.Authorization"}},
		{"gemini", aiConfigFor(t, "Gemini CLI", "json"), gemini, []string{"mcpServers.fs.trust = true"}},
		{"continue", aiConfigFor(t, "Continue", "text"), continueYAML, []string{"line 4 (apiKey)"}},
	} {
		found := s.scanConfig(tc.cfg, "~/x", []byte(tc.data), true, true)
		var wheres []string
		for _, f := range found {
			wheres = append(wheres, f.where)
			assertNoLeak(t, tc.name, f.String())
		}
		slices.Sort(wheres)
		want := slices.Clone(tc.wheres)
		slices.Sort(want)
		if !slices.Equal(wheres, want) {
			t.Errorf("%s: got %q, want %q", tc.name, wheres, want)
		}
		// Each sub-rule switches off on its own.
		for _, f := range s.scanConfig(tc.cfg, "~/x", []byte(tc.data), false, true) {
			if strings.HasSuffix(f.what, "in plain text") {
				t.Errorf("%s: token found with tokens off: %v", tc.name, f)
			}
		}
		for _, f := range s.scanConfig(tc.cfg, "~/x", []byte(tc.data), true, false) {
			if !strings.HasSuffix(f.what, "in plain text") {
				t.Errorf("%s: guardrail found with guardrails off: %v", tc.name, f)
			}
		}
	}
	// The GitHub token keeps its provider kind and last 4 characters.
	found := s.scanConfig(aiConfigs[0], "~/.claude.json", []byte(claudeJSON), true, false)
	if len(found) == 0 || found[0].tail != "WXYZ" || !strings.Contains(found[0].what, "GitHub token") {
		t.Errorf("github token: %+v", found)
	}
}

func TestAIAgentsScanAll(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".cursor/mcp.json", `{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"`+fakeGitHub+`"}}}}`, 0o600)
	writeFile(t, home, "Library/Application Support/Claude/claude_desktop_config.json", `{"mcpServers":{"s":{"env":{"SLACK_BOT_TOKEN":"`+fakeSecret+`"}}}}`, 0o600)
	writeFile(t, home, "AppData/Roaming/Claude/claude_desktop_config.json", `{"mcpServers":{"s":{"env":{"SLACK_BOT_TOKEN":"`+fakeSecret+`"}}}}`, 0o600)
	writeFile(t, home, ".codex/config.toml", "sandbox_mode = \"danger-full-access\"\n", 0o600)
	writeFile(t, home, "work/agent.json", `{"servers":{"x":{"env":{"ACME_SECRET":"`+fakeSecret+`"}}}}`, 0o600)
	writeFile(t, home, ".cursor/cli-config.json", `{"approvalMode":"allowlist"}`, 0o600)

	p := policy.Default().Checks.AIAgents
	p.ExtraPaths = []string{"~/work/agent.json"}
	found, files := testAIScanner(t, p).scanAll(home, "darwin", p)
	var paths []string
	for _, f := range found {
		paths = append(paths, filepath.ToSlash(tildePath(home, f.path)))
	}
	slices.Sort(paths)
	want := []string{"~/.codex/config.toml", "~/.cursor/mcp.json", "~/Library/Application Support/Claude/claude_desktop_config.json", "~/work/agent.json"}
	if !slices.Equal(paths, want) || files != 5 {
		t.Errorf("darwin: got %q from %d files, want %q from 5", paths, files, want)
	}
	r := evalAIAgents(found, files)
	if r.Status != check.Fail || !strings.Contains(r.Evidence[0], "sandbox_mode") {
		t.Errorf("eval: %s %q", r.Status, r.Evidence)
	}
	assertNoLeak(t, "ai-agents result", append(r.Evidence, r.Summary, r.Fix)...)

	found, _ = testAIScanner(t, p).scanAll(home, "windows", p)
	if !slices.ContainsFunc(found, func(f aiFinding) bool { return strings.Contains(f.path, "AppData") }) {
		t.Errorf("windows Claude Desktop path not read: %v", found)
	}

	p.IgnorePaths = []string{"~/.cursor/**", "~/work/*"}
	found, _ = testAIScanner(t, p).scanAll(home, "darwin", p)
	if len(found) != 2 {
		t.Errorf("ignore_paths: %v", found)
	}
	if r := evalAIAgents(nil, 3); r.Status != check.Pass {
		t.Errorf("none: %s", r.Status)
	}
}

func TestStripJSONC(t *testing.T) {
	in := `{"a": "http://x//y", /* c */ "b": [1, 2,], // end
"c": "q\"//"}`
	if got := string(stripJSONC([]byte(in))); !strings.Contains(got, `"http://x//y"`) || strings.Contains(got, "/* c */") ||
		strings.Contains(got, ",]") || !strings.Contains(got, `"q\"//"`) {
		t.Errorf("got %s", got)
	}
}

func TestPolicyDefaultsForKeyAndAgentChecks(t *testing.T) {
	c := policy.Default().Checks
	if !c.SSHKeys.NoPassphrase || !c.Tunnels.TailscaleFunnel || !c.AIAgents.Guardrails || !c.Secrets.Locations.Kube ||
		!slices.Equal(c.Tunnels.LowerSeverity, []string{"cloudflared"}) {
		t.Errorf("defaults: %+v", c)
	}
	var ids []string
	for _, ch := range All(policy.Default()) {
		ids = append(ids, ch.ID)
	}
	for _, id := range []string{"ssh-keys", "tunnels", "ai-agents"} {
		if !slices.Contains(ids, id) {
			t.Errorf("%s not in All", id)
		}
	}
}
