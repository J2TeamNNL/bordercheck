package checks

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func writeTestFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTrashKeyFilesAndAPIClients(t *testing.T) {
	home := t.TempDir()
	for _, v := range []string{"CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "COPILOT_HOME", "CLINE_DATA_DIR", "CLINE_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"} {
		t.Setenv(v, "")
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	old := osName
	osName = func() string { return "darwin" }
	t.Cleanup(func() { osName = old })

	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n"
	writeTestFile(t, filepath.Join(home, ".Trash", "old-ssh", "id_ed25519"), key)
	writeTestFile(t, filepath.Join(home, ".Trash", "old-ssh", "id_ed25519.pub"), "ssh-ed25519 AAAA an@mac\n")
	writeTestFile(t, filepath.Join(home, ".Trash", "api", ".env"), "STRIPE_KEY=sk_"+"live_"+strings.Repeat("a1B2", 8)+"\n")
	writeTestFile(t, filepath.Join(home, "Downloads", "my-proj-1a2b3c.json"),
		`{"type": "service_account", "client_email": "deploy@my-proj.iam.gserviceaccount.com", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEv`+strings.Repeat("Q", 40)+`\n-----END PRIVATE KEY-----\n"}`)
	writeTestFile(t, filepath.Join(home, "Downloads", "package.json"), `{"name": "x", "type": "module"}`)
	writeTestFile(t, filepath.Join(home, "work", "api", "dev.postman_environment.json"),
		`{"name": "dev", "values": [{"key": "API_TOKEN", "value": "pm7Kq2pLw8Zx", "enabled": true}, {"key": "base_url", "value": "https://api.dev"}, {"key": "PASSWORD", "value": "{{vault:pw}}"}]}`)
	ins := insomniaDir(home, runtime.GOOS)
	writeTestFile(t, filepath.Join(ins, "insomnia.Environment.db"),
		`{"_id":"env_1","type":"Environment","name":"Base","data":{"base":"https://x","auth":{"api_key":"ik9Zq2pLw8Rt"}}}`+"\n")
	writeTestFile(t, filepath.Join(ins, "insomnia.Request.db"),
		`{"_id":"req_1","type":"Request","name":"Get users","authentication":{"type":"bearer","token":"eyJhbGciOiJIUzI1NiJ9.e30.x1y2z3"},"headers":[]}`+"\n")
	writeTestFile(t, dbeaverCredentials(home, runtime.GOOS)[0], "\x8a\x01binary")

	r := secrets(policy.Default().Checks.Secrets, Local{})(t.Context())
	ev := strings.Join(r.Evidence, "\n")
	for _, want := range []string{
		"~/.Trash/old-ssh/id_ed25519:1  Private key",
		"~/.Trash/api/.env:1  Stripe live key",
		"~/Downloads/my-proj-1a2b3c.json  Google service account key (deploy@my-proj.iam.gserviceaccount.com)",
		"~/work/api/dev.postman_environment.json  Postman environment secret (API_TOKEN)",
		"Insomnia environment secret (auth.api_key)",
		"Insomnia request credential (Get users (token))",
		"DBeaver saved passwords",
	} {
		if !strings.Contains(filepath.ToSlash(ev), want) {
			t.Errorf("no %q in:\n%s", want, ev)
		}
	}
	for _, not := range []string{"id_ed25519.pub", "package.json", "base_url", "PASSWORD"} {
		if strings.Contains(ev, not) {
			t.Errorf("%q reported:\n%s", not, ev)
		}
	}
	if r.Status != check.Fail || !strings.Contains(r.Fix, "Files in the Trash are still on disk") || !strings.Contains(r.Fix, "DBeaver encrypts") ||
		!strings.Contains(r.Fix, "exported Postman environment") {
		t.Errorf("status %s, fix:\n%s", r.Status, r.Fix)
	}

	// Each switches off alone.
	p := policy.Default().Checks.Secrets
	p.Locations.Trash, p.Locations.KeyFiles, p.Locations.APIClients = false, false, false
	ev = strings.Join(secrets(p, Local{})(t.Context()).Evidence, "\n")
	for _, gone := range []string{".Trash", "service account", "Postman", "Insomnia", "DBeaver"} {
		if strings.Contains(ev, gone) {
			t.Errorf("%s still reported with its switch off:\n%s", gone, ev)
		}
	}
}

func TestKeystoresAndSigningProperties(t *testing.T) {
	home := isolatedHome(t)
	writeTestFile(t, filepath.Join(home, ".android-keys", "app-release.jks"), "\xfe\xed\xfe\xedbinary")
	writeTestFile(t, filepath.Join(home, ".android", "debug.keystore"), "\xfe\xed\xfe\xedbinary")
	writeTestFile(t, filepath.Join(home, "code", "app", "android", "keystore.properties"), "storeFile=../app.jks\nstorePassword=Xk29dLq7wPq\nkeyAlias=upload\n")
	writeTestFile(t, filepath.Join(home, ".gradle", "gradle.properties"), "org.gradle.jvmargs=-Xmx4g\nMYAPP_UPLOAD_STORE_PASSWORD=Tr0ub4dor-x9q\n")
	writeTestFile(t, filepath.Join(home, "code", "app", "android", "app", "version.properties"), "VERSION_PASSWORD_HINT=notscanned123\n")
	r := secrets(policy.Default().Checks.Secrets, Local{})(t.Context())
	ev := filepath.ToSlash(strings.Join(r.Evidence, "\n"))
	for _, want := range []string{
		"~/.android-keys/app-release.jks  Java/Android keystore (a signing key behind a password)",
		"~/code/app/android/keystore.properties:2  Secret-looking variable (storePassword)",
		"~/.gradle/gradle.properties:2  Secret-looking variable (MYAPP_UPLOAD_STORE_PASSWORD)",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("no %q in:\n%s", want, ev)
		}
	}
	if strings.Contains(ev, "debug.keystore") {
		t.Errorf("the SDK's debug keystore was reported:\n%s", ev)
	}
	if strings.Contains(ev, "version.properties") {
		t.Errorf("an unrelated .properties file was read:\n%s", ev)
	}
	if !strings.Contains(r.Fix, "A keystore is a signing key behind a password") {
		t.Errorf("fix: %s", r.Fix)
	}
	if !strings.Contains(ev, "app-release.jks  Java/Android keystore (a signing key behind a password)  [keystore, information]") {
		t.Errorf("a keystore where it belongs is not information:\n%s", ev)
	}
}

func TestKeystoreAloneIsInformation(t *testing.T) {
	home := isolatedHome(t)
	writeTestFile(t, filepath.Join(home, "keystores", "app.jks"), "\xfe\xed\xfe\xedbinary")
	r := secrets(policy.Default().Checks.Secrets, Local{})(t.Context())
	if r.Status != check.Pass || !strings.Contains(strings.Join(r.Evidence, "\n"), "[keystore, information]") {
		t.Errorf("status %v, evidence %q", r.Status, r.Evidence)
	}
	if len(r.Info) != 1 || r.Info[0].Key != "secrets.keystoreInfo" {
		t.Errorf("info %+v, want the keystore message", r.Info)
	}
	// In the Trash it counts. (The Windows Recycle Bin names files differently; TestRecycledName covers it.)
	if runtime.GOOS == "windows" {
		return
	}
	writeTestFile(t, filepath.Join(trashDir(home, runtime.GOOS), "old.jks"), "\xfe\xed\xfe\xedbinary")
	if r := secrets(policy.Default().Checks.Secrets, Local{})(t.Context()); r.Status != check.Warn || !strings.Contains(r.Fix, "A keystore is") {
		t.Errorf("a keystore in the Trash: status %v, fix %q", r.Status, r.Fix)
	}
}
