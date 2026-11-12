package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/ignore"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func samplePolicy(rules ...string) policy.Secrets { return policy.Secrets{SampleRules: rules} }

// classifier uses a temp folder as home, whatever home is given: the
// findings' paths are shown with ~, and nothing is on disk there.
func classifier(t *testing.T, _ string, rules ...string) *sampleClassifier {
	t.Helper()
	home := t.TempDir()
	if rules == nil {
		rules = policy.SampleRuleNames
	}
	return newSampleClassifier(context.Background(), samplePolicy(rules...), home)
}

func TestSampleDirRule(t *testing.T) {
	for p, want := range map[string]bool{
		"~/code/demo-apps/watch/keys/sign.pem":   true,
		"~/demo-key/author.p12":                  true,
		"~/src/lib/Examples/server.key":          true,
		"~/src/lib/test_fixtures/.env":           true,
		"~/go/src/x/testdata/rsa.pem":            true,
		"~/proj/mocks/.env":                      true,
		"~/proj/sample.d/.env":                   true,
		"~/proj/samples/.env":                    true,
		"~/proj/tests/.env":                      false, // test/tests are left out
		"~/proj/test/.env":                       false,
		"~/proj/demonstration/.env":              false, // whole words only
		"~/proj/myDemoApp/.env":                  false, // no camelCase split
		"~/proj/.env.example-ish":                false, // the file's own name does not count
		"~/example.pem":                          false,
		"/opt/demo/.env":                         false, // outside the home folder
		"~/proj/samples/.git/config":             false, // inside .git: never
		"~" + string(filepath.Separator) + "x":   false,
		"~/work/DEMO/production-like/server.key": true,
	} {
		c := classifier(t, "/home/an", "sample-dir")
		if got := c.take(p, "", "Private key", false); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}

func TestSDKRule(t *testing.T) {
	for p, want := range map[string]bool{
		"~/tizen-studio/tools/certificate-generator/certificates/distributor/tizen-distributor-signer.p12":             true,
		"~/tizen-studio/tools/certificate-generator/certificates/distributor/sdk-partner/tizen-distributor-signer.p12": true,
		"~/tizen-studio/tools/certificate-generator/certificates/developer/tizen-developer-ca.cer":                     true,
		"~/tizen-sdk/tools/certificate-generator/certificates/distributor/tizen-distributor-signer.p12":                true,
		"~/tizen-studio-data/keystore/author/author.p12":                                                               false, // generated per user
		"~/tizen-studio/certificates.p12":   false,
		"~/certificates/tizen-studio/x.p12": false,
		"~/Android/Sdk/debug.keystore":      false,
	} {
		c := classifier(t, "/home/an", "sdk")
		if got := c.take(p, "", bundleKind, false); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
	// sdk (like git-tracked) may set aside a live-looking token; sample-dir alone may not.
	c := classifier(t, "/home/an")
	if !c.take("~/tizen-studio/x/certificates/demo/.env", "GH_TOKEN", "GitHub token", true) || c.found[0].Rule != "sdk" {
		t.Errorf("token under an SDK folder: %+v", c.found)
	}
	if c.take("~/demo/.env", "GH_TOKEN", "GitHub token", true) {
		t.Error("sample-dir set aside a token")
	}
}

func TestEvalSecretsSamples(t *testing.T) {
	found := []secretFinding{
		{path: "~/code/demo-apps/app/.env", line: 1, kind: "Secret-looking variable", name: "API_SECRET"},
		{path: "~/code/demo-apps/app/.env", line: 2, kind: "GitHub token", name: "GH_TOKEN", tail: "wxyz"},
		{path: "~/code/demo-apps/app/.env.production", line: 1, kind: "Private key", severe: true, prod: true},
		{path: "~/.zshrc", line: 3, kind: "OpenAI API key", name: "OPENAI_API_KEY", tail: "ab12"},
	}
	bundles := []string{"~/tizen-studio/tools/certificate-generator/certificates/distributor/tizen-distributor-signer.p12"}
	c := classifier(t, "/home/an")
	r := evalSecretsSamples(found, bundles, false, nil, nil, c)
	// Left: the GitHub token (sample-dir alone never sets a provider token
	// aside), the production key, the OpenAI key.
	if r.Status != check.Fail || len(r.Evidence) != 3 || !strings.Contains(r.Summary, "3 secrets") ||
		!strings.Contains(r.Summary, "2 more look like sample keys.") {
		t.Errorf("result: %s %q %v", r.Status, r.Summary, r.Evidence)
	}
	want := []check.LikelySample{
		{Path: "~/code/demo-apps/app/.env", Name: "API_SECRET", Kind: "Secret-looking variable", Rule: "sample-dir"},
		{Path: "~/tizen-studio/tools/certificate-generator/certificates/distributor/tizen-distributor-signer.p12", Kind: bundleKind, Rule: "sdk"},
	}
	if !slices.Equal(r.LikelySamples, want) {
		t.Errorf("likely samples: %+v", r.LikelySamples)
	}
	for _, e := range r.Evidence {
		if strings.Contains(e, "API_SECRET") || strings.Contains(e, "tizen") {
			t.Errorf("a sample is in the evidence: %q", e)
		}
	}
	data, _ := json.Marshal(r)
	if !strings.Contains(string(data), `"likely_samples":[{"path":"~/code/demo-apps/app/.env","name":"API_SECRET","kind":"Secret-looking variable","rule":"sample-dir"}`) {
		t.Errorf("json: %s", data)
	}

	// Only samples: the check passes and says so.
	r = evalSecretsSamples(found[:1], bundles, true, nil, nil, classifier(t, "/home/an"))
	if r.Status != check.Pass || r.Severity != "" || len(r.LikelySamples) != 2 || r.Fix != "" ||
		r.Summary != "The only findings are 2 that look like sample keys, not real ones. The scan hit its time limit, so some folders were not checked." {
		t.Errorf("all samples: %s %q", r.Status, r.Summary)
	}
	if r.SummaryParts[0].Key != "samples.all" {
		t.Errorf("parts: %+v", r.SummaryParts)
	}

	// Off: nothing set aside, no field.
	r = evalSecretsSamples(found, bundles, false, nil, nil, newSampleClassifier(context.Background(), samplePolicy(), "/home/an"))
	if len(r.LikelySamples) != 0 || len(r.Evidence) != 5 || strings.Contains(r.Summary, "sample") {
		t.Errorf("off: %q %+v", r.Summary, r.LikelySamples)
	}
	// Only some rules on.
	r = evalSecretsSamples(found, bundles, false, nil, nil, classifier(t, "/home/an", "sdk"))
	if len(r.LikelySamples) != 1 || r.LikelySamples[0].Rule != "sdk" {
		t.Errorf("sdk only: %+v", r.LikelySamples)
	}
}

func TestSamplesAndUserIgnore(t *testing.T) {
	found := []secretFinding{
		{path: "~/demo/.env", line: 1, kind: "Secret-looking variable", name: "A_SECRET"},
		{path: "~/demo/.env", line: 2, kind: "Secret-looking variable", name: "B_SECRET"},
	}
	// The user's entry wins: the finding stays in the user's list, not in the samples.
	u := newUserIgnore("secrets", Local{Ignored: []ignore.Entry{{Check: "secrets", Path: "~/demo/.env", Name: "A_SECRET", Reason: "mine"}}}, true, "/home/an")
	r := evalSecretsSamples(found, nil, false, nil, u, classifier(t, "/home/an"))
	if r.Status != check.Pass || len(r.UserIgnored) != 1 || r.UserIgnored[0].Name != "A_SECRET" ||
		len(r.LikelySamples) != 1 || r.LikelySamples[0].Name != "B_SECRET" {
		t.Errorf("both: %s %+v %+v", r.Status, r.UserIgnored, r.LikelySamples)
	}
	if r.Summary != "The only finding is one you marked as not sensitive. 1 more looks like a sample key." {
		t.Errorf("summary: %q", r.Summary)
	}
}

func TestSamplesCapped(t *testing.T) {
	var found []secretFinding
	for i := range maxSamplesListed + 50 {
		found = append(found, secretFinding{path: "~/examples/.env", line: i + 1, kind: "Secret-looking variable", name: "K_SECRET"})
	}
	r := evalSecretsSamples(found, nil, false, nil, nil, classifier(t, "/home/an"))
	if len(r.LikelySamples) != maxSamplesListed || !strings.Contains(r.Summary, "250") {
		t.Errorf("%d listed, %q", len(r.LikelySamples), r.Summary)
	}
}

// End to end on a made-up home folder: the secrets check finds keys in a git
// repository, a demo folder and an SDK folder, and sets the right ones aside.
func TestSecretsCheckSamplesEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pem := "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA\n-----END PRIVATE KEY-----\n"
	writeRepo(t, filepath.Join(home, "forks", "app"), "sha1", 2, []idxEntry{
		{name: "config/default.pem", content: pem},
		{name: "config/changed.pem", content: pem},
	}, map[string]string{
		"config/default.pem": pem,
		"config/changed.pem": pem + "\n",
		"config/local.pem":   pem, // untracked
	})
	files := map[string]string{
		"demo-key/sign.pem": pem,
		"tizen-studio/tools/certificate-generator/certificates/distributor/tizen-distributor-signer.p12": "binary",
		"work/server.key": pem,
	}
	for rel, c := range files {
		p := filepath.Join(home, filepath.FromSlash(rel))
		must(t, os.MkdirAll(filepath.Dir(p), 0o700))
		must(t, os.WriteFile(p, []byte(c), 0o600))
	}
	p := policy.Default().Checks.Secrets
	p.Locations = policy.SecretLocations{}
	r := secrets(p, Local{})(t.Context())
	rules := map[string]string{}
	for _, s := range r.LikelySamples {
		rules[filepath.ToSlash(s.Path)] = s.Rule
	}
	want := map[string]string{
		"~/forks/app/config/default.pem": "git-tracked",
		"~/demo-key/sign.pem":            "sample-dir",
		"~/tizen-studio/tools/certificate-generator/certificates/distributor/tizen-distributor-signer.p12": "sdk",
	}
	if len(rules) != len(want) {
		t.Errorf("likely samples: %v", rules)
	}
	for k, v := range want {
		if rules[k] != v {
			t.Errorf("%s: %q, want %q", k, rules[k], v)
		}
	}
	if r.Status != check.Fail || len(r.Evidence) != 3 {
		t.Errorf("left: %s %v", r.Status, r.Evidence)
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "MIIBVAIBADAN") {
		t.Error("a value in the result")
	}

	p.SampleRules = []string{}
	if r := secrets(p, Local{})(t.Context()); len(r.LikelySamples) != 0 || len(r.Evidence) != 6 {
		t.Errorf("off: %v %v", r.LikelySamples, r.Evidence)
	}
}
