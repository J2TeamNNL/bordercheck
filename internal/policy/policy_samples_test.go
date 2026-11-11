package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestSampleRules(t *testing.T) {
	if got := Default().Checks.Secrets.SampleRules; !slices.Equal(got, []string{"git-tracked", "sdk", "sample-dir"}) {
		t.Errorf("default: %v", got)
	}
	// Default is a copy: changing it does not change the next default.
	d := Default()
	d.Checks.Secrets.SampleRules[0] = "x"
	if Default().Checks.Secrets.SampleRules[0] != "git-tracked" {
		t.Error("default shares its slice")
	}
	for body, want := range map[string][]string{
		`{"checks": {"secrets": {}}}`:                                             {"git-tracked", "sdk", "sample-dir"},
		`{"checks": {"secrets": {"sample_rules": []}}}`:                           {},
		`{"checks": {"secrets": {"sample_rules": ["sdk"]}}}`:                      {"sdk"},
		`{"checks": {"secrets": {"sample_rules": ["sample-dir","git-tracked"]}}}`: {"sample-dir", "git-tracked"},
	} {
		p, err := Parse([]byte(body), "t")
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if got := p.Checks.Secrets.SampleRules; !slices.Equal(got, want) {
			t.Errorf("%s: %v", body, got)
		}
	}
	for body, msg := range map[string]string{
		`{"checks": {"secrets": {"sample_rules": ["tests"]}}}`:      `unknown rule "tests"`,
		`{"checks": {"secrets": {"sample_rules": ["sdk", "sdk"]}}}`: `"sdk" is listed twice`,
		`{"checks": {"secrets": {"sample_rules": "sdk"}}}`:          "cannot unmarshal",
	} {
		if _, err := Parse([]byte(body), "t"); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v", body, err)
		}
	}
}
