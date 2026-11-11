package policy

import (
	"fmt"
	"slices"
	"strings"
)

// SampleRuleNames are the rules that set a secrets finding aside as a likely
// sample key, in the order they are tried; checks.secrets.sample_rules picks
// from them, and all of them are on by default.
//
//   - git-tracked: the file is tracked by git and unchanged from what the
//     repository's index records
//   - sdk: a file an SDK ships identically to every user
//   - sample-dir: the file sits in a folder named like demo, sample, example,
//     fixtures, testdata or mocks
var SampleRuleNames = []string{"git-tracked", "sdk", "sample-dir"}

func validateSampleRules(rules []string) error {
	for i, r := range rules {
		if !slices.Contains(SampleRuleNames, r) {
			return fmt.Errorf("checks.secrets.sample_rules: unknown rule %q (known: %s)", r, strings.Join(SampleRuleNames, ", "))
		}
		if slices.Contains(rules[:i], r) {
			return fmt.Errorf("checks.secrets.sample_rules: %q is listed twice", r)
		}
	}
	return nil
}
