package report

import (
	"fmt"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
)

// sampleRuleWords say what each sample rule means, for the text report.
var sampleRuleWords = map[string]string{
	"git-tracked": "unchanged in a git repository",
	"sdk":         "shipped with an SDK",
	"sample-dir":  "in a demo or example folder",
}

// SamplesLine counts the likely sample keys of one result by rule, e.g.
// "3 (2 unchanged in a git repository, 1 shipped with an SDK; sent to IT; -json lists them)";
// "" when there are none. The list itself is in -json only.
func SamplesLine(samples []check.LikelySample) string {
	if len(samples) == 0 {
		return ""
	}
	counts := map[string]int{}
	var order []string
	for _, s := range samples {
		if counts[s.Rule] == 0 {
			order = append(order, s.Rule)
		}
		counts[s.Rule]++
	}
	var parts []string
	for _, rule := range []string{"git-tracked", "sdk", "sample-dir"} {
		if counts[rule] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[rule], sampleRuleWords[rule]))
		}
	}
	for _, rule := range order {
		if _, known := sampleRuleWords[rule]; !known {
			parts = append(parts, fmt.Sprintf("%d %s", counts[rule], rule))
		}
	}
	return fmt.Sprintf("%d (%s; not counted, sent to IT; -json lists them)", len(samples), strings.Join(parts, ", "))
}

// LikelySamples counts the findings set aside as likely sample keys, across all results.
func (r Report) LikelySamples() int {
	n := 0
	for _, res := range r.Results {
		n += len(res.LikelySamples)
	}
	return n
}
