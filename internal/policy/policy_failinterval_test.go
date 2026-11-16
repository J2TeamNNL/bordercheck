package policy

import (
	"strings"
	"testing"
	"time"
)

func TestFailEvery(t *testing.T) {
	for _, c := range []struct {
		interval, fail string
		want           time.Duration
	}{
		{"168h", "", 24 * time.Hour},    // the default: daily while failing
		{"168h", "12h", 12 * time.Hour}, // set
		{"168h", "0", 168 * time.Hour},  // off: weekly whatever happens
		{"12h", "", 12 * time.Hour},     // never longer than the report interval
		{"24h", "48h", 24 * time.Hour},
	} {
		r := Report{Interval: c.interval, FailInterval: c.fail}
		if got := r.FailEvery(); got != c.want {
			t.Errorf("interval %s, fail_interval %q: %s, want %s", c.interval, c.fail, got, c.want)
		}
	}
}

func TestFailIntervalValidation(t *testing.T) {
	for v, ok := range map[string]bool{"": true, "0": true, "24h": true, "1h": true, "30m": false, "daily": false} {
		p := Default()
		p.Report.URL = "https://example.com/report"
		p.Report.FailInterval = v
		err := p.validate()
		if ok != (err == nil) || (err != nil && !strings.Contains(err.Error(), "fail_interval")) {
			t.Errorf("fail_interval %q: %v", v, err)
		}
	}
}

func TestAccessGraceValidation(t *testing.T) {
	if d := Default(); d.Access.WarnGrace != "168h" || d.Access.FailGrace != "72h" {
		t.Errorf("defaults: %+v", d.Access)
	}
	for v, ok := range map[string]bool{"0": true, "72h": true, "2160h": true, "2161h": false, "-1h": false, "3d": false, "": false} {
		p := Default()
		p.Report.URL = "https://example.com/report"
		p.Access.FailGrace = v
		err := p.validate()
		if ok != (err == nil) || (err != nil && !strings.Contains(err.Error(), "access.fail_grace")) {
			t.Errorf("fail_grace %q: %v", v, err)
		}
	}
}
