package policy

import "testing"

func TestCompromiseAlert(t *testing.T) {
	if !Default().Report.CompromiseAlert {
		t.Error("report.compromise_alert should be on by default")
	}
	p, err := Parse([]byte(`{"report": {"interval": "24h"}}`), "p")
	if err != nil || !p.Report.CompromiseAlert {
		t.Errorf("absent: %v %v", err, p.Report.CompromiseAlert)
	}
	p, err = Parse([]byte(`{"report": {"interval": "24h", "compromise_alert": false}}`), "p")
	if err != nil || p.Report.CompromiseAlert {
		t.Errorf("off: %v %v", err, p.Report.CompromiseAlert)
	}
	if _, err := Parse([]byte(`{"report": {"compromise_alert": "yes"}}`), "p"); err == nil {
		t.Error("a string should not parse as a bool")
	}
}
