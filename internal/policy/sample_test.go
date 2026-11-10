package policy

import "testing"

// The receiver's "Paste sample policy" button fills in this file; bordercheck
// must accept it as it is, or a role made from it would never reach a machine.
func TestReceiverSamplePolicyIsValid(t *testing.T) {
	p, err := Load("../../receiver/src/sample-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Update.Binary || p.Checks.ScreenLock.MaxLockMinutes != 10 {
		t.Errorf("sample policy not read as written: %+v", p.Checks.ScreenLock)
	}
}
