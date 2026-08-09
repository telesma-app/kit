package ctap23

import "testing"

func TestHID1TailCaseOwnership(t *testing.T) {
	cases := hid1TailCases()
	if len(cases) != 9 || cases[0].id != TestIDHID1P11 || cases[len(cases)-1].id != TestIDHID1F4 {
		t.Fatalf("tail cases = %#v", cases)
	}
}
