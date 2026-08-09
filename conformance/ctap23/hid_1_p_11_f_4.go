package ctap23

func hid1TailCases() []hid1Case {
	return []hid1Case{
		{TestIDHID1P11, "P-11", "Legacy GetAssertion keepalive", nil, "upstream case is explicitly disabled for CTAP 2.1 and later", false},
		{TestIDHID1P12, "P-12", "Execute WINK when advertised", hid1P12, "", false},
		{TestIDHID1P13, "P-13", "Unlock a CTAPHID channel", hid1P13, "", false},
		{TestIDHID1P14, "P-14", "Enforce and release a CTAPHID channel lock", hid1P14, "", false},
		{TestIDHID1P15, "P-15", "Cancel authenticatorSelection", hid1P15, "", false},
		{TestIDHID1F1, "F-1", "Reject an unknown CTAPHID command", hid1F1, "", false},
		{TestIDHID1F2, "F-2", "Reject INIT on channel zero", hid1F2, "", false},
		{TestIDHID1F3, "F-3", "Reject PING on channel zero", hid1F3, "", false},
		{TestIDHID1F4, "F-4", "Reject an out-of-order continuation report", hid1F4, "", false},
	}
}
