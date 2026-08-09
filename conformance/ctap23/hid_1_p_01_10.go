package ctap23

func hid1FirstCases() []hid1Case {
	return []hid1Case{
		{TestIDHID1P1, "P-1", "Remain silent while idle", hid1P1, "", false},
		{TestIDHID1P2, "P-2", "Ignore an unsolicited continuation report", hid1P2, "", false},
		{TestIDHID1P3, "P-3", "Initialize a broadcast channel", hid1P3, "", false},
		{TestIDHID1P4, "P-4", "Allocate unique channels", hid1P4, "", false},
		{TestIDHID1P5, "P-5", "Echo a single-report ping", hid1P5, "", false},
		{TestIDHID1P6, "P-6", "Echo a multi-report ping", hid1P6, "", false},
		{TestIDHID1P7, "P-7", "Abort an incomplete ping with INIT", hid1P7, "", false},
		{TestIDHID1P8, "P-8", "Preserve a leading zero in ping data", hid1P8, "", false},
		{TestIDHID1P9, "P-9", "Report keepalive while awaiting user presence", nil, "", true},
		{TestIDHID1P10, "P-10", "Cancel a pending MakeCredential command", nil, "", true},
	}
}
