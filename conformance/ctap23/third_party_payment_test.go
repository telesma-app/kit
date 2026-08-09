package ctap23

import (
	"bytes"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

func TestThirdPartyPaymentDefinitionsMatchPinnedSource(t *testing.T) {
	tests := thirdPartyPaymentTests(Config{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDThirdPartyPaymentP1, "P-1"},
		{TestIDThirdPartyPaymentP2, "P-2"},
		{TestIDThirdPartyPaymentF1, "F-1"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != thirdPartyPaymentSourcePath ||
			test.Source.Case != expected.marker || !test.Destructive || test.Run == nil ||
			len(test.References) != 1 || test.References[0].Section != "12.9" {
			t.Fatalf("test[%d] = %#v", index, test)
		}
	}
}

func TestThirdPartyPaymentCasesExecuteExactWire(t *testing.T) {
	for index := range 3 {
		t.Run(thirdPartyPaymentTests(Config{})[index].Source.Case, func(t *testing.T) {
			device := newCredentialExtensionTestDevice(t)
			config := device.config()
			result := runCredentialExtensionTest(t, device, thirdPartyPaymentTests(config)[index])
			requireCredentialExtensionPassed(t, result)

			if len(device.makeRecords) != 1 || len(device.getRecords) != 1 ||
				len(device.tokenRequests) != 2 {
				t.Fatalf("Make/Get/tokens = %d/%d/%d, want 1/1/2", len(device.makeRecords), len(device.getRecords), len(device.tokenRequests))
			}
			makeRecord := device.makeRecords[0]
			wantDiscoverable := index == 0
			if makeRecord.options[string(protocol.OptionResidentKeys)] != wantDiscoverable {
				t.Fatalf("MakeCredential options = %#v, want rk=%t", makeRecord.options, wantDiscoverable)
			}
			createRaw, createPresent := makeRecord.extensions[string(extension.ExtensionIdentifierThirdPartyPayment)]
			wantCreate := index < 2
			if createPresent != wantCreate || (createPresent && !bytes.Equal(createRaw, []byte{0xf5})) {
				t.Fatalf("MakeCredential thirdPartyPayment = %x, present %t, want canonical true present %t", createRaw, createPresent, wantCreate)
			}
			getRecord := device.getRecords[0]
			if !getRecord.allowList || !bytes.Equal(
				getRecord.extensions[string(extension.ExtensionIdentifierThirdPartyPayment)],
				[]byte{0xf5},
			) {
				t.Fatalf("GetAssertion wire = %#v", getRecord)
			}
			wantPermissions := []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionGetAssertion,
			}
			gotPermissions := []protocol.Permission{
				device.tokenRequests[0].Permission,
				device.tokenRequests[1].Permission,
			}
			if !slices.Equal(gotPermissions, wantPermissions) ||
				device.tokenRequests[0].RPID == "" || device.tokenRequests[1].RPID == "" {
				t.Fatalf("token scopes = %#v", device.tokenRequests)
			}
			device.assertOwnedBuffersWiped(t)
		})
	}
}

func TestThirdPartyPaymentApplicabilityAndOutputFailures(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		index  int
		want   conformance.Status
		mutate func(*credentialExtensionTestDevice)
	}{
		{name: "resident keys unavailable", index: 0, want: conformance.StatusSkipped, mutate: func(device *credentialExtensionTestDevice) {
			device.info.Options[protocol.OptionResidentKeys] = false
		}},
		{name: "unsolicited create output", index: 0, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.createOutputOverride = map[string]any{string(extension.ExtensionIdentifierThirdPartyPayment): true}
		}},
		{name: "missing get output", index: 1, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.omitGetOutput = string(extension.ExtensionIdentifierThirdPartyPayment)
		}},
		{name: "wrong false output", index: 2, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.getOutputOverride = map[string]any{string(extension.ExtensionIdentifierThirdPartyPayment): true}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newCredentialExtensionTestDevice(t)
			testCase.mutate(device)
			config := device.config()
			result := runCredentialExtensionTest(t, device, thirdPartyPaymentTests(config)[testCase.index])
			if result.Status != testCase.want {
				t.Fatalf("status = %s, want %s: %#v", result.Status, testCase.want, result.Tests)
			}
			if testCase.want == conformance.StatusSkipped &&
				(device.resetCalls != 0 || len(device.tokenRequests) != 0) {
				t.Fatalf("skip mutated state: reset/tokens = %d/%d", device.resetCalls, len(device.tokenRequests))
			}
		})
	}
}
