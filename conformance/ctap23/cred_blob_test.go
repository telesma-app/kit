package ctap23

import (
	"bytes"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

func TestCredBlobDefinitionsMatchPinnedSource(t *testing.T) {
	tests := credBlobTests(Config{})
	want := []struct {
		id          conformance.TestID
		marker      string
		destructive bool
	}{
		{TestIDCredBlobP1, "P-1", false},
		{TestIDCredBlobP2, "P-2", true},
		{TestIDCredBlobP3, "P-3", true},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != credBlobSourcePath ||
			test.Source.Case != expected.marker || test.Destructive != expected.destructive ||
			test.Run == nil {
			t.Fatalf("test[%d] = %#v", index, test)
		}
	}
}

func TestCredBlobCasesExecuteExactWireAndEmptyOutput(t *testing.T) {
	for index := range 3 {
		t.Run(credBlobTests(Config{})[index].Source.Case, func(t *testing.T) {
			device := newCredentialExtensionTestDevice(t)
			config := device.config()
			result := runCredentialExtensionTest(t, device, credBlobTests(config)[index])
			requireCredentialExtensionPassed(t, result)

			if index == 0 {
				if len(device.makeRecords) != 0 || len(device.tokenRequests) != 0 || device.resetCalls != 0 {
					t.Fatalf("P-1 mutated state: make/tokens/reset = %d/%d/%d", len(device.makeRecords), len(device.tokenRequests), device.resetCalls)
				}
				return
			}
			if len(device.makeRecords) != 1 || len(device.getRecords) != 1 || len(device.tokenRequests) != 2 {
				t.Fatalf("Make/Get/tokens = %d/%d/%d, want 1/1/2", len(device.makeRecords), len(device.getRecords), len(device.tokenRequests))
			}
			makeRecord := device.makeRecords[0]
			if !makeRecord.options[string(protocol.OptionResidentKeys)] {
				t.Fatalf("MakeCredential options = %#v, want rk=true", makeRecord.options)
			}
			rawBlob, present := makeRecord.extensions[string(extension.ExtensionIdentifierCredentialBlob)]
			if index == 1 {
				var blob []byte
				if !present || getInfoDecMode.Unmarshal(rawBlob, &blob) != nil || len(blob) != 32 ||
					!bytes.Equal(blob, bytes.Repeat([]byte{0x42}, 32)) {
					t.Fatalf("P-2 credBlob input = %x", rawBlob)
				}
				clear(blob)
			} else if present {
				t.Fatalf("P-3 unexpectedly sent credBlob: %x", rawBlob)
			}
			getRecord := device.getRecords[0]
			if !getRecord.allowList || !bytes.Equal(
				getRecord.extensions[string(extension.ExtensionIdentifierCredentialBlob)],
				[]byte{0xf5},
			) {
				t.Fatalf("GetAssertion wire = %#v", getRecord)
			}
			if device.tokenRequests[0].Permission != protocol.PermissionMakeCredential ||
				device.tokenRequests[1].Permission != protocol.PermissionGetAssertion ||
				device.tokenRequests[0].RPID == "" || device.tokenRequests[1].RPID == "" {
				t.Fatalf("token scopes = %#v", device.tokenRequests)
			}
			device.assertOwnedBuffersWiped(t)
		})
	}
}

func TestCredBlobApplicabilityAndOutputFailures(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*credentialExtensionTestDevice)
		index  int
		want   conformance.Status
	}{
		{name: "missing maximum", index: 0, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.info.MaxCredBlobLength = 0
		}},
		{name: "short maximum", index: 0, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.info.MaxCredBlobLength = 31
		}},
		{name: "missing credProtect dependency", index: 0, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.info.Extensions = []extension.ExtensionIdentifier{extension.ExtensionIdentifierCredentialBlob}
		}},
		{name: "resident keys unavailable", index: 1, want: conformance.StatusSkipped, mutate: func(device *credentialExtensionTestDevice) {
			device.info.Options[protocol.OptionResidentKeys] = false
		}},
		{name: "missing create output", index: 1, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.omitCreateOutput = string(extension.ExtensionIdentifierCredentialBlob)
		}},
		{name: "false create output", index: 1, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.createOutputOverride = map[string]any{string(extension.ExtensionIdentifierCredentialBlob): false}
		}},
		{name: "wrong get output", index: 1, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.getOutputOverride = map[string]any{string(extension.ExtensionIdentifierCredentialBlob): "not-bytes"}
		}},
		{name: "missing empty get output", index: 2, want: conformance.StatusFailed, mutate: func(device *credentialExtensionTestDevice) {
			device.omitGetOutput = string(extension.ExtensionIdentifierCredentialBlob)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newCredentialExtensionTestDevice(t)
			testCase.mutate(device)
			config := device.config()
			result := runCredentialExtensionTest(t, device, credBlobTests(config)[testCase.index])
			if result.Status != testCase.want {
				t.Fatalf("status = %s, want %s: %#v", result.Status, testCase.want, result.Tests)
			}
			if testCase.want == conformance.StatusSkipped && (device.resetCalls != 0 || len(device.tokenRequests) != 0) {
				t.Fatalf("skip mutated state: reset/tokens = %d/%d", device.resetCalls, len(device.tokenRequests))
			}
		})
	}
}
