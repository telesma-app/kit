package ctap23

import (
	"bytes"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

func TestCredProtectDefinitionsAndExactCases(t *testing.T) {
	tests := credProtectTests(Config{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDCredProtectP1, "P-1"},
		{TestIDCredProtectP2, "P-2"},
		{TestIDCredProtectP3, "P-3"},
		{TestIDCredProtectP4, "P-4"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		if tests[index].ID != expected.id || tests[index].Source.Path != credProtectSourcePath ||
			tests[index].Source.Case != expected.marker || !tests[index].Destructive {
			t.Fatalf("test[%d] = %#v", index, tests[index])
		}
		if tests[index].Run == nil || len(tests[index].References) != 2 ||
			tests[index].References[0].Section != "12.1" {
			t.Fatalf("test[%d] contract = %#v", index, tests[index])
		}
	}
}
func TestCredProtectCasesRunWithEffectivePolicyAndExactWire(t *testing.T) {
	for index, expectedGets := range []int{2, 2, 2, 0} {
		t.Run(credProtectTests(Config{})[index].Source.Case, func(t *testing.T) {
			device := newCredentialExtensionTestDevice(t)
			config := device.config()
			result := runCredentialExtensionTest(t, device, credProtectTests(config)[index])
			requireCredentialExtensionPassed(t, result)

			if index < 3 {
				if len(device.makeRecords) != 1 || len(device.getRecords) != expectedGets {
					t.Fatalf("Make/Get records = %d/%d", len(device.makeRecords), len(device.getRecords))
				}
				raw := device.makeRecords[0].extensions[string(extension.ExtensionIdentifierCredentialProtection)]
				if !bytes.Equal(raw, []byte{byte(index + 1)}) ||
					device.makeRecords[0].options[string(protocol.OptionResidentKeys)] != true {
					t.Fatalf("MakeCredential wire = %#v", device.makeRecords[0])
				}
				for _, record := range device.getRecords {
					if len(record.extensions) != 0 || record.options[string(protocol.OptionUserPresence)] != false {
						t.Fatalf("GetAssertion wire = %#v", record)
					}
				}
				if !device.getRecords[0].allowList || device.getRecords[1].allowList {
					t.Fatalf("allowList order = %#v", device.getRecords)
				}
			} else {
				if len(device.makeRecords) != 3 || device.cmCalls != 3 {
					t.Fatalf("P-4 Make/CM calls = %d/%d", len(device.makeRecords), device.cmCalls)
				}
				for requested, record := range device.makeRecords {
					raw := record.extensions[string(extension.ExtensionIdentifierCredentialProtection)]
					if !bytes.Equal(raw, []byte{byte(requested + 1)}) ||
						!record.options[string(protocol.OptionResidentKeys)] {
						t.Fatalf("P-4 record %d = %#v", requested, record)
					}
				}
			}

			wantScopes := []protocol.Permission{protocol.PermissionMakeCredential}
			if index == 3 {
				wantScopes = []protocol.Permission{
					protocol.PermissionMakeCredential, protocol.PermissionCredentialManagement,
					protocol.PermissionMakeCredential, protocol.PermissionCredentialManagement,
					protocol.PermissionMakeCredential, protocol.PermissionCredentialManagement,
				}
			}
			gotScopes := make([]protocol.Permission, len(device.tokenRequests))
			for tokenIndex, request := range device.tokenRequests {
				gotScopes[tokenIndex] = request.Permission
				if request.Permission == protocol.PermissionCredentialManagement && request.RPID != "" {
					t.Fatalf("credential-management token is RP-bound: %#v", request)
				}
			}
			if !slices.Equal(gotScopes, wantScopes) {
				t.Fatalf("token scopes = %v, want %v", gotScopes, wantScopes)
			}
			device.assertOwnedBuffersWiped(t)
		})
	}
}

func TestCredProtectAcceptsEffectiveElevationAndRejectsMissingOutput(t *testing.T) {
	device := newCredentialExtensionTestDevice(t)
	device.elevateCredProtect = true
	config := device.config()
	result := runCredentialExtensionTest(t, device, credProtectTests(config)[0])
	requireCredentialExtensionPassed(t, result)
	if len(device.getRecords) != 2 {
		t.Fatalf("effective level 3 GetAssertion calls = %d, want 2 rejected attempts", len(device.getRecords))
	}

	device = newCredentialExtensionTestDevice(t)
	device.omitCreateOutput = string(extension.ExtensionIdentifierCredentialProtection)
	config = device.config()
	result = runCredentialExtensionTest(t, device, credProtectTests(config)[1])
	if result.Status != conformance.StatusFailed {
		t.Fatalf("missing output status = %s, want failed", result.Status)
	}
}

func TestCredProtectApplicabilityStopsBeforeReset(t *testing.T) {
	device := newCredentialExtensionTestDevice(t)
	device.info.Options[protocol.OptionAlwaysUv] = true
	config := device.config()
	result := runCredentialExtensionTest(t, device, credProtectTests(config)[0])
	if result.Status != conformance.StatusSkipped || device.resetCalls != 0 || len(device.tokenRequests) != 0 {
		t.Fatalf("alwaysUv preflight = %s, reset/tokens %d/%d", result.Status, device.resetCalls, len(device.tokenRequests))
	}

	device = newCredentialExtensionTestDevice(t)
	delete(device.info.Options, protocol.OptionCredentialManagement)
	config = device.config()
	result = runCredentialExtensionTest(t, device, credProtectTests(config)[3])
	if result.Status != conformance.StatusSkipped || device.resetCalls != 0 {
		t.Fatalf("credMgmt preflight = %s, reset %d", result.Status, device.resetCalls)
	}
}
