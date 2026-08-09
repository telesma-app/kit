package ctap23

import (
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestHMACSecretMCDefinitionsMatchPinnedSource(t *testing.T) {
	tests := hmacSecretMCTests(Config{})
	wantIDs := []conformance.TestID{
		TestIDHMACSecretMCP1,
		TestIDHMACSecretMCP2,
		TestIDHMACSecretMCP3,
		TestIDHMACSecretMCF1,
		TestIDHMACSecretMCF2,
		TestIDHMACSecretMCF3,
		TestIDHMACSecretMCF4,
	}
	wantCases := []string{"P-1", "P-2", "P-3", "F-1", "F-2", "F-3", "F-4"}
	if len(tests) != len(wantIDs) {
		t.Fatalf("test count = %d, want %d", len(tests), len(wantIDs))
	}
	for index, test := range tests {
		if test.ID != wantIDs[index] || test.Source.Path != hmacSecretMCSourcePath ||
			test.Source.Case != wantCases[index] {
			t.Fatalf("test[%d] identity/source = %q/%#v", index, test.ID, test.Source)
		}
		if !test.Destructive || test.Run == nil {
			t.Fatalf("test[%d] destructive/run = %t/%v", index, test.Destructive, test.Run)
		}
		if !hasHMACSecretReference(test.References, "12.8", "feature-detection") ||
			!hasHMACSecretReference(test.References, "6.5.7", "pin-uv-auth-protocol-two") {
			t.Fatalf("test[%d] omits hmac-secret-mc/protocol references", index)
		}
	}
}

func TestHMACSecretMCApplicabilityUsesBothRequiredExtensions(t *testing.T) {
	base := protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
	}
	for _, extensions := range [][]extension.ExtensionIdentifier{
		{extension.ExtensionIdentifierHMACSecret},
		{extension.ExtensionIdentifierHMACSecretMC},
	} {
		info := base
		info.Extensions = extensions
		var skip *conformance.SkipError
		if err := hmacSecretMCApplicability(map[uint64]cbor.RawMessage{}, info, Config{}); err == nil ||
			!errors.As(err, &skip) {
			t.Fatalf("partial extension set %v error = %T %v, want skip", extensions, err, err)
		}
		var failure *conformance.AssertionError
		if err := hmacSecretMCApplicability(
			map[uint64]cbor.RawMessage{}, info, Config{Featureful: true},
		); err == nil || !errors.As(err, &failure) {
			t.Fatalf("featureful partial set %v error = %T %v, want failure", extensions, err, err)
		}
	}
}

func TestHMACSecretMCCasesExecuteAdvertisedProtocolAndCredentialMatrix(t *testing.T) {
	tests := []struct {
		id         conformance.TestID
		wantTokens int
		wantMC     []hmacSecretExecutionRecord
		wantGA     []hmacSecretExecutionRecord
	}{
		{
			id: TestIDHMACSecretMCP1, wantTokens: 2,
			wantMC: hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1, 2}, []bool{false}, false, true, 64),
			wantGA: hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1, 2}, []bool{false}, true, false, 64),
		},
		{
			id: TestIDHMACSecretMCP2, wantTokens: 8,
			wantMC: hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1, 2}, []bool{false, true}, true, true, 32),
			wantGA: hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1, 2}, []bool{false, true}, true, false, 32),
		},
		{
			id: TestIDHMACSecretMCP3, wantTokens: 12,
			wantMC: slices.Concat(
				hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1}, []bool{false}, true, true, 64),
				hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1}, []bool{false}, true, true, 64),
				hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1}, []bool{true}, true, true, 64),
				hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1}, []bool{true}, true, true, 64),
				hmacSecretMCRecords([]protocol.PinUvAuthProtocol{2}, []bool{false}, true, true, 64),
				hmacSecretMCRecords([]protocol.PinUvAuthProtocol{2}, []bool{false}, true, true, 64),
				hmacSecretMCRecords([]protocol.PinUvAuthProtocol{2}, []bool{true}, true, true, 64),
				hmacSecretMCRecords([]protocol.PinUvAuthProtocol{2}, []bool{true}, true, true, 64),
			),
			wantGA: hmacSecretMCRecords([]protocol.PinUvAuthProtocol{1, 2}, []bool{false, true}, true, false, 64),
		},
		{id: TestIDHMACSecretMCF1, wantTokens: 4},
		{id: TestIDHMACSecretMCF2, wantTokens: 4},
		{id: TestIDHMACSecretMCF3, wantTokens: 4},
		{id: TestIDHMACSecretMCF4, wantTokens: 4},
	}

	for _, testCase := range tests {
		t.Run(string(testCase.id), func(t *testing.T) {
			device := newHMACSecretMCExecutionDevice(t)
			result := runHMACSecretMCDefinition(
				t, device, hmacSecretExecutionConfig(device), testCase.id,
			)

			assertHMACSecretExecutionStatus(t, result, conformance.StatusPassed)
			if device.permissionTokenCalls != testCase.wantTokens {
				t.Fatalf("permission tokens = %d, want %d", device.permissionTokenCalls, testCase.wantTokens)
			}
			if !slices.Equal(device.makeCredentialRecords, testCase.wantMC) {
				t.Fatalf("MakeCredential records = %#v, want %#v", device.makeCredentialRecords, testCase.wantMC)
			}
			if !slices.Equal(device.getAssertionRecords, testCase.wantGA) {
				t.Fatalf("GetAssertion records = %#v, want %#v", device.getAssertionRecords, testCase.wantGA)
			}
			if device.base.setPINCalls != 1 || device.powerCycles != 4 || device.resets != 2 {
				t.Fatalf("setPIN/cycles/resets = %d/%d/%d, want 1/4/2",
					device.base.setPINCalls, device.powerCycles, device.resets)
			}
		})
	}
}

func TestHMACSecretMCNegativeStatusesAreExact(t *testing.T) {
	device := newHMACSecretMCExecutionDevice(t)
	device.invalidSaltStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
	result := runHMACSecretMCDefinition(
		t, device, hmacSecretExecutionConfig(device), TestIDHMACSecretMCF3,
	)
	assertHMACSecretExecutionStatus(t, result, conformance.StatusFailed)

	device = newHMACSecretMCExecutionDevice(t)
	device.makeCredentialNegative = hmacSecretNegativeSuccess
	result = runHMACSecretMCDefinition(
		t, device, hmacSecretExecutionConfig(device), TestIDHMACSecretMCF2,
	)
	assertHMACSecretExecutionStatus(t, result, conformance.StatusFailed)
}

func TestHMACSecretMCP1ApplicabilityAndEnvironmentDoNotMutate(t *testing.T) {
	device := newHMACSecretMCExecutionDevice(t)
	device.makeCredUvNotRqd = false
	result := runHMACSecretMCDefinition(
		t, device, hmacSecretExecutionConfig(device), TestIDHMACSecretMCP1,
	)
	assertHMACSecretExecutionStatus(t, result, conformance.StatusSkipped)
	if len(device.makeCredentialRecords) != 0 || len(device.getAssertionRecords) != 0 {
		t.Fatal("P-1 option skip reached a credential command")
	}

	device = newHMACSecretMCExecutionDevice(t)
	result = runHMACSecretMCDefinition(t, device, Config{}, TestIDHMACSecretMCP2)
	assertHMACSecretExecutionStatus(t, result, conformance.StatusError)
	if device.resets != 0 || device.powerCycles != 0 || device.base.setPINCalls != 0 {
		t.Fatal("environment failure mutated the authenticator")
	}
}

func newHMACSecretMCExecutionDevice(t testing.TB) *hmacSecretExecutionDevice {
	t.Helper()

	device := newHMACSecret2ExecutionDevice(t)
	device.hmacSecretMCSupported = true
	device.makeCredUvNotRqd = true

	return device
}

func runHMACSecretMCDefinition(
	t *testing.T,
	device *hmacSecretExecutionDevice,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range hmacSecretMCTests(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("hmac-secret-mc test %q not found", id)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "hmac-secret-mc-definition-execution",
		Name:  "HMAC secret MC definition execution",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func hmacSecretMCRecords(
	protocols []protocol.PinUvAuthProtocol,
	discoverableValues []bool,
	verified bool,
	makeOutput bool,
	saltLength int,
) []hmacSecretExecutionRecord {
	var records []hmacSecretExecutionRecord
	for _, selectedProtocol := range protocols {
		for _, discoverable := range discoverableValues {
			records = append(records, hmacSecretExecutionRecord{
				protocol:     selectedProtocol,
				discoverable: discoverable,
				verified:     verified,
				makeOutput:   makeOutput,
				saltLength:   saltLength,
			})
		}
	}

	return records
}
