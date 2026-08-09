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

func TestHMACSecret2DefinitionsMatchPinnedSource(t *testing.T) {
	tests := hmacSecret2Tests(Config{})
	wantIDs := []conformance.TestID{
		TestIDHMACSecret2P1,
		TestIDHMACSecret2P2,
		TestIDHMACSecret2P3,
		TestIDHMACSecret2F1,
		TestIDHMACSecret2F2,
		TestIDHMACSecret2F3,
	}
	if len(tests) != len(wantIDs) {
		t.Fatalf("test count = %d, want %d", len(tests), len(wantIDs))
	}
	for index, test := range tests {
		if test.ID != wantIDs[index] || test.Source.Path != hmacSecret2SourcePath ||
			test.Source.Case != []string{"P-1", "P-2", "P-3", "F-1", "F-2", "F-3"}[index] {
			t.Fatalf("test[%d] identity/source = %q/%#v", index, test.ID, test.Source)
		}
		if !test.Destructive || test.Run == nil {
			t.Fatalf("test[%d] destructive/run = %t/%v", index, test.Destructive, test.Run)
		}
		if !hasHMACSecretReference(test.References, "6.5.7", "pin-uv-auth-protocol-two") {
			t.Fatalf("test[%d] omits the protocol 2 crypto reference", index)
		}
	}
}

func TestHMACSecret2ApplicabilityRequiresExactProtocolTwo(t *testing.T) {
	extensions, err := cbor.Marshal([]extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[uint64]cbor.RawMessage{
		2: extensions,
	}
	info := protocol.AuthenticatorGetInfoResponse{
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
	}
	var skip *conformance.SkipError
	if err := hmacSecret2Applicability(fields, info, Config{}); err == nil || !errors.As(err, &skip) {
		t.Fatalf("protocol-1-only error = %T %v, want skip", err, err)
	}
	info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	}
	if err := hmacSecret2Applicability(fields, info, Config{}); err != nil {
		t.Fatalf("advertised protocol 2: %v", err)
	}
}

func TestHMACSecret2CasesExecuteExactProtocolTwoTranscripts(t *testing.T) {
	tests := []struct {
		id             conformance.TestID
		wantTokens     int
		wantMC         int
		wantGA         int
		wantSaltLength []int
	}{
		{id: TestIDHMACSecret2P1, wantTokens: 2, wantMC: 2},
		{id: TestIDHMACSecret2P2, wantTokens: 2, wantMC: 2, wantGA: 6, wantSaltLength: []int{32, 32, 64, 32, 32, 64}},
		{id: TestIDHMACSecret2P3, wantTokens: 4, wantMC: 2, wantGA: 4, wantSaltLength: []int{64, 64, 64, 64}},
		{id: TestIDHMACSecret2F1, wantTokens: 2},
		{id: TestIDHMACSecret2F2, wantTokens: 4, wantMC: 2},
		{id: TestIDHMACSecret2F3, wantTokens: 4, wantMC: 2},
	}

	for _, testCase := range tests {
		t.Run(string(testCase.id), func(t *testing.T) {
			device := newHMACSecret2ExecutionDevice(t)
			result := runHMACSecretDefinition(
				t, device, hmacSecretExecutionConfig(device), hmacSecret2Tests, testCase.id,
			)

			assertHMACSecretExecutionStatus(t, result, conformance.StatusPassed)
			if device.permissionTokenCalls != testCase.wantTokens ||
				len(device.makeCredentialRecords) != testCase.wantMC ||
				len(device.getAssertionRecords) != testCase.wantGA {
				t.Fatalf("tokens/MC/GA = %d/%d/%d, want %d/%d/%d",
					device.permissionTokenCalls,
					len(device.makeCredentialRecords),
					len(device.getAssertionRecords),
					testCase.wantTokens,
					testCase.wantMC,
					testCase.wantGA,
				)
			}
			for _, selectedProtocol := range device.base.clientPINProtocols {
				if selectedProtocol != protocol.PinUvAuthProtocolTwo {
					t.Fatalf("ClientPIN transcript selected protocol %d, want only 2", selectedProtocol)
				}
			}
			for _, record := range append(
				slices.Clone(device.makeCredentialRecords),
				device.getAssertionRecords...,
			) {
				if record.protocol != protocol.PinUvAuthProtocolTwo {
					t.Fatalf("command selected protocol %d, want 2", record.protocol)
				}
			}
			gotSaltLengths := make([]int, 0, len(device.getAssertionRecords))
			for _, record := range device.getAssertionRecords {
				gotSaltLengths = append(gotSaltLengths, record.saltLength)
			}
			if !slices.Equal(gotSaltLengths, testCase.wantSaltLength) {
				t.Fatalf("GA salt lengths = %v, want %v", gotSaltLengths, testCase.wantSaltLength)
			}
			if device.base.setPINCalls != 1 || device.powerCycles != 4 || device.resets != 2 {
				t.Fatalf("setPIN/cycles/resets = %d/%d/%d, want 1/4/2",
					device.base.setPINCalls, device.powerCycles, device.resets)
			}
		})
	}
}

func TestHMACSecret2NegativeResponseClassification(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		mode       hmacSecretNegativeMode
		wantStatus conformance.Status
	}{
		{name: "ctap-error", mode: hmacSecretNegativeCTAPError, wantStatus: conformance.StatusPassed},
		{name: "unexpected-success", mode: hmacSecretNegativeSuccess, wantStatus: conformance.StatusFailed},
		{name: "transport-error", mode: hmacSecretNegativeTransportError, wantStatus: conformance.StatusError},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newHMACSecret2ExecutionDevice(t)
			device.makeCredentialNegative = testCase.mode
			result := runHMACSecretDefinition(
				t, device, hmacSecretExecutionConfig(device), hmacSecret2Tests, TestIDHMACSecret2F1,
			)
			assertHMACSecretExecutionStatus(t, result, testCase.wantStatus)
			if testCase.mode != hmacSecretNegativeCTAPError && !allZeroHMACSecret(device.retainedResponseData) {
				t.Fatal("unexpected/transport response data was retained")
			}
		})
	}

	for _, id := range []conformance.TestID{TestIDHMACSecret2F2, TestIDHMACSecret2F3} {
		t.Run(string(id)+"/wrong-status", func(t *testing.T) {
			device := newHMACSecret2ExecutionDevice(t)
			device.invalidSaltStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			result := runHMACSecretDefinition(
				t, device, hmacSecretExecutionConfig(device), hmacSecret2Tests, id,
			)
			assertHMACSecretExecutionStatus(t, result, conformance.StatusFailed)
		})
	}
}

func TestHMACSecret2AlwaysUVAndEnvironmentDoNotReachCommands(t *testing.T) {
	device := newHMACSecret2ExecutionDevice(t)
	device.alwaysUV = true
	result := runHMACSecretDefinition(
		t, device, hmacSecretExecutionConfig(device), hmacSecret2Tests, TestIDHMACSecret2P2,
	)
	assertHMACSecretExecutionStatus(t, result, conformance.StatusSkipped)
	if len(device.makeCredentialRecords) != 0 || len(device.getAssertionRecords) != 0 {
		t.Fatal("alwaysUv skip reached a credential command")
	}

	device = newHMACSecret2ExecutionDevice(t)
	result = runHMACSecretDefinition(t, device, Config{}, hmacSecret2Tests, TestIDHMACSecret2P1)
	assertHMACSecretExecutionStatus(t, result, conformance.StatusError)
	if device.resets != 0 || device.powerCycles != 0 || device.base.setPINCalls != 0 {
		t.Fatal("environment failure mutated the authenticator")
	}
}

func newHMACSecret2ExecutionDevice(t testing.TB) *hmacSecretExecutionDevice {
	t.Helper()

	device := newHMACSecretExecutionDevice(t)
	device.advertisedProtocols = []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	}

	return device
}

func runHMACSecretDefinition(
	t *testing.T,
	device *hmacSecretExecutionDevice,
	config Config,
	definitions func(Config) []conformance.Test,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range definitions(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("HMAC test %q not found", id)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "hmac-secret-definition-execution",
		Name:  "HMAC secret definition execution",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func hasHMACSecretReference(
	references []conformance.RequirementRef,
	section string,
	clause string,
) bool {
	return slices.ContainsFunc(references, func(reference conformance.RequirementRef) bool {
		return reference.Section == section && reference.Clause == clause
	})
}
