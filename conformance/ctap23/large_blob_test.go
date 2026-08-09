package ctap23

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestLargeBlobCasesPassWithIndependentLifecycleExactProtocolTwoAndWireSemantics(t *testing.T) {
	want := []struct {
		id          conformance.TestID
		marker      string
		permissions []protocol.Permission
		operations  []string
	}{
		{TestIDLargeBlobP1, "P-1", []protocol.Permission{protocol.PermissionMakeCredential}, []string{"token:1", "makeCredential"}},
		{TestIDLargeBlobP2, "P-2", []protocol.Permission{protocol.PermissionMakeCredential}, []string{"token:1", "makeCredential"}},
		{TestIDLargeBlobP3, "P-3", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobP4, "P-4", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion", "token:2", "getAssertion"}},
		{TestIDLargeBlobP5, "P-5", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobP6, "P-6", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobP7, "P-7", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobF1, "F-1", []protocol.Permission{protocol.PermissionMakeCredential}, []string{"token:1", "makeCredential"}},
		{TestIDLargeBlobF2, "F-2", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobF3, "F-3", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobF4, "F-4", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobF5, "F-5", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
	}

	for index, expected := range want {
		t.Run(expected.marker, func(t *testing.T) {
			environment := &largeBlobTestEnvironment{}
			device := &largeBlobTestDevice{t: t, marker: expected.marker, environment: environment}
			environment.device = device
			config := environment.config(t)
			if expected.marker == "P-6" || expected.marker == "P-7" {
				policy := expected.marker == "P-7"
				config.LargeBlobEnabledByDefault = &policy
				device.enabledByDefault = policy
			}

			result := runLargeBlobTest(t, device, config, index)
			if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
				t.Fatalf("result = %#v, want passed", result)
			}
			testResult := result.Tests[0]
			if testResult.ID != expected.id || testResult.Source.Path != largeBlobSourcePath || testResult.Source.Case != expected.marker {
				t.Fatalf("source mapping = %#v", testResult)
			}
			if !testResult.Destructive || len(testResult.References) < 6 || testResult.References[0].Section != "12.4" {
				t.Fatalf("metadata = %#v", testResult)
			}
			if len(testResult.Steps) != 5 ||
				testResult.Steps[0].ID != "large-blob.applicability" ||
				testResult.Steps[1].ID != "large-blob.reset" ||
				testResult.Steps[2].ID != "large-blob.authorization" ||
				testResult.Steps[4].ID != "large-blob.cleanup" {
				t.Fatalf("steps = %#v", testResult.Steps)
			}
			for _, step := range testResult.Steps {
				if step.Status != conformance.StatusPassed {
					t.Fatalf("step = %#v, want passed", step)
				}
			}

			wantLifecycle := []string{
				"power-cycle", "reset", "power-cycle",
				"power-cycle", "reset", "power-cycle",
			}
			if !slices.Equal(environment.events, wantLifecycle) {
				t.Fatalf("lifecycle = %v, want %v", environment.events, wantLifecycle)
			}
			wantRPIDs := make([]string, len(expected.permissions))
			for index := range wantRPIDs {
				wantRPIDs[index] = largeBlobRPID(expected.marker)
			}
			if !slices.Equal(device.pinUV.permissionScopes, expected.permissions) ||
				!slices.Equal(device.pinUV.permissionRPIDs, wantRPIDs) {
				t.Fatalf("token scopes = %v/%v, want %v/%v", device.pinUV.permissionScopes, device.pinUV.permissionRPIDs, expected.permissions, wantRPIDs)
			}
			if !slices.Equal(device.operations, expected.operations) {
				t.Fatalf("authorization/command operations = %v, want %v", device.operations, expected.operations)
			}
			if environment.genericTokenProviderCalled {
				t.Fatal("generic TokenProvider was called")
			}
			if device.pinUV.setPINCalls != 1 || !device.pinUV.permissionWiresExact || !device.pinUV.permissionCryptoExact {
				t.Fatalf("exact P2 setup/token transcript = setPIN %d, wire %t, crypto %t", device.pinUV.setPINCalls, device.pinUV.permissionWiresExact, device.pinUV.permissionCryptoExact)
			}
			if device.getInfoCalls != 3 {
				t.Fatalf("GetInfo calls = %d, want pre-reset, post-reset, and post-SetPIN", device.getInfoCalls)
			}
			for requestIndex, pinProtocol := range device.pinUV.pinProtocols {
				if pinProtocol != protocol.PinUvAuthProtocolTwo {
					t.Fatalf("ClientPIN request %d used protocol %d, want 2", requestIndex, pinProtocol)
				}
			}
			if !slices.Equal(device.advertisedProtocols, []protocol.PinUvAuthProtocol{
				protocol.PinUvAuthProtocolOne,
				protocol.PinUvAuthProtocolTwo,
			}) {
				t.Fatalf("advertised PIN/UV protocols = %v, want [1 2]", device.advertisedProtocols)
			}
			if expected.marker == "P-5" && !device.sawWriteWithoutAllowList {
				t.Fatal("P-5 did not omit allowList")
			}
			if (expected.marker == "P-6" || expected.marker == "P-7") && !device.sawMakeCredentialWithoutLargeBlob {
				t.Fatalf("%s did not omit the MakeCredential largeBlob extension", expected.marker)
			}
			for pinIndex, pin := range environment.pins {
				if !allZeroLargeBlob(pin) {
					t.Fatalf("temporary PIN %d was not wiped: %x", pinIndex, pin)
				}
			}
			for tokenIndex, token := range device.tokenSecretBuffers {
				if !allZeroLargeBlob(token) {
					t.Fatalf("token %d was not wiped by cleanup: %x", tokenIndex, token)
				}
			}
			for responseIndex, data := range device.responseData {
				if !allZeroLargeBlob(data) {
					t.Fatalf("response buffer %d was not wiped: %x", responseIndex, data)
				}
			}
			for credentialID, credential := range device.credentials {
				if !allZeroLargeBlob(credential.blob) {
					t.Fatalf("credential %x blob was not wiped by cleanup: %x", credentialID, credential.blob)
				}
			}
		})
	}
}

func TestLargeBlobP4IsSelfContainedAndUsesFreshGetAssertionTokens(t *testing.T) {
	environment := &largeBlobTestEnvironment{}
	device := &largeBlobTestDevice{t: t, marker: "P-4", environment: environment}
	environment.device = device

	result := runLargeBlobTest(t, device, environment.config(t), 3)
	if result.Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
	if device.makeCredentialCalls != 1 || device.getAssertionCalls != 2 {
		t.Fatalf("atomic P-4 commands = MC %d, GA %d, want 1/2", device.makeCredentialCalls, device.getAssertionCalls)
	}
	if device.tokenRequests != 3 || len(device.pinUV.permissionScopes) != 3 {
		t.Fatalf("fresh authorization count = %d/%d, want 3", device.tokenRequests, len(device.pinUV.permissionScopes))
	}
	if !device.sawReadAfterWrite {
		t.Fatal("P-4 did not read the blob written inside the same case")
	}
}

func TestLargeBlobDefaultPolicyIsStrictlyDeclaredAndNilSkipsOnlyP6P7(t *testing.T) {
	for index, marker := range []string{"P-6", "P-7"} {
		t.Run(marker+" nil", func(t *testing.T) {
			environment := &largeBlobTestEnvironment{}
			device := &largeBlobTestDevice{t: t, marker: marker, environment: environment}
			environment.device = device

			result := runLargeBlobTest(t, device, environment.config(t), 5+index)
			if result.Status != conformance.StatusSkipped || len(result.Tests[0].Steps) != 1 {
				t.Fatalf("result = %#v, want applicability skip", result)
			}
			if len(environment.events) != 0 || device.makeCredentialCalls != 0 || environment.genericTokenProviderCalled {
				t.Fatalf("nil policy touched lifecycle/command/provider: %v/%d/%t", environment.events, device.makeCredentialCalls, environment.genericTokenProviderCalled)
			}
		})

		t.Run(marker+" opposite", func(t *testing.T) {
			environment := &largeBlobTestEnvironment{}
			device := &largeBlobTestDevice{t: t, marker: marker, environment: environment}
			environment.device = device
			config := environment.config(t)
			opposite := marker == "P-6"
			config.LargeBlobEnabledByDefault = &opposite

			result := runLargeBlobTest(t, device, config, 5+index)
			if result.Status != conformance.StatusSkipped || len(result.Tests[0].Steps) != 1 {
				t.Fatalf("result = %#v, want applicability skip", result)
			}
		})
	}

	for index, marker := range []string{"P-6", "P-7"} {
		opposite := marker == "P-6"
		for _, policyCase := range []struct {
			name  string
			value *bool
		}{
			{name: "nil"},
			{name: "opposite", value: &opposite},
		} {
			t.Run(marker+" "+policyCase.name+" policy precedes missing P2", func(t *testing.T) {
				fields := largeBlobTestInfoFields()
				fields[6] = []uint{uint(protocol.PinUvAuthProtocolOne)}
				transport := newScriptedCBORTransport(t, scriptedCBORExchange{
					request: []byte{byte(protocol.AuthenticatorGetInfo)},
					response: ctaptransport.CBORResponse{
						StatusCode: ctaptransport.CTAP2_OK,
						Data:       marshalLargeBlobTest(t, fields),
					},
				})
				environment := &largeBlobTestEnvironment{}
				config := environment.config(t)
				config.LargeBlobEnabledByDefault = policyCase.value

				result := runLargeBlobTest(t, transport, config, 5+index)
				if result.Status != conformance.StatusSkipped || len(result.Tests[0].Steps) != 1 {
					t.Fatalf("result = %#v, want policy applicability skip", result)
				}
				if len(environment.events) != 0 || len(environment.pins) != 0 ||
					environment.uvConfiguratorCalls != 0 || environment.genericTokenProviderCalled {
					t.Fatalf(
						"policy skip touched environment: events=%v pins=%d UV=%d generic=%t",
						environment.events,
						len(environment.pins),
						environment.uvConfiguratorCalls,
						environment.genericTokenProviderCalled,
					)
				}
			})
		}
	}

	t.Run("ordinary case does not need policy", func(t *testing.T) {
		environment := &largeBlobTestEnvironment{}
		device := &largeBlobTestDevice{t: t, marker: "P-1", environment: environment}
		environment.device = device

		result := runLargeBlobTest(t, device, environment.config(t), 0)
		if result.Status != conformance.StatusPassed {
			t.Fatalf("result = %#v, want passed", result)
		}
	})
}

func TestLargeBlobUsesExactProtocolTwoUVFallback(t *testing.T) {
	environment := &largeBlobTestEnvironment{}
	device := &largeBlobTestDevice{t: t, marker: "P-4", environment: environment, forceUV: true}
	environment.device = device

	result := runLargeBlobTest(t, device, environment.config(t), 3)
	if result.Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
	if environment.genericTokenProviderCalled {
		t.Fatal("generic TokenProvider was called")
	}
	if environment.uvConfiguratorCalls != 1 || device.pinUV.setPINCalls != 0 {
		t.Fatalf("UV/PIN setup calls = %d/%d, want 1/0", environment.uvConfiguratorCalls, device.pinUV.setPINCalls)
	}
	if device.getInfoCalls != 3 || !device.pinUV.permissionWiresExact || !device.pinUV.permissionCryptoExact {
		t.Fatalf("UV transcript GetInfo/wire/crypto = %d/%t/%t", device.getInfoCalls, device.pinUV.permissionWiresExact, device.pinUV.permissionCryptoExact)
	}
	for _, protocolVersion := range device.pinUV.pinProtocols {
		if protocolVersion != protocol.PinUvAuthProtocolTwo {
			t.Fatalf("UV request protocol = %d, want 2", protocolVersion)
		}
	}
}

func TestLargeBlobApplicabilityUsesRawGetInfoAndReconfirmsAfterReset(t *testing.T) {
	tests := []struct {
		name       string
		featureful bool
		extensions []string
		protocols  []uint
		status     conformance.Status
	}{
		{"missing extension skips", false, nil, nil, conformance.StatusSkipped},
		{"featureful missing both fails", true, nil, nil, conformance.StatusFailed},
		{"mutually exclusive fails", true, []string{string(extension.ExtensionIdentifierLargeBlob), string(extension.ExtensionIdentifierLargeBlobKey)}, nil, conformance.StatusFailed},
		{"missing P2 skips", false, []string{string(extension.ExtensionIdentifierLargeBlob)}, []uint{uint(protocol.PinUvAuthProtocolOne)}, conformance.StatusSkipped},
		{"featureful missing P2 fails", true, []string{string(extension.ExtensionIdentifierLargeBlob)}, []uint{uint(protocol.PinUvAuthProtocolOne)}, conformance.StatusFailed},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			fields := largeBlobTestInfoFields()
			fields[2] = testCase.extensions
			if testCase.protocols != nil {
				fields[6] = testCase.protocols
			}
			transport := newScriptedCBORTransport(t, scriptedCBORExchange{
				request: []byte{byte(protocol.AuthenticatorGetInfo)},
				response: ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP2_OK,
					Data:       marshalLargeBlobTest(t, fields),
				},
			})
			environment := &largeBlobTestEnvironment{}
			config := environment.config(t)
			config.Featureful = testCase.featureful

			result := runLargeBlobTest(t, transport, config, 0)
			if result.Status != testCase.status || len(result.Tests[0].Steps) != 1 {
				t.Fatalf("result = %#v, want %s applicability", result, testCase.status)
			}
			if len(environment.events) != 0 || len(environment.pins) != 0 || environment.genericTokenProviderCalled {
				t.Fatalf("inapplicable case touched environment: %v/%d/%t", environment.events, len(environment.pins), environment.genericTokenProviderCalled)
			}
		})
	}

	t.Run("P2 disappears after reset", func(t *testing.T) {
		environment := &largeBlobTestEnvironment{}
		device := &largeBlobTestDevice{t: t, marker: "P-1", environment: environment, dropP2AfterReset: true}
		environment.device = device

		result := runLargeBlobTest(t, device, environment.config(t), 0)
		if result.Status != conformance.StatusFailed || result.Tests[0].Steps[2].Status != conformance.StatusFailed {
			t.Fatalf("result = %#v, want post-reset failure", result)
		}
		if device.getInfoCalls != 2 || len(environment.pins) != 0 || environment.genericTokenProviderCalled {
			t.Fatalf("post-reset failure touched providers: GetInfo=%d pins=%d generic=%t", device.getInfoCalls, len(environment.pins), environment.genericTokenProviderCalled)
		}
	})
}

func TestLargeBlobRequiresUnsignedResponseWirePresenceAndExactMemberCombinations(t *testing.T) {
	tests := []struct {
		name   string
		index  int
		marker string
		mutate func(*largeBlobTestDevice)
	}{
		{"MakeCredential unsigned output absent", 0, "P-1", func(device *largeBlobTestDevice) { device.omitUnsignedOutput = true }},
		{"MakeCredential largeBlob output absent", 0, "P-1", func(device *largeBlobTestDevice) { device.omitLargeBlobOutput = true }},
		{"MakeCredential supported false", 0, "P-1", func(device *largeBlobTestDevice) { device.forceSupportedFalse = true }},
		{"MakeCredential contains written", 0, "P-1", func(device *largeBlobTestDevice) { device.addWrittenToCreateOutput = true }},
		{"MakeCredential contains unknown member", 0, "P-1", func(device *largeBlobTestDevice) { device.addUnknownToCreateOutput = true }},
		{"MakeCredential contains unsolicited extension output", 0, "P-1", func(device *largeBlobTestDevice) { device.addTopLevelToCreateOutput = true }},
		{"write missing written", 2, "P-3", func(device *largeBlobTestDevice) { device.omitWritten = true }},
		{"write includes read member", 2, "P-3", func(device *largeBlobTestDevice) { device.addBlobToWriteOutput = true }},
		{"write contains unknown member", 2, "P-3", func(device *largeBlobTestDevice) { device.addUnknownToWriteOutput = true }},
		{"write contains unsolicited extension output", 2, "P-3", func(device *largeBlobTestDevice) { device.addTopLevelToAssertionOutput = true }},
		{"read missing blob", 3, "P-4", func(device *largeBlobTestDevice) { device.omitBlobOnRead = true }},
		{"read wrong originalSize", 3, "P-4", func(device *largeBlobTestDevice) { device.wrongOriginalSize = true }},
		{"read contains unknown member", 3, "P-4", func(device *largeBlobTestDevice) { device.addUnknownToReadOutput = true }},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			environment := &largeBlobTestEnvironment{}
			device := &largeBlobTestDevice{t: t, marker: testCase.marker, environment: environment}
			environment.device = device
			testCase.mutate(device)

			result := runLargeBlobTest(t, device, environment.config(t), testCase.index)
			if result.Status != conformance.StatusFailed || result.Tests[0].Status != conformance.StatusFailed {
				t.Fatalf("result = %#v, want failed", result)
			}
			for responseIndex, data := range device.responseData {
				if !allZeroLargeBlob(data) {
					t.Fatalf("response buffer %d was not wiped after failure: %x", responseIndex, data)
				}
			}
		})
	}
}

func TestLargeBlobDecodedOutputsAndResultsClearEveryOwnedBlobCopy(t *testing.T) {
	sourceBlob := []byte("decoded raw blob")
	defer clear(sourceBlob)
	raw := marshalLargeBlobTest(t, map[string]any{
		string(extension.ExtensionIdentifierLargeBlob): map[string]any{
			"blob":         sourceBlob,
			"originalSize": uint(16),
		},
	})
	defer clear(raw)
	decoded, err := decodeLargeBlobRawOutput("authenticatorGetAssertion", raw)
	if err != nil {
		t.Fatal(err)
	}
	direct := decoded.direct()
	nestedBlob := decoded.nested["blob"]
	decoded.clear()
	if !allZeroLargeBlob(direct) || !allZeroLargeBlob(nestedBlob) {
		t.Fatalf("decoded raw copies were not cleared: direct=%x nested=%x", direct, nestedBlob)
	}

	fieldBlob := cbor.RawMessage(bytes.Clone(raw))
	typedBlob := []byte("typed response blob")
	result := largeBlobGetAssertionResult{
		fields: map[uint64]cbor.RawMessage{8: fieldBlob},
		response: protocol.AuthenticatorGetAssertionResponse{
			UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
				extension.ExtensionIdentifierLargeBlob: map[string]any{"blob": typedBlob},
			},
		},
	}
	result.clear()
	if !allZeroLargeBlob(fieldBlob) || !allZeroLargeBlob(typedBlob) {
		t.Fatalf("result-owned copies were not cleared: field=%x typed=%x", fieldBlob, typedBlob)
	}
}

func TestLargeBlobClassifiesExactStatusSetupTokenAndTransportFailures(t *testing.T) {
	t.Run("wrong malformed-input status fails", func(t *testing.T) {
		environment := &largeBlobTestEnvironment{}
		device := &largeBlobTestDevice{
			t:              t,
			marker:         "F-1",
			environment:    environment,
			negativeStatus: ctaptransport.CTAP1_ERR_INVALID_PARAMETER,
		}
		environment.device = device

		result := runLargeBlobTest(t, device, environment.config(t), 7)
		if result.Status != conformance.StatusFailed {
			t.Fatalf("result = %#v, want failed", result)
		}
	})

	for _, testCase := range []struct {
		name   string
		marker string
		index  int
	}{
		{name: "MakeCredential malformed input", marker: "F-1", index: 7},
		{name: "GetAssertion malformed input", marker: "F-2", index: 8},
	} {
		t.Run(testCase.name+" unexpected success data is wiped", func(t *testing.T) {
			environment := &largeBlobTestEnvironment{}
			data := []byte("unexpected successful malformed-input response")
			device := &largeBlobTestDevice{
				t:                    t,
				marker:               testCase.marker,
				environment:          environment,
				negativeSuccess:      true,
				negativeResponseData: data,
			}
			environment.device = device

			result := runLargeBlobTest(t, device, environment.config(t), testCase.index)
			if result.Status != conformance.StatusFailed {
				t.Fatalf("result = %#v, want failed", result)
			}
			if !allZeroLargeBlob(data) {
				t.Fatalf("unexpected success data was not wiped: %x", data)
			}
		})
	}

	for _, testCase := range []struct {
		name   string
		status conformance.Status
		mutate func(*largeBlobTestDevice)
	}{
		{
			name:   "SetPIN CTAP status is a conformance failure",
			status: conformance.StatusFailed,
			mutate: func(device *largeBlobTestDevice) {
				device.ensurePINUV()
				device.pinUV.setPINStatus = ctaptransport.CTAP2_ERR_OPERATION_DENIED
			},
		},
		{
			name:   "permission token CTAP status is a conformance failure",
			status: conformance.StatusFailed,
			mutate: func(device *largeBlobTestDevice) {
				device.ensurePINUV()
				device.pinUV.permissionTokenStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
			},
		},
		{
			name:   "permission token wrong length is a conformance failure",
			status: conformance.StatusFailed,
			mutate: func(device *largeBlobTestDevice) {
				device.ensurePINUV()
				device.pinUV.permissionTokenLength = 16
			},
		},
		{
			name:   "permission token transport error remains an execution error",
			status: conformance.StatusError,
			mutate: func(device *largeBlobTestDevice) {
				device.tokenTransportError = true
			},
		},
		{
			name:   "setup transport error remains an execution error",
			status: conformance.StatusError,
			mutate: func(device *largeBlobTestDevice) {
				device.ensurePINUV()
				device.pinUV.transportErrorCommand = protocol.AuthenticatorClientPIN
			},
		},
		{
			name:   "command transport error remains an execution error",
			status: conformance.StatusError,
			mutate: func(device *largeBlobTestDevice) {
				device.commandError = true
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			environment := &largeBlobTestEnvironment{}
			device := &largeBlobTestDevice{
				t:           t,
				marker:      "P-1",
				environment: environment,
			}
			environment.device = device
			testCase.mutate(device)

			result := runLargeBlobTest(t, device, environment.config(t), 0)
			if result.Status != testCase.status || result.Tests[0].Status != testCase.status {
				t.Fatalf("result = %#v, want %s", result, testCase.status)
			}
			if environment.genericTokenProviderCalled {
				t.Fatal("generic TokenProvider was called")
			}
			for _, pin := range environment.pins {
				if !allZeroLargeBlob(pin) {
					t.Fatalf("temporary PIN was not wiped after failure: %x", pin)
				}
			}
		})
	}

	t.Run("temporary PIN provider error remains execution error", func(t *testing.T) {
		environment := &largeBlobTestEnvironment{}
		device := &largeBlobTestDevice{t: t, marker: "P-1", environment: environment}
		environment.device = device
		config := environment.config(t)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
			return nil, errors.New("temporary PIN unavailable")
		}

		result := runLargeBlobTest(t, device, config, 0)
		if result.Status != conformance.StatusError {
			t.Fatalf("result = %#v, want error", result)
		}
	})
}

type largeBlobTestEnvironment struct {
	events                     []string
	pins                       [][]byte
	device                     *largeBlobTestDevice
	genericTokenProviderCalled bool
	uvConfiguratorCalls        int
}

func (environment *largeBlobTestEnvironment) config(t *testing.T) Config {
	t.Helper()

	return Config{
		Featureful: true,
		PowerCycler: func(context.Context) error {
			environment.events = append(environment.events, "power-cycle")

			return nil
		},
		Resetter: func(_ context.Context, ctapClient *client.Client) error {
			if ctapClient == nil {
				t.Fatal("resetter received nil client")
			}
			environment.events = append(environment.events, "reset")
			if environment.device != nil {
				environment.device.resetSecurityState()
			}

			return nil
		},
		TokenProvider: func(context.Context, *client.Client, PinUvAuthTokenRequest) (PinUvAuthToken, error) {
			environment.genericTokenProviderCalled = true

			return PinUvAuthToken{}, errors.New("generic token provider must not be called")
		},
		TemporaryPINProvider: func(context.Context, TemporaryPINRequest) ([]byte, error) {
			pin := []byte("123456")
			environment.pins = append(environment.pins, pin)

			return pin, nil
		},
		UVConfigurator: func(_ context.Context, pin []byte) error {
			if !bytes.Equal(pin, []byte("123456")) {
				t.Fatalf("UV configurator PIN = %q", pin)
			}
			environment.uvConfiguratorCalls++
			environment.device.ensurePINUV()
			environment.device.pinUV.uvConfigured = true

			return nil
		},
	}
}

type largeBlobTestCredential struct {
	capable      bool
	blob         []byte
	originalSize uint
}

type largeBlobTestDevice struct {
	t                                 testing.TB
	marker                            string
	environment                       *largeBlobTestEnvironment
	pinUV                             *clientPIN2UVPermissionsAuthenticator
	advertisedProtocols               []protocol.PinUvAuthProtocol
	tokenSecretBuffers                [][]byte
	operations                        []string
	credentials                       map[string]*largeBlobTestCredential
	forceUV                           bool
	enabledByDefault                  bool
	dropP2AfterReset                  bool
	resetCalls                        int
	getInfoCalls                      int
	makeCredentialCalls               int
	getAssertionCalls                 int
	tokenRequests                     int
	sawWriteWithoutAllowList          bool
	sawMakeCredentialWithoutLargeBlob bool
	sawReadAfterWrite                 bool
	negativeStatus                    ctaptransport.StatusCode
	negativeSuccess                   bool
	negativeResponseData              []byte
	tokenTransportError               bool
	commandError                      bool
	omitUnsignedOutput                bool
	omitLargeBlobOutput               bool
	forceSupportedFalse               bool
	addWrittenToCreateOutput          bool
	addUnknownToCreateOutput          bool
	addTopLevelToCreateOutput         bool
	omitWritten                       bool
	addBlobToWriteOutput              bool
	addUnknownToWriteOutput           bool
	addTopLevelToAssertionOutput      bool
	omitBlobOnRead                    bool
	wrongOriginalSize                 bool
	addUnknownToReadOutput            bool
	responseData                      [][]byte
}

func (device *largeBlobTestDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		device.t.Fatal("empty CBOR request")
	}

	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		return device.getInfo()
	case protocol.AuthenticatorClientPIN:
		return device.clientPIN(ctx, request)
	case protocol.AuthenticatorMakeCredential:
		return device.makeCredential(request[1:])
	case protocol.AuthenticatorGetAssertion:
		return device.getAssertion(request[1:])
	default:
		device.t.Fatalf("unexpected command %s", protocol.Command(request[0]))

		return ctaptransport.CBORResponse{}, nil
	}
}

func (device *largeBlobTestDevice) getInfo() (ctaptransport.CBORResponse, error) {
	device.ensurePINUV()
	device.getInfoCalls++
	device.advertisedProtocols = []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	}
	fields := largeBlobTestInfoFields()
	if device.dropP2AfterReset && device.resetCalls != 0 {
		fields[6] = []uint{uint(protocol.PinUvAuthProtocolOne)}
	}
	options := fields[4].(map[string]any)
	if device.forceUV {
		delete(options, string(protocol.OptionClientPIN))
		options[string(protocol.OptionUserVerification)] = device.pinUV.uvConfigured
	} else {
		options[string(protocol.OptionClientPIN)] = len(device.pinUV.pin) != 0
	}
	options[string(protocol.OptionPinUvAuthToken)] = true

	return largeBlobTestSuccess(device.t, fields), nil
}

func (device *largeBlobTestDevice) ensurePINUV() {
	device.t.Helper()
	if device.pinUV == nil {
		test, ok := device.t.(*testing.T)
		if !ok {
			device.t.Fatal("largeBlob test device requires *testing.T")
		}
		device.pinUV = newClientPIN2UVPermissionsAuthenticator(test)
	}
}

func (device *largeBlobTestDevice) clientPIN(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.ensurePINUV()

	var body protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
		device.t.Fatal(err)
	}
	isTokenRequest := body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions ||
		body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions
	if device.tokenTransportError && isTokenRequest {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected during permission-token request")
	}
	response, err := device.pinUV.CBOR(ctx, request)
	if err != nil {
		return response, err
	}
	if isTokenRequest {
		device.tokenRequests++
		token := device.pinUV.issuedTokens[body.Permissions]
		device.tokenSecretBuffers = append(device.tokenSecretBuffers, token)
		device.operations = append(device.operations, fmt.Sprintf("token:%d", body.Permissions))
	}

	return response, nil
}

func (device *largeBlobTestDevice) resetSecurityState() {
	device.ensurePINUV()
	device.resetCalls++
	clear(device.pinUV.pin)
	device.pinUV.pin = nil
	for _, token := range device.pinUV.issuedTokens {
		clear(token)
	}
	device.pinUV.issuedTokens = make(map[protocol.Permission][]byte)
	device.pinUV.activeToken = nil
	device.pinUV.activePermission = protocol.PermissionNone
	device.pinUV.uvConfigured = false
	for _, credential := range device.credentials {
		clear(credential.blob)
		credential.blob = nil
	}
}

func (device *largeBlobTestDevice) makeCredential(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	device.makeCredentialCalls++
	device.operations = append(device.operations, "makeCredential")
	if device.commandError {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected during MakeCredential")
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatal(err)
	}
	if device.marker == "F-1" {
		device.requireRawLargeBlobInput(fields, 6)
		device.requireRawAuthorization(fields, 1, 8, 9, protocol.PermissionMakeCredential, largeBlobRPID(device.marker))

		return device.negativeResponse(), nil
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatal(err)
	}
	device.requireAuthorization(
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
		protocol.PermissionMakeCredential,
		request.RP.ID,
	)
	if !request.Options[protocol.OptionResidentKeys] {
		device.t.Fatal("MakeCredential did not request a discoverable credential")
	}

	support := request.Extensions.CreateLargeBlobInput.LargeBlob.Support
	capable := support == extension.LargeBlobSupportPreferred || support == extension.LargeBlobSupportRequired
	if device.marker == "P-6" || device.marker == "P-7" {
		if _, present := fields[6]; present {
			device.t.Fatal("default-policy MakeCredential request unexpectedly contains extensions")
		}
		device.sawMakeCredentialWithoutLargeBlob = true
		capable = device.enabledByDefault
	} else if support != extension.LargeBlobSupportPreferred && support != extension.LargeBlobSupportRequired {
		device.t.Fatalf("MakeCredential largeBlob support = %q", support)
	}

	credentialID := []byte{0xa0, byte(device.makeCredentialCalls)}
	if device.credentials == nil {
		device.credentials = make(map[string]*largeBlobTestCredential)
	}
	device.credentials[string(credentialID)] = &largeBlobTestCredential{capable: capable}

	response := map[uint64]any{
		1: string(attestation.AttestationStatementFormatIdentifierNone),
		2: getAssertionFixtureMakeCredentialAuthData(device.t, credentialID),
		3: map[string]any{},
	}
	if support != "" && !device.omitUnsignedOutput {
		outputs := map[string]any{}
		if !device.omitLargeBlobOutput {
			largeBlobOutput := map[string]any{
				"supported": !device.forceSupportedFalse,
			}
			if device.addWrittenToCreateOutput {
				largeBlobOutput["written"] = true
			}
			if device.addUnknownToCreateOutput {
				largeBlobOutput["unexpected"] = true
			}
			outputs[string(extension.ExtensionIdentifierLargeBlob)] = largeBlobOutput
		}
		if device.addTopLevelToCreateOutput {
			outputs["vendor.example"] = map[string]any{"value": true}
		}
		response[6] = outputs
	}

	return device.success(response), nil
}

func (device *largeBlobTestDevice) getAssertion(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	device.getAssertionCalls++
	device.operations = append(device.operations, "getAssertion")
	if device.commandError {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected during GetAssertion")
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatal(err)
	}
	if slices.Contains([]string{"F-2", "F-3", "F-4", "F-5"}, device.marker) {
		device.requireRawLargeBlobInput(fields, 4)
		device.requireRawAuthorization(fields, 2, 6, 7, protocol.PermissionGetAssertion, largeBlobRPID(device.marker))

		return device.negativeResponse(), nil
	}

	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatal(err)
	}
	device.requireAuthorization(
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
		protocol.PermissionGetAssertion,
		request.RPID,
	)

	var (
		credentialID []byte
		credential   *largeBlobTestCredential
	)
	if len(request.AllowList) == 0 {
		if device.marker != "P-5" {
			device.t.Fatalf("%s GetAssertion unexpectedly omitted allowList", device.marker)
		}
		device.sawWriteWithoutAllowList = true
		for id, stored := range device.credentials {
			credentialID = []byte(id)
			credential = stored
			break
		}
	} else {
		if len(request.AllowList) != 1 {
			device.t.Fatalf("allowList length = %d, want 1", len(request.AllowList))
		}
		credentialID = request.AllowList[0].ID
		credential = device.credentials[string(credentialID)]
	}
	if credential == nil {
		device.t.Fatalf("unknown credential ID %x", credentialID)
	}

	params := request.Extensions.GetLargeBlobInput.LargeBlob
	output := map[string]any{}
	switch {
	case params.Read:
		if len(credential.blob) == 0 {
			device.t.Fatal("read occurred before the case wrote a blob")
		}
		device.sawReadAfterWrite = true
		if !device.omitBlobOnRead {
			output["blob"] = slices.Clone(credential.blob)
		}
		originalSize := credential.originalSize
		if device.wrongOriginalSize {
			originalSize++
		}
		output["originalSize"] = originalSize
		if device.addUnknownToReadOutput {
			output["unexpected"] = true
		}
	case params.OriginalSize != nil:
		written := len(request.AllowList) != 0 && credential.capable
		if written {
			clear(credential.blob)
			credential.blob = slices.Clone(params.Write)
			credential.originalSize = *params.OriginalSize
		}
		if !device.omitWritten {
			output["written"] = written
		}
		if device.addBlobToWriteOutput {
			output["blob"] = []byte("unexpected")
		}
		if device.addUnknownToWriteOutput {
			output["unexpected"] = true
		}
	default:
		device.t.Fatalf("invalid typed largeBlob request = %#v", params)
	}

	unsignedOutputs := map[string]any{
		string(extension.ExtensionIdentifierLargeBlob): output,
	}
	if device.addTopLevelToAssertionOutput {
		unsignedOutputs["vendor.example"] = map[string]any{"value": true}
	}
	response := map[uint64]any{
		1: map[string]any{
			"type": "public-key",
			"id":   credentialID,
		},
		2: getAssertionFixtureAuthData(),
		3: []byte{0x30, 0x00},
		8: unsignedOutputs,
	}

	return device.success(response), nil
}

func (device *largeBlobTestDevice) requireRawLargeBlobInput(
	fields map[uint64]cbor.RawMessage,
	field uint64,
) {
	device.t.Helper()
	rawExtensions, present := fields[field]
	if !present {
		device.t.Fatalf("request is missing extension map field %d", field)
	}
	var extensions map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(rawExtensions, &extensions); err != nil {
		device.t.Fatal(err)
	}
	raw, present := extensions[string(extension.ExtensionIdentifierLargeBlob)]
	if !present {
		device.t.Fatal("request is missing explicitly encoded largeBlob input")
	}
	var value map[string]any
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		device.t.Fatal(err)
	}
	switch device.marker {
	case "F-1", "F-2":
		if value["wrong"] != "123" {
			device.t.Fatalf("largeBlob input = %#v", value)
		}
	case "F-3":
		if value["read"] != true || value["write"] == nil || value["originalSize"] == nil {
			device.t.Fatalf("largeBlob input = %#v", value)
		}
	case "F-4":
		if _, ok := value["read"].(string); !ok {
			device.t.Fatalf("largeBlob read = %#v, want string", value["read"])
		}
	case "F-5":
		if _, ok := value["write"].(string); !ok {
			device.t.Fatalf("largeBlob write = %#v, want string", value["write"])
		}
		if _, ok := value["originalSize"].(string); !ok {
			device.t.Fatalf("largeBlob originalSize = %#v, want string", value["originalSize"])
		}
	default:
		device.t.Fatalf("unexpected negative marker %s", device.marker)
	}
}

func (device *largeBlobTestDevice) requireAuthorization(
	protocolVersion protocol.PinUvAuthProtocol,
	parameter []byte,
	clientDataHash []byte,
	permission protocol.Permission,
	rpID string,
) {
	device.t.Helper()
	if protocolVersion != protocol.PinUvAuthProtocolTwo {
		device.t.Fatalf("pinUvAuthProtocol = %d, want 2", protocolVersion)
	}
	device.ensurePINUV()
	if len(device.pinUV.permissionScopes) == 0 || len(device.pinUV.permissionRPIDs) == 0 {
		device.t.Fatal("command issued without a permission token")
	}
	index := len(device.pinUV.permissionScopes) - 1
	if device.pinUV.permissionScopes[index] != permission || device.pinUV.permissionRPIDs[index] != rpID {
		device.t.Fatalf("token scope = %d/%q, want %d/%q", device.pinUV.permissionScopes[index], device.pinUV.permissionRPIDs[index], permission, rpID)
	}
	token := device.pinUV.issuedTokens[permission]
	if len(token) != 32 {
		device.t.Fatalf("issued token length = %d, want 32", len(token))
	}
	expected := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, clientDataHash)
	defer clear(expected)
	if !bytes.Equal(parameter, expected) {
		device.t.Fatalf("pinUvAuthParam = %x, want %x", parameter, expected)
	}
}

func (device *largeBlobTestDevice) requireRawAuthorization(
	fields map[uint64]cbor.RawMessage,
	clientDataHashField uint64,
	parameterField uint64,
	protocolField uint64,
	permission protocol.Permission,
	rpID string,
) {
	device.t.Helper()
	var clientDataHash []byte
	if err := getInfoDecMode.Unmarshal(fields[clientDataHashField], &clientDataHash); err != nil {
		device.t.Fatal(err)
	}
	var parameter []byte
	if err := getInfoDecMode.Unmarshal(fields[parameterField], &parameter); err != nil {
		device.t.Fatal(err)
	}
	var protocolVersion protocol.PinUvAuthProtocol
	if err := getInfoDecMode.Unmarshal(fields[protocolField], &protocolVersion); err != nil {
		device.t.Fatal(err)
	}
	device.requireAuthorization(protocolVersion, parameter, clientDataHash, permission, rpID)
}

func (device *largeBlobTestDevice) expectedNegativeStatus() ctaptransport.StatusCode {
	if device.negativeSuccess {
		return ctaptransport.CTAP2_OK
	}
	if device.negativeStatus != ctaptransport.CTAP2_OK {
		return device.negativeStatus
	}

	return ctaptransport.CTAP2_ERR_INVALID_CBOR
}

func (device *largeBlobTestDevice) negativeResponse() ctaptransport.CBORResponse {
	return ctaptransport.CBORResponse{
		StatusCode: device.expectedNegativeStatus(),
		Data:       device.negativeResponseData,
	}
}

func (device *largeBlobTestDevice) success(value any) ctaptransport.CBORResponse {
	data := marshalLargeBlobTest(device.t, value)
	device.responseData = append(device.responseData, data)

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

func largeBlobTestInfoFields() map[uint64]any {
	return map[uint64]any{
		1: []string{"FIDO_2_1"},
		2: []string{string(extension.ExtensionIdentifierLargeBlob)},
		3: make([]byte, 16),
		4: map[string]any{
			string(protocol.OptionPinUvAuthToken):   true,
			string(protocol.OptionClientPIN):        false,
			string(protocol.OptionUserVerification): false,
		},
		6: []uint{
			uint(protocol.PinUvAuthProtocolOne),
			uint(protocol.PinUvAuthProtocolTwo),
		},
		10: []map[string]any{{
			"type": "public-key",
			"alg":  int64(-7),
		}},
	}
}

func runLargeBlobTest(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	index int,
) conformance.SuiteResult {
	t.Helper()
	tests := largeBlobTests(config)
	if index < 0 || index >= len(tests) {
		t.Fatalf("test index %d is out of range", index)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "large-blob-test",
		Name:  "largeBlob test",
		Tests: []conformance.Test{tests[index]},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func marshalLargeBlobTest(t testing.TB, value any) []byte {
	t.Helper()
	data, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func largeBlobTestSuccess(t testing.TB, value any) ctaptransport.CBORResponse {
	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       marshalLargeBlobTest(t, value),
	}
}

func allZeroLargeBlob(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}

	return true
}
