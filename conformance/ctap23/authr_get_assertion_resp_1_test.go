package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrGetAssertionResp1Definitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrGetAssertionResp1P1, "P-1"},
		{TestIDAuthrGetAssertionResp1P2, "P-2"},
		{TestIDAuthrGetAssertionResp1P3, "P-3"},
		{TestIDAuthrGetAssertionResp1P4, "P-4"},
		{TestIDAuthrGetAssertionResp1F1, "F-1"},
	}
	tests := authrGetAssertionResp1Tests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrGetAssertionResp1SourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive || len(test.References) < 2 {
			t.Fatalf("test %d = %#v", index, test)
		}
		for _, reference := range test.References {
			if reference.Section == "" || reference.Clause == "" || reference.URL == "" {
				t.Fatalf("test %d reference = %#v", index, reference)
			}
		}
	}
}

func TestAuthrGetAssertionResp1P3P4AndF1NormativeReferences(t *testing.T) {
	const ctapURL = "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion"

	commandReference := conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.2:authenticator-get-assertion-request",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.2",
		Clause:        "authenticator-get-assertion-request",
		URL:           ctapURL,
		Level:         conformance.RequirementConstraint,
	}
	tests := []struct {
		id         conformance.TestID
		marker     string
		references []conformance.RequirementRef
	}{
		{
			id:     TestIDAuthrGetAssertionResp1P3,
			marker: "P-3",
			references: []conformance.RequirementRef{
				commandReference,
				{
					ID:            "ctap-2.3-ps-20260226:6.2:get-assertion-response-members",
					Specification: conformance.SpecificationCTAP23,
					Section:       "6.2",
					Clause:        "get-assertion-response-members",
					URL:           ctapURL,
					Level:         conformance.RequirementConstraint,
				},
				{
					ID:            "webauthn-3:6.1.1:signature-counter",
					Specification: "webauthn-level-3",
					Section:       "6.1.1",
					Clause:        "signature-counter",
					URL:           "https://www.w3.org/TR/webauthn-3/#sctn-sign-counter",
					Level:         conformance.RequirementConstraint,
				},
			},
		},
		{
			id:     TestIDAuthrGetAssertionResp1P4,
			marker: "P-4",
			references: []conformance.RequirementRef{
				commandReference,
				{
					ID:            "ctap-2.3-ps-20260226:6.2:get-assertion-response-members",
					Specification: conformance.SpecificationCTAP23,
					Section:       "6.2",
					Clause:        "get-assertion-response-members",
					URL:           ctapURL,
					Level:         conformance.RequirementConstraint,
				},
				{
					ID:            "webauthn-3:7.2:verify-assertion-signature",
					Specification: "webauthn-level-3",
					Section:       "7.2",
					Clause:        "verify-assertion-signature",
					URL:           "https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion",
					Level:         conformance.RequirementMust,
				},
			},
		},
		{
			id:     TestIDAuthrGetAssertionResp1F1,
			marker: "F-1",
			references: []conformance.RequirementRef{
				commandReference,
				{
					ID:            "ctap-2.3-ps-20260226:6.2:unsigned-extension-outputs",
					Specification: conformance.SpecificationCTAP23,
					Section:       "6.2",
					Clause:        "unsigned-extension-outputs",
					URL:           ctapURL,
					Level:         conformance.RequirementShould,
				},
			},
		},
	}
	definitions := authrGetAssertionResp1Tests(Config{})
	for _, testCase := range tests {
		t.Run(testCase.marker, func(t *testing.T) {
			var definition conformance.Test
			for _, candidate := range definitions {
				if candidate.ID == testCase.id {
					definition = candidate
					break
				}
			}
			if !slices.Equal(definition.References, testCase.references) {
				t.Fatalf("definition references = %#v, want %#v", definition.References, testCase.references)
			}

			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			config, _ := authrGetAssertionResp1Config(t, device, []string{material.name})
			result := runAuthrGetAssertionResp1Test(t, device, config, testCase.id)

			assertAuthrGetAssertionResp1Status(t, result, conformance.StatusPassed)
			validateStepID := conformance.StepID("get-assertion-resp-1." + strings.ToLower(testCase.marker) + ".validate")
			for _, step := range result.Tests[0].Steps {
				if step.ID != validateStepID {
					continue
				}
				if !slices.Equal(step.References, testCase.references) {
					t.Fatalf("validate step references = %#v, want %#v", step.References, testCase.references)
				}

				return
			}
			t.Fatalf("validate step %q was not executed", validateStepID)
		})
	}
}

func TestAuthrGetAssertionResp1P1ValidatesRawRequiredAndNestedFields(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrGetAssertionResp1Device(t, material)
	config, lifecycle := authrGetAssertionResp1Config(t, device, []string{material.name})

	result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P1)

	assertAuthrGetAssertionResp1Status(t, result, conformance.StatusPassed)
	assertAuthrGetAssertionResp1Lifecycle(t, device, lifecycle, 1, 1, 2)
}

func TestAuthrGetAssertionResp1P1RejectsRawTopLevelFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[uint64]any)
	}{
		{name: "missing credential", mutate: func(fields map[uint64]any) { delete(fields, 1) }},
		{name: "credential wrong type", mutate: func(fields map[uint64]any) { fields[1] = "descriptor" }},
		{name: "missing authData", mutate: func(fields map[uint64]any) { delete(fields, 2) }},
		{name: "authData wrong type", mutate: func(fields map[uint64]any) { fields[2] = "authData" }},
		{name: "missing signature", mutate: func(fields map[uint64]any) { delete(fields, 3) }},
		{name: "signature wrong type", mutate: func(fields map[uint64]any) { fields[3] = "signature" }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			device.getResponse = func(_ int, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) []byte {
				testCase.mutate(fields)

				return marshalAuthrGetAssertionResp1(t, fields)
			}
			config, _ := authrGetAssertionResp1Config(t, device, []string{material.name})

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P1)

			assertAuthrGetAssertionResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrGetAssertionResp1P1RejectsRawNestedDescriptorFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "missing type", mutate: func(fields map[string]any) { delete(fields, "type") }},
		{name: "type wrong wire type", mutate: func(fields map[string]any) { fields["type"] = []byte("public-key") }},
		{name: "type wrong value", mutate: func(fields map[string]any) { fields["type"] = "vendor-key" }},
		{name: "missing id", mutate: func(fields map[string]any) { delete(fields, "id") }},
		{name: "id wrong wire type", mutate: func(fields map[string]any) { fields["id"] = "credential" }},
		{name: "id does not match", mutate: func(fields map[string]any) { fields["id"] = []byte{0xff} }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			device.getResponse = func(_ int, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) []byte {
				descriptor := fields[1].(map[string]any)
				testCase.mutate(descriptor)

				return marshalAuthrGetAssertionResp1(t, fields)
			}
			config, _ := authrGetAssertionResp1Config(t, device, []string{material.name})

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P1)

			assertAuthrGetAssertionResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrGetAssertionResp1ClassifiesResponseAndCommandFailures(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*authrGetAssertionResp1Device)
		want      conformance.Status
	}{
		{
			name: "CTAP status",
			configure: func(device *authrGetAssertionResp1Device) {
				device.getStatus = ctaptransport.CTAP2_ERR_PROCESSING
			},
			want: conformance.StatusFailed,
		},
		{
			name: "transport error",
			configure: func(device *authrGetAssertionResp1Device) {
				device.getError = errors.New("transport unavailable")
			},
			want: conformance.StatusError,
		},
		{
			name: "malformed CBOR",
			configure: func(device *authrGetAssertionResp1Device) {
				device.getResponse = func(int, protocol.AuthenticatorGetAssertionRequest, map[uint64]any) []byte {
					return []byte{0xff}
				}
			},
			want: conformance.StatusFailed,
		},
		{
			name: "noncanonical CBOR",
			configure: func(device *authrGetAssertionResp1Device) {
				device.getResponse = func(_ int, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) []byte {
					return nonCanonicalAuthrGetAssertionResp1(t, fields)
				}
			},
			want: conformance.StatusFailed,
		},
		{
			name: "invalid authData schema",
			configure: func(device *authrGetAssertionResp1Device) {
				device.getResponse = func(_ int, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) []byte {
					fields[2] = []byte{0x01}

					return marshalAuthrGetAssertionResp1(t, fields)
				}
			},
			want: conformance.StatusFailed,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			testCase.configure(device)
			config, _ := authrGetAssertionResp1Config(t, device, []string{material.name})

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P1)

			assertAuthrGetAssertionResp1Status(t, result, testCase.want)
		})
	}
}

func TestAuthrGetAssertionResp1P2ValidatesAuthenticatorData(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   conformance.Status
	}{
		{name: "valid", want: conformance.StatusPassed},
		{
			name: "wrong length",
			mutate: func(authData []byte) []byte {
				return append(authData, 0x00)
			},
			want: conformance.StatusFailed,
		},
		{
			name: "wrong RP ID hash",
			mutate: func(authData []byte) []byte {
				authData[0] ^= 0xff

				return authData
			},
			want: conformance.StatusFailed,
		},
		{
			name: "AT flag set",
			mutate: func(authData []byte) []byte {
				authData[32] |= byte(protocol.AuthDataFlagAttestedCredentialDataIncluded)

				return authData
			},
			want: conformance.StatusFailed,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			if testCase.mutate != nil {
				device.getResponse = func(_ int, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) []byte {
					fields[2] = testCase.mutate(fields[2].([]byte))

					return marshalAuthrGetAssertionResp1(t, fields)
				}
			}
			config, _ := authrGetAssertionResp1Config(t, device, []string{material.name})

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P2)

			assertAuthrGetAssertionResp1Status(t, result, testCase.want)
		})
	}
}

func TestAuthrGetAssertionResp1P2DoesNotRequireUPOrUV(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrGetAssertionResp1Device(t, material)
	device.getResponse = func(_ int, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) []byte {
		fields[2].([]byte)[32] = 0

		return marshalAuthrGetAssertionResp1(t, fields)
	}
	config, _ := authrGetAssertionResp1Config(t, device, []string{material.name})

	result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P2)

	assertAuthrGetAssertionResp1Status(t, result, conformance.StatusPassed)
}

func TestAuthrGetAssertionResp1P3CounterSequences(t *testing.T) {
	tests := []struct {
		name     string
		counters []uint32
		want     conformance.Status
	}{
		{name: "unsupported all zero", counters: []uint32{0, 0, 0}, want: conformance.StatusPassed},
		{name: "strictly increasing from zero", counters: []uint32{0, 1, 2}, want: conformance.StatusPassed},
		{name: "strictly increasing nonzero", counters: []uint32{7, 8, 10}, want: conformance.StatusPassed},
		{name: "equal", counters: []uint32{1, 1, 2}, want: conformance.StatusFailed},
		{name: "decreasing", counters: []uint32{3, 2, 4}, want: conformance.StatusFailed},
		{name: "partial zero prefix", counters: []uint32{0, 0, 1}, want: conformance.StatusFailed},
		{name: "partial zero suffix", counters: []uint32{0, 1, 0}, want: conformance.StatusFailed},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			device.counters = testCase.counters
			config, lifecycle := authrGetAssertionResp1Config(t, device, []string{material.name})

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P3)

			assertAuthrGetAssertionResp1Status(t, result, testCase.want)
			assertAuthrGetAssertionResp1Lifecycle(t, device, lifecycle, 1, 3, 4)
			assertAuthrGetAssertionResp1FreshRequests(t, device.getRequests)
		})
	}
}

func TestAuthrGetAssertionResp1P4VerifiesAllRegistryCOSEProfiles(t *testing.T) {
	for _, name := range authrMakeCredResp1ProfileAlgorithms {
		t.Run(name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, name)
			device := newAuthrGetAssertionResp1Device(t, material)
			config, lifecycle := authrGetAssertionResp1Config(
				t,
				device,
				metadataCOSEProfileTestAlgorithmNames,
			)

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P4)

			assertAuthrGetAssertionResp1Status(t, result, conformance.StatusPassed)
			assertAuthrGetAssertionResp1Lifecycle(t, device, lifecycle, 1, 1, 2)
			assertAuthrGetAssertionResp1Parameters(
				t,
				device.makeRequests[0].PubKeyCredParams,
				metadataCOSEProfileTestAlgorithmNames,
			)
		})
	}
}

func TestAuthrGetAssertionResp1P4RejectsCorruptMismatchAndWrongSignedBytes(t *testing.T) {
	tests := []struct {
		name           string
		algorithmNames []string
		keyMutate      func(cose.Key)
		response       func(authrMakeCredResp1Key, protocol.AuthenticatorGetAssertionRequest, map[uint64]any)
	}{
		{
			name:           "corrupt signature",
			algorithmNames: []string{"secp256r1_ecdsa_sha256_raw"},
			response: func(_ authrMakeCredResp1Key, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) {
				signature := fields[3].([]byte)
				signature[len(signature)-1] ^= 0x01
			},
		},
		{
			name:           "wrong signed clientDataHash",
			algorithmNames: []string{"secp256r1_ecdsa_sha256_raw"},
			response: func(material authrMakeCredResp1Key, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) {
				fields[3] = material.sign(t, slices.Concat(fields[2].([]byte), makeCredentialFixtureClientDataHash[:]))
			},
		},
		{
			name:           "invalid credential key",
			algorithmNames: []string{"secp256r1_ecdsa_sha256_raw"},
			keyMutate: func(key cose.Key) {
				key[cose.EC2KeyParameterX] = []byte{0x01}
			},
		},
		{
			name:           "credential profile absent from metadata",
			algorithmNames: []string{"secp384r1_ecdsa_sha384_raw"},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			device.keyMutate = testCase.keyMutate
			if testCase.response != nil {
				device.getResponse = func(_ int, request protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) []byte {
					testCase.response(material, request, fields)

					return marshalAuthrGetAssertionResp1(t, fields)
				}
			}
			config, _ := authrGetAssertionResp1Config(t, device, testCase.algorithmNames)

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P4)

			assertAuthrGetAssertionResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrGetAssertionResp1MetadataPreflightErrorsBeforeReset(t *testing.T) {
	for _, name := range []string{
		"sm2_sm3_raw",
		"rsa_emsa_pkcs1_sha256_raw",
		"rsa_emsa_pkcs1_sha256_der",
	} {
		t.Run(name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			config, lifecycle := authrGetAssertionResp1Config(t, device, []string{name})

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P1)

			assertAuthrGetAssertionResp1Status(t, result, conformance.StatusError)
			if lifecycle.powerCycles != 0 || device.resets != 0 || len(device.makeRequests) != 0 {
				t.Fatalf(
					"preflight used device: power=%d resets=%d make=%d",
					lifecycle.powerCycles,
					device.resets,
					len(device.makeRequests),
				)
			}
		})
	}
}

func TestAuthrGetAssertionResp1F1RejectsAnyRawKeyPresence(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "empty map", value: map[string]any{}},
		{name: "populated map", value: map[string]any{"vendor": true}},
		{name: "null", value: nil},
		{name: "wrong type", value: "extension output"},
		{name: "empty bytes", value: []byte{}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
			device := newAuthrGetAssertionResp1Device(t, material)
			device.getResponse = func(_ int, _ protocol.AuthenticatorGetAssertionRequest, fields map[uint64]any) []byte {
				fields[8] = testCase.value

				return marshalAuthrGetAssertionResp1(t, fields)
			}
			config, _ := authrGetAssertionResp1Config(t, device, []string{material.name})

			result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1F1)

			assertAuthrGetAssertionResp1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestAuthrGetAssertionResp1F1PassesOnlyWhenRawKeyIsAbsent(t *testing.T) {
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrGetAssertionResp1Device(t, material)
	config, _ := authrGetAssertionResp1Config(t, device, []string{material.name})

	result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1F1)

	assertAuthrGetAssertionResp1Status(t, result, conformance.StatusPassed)
}

func TestAuthrGetAssertionResp1ProviderFailureWipesSecretsAndCleansUp(t *testing.T) {
	providerFailure := errors.New("token provider failed")
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrGetAssertionResp1Device(t, material)
	config, lifecycle := authrGetAssertionResp1Config(t, device, []string{material.name})
	lifecycle.providerErrorAt = 2
	lifecycle.providerError = providerFailure

	result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P1)

	assertAuthrGetAssertionResp1Status(t, result, conformance.StatusError)
	if lifecycle.powerCycles != 3 || device.resets != 2 || len(device.getRequests) != 0 {
		t.Fatalf(
			"lifecycle power=%d resets=%d get=%d",
			lifecycle.powerCycles,
			device.resets,
			len(device.getRequests),
		)
	}
	assertAuthrGetAssertionResp1SecretsZeroed(t, lifecycle.tokens)
}

func TestAuthrGetAssertionResp1CleanupFailureIsReported(t *testing.T) {
	cleanupFailure := errors.New("cleanup power cycle failed")
	material := newAuthrMakeCredResp1Key(t, "secp256r1_ecdsa_sha256_raw")
	device := newAuthrGetAssertionResp1Device(t, material)
	config, lifecycle := authrGetAssertionResp1Config(t, device, []string{material.name})
	lifecycle.cleanupFailure = cleanupFailure

	result := runAuthrGetAssertionResp1Test(t, device, config, TestIDAuthrGetAssertionResp1P1)

	assertAuthrGetAssertionResp1Status(t, result, conformance.StatusError)
	if countGetAssertionFixtureSteps(result.Tests[0].Steps, "make-credential-fixture.cleanup") != 1 {
		t.Fatalf("steps = %#v", result.Tests[0].Steps)
	}
	assertAuthrGetAssertionResp1SecretsZeroed(t, lifecycle.tokens)
}

type authrGetAssertionResp1Device struct {
	t            testing.TB
	material     authrMakeCredResp1Key
	lifecycle    *authrGetAssertionResp1Lifecycle
	info         protocol.AuthenticatorGetInfoResponse
	credentialID []byte
	makeRequests []protocol.AuthenticatorMakeCredentialRequest
	getRequests  []protocol.AuthenticatorGetAssertionRequest
	counters     []uint32
	keyMutate    func(cose.Key)
	getResponse  func(int, protocol.AuthenticatorGetAssertionRequest, map[uint64]any) []byte
	getStatus    ctaptransport.StatusCode
	getError     error
	resets       int
}

func newAuthrGetAssertionResp1Device(
	t testing.TB,
	material authrMakeCredResp1Key,
) *authrGetAssertionResp1Device {
	t.Helper()

	return &authrGetAssertionResp1Device{
		t:            t,
		material:     material,
		credentialID: bytes.Repeat([]byte{0x5c}, 32),
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:           []protocol.Version{protocol.FIDO_2_3},
			Extensions:         []extension.ExtensionIdentifier{},
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Algorithms: []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.Algorithm(material.profile.Algorithm),
			}},
		},
	}
}

func (device *authrGetAssertionResp1Device) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	command := protocol.Command(request[0])
	switch command {
	case protocol.AuthenticatorReset:
		device.resets++

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.AuthenticatorGetInfo:
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalAuthrGetAssertionResp1(device.t, device.info),
		}, nil
	case protocol.AuthenticatorMakeCredential:
		var decoded protocol.AuthenticatorMakeCredentialRequest
		if err := cbor.Unmarshal(request[1:], &decoded); err != nil {
			device.t.Fatal(err)
		}
		device.assertAuthorization(decoded.ClientDataHash, decoded.PinUvAuthParam)
		device.makeRequests = append(device.makeRequests, decoded)
		key := cloneAuthrGetAssertionResp1Key(device.material.key)
		if device.keyMutate != nil {
			device.keyMutate(key)
		}
		authData := authrGetAssertionResp1MakeAuthData(
			device.t,
			decoded.RP.ID,
			device.credentialID,
			key,
		)

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalAuthrGetAssertionResp1(device.t, map[uint64]any{
				1: "none",
				2: authData,
				3: map[string]any{},
			}),
		}, nil
	case protocol.AuthenticatorGetAssertion:
		if device.getError != nil {
			return ctaptransport.CBORResponse{}, device.getError
		}
		if device.getStatus != ctaptransport.CTAP2_OK {
			return ctaptransport.CBORResponse{StatusCode: device.getStatus}, nil
		}
		var decoded protocol.AuthenticatorGetAssertionRequest
		if err := cbor.Unmarshal(request[1:], &decoded); err != nil {
			device.t.Fatal(err)
		}
		device.assertAuthorization(decoded.ClientDataHash, decoded.PinUvAuthParam)
		device.getRequests = append(device.getRequests, cloneAuthrGetAssertionResp1Request(decoded))
		index := len(device.getRequests) - 1
		counter := uint32(0)
		if index < len(device.counters) {
			counter = device.counters[index]
		}
		authData := authrGetAssertionResp1AuthData(decoded.RPID, counter)
		fields := map[uint64]any{
			1: map[string]any{
				"type": string(credential.PublicKeyCredentialTypePublicKey),
				"id":   slices.Clone(device.credentialID),
			},
			2: authData,
			3: device.material.sign(device.t, slices.Concat(authData, decoded.ClientDataHash)),
		}
		data := marshalAuthrGetAssertionResp1(device.t, fields)
		if device.getResponse != nil {
			data = device.getResponse(index, decoded, fields)
		}

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}, nil
	default:
		device.t.Fatalf("unexpected command %s", command)

		return ctaptransport.CBORResponse{}, nil
	}
}

func (device *authrGetAssertionResp1Device) assertAuthorization(hash, authParam []byte) {
	device.t.Helper()
	if device.lifecycle == nil || len(device.lifecycle.tokenValues) == 0 {
		device.t.Fatal("command ran without a current PIN/UV token")
	}
	want := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		device.lifecycle.tokenValues[len(device.lifecycle.tokenValues)-1],
		hash,
	)
	if !bytes.Equal(authParam, want) {
		device.t.Fatalf("pinUvAuthParam = %x, want HMAC for request hash", authParam)
	}
}

type authrGetAssertionResp1Lifecycle struct {
	powerCycles     int
	providerCalls   []PinUvAuthTokenRequest
	tokens          [][]byte
	tokenValues     [][]byte
	providerErrorAt int
	providerError   error
	cleanupFailure  error
}

func authrGetAssertionResp1Config(
	t testing.TB,
	device *authrGetAssertionResp1Device,
	algorithmNames []string,
) (Config, *authrGetAssertionResp1Lifecycle) {
	t.Helper()
	statement, err := json.Marshal(map[string]any{
		"authenticationAlgorithms": algorithmNames,
	})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &authrGetAssertionResp1Lifecycle{}
	device.lifecycle = lifecycle

	return Config{
		Metadata: Metadata{StatementJSON: string(statement)},
		PowerCycler: func(context.Context) error {
			lifecycle.powerCycles++
			if lifecycle.cleanupFailure != nil && lifecycle.powerCycles == 3 {
				return lifecycle.cleanupFailure
			}

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			lifecycle.providerCalls = append(lifecycle.providerCalls, request)
			value := bytes.Repeat([]byte{byte(len(lifecycle.providerCalls))}, 32)
			lifecycle.tokens = append(lifecycle.tokens, value)
			lifecycle.tokenValues = append(lifecycle.tokenValues, slices.Clone(value))
			if lifecycle.providerErrorAt == len(lifecycle.providerCalls) {
				return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: value}, lifecycle.providerError
			}

			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: value}, nil
		},
	}, lifecycle
}

func authrGetAssertionResp1MakeAuthData(
	t testing.TB,
	rpID string,
	credentialID []byte,
	key cose.Key,
) []byte {
	t.Helper()
	authData := make([]byte, 37)
	hash := sha256.Sum256([]byte(rpID))
	copy(authData, hash[:])
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagAttestedCredentialDataIncluded)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, byte(len(credentialID)>>8), byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, marshalAuthrGetAssertionResp1(t, key)...)

	return authData
}

func authrGetAssertionResp1AuthData(rpID string, counter uint32) []byte {
	authData := make([]byte, 37)
	hash := sha256.Sum256([]byte(rpID))
	copy(authData, hash[:])
	authData[32] = byte(protocol.AuthDataFlagUserPresent)
	binary.BigEndian.PutUint32(authData[33:], counter)

	return authData
}

func cloneAuthrGetAssertionResp1Key(key cose.Key) cose.Key {
	clone := make(cose.Key, len(key))
	for label, value := range key {
		if valueBytes, ok := value.([]byte); ok {
			value = slices.Clone(valueBytes)
		}
		clone[label] = value
	}

	return clone
}

func cloneAuthrGetAssertionResp1Request(
	request protocol.AuthenticatorGetAssertionRequest,
) protocol.AuthenticatorGetAssertionRequest {
	request.ClientDataHash = slices.Clone(request.ClientDataHash)
	request.PinUvAuthParam = slices.Clone(request.PinUvAuthParam)
	request.AllowList = slices.Clone(request.AllowList)
	for index := range request.AllowList {
		request.AllowList[index].ID = slices.Clone(request.AllowList[index].ID)
	}

	return request
}

func marshalAuthrGetAssertionResp1(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func nonCanonicalAuthrGetAssertionResp1(t testing.TB, fields map[uint64]any) []byte {
	t.Helper()
	encoded := []byte{0xa3}
	for _, key := range []uint64{2, 1, 3} {
		encoded = append(encoded, marshalAuthrGetAssertionResp1(t, key)...)
		encoded = append(encoded, marshalAuthrGetAssertionResp1(t, fields[key])...)
	}

	return encoded
}

func runAuthrGetAssertionResp1Test(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()
	var selected conformance.Test
	for _, test := range authrGetAssertionResp1Tests(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("test %q not found", id)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "authr-get-assertion-resp-1-test",
		Name:  "Authr GetAssertion Resp 1 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrGetAssertionResp1Status(
	t testing.TB,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()
	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertAuthrGetAssertionResp1Lifecycle(
	t testing.TB,
	device *authrGetAssertionResp1Device,
	lifecycle *authrGetAssertionResp1Lifecycle,
	wantMake int,
	wantGet int,
	wantTokens int,
) {
	t.Helper()
	if lifecycle.powerCycles != 3 || device.resets != 2 || len(device.makeRequests) != wantMake ||
		len(device.getRequests) != wantGet || len(lifecycle.providerCalls) != wantTokens {
		t.Fatalf(
			"lifecycle power=%d resets=%d make=%d get=%d provider=%d",
			lifecycle.powerCycles,
			device.resets,
			len(device.makeRequests),
			len(device.getRequests),
			len(lifecycle.providerCalls),
		)
	}
	if lifecycle.providerCalls[0] != (PinUvAuthTokenRequest{
		Permission: protocol.PermissionMakeCredential,
		RPID:       authrGetAssertionResp1RPID,
	}) {
		t.Fatalf("make token request = %#v", lifecycle.providerCalls[0])
	}
	for _, request := range lifecycle.providerCalls[1:] {
		if request != (PinUvAuthTokenRequest{
			Permission: protocol.PermissionGetAssertion,
			RPID:       authrGetAssertionResp1RPID,
		}) {
			t.Fatalf("GetAssertion token request = %#v", request)
		}
	}
	assertAuthrGetAssertionResp1SecretsZeroed(t, lifecycle.tokens)
}

func assertAuthrGetAssertionResp1SecretsZeroed(t testing.TB, secrets [][]byte) {
	t.Helper()
	for index, secret := range secrets {
		if slices.ContainsFunc(secret, func(value byte) bool { return value != 0 }) {
			t.Fatalf("secret %d was not zeroed: %x", index, secret)
		}
	}
}

func assertAuthrGetAssertionResp1FreshRequests(
	t testing.TB,
	requests []protocol.AuthenticatorGetAssertionRequest,
) {
	t.Helper()
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want 3", len(requests))
	}
	for left := range requests {
		if len(requests[left].ClientDataHash) != sha256.Size || len(requests[left].PinUvAuthParam) == 0 {
			t.Fatalf("request %d = %#v", left, requests[left])
		}
		for right := left + 1; right < len(requests); right++ {
			if bytes.Equal(requests[left].ClientDataHash, requests[right].ClientDataHash) {
				t.Fatalf("requests %d and %d reused clientDataHash", left, right)
			}
			if bytes.Equal(requests[left].PinUvAuthParam, requests[right].PinUvAuthParam) {
				t.Fatalf("requests %d and %d reused pinUvAuthParam", left, right)
			}
		}
	}
}

func assertAuthrGetAssertionResp1Parameters(
	t testing.TB,
	parameters []credential.PublicKeyCredentialParameters,
	names []string,
) {
	t.Helper()
	algorithms, err := resolveMetadataCOSEAlgorithms(names)
	if err != nil {
		t.Fatal(err)
	}
	if len(parameters) != len(algorithms) {
		t.Fatalf("pubKeyCredParams = %d, want %d", len(parameters), len(algorithms))
	}
	for index, algorithm := range algorithms {
		want := credential.PublicKeyCredentialParameters{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.Algorithm(algorithm.profile.Algorithm),
		}
		if parameters[index] != want {
			t.Fatalf("pubKeyCredParams[%d] = %#v, want %#v", index, parameters[index], want)
		}
	}
}
