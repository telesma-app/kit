package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN1KeyAgreementP1PassesAndPreservesSourceMapping(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
		scriptedCBORExchange{
			request: expectedClientPIN1GetKeyAgreementRequest(),
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       clientPIN1Response(t, validClientPIN1KeyAgreement(t)),
			},
		},
	)
	resetCalls := 0
	config := Config{
		Transport:  AuthenticatorTransportHID,
		Featureful: true,
		Resetter: func(_ context.Context, client *client.Client) error {
			resetCalls++
			if transport.next != 1 {
				t.Fatalf("reset after exchange %d, want after GetInfo", transport.next)
			}
			if client == nil {
				t.Fatal("resetter received nil client")
			}

			return nil
		},
	}

	result := runClientPIN1KeyAgreementTest(t, transport, config)
	if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
	if resetCalls != 1 {
		t.Fatalf("reset calls = %d, want 1", resetCalls)
	}

	test := authrClientPIN1KeyAgreementTest(config)
	if test.ID != TestIDAuthrClientPIN1KeyAgreementP1 {
		t.Fatalf("test ID = %q, want %q", test.ID, TestIDAuthrClientPIN1KeyAgreementP1)
	}
	if test.Source.Path != authrClientPIN1KeyAgreementSourcePath || test.Source.Case != "P-1" {
		t.Fatalf("source = %#v", test.Source)
	}
	if len(test.References) != 9 {
		t.Fatalf("references = %#v, want eight normative locators and one certification policy locator", test.References)
	}
	for index, section := range []string{"6.4", "6.5.5", "6.5.5", "6.5.5", "6.5.5.4", "6.5.6", "8", "6.6"} {
		if test.References[index].Section != section {
			t.Fatalf("reference %d section = %q, want %q", index, test.References[index].Section, section)
		}
	}
	if test.References[2].Clause != "key-agreement-alg-parameter" || test.References[2].Level != conformance.RequirementMust {
		t.Fatalf("alg reference = %#v", test.References[2])
	}
	if test.References[3].Clause != "key-agreement-no-other-optional-parameters" || test.References[3].Level != conformance.RequirementMustNot {
		t.Fatalf("parameter reference = %#v", test.References[3])
	}
	if test.References[8].Specification != conformance.SpecificationID(clientPIN1CertificationPolicy) || test.References[8].URL != "https://github.com/fido-alliance/certification/issues/38" {
		t.Fatalf("profile reference = %#v", test.References[8])
	}

	steps := result.Tests[0].Steps
	if len(steps) != 4 {
		t.Fatalf("steps = %#v, want four passed steps", steps)
	}
	for _, step := range steps {
		if step.Status != conformance.StatusPassed {
			t.Fatalf("step %q = %#v, want passed", step.ID, step)
		}
	}
}

func TestAuthrClientPIN1KeyAgreementP1UsesLowLevelResetWhenCallbackIsNil(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
		scriptedCBORExchange{
			request: []byte{byte(protocol.AuthenticatorReset)},
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
			},
		},
		scriptedCBORExchange{
			request: expectedClientPIN1GetKeyAgreementRequest(),
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       clientPIN1Response(t, validClientPIN1KeyAgreement(t)),
			},
		},
	)

	result := runClientPIN1KeyAgreementTest(t, transport, Config{
		Transport:  AuthenticatorTransportHID,
		Featureful: true,
	})
	if result.Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
}

func TestAuthrClientPIN1KeyAgreementP1AllowsUnknownOuterResponseMember(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
		scriptedCBORExchange{
			request: expectedClientPIN1GetKeyAgreementRequest(),
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data: marshalClientPIN1Fixture(t, map[int]any{
					1:  validClientPIN1KeyAgreement(t),
					99: "future response member",
				}),
			},
		},
	)

	result := runClientPIN1KeyAgreementTest(t, transport, successfulClientPIN1Reset())
	if result.Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want unknown outer member ignored", result)
	}
}

func TestAuthrClientPIN1KeyAgreementP1RejectsMalformedAndWrongKeys(t *testing.T) {
	valid := validClientPIN1KeyAgreement(t)
	tests := []struct {
		name     string
		response func(*testing.T) []byte
		message  string
	}{
		{
			name: "malformed response",
			response: func(*testing.T) []byte {
				return []byte{0xa1, 0x01}
			},
			message: "invalid authenticatorClientPIN response CBOR",
		},
		{
			name: "key is not a map",
			response: func(t *testing.T) []byte {
				return marshalClientPIN1Fixture(t, map[int]any{1: []any{1, 2}})
			},
			message: "keyAgreement is not a CBOR map",
		},
		{
			name: "missing curve",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN1Key(valid)
				delete(key, cose.EC2KeyParameterCrv)

				return clientPIN1Response(t, key)
			},
			message: "has 4 parameters, want 5",
		},
		{
			name: "missing algorithm",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN1Key(valid)
				delete(key, cose.KeyParameterAlg)

				return clientPIN1Response(t, key)
			},
			message: "has 4 parameters, want 5",
		},
		{
			name: "unexpected coefficient",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN1Key(valid)
				key[-4] = make([]byte, 32)

				return clientPIN1Response(t, key)
			},
			message: "has 6 parameters, want 5",
		},
		{
			name: "wrong algorithm",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN1Key(valid)
				key[cose.KeyParameterAlg] = cose.AlgorithmES256

				return clientPIN1Response(t, key)
			},
			message: "invalid alg -7, want -25",
		},
		{
			name: "x is text",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN1Key(valid)
				key[cose.EC2KeyParameterX] = strings.Repeat("x", 32)

				return clientPIN1Response(t, key)
			},
			message: "x coordinate is not a CBOR byte string",
		},
		{
			name: "y has wrong length",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN1Key(valid)
				key[cose.EC2KeyParameterY] = make([]byte, 31)

				return clientPIN1Response(t, key)
			},
			message: "invalid y coordinate length 31",
		},
		{
			name: "point is not on P-256",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN1Key(valid)
				key[cose.EC2KeyParameterX] = make([]byte, 32)
				key[cose.EC2KeyParameterY] = make([]byte, 32)

				return clientPIN1Response(t, key)
			},
			message: "invalid P-256 public key",
		},
		{
			name: "non-canonical response",
			response: func(t *testing.T) []byte {
				canonical := clientPIN1Response(t, valid)

				return append([]byte{0xa1, 0x18, 0x01}, canonical[2:]...)
			},
			message: "not CTAP2 canonical CBOR",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := newScriptedCBORTransport(t,
				clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
				scriptedCBORExchange{
					request: expectedClientPIN1GetKeyAgreementRequest(),
					response: ctaptransport.CBORResponse{
						StatusCode: ctaptransport.CTAP2_OK,
						Data:       test.response(t),
					},
				},
			)
			result := runClientPIN1KeyAgreementTest(t, transport, successfulClientPIN1Reset())

			testResult := result.Tests[0]
			if result.Status != conformance.StatusFailed || testResult.Status != conformance.StatusFailed {
				t.Fatalf("result = %#v, want failed", result)
			}
			step := testResult.Steps[len(testResult.Steps)-1]
			if step.ID != "client-pin1.key-agreement" || step.Status != conformance.StatusFailed || !strings.Contains(step.Message, test.message) {
				t.Fatalf("key step = %#v, want failed containing %q", step, test.message)
			}
		})
	}
}

func TestAuthrClientPIN1KeyAgreementP1ClassifiesMissingProtocolByTransport(t *testing.T) {
	tests := []struct {
		name       string
		transport  AuthenticatorTransport
		featureful bool
		status     conformance.Status
	}{
		{
			name:       "HID is nonconforming",
			transport:  AuthenticatorTransportHID,
			featureful: true,
			status:     conformance.StatusFailed,
		},
		{
			name:       "NFC profile does not apply",
			transport:  AuthenticatorTransportNFC,
			featureful: true,
			status:     conformance.StatusSkipped,
		},
		{
			name:       "BLE is nonconforming",
			transport:  AuthenticatorTransportBLE,
			featureful: true,
			status:     conformance.StatusFailed,
		},
		{
			name:       "missing transport is an environment error",
			featureful: true,
			status:     conformance.StatusError,
		},
		{
			name:       "unknown transport is an environment error",
			transport:  AuthenticatorTransport("future"),
			featureful: true,
			status:     conformance.StatusError,
		},
		{
			name:       "non-featureful profile does not apply",
			transport:  AuthenticatorTransportHID,
			featureful: false,
			status:     conformance.StatusSkipped,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := newScriptedCBORTransport(t, clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolTwo))
			resetCalls := 0
			result := runClientPIN1KeyAgreementTest(t, transport, Config{
				Transport:  test.transport,
				Featureful: test.featureful,
				Resetter: func(context.Context, *client.Client) error {
					resetCalls++

					return nil
				},
			})

			testResult := result.Tests[0]
			if result.Status != test.status || testResult.Status != test.status {
				t.Fatalf("result = %#v, want %s", result, test.status)
			}
			if len(testResult.Steps) != 1 || testResult.Steps[0].ID != "client-pin1.support" {
				t.Fatalf("steps = %#v, want only support classification", testResult.Steps)
			}
			if resetCalls != 0 {
				t.Fatalf("reset calls = %d, want 0", resetCalls)
			}
		})
	}
}

func TestAuthrClientPIN1KeyAgreementP1RequiresRawExtensionsPresenceForApplicability(t *testing.T) {
	transport := newScriptedCBORTransport(t, clientPIN1GetInfoWithoutExtensionsExchange(t, protocol.PinUvAuthProtocolOne))
	resetCalls := 0
	result := runClientPIN1KeyAgreementTest(t, transport, Config{
		Transport:  AuthenticatorTransportHID,
		Featureful: true,
		Resetter: func(context.Context, *client.Client) error {
			resetCalls++

			return nil
		},
	})

	if result.Status != conformance.StatusFailed {
		t.Fatalf("result = %#v, want failed applicability", result)
	}
	if resetCalls != 0 {
		t.Fatalf("reset calls = %d, want 0", resetCalls)
	}
}

func TestAuthrClientPIN1KeyAgreementP1RunsAdvertisedProtocolWithUnknownTransport(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
		scriptedCBORExchange{
			request: expectedClientPIN1GetKeyAgreementRequest(),
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       clientPIN1Response(t, validClientPIN1KeyAgreement(t)),
			},
		},
	)
	result := runClientPIN1KeyAgreementTest(t, transport, Config{
		Featureful: true,
		Resetter: func(context.Context, *client.Client) error {
			return nil
		},
	})

	if result.Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
}

func TestAuthrClientPIN1KeyAgreementP1ClassifiesResetAndTransportFailuresAsErrors(t *testing.T) {
	t.Run("reset callback", func(t *testing.T) {
		resetFailure := errors.New("reset interaction unavailable")
		transport := newScriptedCBORTransport(t, clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne))
		result := runClientPIN1KeyAgreementTest(t, transport, Config{
			Transport: AuthenticatorTransportHID,
			Resetter: func(context.Context, *client.Client) error {
				return resetFailure
			},
		})

		step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
		if result.Status != conformance.StatusError || step.ID != "client-pin1.reset" || step.Status != conformance.StatusError || step.Message != resetFailure.Error() {
			t.Fatalf("result = %#v, want reset error", result)
		}
	})

	t.Run("key agreement transport", func(t *testing.T) {
		transportFailure := errors.New("device disconnected")
		transport := newScriptedCBORTransport(t,
			clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
			scriptedCBORExchange{
				request: expectedClientPIN1GetKeyAgreementRequest(),
				err:     transportFailure,
			},
		)
		result := runClientPIN1KeyAgreementTest(t, transport, successfulClientPIN1Reset())

		step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
		if result.Status != conformance.StatusError || step.ID != "client-pin1.get-key-agreement" || step.Status != conformance.StatusError || step.Message != transportFailure.Error() {
			t.Fatalf("result = %#v, want transport error", result)
		}
	})
}

func TestAuthrClientPIN1KeyAgreementP1ClassifiesCommandStatusAsFailure(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
		scriptedCBORExchange{
			request: expectedClientPIN1GetKeyAgreementRequest(),
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP1_ERR_INVALID_PARAMETER,
			},
		},
	)
	result := runClientPIN1KeyAgreementTest(t, transport, successfulClientPIN1Reset())

	step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if result.Status != conformance.StatusFailed || step.ID != "client-pin1.get-key-agreement" || step.Status != conformance.StatusFailed {
		t.Fatalf("result = %#v, want command nonconformance", result)
	}
}

func TestAuthrClientPIN1KeyAgreementP1ClassifiesResetCTAPStatusAsFailure(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN1GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
		scriptedCBORExchange{
			request: []byte{byte(protocol.AuthenticatorReset)},
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_ERR_OPERATION_DENIED,
			},
		},
	)
	result := runClientPIN1KeyAgreementTest(t, transport, Config{
		Transport:  AuthenticatorTransportHID,
		Featureful: true,
	})

	step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if result.Status != conformance.StatusFailed || step.ID != "client-pin1.reset" || step.Status != conformance.StatusFailed || !strings.Contains(step.Message, "CTAP2_ERR_OPERATION_DENIED") {
		t.Fatalf("result = %#v, want reset CTAP nonconformance", result)
	}
}

func runClientPIN1KeyAgreementTest(t *testing.T, transport *scriptedCBORTransport, config Config) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(transport)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), conformance.Suite{
		ID:    "client-pin1-key-agreement-test",
		Name:  "client PIN 1 key agreement test",
		Tests: []conformance.Test{authrClientPIN1KeyAgreementTest(config)},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func successfulClientPIN1Reset() Config {
	return Config{
		Transport:  AuthenticatorTransportHID,
		Featureful: true,
		Resetter: func(context.Context, *client.Client) error {
			return nil
		},
	}
}

func clientPIN1GetInfoExchange(t *testing.T, protocols ...protocol.PinUvAuthProtocol) scriptedCBORExchange {
	t.Helper()

	return scriptedCBORExchange{
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalClientPIN1Fixture(t, map[int]any{
				2: []string{},
				6: protocols,
			}),
		},
	}
}

func clientPIN1GetInfoWithoutExtensionsExchange(t *testing.T, protocols ...protocol.PinUvAuthProtocol) scriptedCBORExchange {
	t.Helper()

	return scriptedCBORExchange{
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalClientPIN1Fixture(t, map[int]any{
				6: protocols,
			}),
		},
	}
}

func expectedClientPIN1GetKeyAgreementRequest() []byte {
	return []byte{0x06, 0xa2, 0x01, 0x01, 0x02, 0x02}
}

func clientPIN1Response(t *testing.T, key map[int]any) []byte {
	t.Helper()

	return marshalClientPIN1Fixture(t, map[int]any{1: key})
}

func validClientPIN1KeyAgreement(t *testing.T) map[int]any {
	t.Helper()

	privateKeyBytes := make([]byte, 32)
	privateKeyBytes[len(privateKeyBytes)-1] = 1
	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()

	return map[int]any{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmECDHESHKDF256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   publicKey[1:33],
		cose.EC2KeyParameterY:   publicKey[33:65],
	}
}

func cloneClientPIN1Key(key map[int]any) map[int]any {
	clone := make(map[int]any, len(key))
	for label, value := range key {
		clone[label] = value
	}

	return clone
}

func marshalClientPIN1Fixture(t *testing.T, value any) []byte {
	t.Helper()

	data, err := clientPINKeyAgreementCTAP2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestClientPINKeyAgreementUsesCTAP2CanonicalMapOrdering(t *testing.T) {
	key := validClientPIN1KeyAgreement(t)
	key[24] = true
	value := map[int]any{1: key}

	ctapData := marshalClientPIN1Fixture(t, value)
	rfcMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	rfcData, err := rfcMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ctapData, rfcData) {
		t.Fatal("fixture does not distinguish CTAP2 ordering from RFC canonical ordering")
	}
	if err := validateCanonicalClientPINResponse(ctapData); err != nil {
		t.Fatalf("CTAP2 canonical response rejected: %v", err)
	}
	if err := validateCanonicalClientPINResponse(rfcData); err == nil {
		t.Fatal("RFC canonical response accepted as CTAP2 canonical")
	}
}
