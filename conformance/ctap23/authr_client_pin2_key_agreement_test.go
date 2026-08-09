package ctap23

import (
	"context"
	"crypto/elliptic"
	"errors"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN2KeyAgreementP1PassesAndPreservesSourceMapping(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo),
		scriptedCBORExchange{
			request: expectedClientPIN2GetKeyAgreementRequest(),
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       clientPIN2Response(t, validClientPIN2KeyAgreement()),
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

	result := runClientPIN2KeyAgreementTest(t, transport, config)
	if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
	if resetCalls != 1 {
		t.Fatalf("reset calls = %d, want 1", resetCalls)
	}

	test := authrClientPIN2KeyAgreementTest(config)
	if test.ID != TestIDAuthrClientPIN2KeyAgreementP1 {
		t.Fatalf("test ID = %q, want %q", test.ID, TestIDAuthrClientPIN2KeyAgreementP1)
	}
	if test.Source.Path != authrClientPIN2KeyAgreementSourcePath || test.Source.Case != "P-1" {
		t.Fatalf("source = %#v", test.Source)
	}
	if len(test.References) != 9 {
		t.Fatalf("references = %#v, want nine normative locators", test.References)
	}
	wantReferences := []struct {
		section string
		level   conformance.RequirementLevel
		anchor  string
	}{
		{section: "6.4", level: conformance.RequirementConstraint, anchor: "#authenticatorGetInfo"},
		{section: "6.5.5", level: conformance.RequirementMust, anchor: "#authenticatorClientPIN"},
		{section: "6.5.5", level: conformance.RequirementMustNot, anchor: "#authenticatorClientPIN"},
		{section: "6.5.5.4", level: conformance.RequirementConstraint, anchor: "#getKeyAgreement"},
		{section: "6.5.6", level: conformance.RequirementConstraint, anchor: "#pinProto1"},
		{section: "6.5.7", level: conformance.RequirementConstraint, anchor: "#pinProto2"},
		{section: "6.6", level: conformance.RequirementConstraint, anchor: "#authenticatorReset"},
		{section: "8", level: conformance.RequirementMust, anchor: "#message-encoding"},
		{section: "9", level: conformance.RequirementMust, anchor: "#mandatory-features"},
	}
	for index, want := range wantReferences {
		got := test.References[index]
		if got.Section != want.section || got.Level != want.level || !strings.HasSuffix(got.URL, want.anchor) {
			t.Fatalf("reference %d = %#v, want section %q, level %q, anchor %q", index, got, want.section, want.level, want.anchor)
		}
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
	if supportReferences := steps[0].References; len(supportReferences) != 3 || supportReferences[2].Section != "9" || supportReferences[2].Level != conformance.RequirementMust || !strings.HasSuffix(supportReferences[2].URL, "#mandatory-features") {
		t.Fatalf("support references = %#v, want CTAP 2.3 section 9 MUST", supportReferences)
	}
	keyReferences := steps[3].References
	if len(keyReferences) != 6 || keyReferences[0].Section != "6.5.5" || keyReferences[0].Level != conformance.RequirementMust || keyReferences[1].Section != "6.5.5" || keyReferences[1].Level != conformance.RequirementMustNot {
		t.Fatalf("key references = %#v, want separate alg MUST and optional-parameter MUST_NOT", keyReferences)
	}
}

func TestAuthrClientPIN2KeyAgreementP1RejectsMalformedAndWrongKeys(t *testing.T) {
	valid := validClientPIN2KeyAgreement()
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
				return marshalClientPIN2Fixture(t, map[int]any{1: []any{1, 2}})
			},
			message: "keyAgreement is not a CBOR map",
		},
		{
			name: "missing curve",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN2Key(valid)
				delete(key, cose.EC2KeyParameterCrv)

				return clientPIN2Response(t, key)
			},
			message: "has 4 parameters, want 5",
		},
		{
			name: "missing algorithm",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN2Key(valid)
				delete(key, cose.KeyParameterAlg)

				return clientPIN2Response(t, key)
			},
			message: "has 4 parameters, want 5",
		},
		{
			name: "unexpected coefficient",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN2Key(valid)
				key[-4] = make([]byte, 32)

				return clientPIN2Response(t, key)
			},
			message: "has 6 parameters, want 5",
		},
		{
			name: "wrong algorithm",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN2Key(valid)
				key[cose.KeyParameterAlg] = cose.AlgorithmES256

				return clientPIN2Response(t, key)
			},
			message: "invalid alg -7, want -25",
		},
		{
			name: "x is text",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN2Key(valid)
				key[cose.EC2KeyParameterX] = strings.Repeat("x", 32)

				return clientPIN2Response(t, key)
			},
			message: "x coordinate is not a CBOR byte string",
		},
		{
			name: "y has wrong length",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN2Key(valid)
				key[cose.EC2KeyParameterY] = make([]byte, 31)

				return clientPIN2Response(t, key)
			},
			message: "invalid y coordinate length 31",
		},
		{
			name: "point is not on P-256",
			response: func(t *testing.T) []byte {
				key := cloneClientPIN2Key(valid)
				key[cose.EC2KeyParameterX] = make([]byte, 32)
				key[cose.EC2KeyParameterY] = make([]byte, 32)

				return clientPIN2Response(t, key)
			},
			message: "invalid P-256 public key",
		},
		{
			name: "non-canonical response",
			response: func(t *testing.T) []byte {
				canonical := clientPIN2Response(t, valid)

				return append([]byte{0xa1, 0x18, 0x01}, canonical[2:]...)
			},
			message: "not CTAP2 canonical CBOR",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := newScriptedCBORTransport(t,
				clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo),
				scriptedCBORExchange{
					request: expectedClientPIN2GetKeyAgreementRequest(),
					response: ctaptransport.CBORResponse{
						StatusCode: ctaptransport.CTAP2_OK,
						Data:       test.response(t),
					},
				},
			)
			result := runClientPIN2KeyAgreementTest(t, transport, successfulClientPIN2Reset())

			testResult := result.Tests[0]
			if result.Status != conformance.StatusFailed || testResult.Status != conformance.StatusFailed {
				t.Fatalf("result = %#v, want failed", result)
			}
			step := testResult.Steps[len(testResult.Steps)-1]
			if step.ID != "client-pin2.key-agreement" || step.Status != conformance.StatusFailed || !strings.Contains(step.Message, test.message) {
				t.Fatalf("key step = %#v, want failed containing %q", step, test.message)
			}
		})
	}
}

func TestAuthrClientPIN2KeyAgreementP1SkipsWhenUpstreamPreconditionDoesNotApply(t *testing.T) {
	tests := []struct {
		name     string
		exchange scriptedCBORExchange
	}{
		{
			name:     "protocol two not advertised",
			exchange: clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
		},
		{
			name:     "extensions field absent",
			exchange: clientPIN2GetInfoWithoutExtensionsExchange(t, protocol.PinUvAuthProtocolTwo),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := newScriptedCBORTransport(t, test.exchange)
			resetCalls := 0
			config := successfulClientPIN2Reset()
			config.Resetter = func(context.Context, *client.Client) error {
				resetCalls++

				return nil
			}

			result := runClientPIN2KeyAgreementTest(t, transport, config)
			testResult := result.Tests[0]
			if result.Status != conformance.StatusSkipped || testResult.Status != conformance.StatusSkipped {
				t.Fatalf("result = %#v, want skipped", result)
			}
			if len(testResult.Steps) != 1 || testResult.Steps[0].ID != "client-pin2.support" || testResult.Steps[0].Status != conformance.StatusSkipped {
				t.Fatalf("steps = %#v, want only skipped support step", testResult.Steps)
			}
			if resetCalls != 0 {
				t.Fatalf("reset calls = %d, want 0", resetCalls)
			}
		})
	}
}

func TestAuthrClientPIN2KeyAgreementP1FailsMissingFeaturefulPrerequisite(t *testing.T) {
	tests := []struct {
		name     string
		exchange scriptedCBORExchange
	}{
		{
			name:     "protocol two not advertised",
			exchange: clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolOne),
		},
		{
			name:     "extensions field absent",
			exchange: clientPIN2GetInfoWithoutExtensionsExchange(t, protocol.PinUvAuthProtocolTwo),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := newScriptedCBORTransport(t, test.exchange)
			resetCalls := 0
			result := runClientPIN2KeyAgreementTest(t, transport, Config{
				Featureful: true,
				Resetter: func(context.Context, *client.Client) error {
					resetCalls++

					return nil
				},
			})

			testResult := result.Tests[0]
			if result.Status != conformance.StatusFailed || testResult.Status != conformance.StatusFailed {
				t.Fatalf("result = %#v, want featureful failure", result)
			}
			if len(testResult.Steps) != 1 || testResult.Steps[0].ID != "client-pin2.support" || testResult.Steps[0].Status != conformance.StatusFailed {
				t.Fatalf("steps = %#v, want only failed support step", testResult.Steps)
			}
			if resetCalls != 0 {
				t.Fatalf("reset calls = %d, want 0", resetCalls)
			}
		})
	}
}

func TestAuthrClientPIN2KeyAgreementP1UsesTypedResetFallback(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo),
		scriptedCBORExchange{
			request: []byte{byte(protocol.AuthenticatorReset)},
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
			},
		},
		scriptedCBORExchange{
			request: expectedClientPIN2GetKeyAgreementRequest(),
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       clientPIN2Response(t, validClientPIN2KeyAgreement()),
			},
		},
	)

	result := runClientPIN2KeyAgreementTest(t, transport, Config{})
	if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed with typed reset fallback", result)
	}
}

func TestAuthrClientPIN2KeyAgreementP1AcceptsBLEResetterAndOuterResponseFields(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo),
		scriptedCBORExchange{
			request: expectedClientPIN2GetKeyAgreementRequest(),
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data: clientPIN2ResponseWithOuterFields(t, map[int]any{
					1: validClientPIN2KeyAgreement(),
					3: uint64(8),
				}),
			},
		},
	)
	resetCalls := 0
	config := Config{
		Transport: AuthenticatorTransportBLE,
		Resetter: func(context.Context, *client.Client) error {
			resetCalls++

			return nil
		},
	}

	result := runClientPIN2KeyAgreementTest(t, transport, config)
	if result.Status != conformance.StatusPassed || resetCalls != 1 {
		t.Fatalf("result = %#v, reset calls = %d, want passed and one BLE reset", result, resetCalls)
	}
}

func TestAuthrClientPIN2KeyAgreementP1ClassifiesResetFailures(t *testing.T) {
	t.Run("callback environment failure is error", func(t *testing.T) {
		resetFailure := errors.New("reset interaction unavailable")
		transport := newScriptedCBORTransport(t, clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo))
		result := runClientPIN2KeyAgreementTest(t, transport, Config{
			Resetter: func(context.Context, *client.Client) error {
				return resetFailure
			},
		})

		step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
		if result.Status != conformance.StatusError || step.ID != "client-pin2.reset" || step.Status != conformance.StatusError || step.Message != resetFailure.Error() {
			t.Fatalf("result = %#v, want reset execution error", result)
		}
	})

	t.Run("callback CTAP status is nonconformance", func(t *testing.T) {
		transport := newScriptedCBORTransport(t, clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo))
		result := runClientPIN2KeyAgreementTest(t, transport, Config{
			Resetter: func(context.Context, *client.Client) error {
				return &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorReset,
					StatusCode: ctaptransport.CTAP2_ERR_OPERATION_DENIED,
				}
			},
		})

		step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
		if result.Status != conformance.StatusFailed || step.ID != "client-pin2.reset" || step.Status != conformance.StatusFailed || !strings.Contains(step.Message, "CTAP2_ERR_OPERATION_DENIED") {
			t.Fatalf("result = %#v, want failed callback reset status", result)
		}
	})

	t.Run("fallback CTAP status is nonconformance", func(t *testing.T) {
		transport := newScriptedCBORTransport(t,
			clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo),
			scriptedCBORExchange{
				request: []byte{byte(protocol.AuthenticatorReset)},
				response: ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED,
				},
			},
		)
		result := runClientPIN2KeyAgreementTest(t, transport, Config{})

		step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
		if result.Status != conformance.StatusFailed || step.ID != "client-pin2.reset" || step.Status != conformance.StatusFailed || !strings.Contains(step.Message, "CTAP2_ERR_NOT_ALLOWED") {
			t.Fatalf("result = %#v, want failed reset status", result)
		}
	})
}

func TestAuthrClientPIN2KeyAgreementP1ClassifiesCommandStatusAndTransportFailure(t *testing.T) {
	t.Run("CTAP status is nonconformance", func(t *testing.T) {
		transport := newScriptedCBORTransport(t,
			clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo),
			scriptedCBORExchange{
				request: expectedClientPIN2GetKeyAgreementRequest(),
				response: ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP1_ERR_INVALID_PARAMETER,
				},
			},
		)
		result := runClientPIN2KeyAgreementTest(t, transport, successfulClientPIN2Reset())

		step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
		if result.Status != conformance.StatusFailed || step.ID != "client-pin2.get-key-agreement" || step.Status != conformance.StatusFailed {
			t.Fatalf("result = %#v, want command failure", result)
		}
	})

	t.Run("transport failure is execution error", func(t *testing.T) {
		transportFailure := errors.New("device disconnected")
		transport := newScriptedCBORTransport(t,
			clientPIN2GetInfoExchange(t, protocol.PinUvAuthProtocolTwo),
			scriptedCBORExchange{
				request: expectedClientPIN2GetKeyAgreementRequest(),
				err:     transportFailure,
			},
		)
		result := runClientPIN2KeyAgreementTest(t, transport, successfulClientPIN2Reset())

		step := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
		if result.Status != conformance.StatusError || step.ID != "client-pin2.get-key-agreement" || step.Status != conformance.StatusError || step.Message != transportFailure.Error() {
			t.Fatalf("result = %#v, want transport error", result)
		}
	})
}

func runClientPIN2KeyAgreementTest(t *testing.T, transport *scriptedCBORTransport, config Config) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(transport)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), conformance.Suite{
		ID:    "client-pin2-key-agreement-test",
		Name:  "client PIN 2 key agreement test",
		Tests: []conformance.Test{authrClientPIN2KeyAgreementTest(config)},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func successfulClientPIN2Reset() Config {
	return Config{
		Transport: AuthenticatorTransportHID,
		Resetter: func(context.Context, *client.Client) error {
			return nil
		},
	}
}

func clientPIN2GetInfoExchange(t *testing.T, protocols ...protocol.PinUvAuthProtocol) scriptedCBORExchange {
	t.Helper()

	return scriptedCBORExchange{
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalClientPIN2Fixture(t, map[int]any{
				2: []string{},
				6: protocols,
			}),
		},
	}
}

func clientPIN2GetInfoWithoutExtensionsExchange(t *testing.T, protocols ...protocol.PinUvAuthProtocol) scriptedCBORExchange {
	t.Helper()

	return scriptedCBORExchange{
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalClientPIN2Fixture(t, map[int]any{
				6: protocols,
			}),
		},
	}
}

func expectedClientPIN2GetKeyAgreementRequest() []byte {
	return []byte{0x06, 0xa2, 0x01, 0x02, 0x02, 0x02}
}

func clientPIN2Response(t *testing.T, key map[int]any) []byte {
	t.Helper()

	return marshalClientPIN2Fixture(t, map[int]any{1: key})
}

func clientPIN2ResponseWithOuterFields(t *testing.T, fields map[int]any) []byte {
	t.Helper()

	return marshalClientPIN2Fixture(t, fields)
}

func validClientPIN2KeyAgreement() map[int]any {
	curve := elliptic.P256().Params()
	x := curve.Gx.FillBytes(make([]byte, 32))
	y := curve.Gy.FillBytes(make([]byte, 32))

	return map[int]any{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmECDHESHKDF256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   x,
		cose.EC2KeyParameterY:   y,
	}
}

func cloneClientPIN2Key(key map[int]any) map[int]any {
	clone := make(map[int]any, len(key))
	for label, value := range key {
		clone[label] = value
	}

	return clone
}

func marshalClientPIN2Fixture(t *testing.T, value any) []byte {
	t.Helper()

	data, err := clientPINKeyAgreementCTAP2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
