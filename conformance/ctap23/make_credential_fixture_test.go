package ctap23

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const makeCredentialFixtureTestRPID = "make-credential.ctap23-conformance.example"

func TestPrepareMakeCredentialFixtureRunsAuthorizedRequestAndCleanup(t *testing.T) {
	token := bytes.Repeat([]byte{0x5a}, 32)
	device := &makeCredentialFixtureDevice{
		t: t,
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:           []protocol.Version{protocol.FIDO_2_3},
			Extensions:         []extension.ExtensionIdentifier{},
			AAGUID:             uuid.UUID{},
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Algorithms: []credential.PublicKeyCredentialParameters{
				{Type: "unsupported", Algorithm: cose.AlgorithmES256},
				{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256},
			},
		},
	}
	powerCycles := 0
	config := Config{
		PowerCycler: func(context.Context) error {
			powerCycles++

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			if request.Permission != protocol.PermissionMakeCredential || request.RPID != makeCredentialFixtureTestRPID {
				t.Fatalf("token request = %#v", request)
			}

			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, nil
		},
	}

	result := runMakeCredentialFixtureTest(t, device, config, func(test *conformance.TestContext) {
		var fixture makeCredentialFixture
		if !test.Step(conformance.Step{
			ID:   "fixture.prepare",
			Name: "Prepare fixture",
			Run: func(ctx context.Context) error {
				var err error
				fixture, err = prepareMakeCredentialFixture(ctx, test, config, makeCredentialFixtureTestRPID)

				return err
			},
		}) {
			return
		}
		defer fixture.clear()

		test.Step(conformance.Step{
			ID:   "fixture.make-credential",
			Name: "Make credential",
			Run: func(ctx context.Context) error {
				_, err := fixture.makeCredential(ctx, test.CBOR(), fixture.Request)

				return err
			},
		})
	})

	assertMakeCredentialFixtureStatus(t, result, conformance.StatusPassed)
	if powerCycles != 3 || device.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/2", powerCycles, device.resets)
	}
	if !slices.Equal(device.commands, []protocol.Command{
		protocol.AuthenticatorReset,
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorMakeCredential,
		protocol.AuthenticatorReset,
	}) {
		t.Fatalf("commands = %v", device.commands)
	}
	if device.makeCredentialRequest.RP.ID != makeCredentialFixtureTestRPID {
		t.Fatalf("RP ID = %q", device.makeCredentialRequest.RP.ID)
	}
	if !slices.Equal(device.makeCredentialRequest.PubKeyCredParams, []credential.PublicKeyCredentialParameters{{
		Type:      credential.PublicKeyCredentialTypePublicKey,
		Algorithm: cose.AlgorithmES256,
	}}) {
		t.Fatalf("algorithms = %#v", device.makeCredentialRequest.PubKeyCredParams)
	}
	wantAuthParam := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		bytes.Repeat([]byte{0x5a}, 32),
		device.makeCredentialRequest.ClientDataHash,
	)
	if device.makeCredentialRequest.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo ||
		!bytes.Equal(device.makeCredentialRequest.PinUvAuthParam, wantAuthParam) {
		t.Fatalf("PIN/UV authorization = %d/%x", device.makeCredentialRequest.PinUvAuthProtocol, device.makeCredentialRequest.PinUvAuthParam)
	}
	assertMakeCredentialFixtureZeroed(t, token)
	steps := result.Tests[0].Steps
	if last := steps[len(steps)-1]; last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusPassed {
		t.Fatalf("cleanup = %#v", last)
	}
}

func TestMakeCredentialFixtureMakeCredentialClassifiesWireFailures(t *testing.T) {
	request := protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash: bytes.Repeat([]byte{0x11}, 32),
		RP: credential.PublicKeyCredentialRpEntity{
			ID:   makeCredentialFixtureTestRPID,
			Name: makeCredentialFixtureRPName,
		},
		User: credential.PublicKeyCredentialUserEntity{
			ID:          []byte{0x21},
			Name:        makeCredentialFixtureUserName,
			DisplayName: makeCredentialFixtureUserDisplayName,
		},
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
	}
	fixture := makeCredentialFixture{}

	t.Run("CTAP status is a failed assertion", func(t *testing.T) {
		_, err := fixture.makeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
			context.Context,
			[]byte,
		) (ctaptransport.CBORResponse, error) {
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_INVALID_CBOR}, nil
		}), request)

		var assertion *conformance.AssertionError
		if !errors.As(err, &assertion) {
			t.Fatalf("error = %#v, want AssertionError", err)
		}
	})

	t.Run("malformed OK CBOR is a failed assertion", func(t *testing.T) {
		_, err := fixture.makeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
			context.Context,
			[]byte,
		) (ctaptransport.CBORResponse, error) {
			return ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       []byte{0xff},
			}, nil
		}), request)

		var assertion *conformance.AssertionError
		if !errors.As(err, &assertion) {
			t.Fatalf("error = %#v, want AssertionError", err)
		}
	})

	t.Run("malformed authData is a failed assertion", func(t *testing.T) {
		response := marshalMakeCredentialFixture(t, protocol.AuthenticatorMakeCredentialResponse{
			Format:               attestation.AttestationStatementFormatIdentifierNone,
			AuthDataRaw:          []byte{0x01},
			AttestationStatement: map[string]any{},
		})
		_, err := fixture.makeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
			context.Context,
			[]byte,
		) (ctaptransport.CBORResponse, error) {
			return ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       response,
			}, nil
		}), request)

		var assertion *conformance.AssertionError
		if !errors.As(err, &assertion) {
			t.Fatalf("error = %#v, want AssertionError", err)
		}
	})

	t.Run("canonical schema-invalid response is a failed assertion", func(t *testing.T) {
		response := marshalMakeCredentialFixture(t, map[uint64]any{
			1: false,
			2: make([]byte, 37),
		})
		_, err := fixture.makeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
			context.Context,
			[]byte,
		) (ctaptransport.CBORResponse, error) {
			return ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       response,
			}, nil
		}), request)

		var assertion *conformance.AssertionError
		if !errors.As(err, &assertion) ||
			err.Error() != "authenticatorMakeCredential response required fmt field is not a CBOR text string" {
			t.Fatalf("error = %#v, want required fmt type AssertionError", err)
		}
	})

	for _, testCase := range []struct {
		name        string
		response    map[uint64]any
		wantMessage string
	}{
		{
			name: "missing fmt is a failed assertion",
			response: map[uint64]any{
				2: make([]byte, 37),
			},
			wantMessage: "authenticatorMakeCredential response is missing required fmt field",
		},
		{
			name: "missing authData is a failed assertion",
			response: map[uint64]any{
				1: string(attestation.AttestationStatementFormatIdentifierNone),
			},
			wantMessage: "authenticatorMakeCredential response is missing required authData field",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := marshalMakeCredentialFixture(t, testCase.response)
			_, err := fixture.makeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
				context.Context,
				[]byte,
			) (ctaptransport.CBORResponse, error) {
				return ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP2_OK,
					Data:       response,
				}, nil
			}), request)

			var assertion *conformance.AssertionError
			if !errors.As(err, &assertion) || err.Error() != testCase.wantMessage {
				t.Fatalf("error = %#v, want %q AssertionError", err, testCase.wantMessage)
			}
		})
	}

	for _, field := range []struct {
		key      uint64
		name     string
		typeName string
	}{
		{key: 1, name: "fmt", typeName: "text string"},
		{key: 2, name: "authData", typeName: "byte string"},
	} {
		for _, invalid := range []struct {
			name string
			raw  cbor.RawMessage
		}{
			{name: "null", raw: cbor.RawMessage{0xf6}},
			{name: "undefined", raw: cbor.RawMessage{0xf7}},
		} {
			t.Run(field.name+" "+invalid.name+" is a failed assertion", func(t *testing.T) {
				fields := map[uint64]cbor.RawMessage{
					1: marshalMakeCredentialFixture(
						t,
						string(attestation.AttestationStatementFormatIdentifierNone),
					),
					2: marshalMakeCredentialFixture(t, make([]byte, 37)),
				}
				fields[field.key] = invalid.raw
				response := marshalMakeCredentialFixture(t, fields)

				_, err := fixture.makeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
					context.Context,
					[]byte,
				) (ctaptransport.CBORResponse, error) {
					return ctaptransport.CBORResponse{
						StatusCode: ctaptransport.CTAP2_OK,
						Data:       response,
					}, nil
				}), request)

				var assertion *conformance.AssertionError
				want := "authenticatorMakeCredential response required " + field.name +
					" field is not a CBOR " + field.typeName
				if !errors.As(err, &assertion) || err.Error() != want {
					t.Fatalf("error = %#v, want %q AssertionError", err, want)
				}
			})
		}
	}

	t.Run("well-formed non-canonical response is a failed assertion", func(t *testing.T) {
		response := []byte{0xa3, 0x03, 0xa0, 0x02, 0x58, 0x25}
		response = append(response, make([]byte, 37)...)
		response = append(response, 0x01, 0x64, 'n', 'o', 'n', 'e')
		_, err := fixture.makeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
			context.Context,
			[]byte,
		) (ctaptransport.CBORResponse, error) {
			return ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       response,
			}, nil
		}), request)

		var assertion *conformance.AssertionError
		if !errors.As(err, &assertion) ||
			err.Error() != "authenticatorMakeCredential response is not CTAP2 canonical CBOR" {
			t.Fatalf("error = %#v, want non-canonical response AssertionError", err)
		}
	})

	t.Run("transport failure is preserved", func(t *testing.T) {
		transportFailure := errors.New("device disconnected")
		_, err := fixture.makeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
			context.Context,
			[]byte,
		) (ctaptransport.CBORResponse, error) {
			return ctaptransport.CBORResponse{}, transportFailure
		}), request)
		if !errors.Is(err, transportFailure) {
			t.Fatalf("error = %v, want transport failure", err)
		}
	})
}

func TestMakeCredentialFixtureOwnsWireResponseAndReturnsDecodedResponse(t *testing.T) {
	authData := bytes.Repeat([]byte{0x7a}, 37)
	authData[32] = 0
	wireData := marshalMakeCredentialFixture(t, protocol.AuthenticatorMakeCredentialResponse{
		Format:                   attestation.AttestationStatementFormatIdentifierNone,
		AuthDataRaw:              authData,
		AttestationStatement:     map[string]any{"sig": []byte{0x31, 0x32}},
		LargeBlobKey:             bytes.Repeat([]byte{0x41}, 32),
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{"fixture": []byte{0x51, 0x52}},
	})
	retainedWireData := wireData

	response, err := (makeCredentialFixture{}).makeCredential(
		t.Context(),
		makeCredentialFixtureCBORFunc(func(context.Context, []byte) (ctaptransport.CBORResponse, error) {
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: wireData}, nil
		}),
		protocol.AuthenticatorMakeCredentialRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	assertMakeCredentialFixtureBytesCleared(t, "wire response", retainedWireData)
	if !bytes.Equal(response.AuthDataRaw, authData) {
		t.Fatalf("decoded authData = %x, want %x", response.AuthDataRaw, authData)
	}

	retainedAuthData := response.AuthDataRaw
	retainedLargeBlobKey := response.LargeBlobKey
	retainedAttestation := response.AttestationStatement["sig"].([]byte)
	retainedUnsigned := response.UnsignedExtensionOutputs["fixture"].([]byte)
	clearMakeCredentialResponse(&response)
	assertMakeCredentialFixtureBytesCleared(t, "decoded authData", retainedAuthData)
	assertMakeCredentialFixtureBytesCleared(t, "decoded largeBlobKey", retainedLargeBlobKey)
	assertMakeCredentialFixtureBytesCleared(t, "decoded attestation statement", retainedAttestation)
	assertMakeCredentialFixtureBytesCleared(t, "decoded unsigned extension output", retainedUnsigned)
	if response.AuthDataRaw != nil || response.AuthData != nil || response.LargeBlobKey != nil ||
		response.AttestationStatement != nil || response.UnsignedExtensionOutputs != nil {
		t.Fatalf("cleared response retains mutable data: %#v", response)
	}
}

func TestMakeCredentialFixtureClearsWireResponseOnDecodeAndValidationErrors(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		response any
	}{
		{
			name: "validation error",
			response: map[uint64]any{
				1: false,
				2: make([]byte, 37),
			},
		},
		{
			name: "decode error after authData allocation",
			response: map[uint64]any{
				1: string(attestation.AttestationStatementFormatIdentifierNone),
				2: bytes.Repeat([]byte{0x61}, 37),
				3: false,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			wireData := marshalMakeCredentialFixture(t, testCase.response)
			retainedWireData := wireData
			_, err := (makeCredentialFixture{}).makeCredential(
				t.Context(),
				makeCredentialFixtureCBORFunc(func(
					context.Context,
					[]byte,
				) (ctaptransport.CBORResponse, error) {
					return ctaptransport.CBORResponse{
						StatusCode: ctaptransport.CTAP2_OK,
						Data:       wireData,
					}, nil
				}),
				protocol.AuthenticatorMakeCredentialRequest{},
			)
			var assertion *conformance.AssertionError
			if !errors.As(err, &assertion) {
				t.Fatalf("error = %#v, want AssertionError", err)
			}
			assertMakeCredentialFixtureBytesCleared(t, "wire response", retainedWireData)
		})
	}
}

func TestPrepareMakeCredentialFixtureUsesUnauthenticatedES256Fallback(t *testing.T) {
	device := &makeCredentialFixtureDevice{
		t: t,
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:   []protocol.Version{protocol.FIDO_2_3},
			Extensions: []extension.ExtensionIdentifier{},
			AAGUID:     uuid.UUID{},
			Options:    map[protocol.Option]bool{},
		},
	}
	powerCycles := 0
	config := Config{
		PowerCycler: func(context.Context) error {
			powerCycles++

			return nil
		},
	}
	var got makeCredentialFixture
	result := runMakeCredentialFixtureTest(t, device, config, func(test *conformance.TestContext) {
		test.Step(conformance.Step{
			ID:   "fixture.prepare",
			Name: "Prepare fixture",
			Run: func(ctx context.Context) error {
				var err error
				got, err = prepareMakeCredentialFixture(ctx, test, config, makeCredentialFixtureTestRPID)

				return err
			},
		})
	})

	assertMakeCredentialFixtureStatus(t, result, conformance.StatusPassed)
	if got.Authorization.Protocol != 0 || got.Authorization.Value != nil ||
		got.Request.PinUvAuthProtocol != 0 || got.Request.PinUvAuthParam != nil {
		t.Fatalf("authorization = %#v, request = %#v", got.Authorization, got.Request)
	}
	if !slices.Equal(got.Request.PubKeyCredParams, []credential.PublicKeyCredentialParameters{{
		Type:      credential.PublicKeyCredentialTypePublicKey,
		Algorithm: cose.AlgorithmES256,
	}}) {
		t.Fatalf("algorithms = %#v", got.Request.PubKeyCredParams)
	}
	if powerCycles != 3 || device.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/2", powerCycles, device.resets)
	}
}

func TestPrepareMakeCredentialFixtureClearsProviderTokenOnError(t *testing.T) {
	providerFailure := errors.New("PIN entry canceled")
	token := bytes.Repeat([]byte{0x73}, 32)
	device := &makeCredentialFixtureDevice{
		t: t,
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:           []protocol.Version{protocol.FIDO_2_3},
			Extensions:         []extension.ExtensionIdentifier{},
			AAGUID:             uuid.UUID{},
			Options:            map[protocol.Option]bool{protocol.OptionUserVerification: true},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		},
	}
	config := Config{
		PowerCycler: func(context.Context) error { return nil },
		TokenProvider: func(
			context.Context,
			*client.Client,
			PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, providerFailure
		},
	}
	result := runMakeCredentialFixtureTest(t, device, config, func(test *conformance.TestContext) {
		test.Step(conformance.Step{
			ID:   "fixture.prepare",
			Name: "Prepare fixture",
			Run: func(ctx context.Context) error {
				_, err := prepareMakeCredentialFixture(ctx, test, config, makeCredentialFixtureTestRPID)

				return err
			},
		})
	})

	assertMakeCredentialFixtureStatus(t, result, conformance.StatusError)
	assertMakeCredentialFixtureZeroed(t, token)
	if got := result.Tests[0].Steps[0].Message; got != providerFailure.Error() {
		t.Fatalf("setup error = %q", got)
	}
}

func TestPrepareMakeCredentialFixtureRequiresEnvironmentCallbacks(t *testing.T) {
	t.Run("power cycler", func(t *testing.T) {
		device := &makeCredentialFixtureDevice{t: t}
		result := runMakeCredentialFixtureTest(t, device, Config{}, func(test *conformance.TestContext) {
			test.Step(conformance.Step{
				ID:   "fixture.prepare",
				Name: "Prepare fixture",
				Run: func(ctx context.Context) error {
					_, err := prepareMakeCredentialFixture(ctx, test, Config{}, makeCredentialFixtureTestRPID)

					return err
				},
			})
		})

		assertMakeCredentialFixtureStatus(t, result, conformance.StatusError)
		if len(device.commands) != 0 {
			t.Fatalf("commands = %v, want none", device.commands)
		}
	})

	t.Run("token provider", func(t *testing.T) {
		device := &makeCredentialFixtureDevice{
			t: t,
			info: protocol.AuthenticatorGetInfoResponse{
				Versions:           []protocol.Version{protocol.FIDO_2_3},
				Extensions:         []extension.ExtensionIdentifier{},
				AAGUID:             uuid.UUID{},
				Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
				PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			},
		}
		config := Config{PowerCycler: func(context.Context) error { return nil }}
		result := runMakeCredentialFixtureTest(t, device, config, func(test *conformance.TestContext) {
			test.Step(conformance.Step{
				ID:   "fixture.prepare",
				Name: "Prepare fixture",
				Run: func(ctx context.Context) error {
					_, err := prepareMakeCredentialFixture(ctx, test, config, makeCredentialFixtureTestRPID)

					return err
				},
			})
		})

		assertMakeCredentialFixtureStatus(t, result, conformance.StatusError)
		if device.resets != 2 {
			t.Fatalf("resets = %d, want setup and cleanup", device.resets)
		}
	})
}

func TestMakeCredentialFixtureRawFieldsAreFreshWireSnapshots(t *testing.T) {
	fixture := makeCredentialFixture{
		Request: protocol.AuthenticatorMakeCredentialRequest{
			ClientDataHash: bytes.Repeat([]byte{0x11}, 32),
			RP: credential.PublicKeyCredentialRpEntity{
				ID:   "raw.example",
				Name: "Raw RP",
			},
			User: credential.PublicKeyCredentialUserEntity{
				ID:          []byte{0x21, 0x22},
				Name:        "raw-user",
				DisplayName: "Raw user",
			},
			PubKeyCredParams: []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}},
			ExcludeList: []credential.PublicKeyCredentialDescriptor{{
				Type:       credential.PublicKeyCredentialTypePublicKey,
				ID:         []byte{0x31, 0x32},
				Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB},
			}},
			Extensions: protocol.CreateExtensionInputs{
				CreateCredBlobInput: protocol.CreateCredBlobInput{CredBlob: []byte{0x41, 0x42}},
			},
			Options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: true,
			},
			PinUvAuthParam:        []byte{0x51, 0x52},
			PinUvAuthProtocol:     protocol.PinUvAuthProtocolTwo,
			EnterpriseAttestation: 2,
			AttestationFormatsPreference: []attestation.AttestationStatementFormatIdentifier{
				attestation.AttestationStatementFormatIdentifierPacked,
			},
		},
	}

	first := fixture.rawFields()
	second := fixture.rawFields()
	first[1].([]byte)[0] = 0xff
	first[2].(map[string]any)["id"] = "mutated.example"
	first[3].(map[string]any)["id"].([]byte)[0] = 0xff
	first[4].([]any)[0].(map[string]any)["alg"] = int64(-1)
	first[5].([]any)[0].(map[string]any)["id"].([]byte)[0] = 0xff
	first[6].(map[string]any)["credBlob"].([]byte)[0] = 0xff
	first[7].(map[string]any)[string(protocol.OptionResidentKeys)] = false
	first[8].([]byte)[0] = 0xff
	first[11].([]any)[0] = "none"
	first[12] = "extra"

	if second[1].([]byte)[0] != 0x11 || fixture.Request.ClientDataHash[0] != 0x11 {
		t.Fatal("clientDataHash aliases another raw snapshot or the fixture")
	}
	if second[2].(map[string]any)["id"] != "raw.example" || fixture.Request.RP.ID != "raw.example" {
		t.Fatal("RP aliases another raw snapshot or the fixture")
	}
	if second[3].(map[string]any)["id"].([]byte)[0] != 0x21 || fixture.Request.User.ID[0] != 0x21 {
		t.Fatal("user ID aliases another raw snapshot or the fixture")
	}
	if second[5].([]any)[0].(map[string]any)["id"].([]byte)[0] != 0x31 || fixture.Request.ExcludeList[0].ID[0] != 0x31 {
		t.Fatal("excludeList aliases another raw snapshot or the fixture")
	}
	if second[6].(map[string]any)["credBlob"].([]byte)[0] != 0x41 || fixture.Request.Extensions.CredBlob[0] != 0x41 {
		t.Fatal("extensions alias another raw snapshot or the fixture")
	}
	if second[7].(map[string]any)[string(protocol.OptionResidentKeys)] != true || !fixture.Request.Options[protocol.OptionResidentKeys] {
		t.Fatal("options alias another raw snapshot or the fixture")
	}
	if second[8].([]byte)[0] != 0x51 || fixture.Request.PinUvAuthParam[0] != 0x51 {
		t.Fatal("pinUvAuthParam aliases another raw snapshot or the fixture")
	}
	if _, present := second[12]; present {
		t.Fatal("outer raw maps alias")
	}
	if _, present := second[10]; !present || second[9] != uint64(protocol.PinUvAuthProtocolTwo) {
		t.Fatalf("wire fields = %#v", second)
	}
}

func TestExchangeRawMakeCredentialUsesCTAP2AndValidatesResponse(t *testing.T) {
	fields := map[uint64]any{
		4: []any{map[string]any{"type": "public-key", "alg": int64(-7)}},
		1: bytes.Repeat([]byte{0x11}, 32),
	}
	wantBody, err := ctap2EncMode.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	device := makeCredentialFixtureCBORFunc(func(
		_ context.Context,
		request []byte,
	) (ctaptransport.CBORResponse, error) {
		if request[0] != byte(protocol.AuthenticatorMakeCredential) || !bytes.Equal(request[1:], wantBody) {
			t.Fatalf("request = %x, want %x", request, slices.Concat(
				[]byte{byte(protocol.AuthenticatorMakeCredential)},
				wantBody,
			))
		}

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_MISSING_PARAMETER}, nil
	})

	_, err = exchangeRawMakeCredential(t.Context(), device, fields)
	var ctapError *ctaptransport.CTAPError
	if !errors.As(err, &ctapError) || ctapError.Command != protocol.AuthenticatorMakeCredential ||
		ctapError.StatusCode != ctaptransport.CTAP2_ERR_MISSING_PARAMETER {
		t.Fatalf("error = %#v", err)
	}

	transportFailure := errors.New("device disconnected")
	_, err = exchangeRawMakeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
		context.Context,
		[]byte,
	) (ctaptransport.CBORResponse, error) {
		return ctaptransport.CBORResponse{}, transportFailure
	}), fields)
	if !errors.Is(err, transportFailure) {
		t.Fatalf("error = %v, want transport failure", err)
	}

	called := false
	_, err = exchangeRawMakeCredential(t.Context(), makeCredentialFixtureCBORFunc(func(
		context.Context,
		[]byte,
	) (ctaptransport.CBORResponse, error) {
		called = true

		return ctaptransport.CBORResponse{}, nil
	}), map[uint64]any{1: make(chan int)})
	if err == nil || called {
		t.Fatalf("encode error/called = %v/%v", err, called)
	}
}

func TestExpectAnyCTAPError(t *testing.T) {
	t.Run("success fails", func(t *testing.T) {
		var assertion *conformance.AssertionError
		if err := expectAnyCTAPError(nil); !errors.As(err, &assertion) {
			t.Fatalf("error = %#v, want AssertionError", err)
		}
	})

	t.Run("CTAP error passes", func(t *testing.T) {
		err := errors.New("outer: " + (&ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorMakeCredential,
			StatusCode: ctaptransport.CTAP2_ERR_INVALID_CBOR,
		}).Error())
		if got := expectAnyCTAPError(err); got != err {
			t.Fatalf("ordinary error = %v, want preserved", got)
		}

		ctapErr := &ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorMakeCredential,
			StatusCode: ctaptransport.CTAP2_ERR_INVALID_CBOR,
		}
		if err := expectAnyCTAPError(ctapErr); err != nil {
			t.Fatal(err)
		}
		if err := expectAnyCTAPError(errors.Join(errors.New("context"), ctapErr)); err != nil {
			t.Fatal(err)
		}
	})
}

type makeCredentialFixtureCBORFunc func(
	context.Context,
	[]byte,
) (ctaptransport.CBORResponse, error)

func (f makeCredentialFixtureCBORFunc) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	return f(ctx, request)
}

type makeCredentialFixtureDevice struct {
	t                     testing.TB
	info                  protocol.AuthenticatorGetInfoResponse
	commands              []protocol.Command
	resets                int
	makeCredentialRequest protocol.AuthenticatorMakeCredentialRequest
}

func (d *makeCredentialFixtureDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	d.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		d.t.Fatal("empty request")
	}

	command := protocol.Command(request[0])
	d.commands = append(d.commands, command)
	switch command {
	case protocol.AuthenticatorReset:
		if len(request) != 1 {
			d.t.Fatalf("reset request = %x", request)
		}
		d.resets++

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.AuthenticatorGetInfo:
		if len(request) != 1 {
			d.t.Fatalf("GetInfo request = %x", request)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalMakeCredentialFixture(d.t, d.info),
		}, nil
	case protocol.AuthenticatorMakeCredential:
		if err := cbor.Unmarshal(request[1:], &d.makeCredentialRequest); err != nil {
			d.t.Fatal(err)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalMakeCredentialFixture(d.t, protocol.AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AuthDataRaw:          make([]byte, 37),
				AttestationStatement: map[string]any{},
			}),
		}, nil
	default:
		d.t.Fatalf("unexpected command %s", command)

		return ctaptransport.CBORResponse{}, nil
	}
}

func marshalMakeCredentialFixture(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func runMakeCredentialFixtureTest(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	run func(*conformance.TestContext),
) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:   "make-credential-fixture-test",
		Name: "MakeCredential fixture test",
		Tests: []conformance.Test{{
			ID:   "make-credential-fixture-test.case",
			Name: "MakeCredential fixture case",
			Run:  run,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertMakeCredentialFixtureStatus(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertMakeCredentialFixtureZeroed(t *testing.T, secret []byte) {
	t.Helper()

	if slices.ContainsFunc(secret, func(value byte) bool { return value != 0 }) {
		t.Fatal("PIN/UV token was not zeroed")
	}
}

func assertMakeCredentialFixtureBytesCleared(t *testing.T, name string, value []byte) {
	t.Helper()

	if slices.ContainsFunc(value, func(b byte) bool { return b != 0 }) {
		t.Fatalf("%s was not cleared", name)
	}
}
