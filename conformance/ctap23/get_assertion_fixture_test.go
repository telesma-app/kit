package ctap23

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"errors"
	"slices"
	"strings"
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

const getAssertionFixtureTestRPID = "get-assertion.ctap23-conformance.example"

func TestPrepareGetAssertionFixtureRunsLifecycleAndScopesFreshTokens(t *testing.T) {
	makeToken := bytes.Repeat([]byte{0x4a}, 32)
	getToken := bytes.Repeat([]byte{0x6b}, 32)
	events := []string{}
	device := newGetAssertionFixtureDevice(t, &events, true)
	providerCalls := 0
	config := Config{
		PowerCycler: func(context.Context) error {
			events = append(events, "power-cycle")

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			providerCalls++
			events = append(events, "token:"+request.Permission.String())
			if request.RPID != getAssertionFixtureTestRPID {
				t.Fatalf("token RP ID = %q", request.RPID)
			}

			switch providerCalls {
			case 1:
				if request.Permission != protocol.PermissionMakeCredential {
					t.Fatalf("first token request = %#v", request)
				}

				return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: makeToken}, nil
			case 2:
				if request.Permission != protocol.PermissionGetAssertion {
					t.Fatalf("second token request = %#v", request)
				}
				assertGetAssertionFixtureZeroed(t, makeToken)

				return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: getToken}, nil
			default:
				t.Fatalf("unexpected token request %#v", request)

				return PinUvAuthToken{}, nil
			}
		},
	}

	result := runGetAssertionFixtureTest(t, device, func(test *conformance.TestContext) {
		var fixture getAssertionFixture
		if !test.Step(conformance.Step{
			ID:   "fixture.prepare",
			Name: "Prepare fixture",
			Run: func(ctx context.Context) error {
				var err error
				fixture, err = prepareGetAssertionFixture(ctx, test, config, getAssertionFixtureSpec{
					RPID: getAssertionFixtureTestRPID,
				})

				return err
			},
		}) {
			return
		}
		defer fixture.clear()

		test.Step(conformance.Step{
			ID:   "fixture.get-assertion",
			Name: "Get assertion",
			Run: func(ctx context.Context) error {
				response, err := fixture.getAssertion(ctx, test.CBOR(), fixture.Request)
				if err != nil {
					return err
				}
				if response.Response.AuthData == nil || !response.Response.AuthData.Flags.UserPresent() {
					return conformance.Fail("parsed GetAssertion authData is missing UP")
				}

				return nil
			},
		})
	})

	assertGetAssertionFixtureStatus(t, result, conformance.StatusPassed)
	wantEvents := []string{
		"power-cycle",
		"reset",
		"power-cycle",
		"get-info",
		"token:mc",
		"make-credential",
		"token:ga",
		"get-assertion",
		"power-cycle",
		"reset",
	}
	if !slices.Equal(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
	if len(device.getAssertionRequest.AllowList) != 1 ||
		!bytes.Equal(device.getAssertionRequest.AllowList[0].ID, device.credentialID) {
		t.Fatalf("allowList = %#v", device.getAssertionRequest.AllowList)
	}
	if device.getAssertionRequest.RPID != getAssertionFixtureTestRPID {
		t.Fatalf("GetAssertion RP ID = %q", device.getAssertionRequest.RPID)
	}
	wantAuthParam := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		bytes.Repeat([]byte{0x6b}, 32),
		device.getAssertionRequest.ClientDataHash,
	)
	if device.getAssertionRequest.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo ||
		!bytes.Equal(device.getAssertionRequest.PinUvAuthParam, wantAuthParam) {
		t.Fatalf("GetAssertion authorization = %d/%x", device.getAssertionRequest.PinUvAuthProtocol, device.getAssertionRequest.PinUvAuthParam)
	}
	assertGetAssertionFixtureZeroed(t, makeToken)
	assertGetAssertionFixtureZeroed(t, getToken)
	steps := result.Tests[0].Steps
	if countGetAssertionFixtureSteps(steps, "make-credential-fixture.cleanup") != 1 {
		t.Fatalf("cleanup steps = %#v", steps)
	}
}

func TestPrepareGetAssertionFixtureUsesUnauthenticatedPath(t *testing.T) {
	events := []string{}
	device := newGetAssertionFixtureDevice(t, &events, false)
	config := Config{
		PowerCycler: func(context.Context) error {
			events = append(events, "power-cycle")

			return nil
		},
		TokenProvider: func(
			context.Context,
			*client.Client,
			PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			t.Fatal("unauthenticated fixture requested a token")

			return PinUvAuthToken{}, nil
		},
	}
	var fixture getAssertionFixture
	result := runGetAssertionFixtureTest(t, device, func(test *conformance.TestContext) {
		test.Step(conformance.Step{
			ID:   "fixture.prepare",
			Name: "Prepare fixture",
			Run: func(ctx context.Context) error {
				var err error
				fixture, err = prepareGetAssertionFixture(ctx, test, config, getAssertionFixtureSpec{
					RPID: getAssertionFixtureTestRPID,
				})

				return err
			},
		})
	})

	assertGetAssertionFixtureStatus(t, result, conformance.StatusPassed)
	if fixture.Authorization.Value != nil || fixture.Request.PinUvAuthParam != nil ||
		fixture.Request.PinUvAuthProtocol != 0 {
		t.Fatalf("fixture authorization = %#v; request = %#v", fixture.Authorization, fixture.Request)
	}
}

func TestPrepareGetAssertionFixtureUsesExplicitCredentialParametersAndRetainsPublicKey(t *testing.T) {
	events := []string{}
	device := newGetAssertionFixtureDevice(t, &events, false)
	explicit := []credential.PublicKeyCredentialParameters{{
		Type:      credential.PublicKeyCredentialTypePublicKey,
		Algorithm: cose.AlgorithmES384,
	}}
	config := Config{PowerCycler: func(context.Context) error {
		events = append(events, "power-cycle")

		return nil
	}}
	var fixture getAssertionFixture
	result := runGetAssertionFixtureTest(t, device, func(test *conformance.TestContext) {
		test.Step(conformance.Step{
			ID:   "fixture.prepare",
			Name: "Prepare fixture",
			Run: func(ctx context.Context) error {
				var err error
				fixture, err = prepareGetAssertionFixture(ctx, test, config, getAssertionFixtureSpec{
					RPID:             getAssertionFixtureTestRPID,
					PubKeyCredParams: explicit,
				})

				return err
			},
		})
	})

	assertGetAssertionFixtureStatus(t, result, conformance.StatusPassed)
	if !slices.Equal(device.makeCredential.PubKeyCredParams, explicit) {
		t.Fatalf("pubKeyCredParams = %#v, want %#v", device.makeCredential.PubKeyCredParams, explicit)
	}
	if fixture.CredentialPublicKey[cose.KeyParameterAlg] != int64(cose.AlgorithmES256) ||
		fixture.CredentialPublicKey[cose.EC2KeyParameterCrv] != uint64(cose.EllipticCurveP256) {
		t.Fatalf("credential public key = %#v", fixture.CredentialPublicKey)
	}
}

func TestGetAssertionFixtureRefreshAuthorizationUsesCurrentHashAndWipesPreviousState(t *testing.T) {
	hashes := [][]byte{
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x22}, 32),
		bytes.Repeat([]byte{0x33}, 32),
	}
	tokens := [][]byte{
		bytes.Repeat([]byte{0x41}, 32),
		bytes.Repeat([]byte{0x52}, 32),
		bytes.Repeat([]byte{0x63}, 32),
	}
	authParams := make([][]byte, 0, len(tokens))
	providerCalls := 0
	config := Config{TokenProvider: func(
		_ context.Context,
		_ *client.Client,
		request PinUvAuthTokenRequest,
	) (PinUvAuthToken, error) {
		if request.Permission != protocol.PermissionGetAssertion || request.RPID != getAssertionFixtureTestRPID {
			t.Fatalf("token request = %#v", request)
		}
		if providerCalls != 0 {
			assertGetAssertionFixtureZeroed(t, tokens[providerCalls-1])
			assertGetAssertionFixtureZeroed(t, authParams[providerCalls-1])
		}
		token := tokens[providerCalls]
		providerCalls++

		return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, nil
	}}
	var fixture getAssertionFixture
	result := runGetAssertionFixtureTest(t, getAssertionFixtureCBORFunc(func(
		context.Context,
		[]byte,
	) (ctaptransport.CBORResponse, error) {
		t.Fatal("refresh issued a CTAP command")

		return ctaptransport.CBORResponse{}, nil
	}), func(test *conformance.TestContext) {
		fixture = getAssertionFixture{
			Info: protocol.AuthenticatorGetInfoResponse{
				Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
				PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			},
			Request: protocol.AuthenticatorGetAssertionRequest{RPID: getAssertionFixtureTestRPID},
		}
		defer fixture.clear()

		test.Step(conformance.Step{
			ID:   "fixture.refresh",
			Name: "Refresh authorization",
			Run: func(ctx context.Context) error {
				for index, hash := range hashes {
					fixture.Request.ClientDataHash = hash
					if err := fixture.refreshAuthorization(ctx, test, config, &fixture.Request); err != nil {
						return err
					}
					want := ctapcrypto.Authenticate(
						protocol.PinUvAuthProtocolTwo,
						bytes.Repeat([]byte{byte(0x41 + index*0x11)}, 32),
						hash,
					)
					if !bytes.Equal(fixture.Request.PinUvAuthParam, want) {
						return conformance.Failf("refresh %d HMAC does not match current clientDataHash", index)
					}
					authParams = append(authParams, fixture.Request.PinUvAuthParam)
				}

				return nil
			},
		})
	})

	assertGetAssertionFixtureStatus(t, result, conformance.StatusPassed)
	if providerCalls != 3 {
		t.Fatalf("provider calls = %d, want 3", providerCalls)
	}
	for _, token := range tokens {
		assertGetAssertionFixtureZeroed(t, token)
	}
	for _, authParam := range authParams {
		assertGetAssertionFixtureZeroed(t, authParam)
	}
}

func TestGetAssertionFixtureRefreshAuthorizationWipesProviderFailures(t *testing.T) {
	providerFailure := errors.New("PIN entry canceled")
	for _, testCase := range []struct {
		name          string
		authorization PinUvAuthToken
		err           error
	}{
		{
			name: "provider error",
			authorization: PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    bytes.Repeat([]byte{0x71}, 32),
			},
			err: providerFailure,
		},
		{
			name: "short token",
			authorization: PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    bytes.Repeat([]byte{0x72}, 16),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			oldToken := bytes.Repeat([]byte{0x81}, 32)
			oldAuthParam := bytes.Repeat([]byte{0x82}, 32)
			fixture := getAssertionFixture{
				Info: protocol.AuthenticatorGetInfoResponse{
					Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
					PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
				},
				Request: protocol.AuthenticatorGetAssertionRequest{
					RPID:              getAssertionFixtureTestRPID,
					ClientDataHash:    bytes.Repeat([]byte{0x91}, 32),
					PinUvAuthParam:    oldAuthParam,
					PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
				},
				Authorization: PinUvAuthToken{
					Protocol: protocol.PinUvAuthProtocolTwo,
					Value:    oldToken,
				},
			}
			config := Config{TokenProvider: func(
				context.Context,
				*client.Client,
				PinUvAuthTokenRequest,
			) (PinUvAuthToken, error) {
				assertGetAssertionFixtureZeroed(t, oldToken)
				assertGetAssertionFixtureZeroed(t, oldAuthParam)

				return testCase.authorization, testCase.err
			}}
			result := runGetAssertionFixtureTest(t, getAssertionFixtureCBORFunc(func(
				context.Context,
				[]byte,
			) (ctaptransport.CBORResponse, error) {
				t.Fatal("refresh issued a CTAP command")

				return ctaptransport.CBORResponse{}, nil
			}), func(test *conformance.TestContext) {
				test.Step(conformance.Step{
					ID:   "fixture.refresh",
					Name: "Refresh authorization",
					Run: func(ctx context.Context) error {
						return fixture.refreshAuthorization(ctx, test, config, &fixture.Request)
					},
				})
			})

			assertGetAssertionFixtureStatus(t, result, conformance.StatusError)
			assertGetAssertionFixtureZeroed(t, testCase.authorization.Value)
			if fixture.Authorization.Value != nil || fixture.Request.PinUvAuthParam != nil ||
				fixture.Request.PinUvAuthProtocol != 0 {
				t.Fatalf("fixture retained authorization = %#v/%#v", fixture.Authorization, fixture.Request)
			}
		})
	}
}

func TestPrepareGetAssertionFixtureRequiresCreatedCredentialID(t *testing.T) {
	events := []string{}
	base := newGetAssertionFixtureDevice(t, &events, false)
	device := getAssertionFixtureCBORFunc(func(
		ctx context.Context,
		request []byte,
	) (ctaptransport.CBORResponse, error) {
		if protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
			return base.CBOR(ctx, request)
		}
		events = append(events, "make-credential")

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalGetAssertionFixture(t, protocol.AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AuthDataRaw:          make([]byte, 37),
				AttestationStatement: map[string]any{},
			}),
		}, nil
	})
	config := Config{PowerCycler: func(context.Context) error {
		events = append(events, "power-cycle")

		return nil
	}}

	result := runPrepareGetAssertionFixture(t, device, config)

	assertGetAssertionFixtureStatus(t, result, conformance.StatusFailed)
	if got := result.Tests[0].Steps[0].Message; got !=
		"authenticatorMakeCredential response does not contain an attested credential ID" {
		t.Fatalf("message = %q", got)
	}
	if countGetAssertionFixtureSteps(result.Tests[0].Steps, "make-credential-fixture.cleanup") != 1 {
		t.Fatalf("steps = %#v", result.Tests[0].Steps)
	}
}

func TestPrepareGetAssertionFixtureClearsTokensOnProviderErrors(t *testing.T) {
	providerFailure := errors.New("PIN entry canceled")

	t.Run("MakeCredential token", func(t *testing.T) {
		token := bytes.Repeat([]byte{0x35}, 32)
		events := []string{}
		device := newGetAssertionFixtureDevice(t, &events, true)
		config := getAssertionFixtureConfig(&events, func(
			context.Context,
			*client.Client,
			PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, providerFailure
		})

		result := runPrepareGetAssertionFixture(t, device, config)

		assertGetAssertionFixtureStatus(t, result, conformance.StatusError)
		assertGetAssertionFixtureZeroed(t, token)
		if slices.Contains(device.commands, protocol.AuthenticatorMakeCredential) {
			t.Fatal("MakeCredential ran after its token provider failed")
		}
	})

	t.Run("GetAssertion token", func(t *testing.T) {
		makeToken := bytes.Repeat([]byte{0x45}, 32)
		getToken := bytes.Repeat([]byte{0x56}, 32)
		events := []string{}
		device := newGetAssertionFixtureDevice(t, &events, true)
		calls := 0
		config := getAssertionFixtureConfig(&events, func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			calls++
			if calls == 1 {
				return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: makeToken}, nil
			}
			if request.Permission != protocol.PermissionGetAssertion {
				t.Fatalf("second token request = %#v", request)
			}
			assertGetAssertionFixtureZeroed(t, makeToken)

			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: getToken}, providerFailure
		})

		result := runPrepareGetAssertionFixture(t, device, config)

		assertGetAssertionFixtureStatus(t, result, conformance.StatusError)
		assertGetAssertionFixtureZeroed(t, makeToken)
		assertGetAssertionFixtureZeroed(t, getToken)
	})

	t.Run("invalid GetAssertion token", func(t *testing.T) {
		makeToken := bytes.Repeat([]byte{0x67}, 32)
		getToken := bytes.Repeat([]byte{0x78}, 32)
		events := []string{}
		device := newGetAssertionFixtureDevice(t, &events, true)
		calls := 0
		config := getAssertionFixtureConfig(&events, func(
			context.Context,
			*client.Client,
			PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			calls++
			if calls == 1 {
				return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: makeToken}, nil
			}

			return PinUvAuthToken{Protocol: 3, Value: getToken}, nil
		})

		result := runPrepareGetAssertionFixture(t, device, config)

		assertGetAssertionFixtureStatus(t, result, conformance.StatusError)
		assertGetAssertionFixtureZeroed(t, makeToken)
		assertGetAssertionFixtureZeroed(t, getToken)
	})
}

func TestGetAssertionFixtureRawFieldsAreFreshWireSnapshots(t *testing.T) {
	fixture := getAssertionFixture{
		Request: protocol.AuthenticatorGetAssertionRequest{
			RPID:           "raw.example",
			ClientDataHash: []byte{0x11, 0x12},
			AllowList: []credential.PublicKeyCredentialDescriptor{{
				Type:       credential.PublicKeyCredentialTypePublicKey,
				ID:         []byte{0x21, 0x22},
				Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB},
			}},
			Options:           map[protocol.Option]bool{protocol.OptionUserPresence: true},
			PinUvAuthParam:    []byte{0x31, 0x32},
			PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
		},
	}

	first := fixture.rawFields()
	second := fixture.rawFields()
	first[2].([]byte)[0] = 0xff
	first[3].([]any)[0].(map[string]any)["id"].([]byte)[0] = 0xff
	first[5].(map[string]any)[string(protocol.OptionUserPresence)] = false
	first[6].([]byte)[0] = 0xff
	first[8] = "extra"

	if second[2].([]byte)[0] != 0x11 || fixture.Request.ClientDataHash[0] != 0x11 {
		t.Fatal("clientDataHash aliases another raw snapshot or the fixture")
	}
	if second[3].([]any)[0].(map[string]any)["id"].([]byte)[0] != 0x21 ||
		fixture.Request.AllowList[0].ID[0] != 0x21 {
		t.Fatal("allowList aliases another raw snapshot or the fixture")
	}
	if second[5].(map[string]any)[string(protocol.OptionUserPresence)] != true ||
		!fixture.Request.Options[protocol.OptionUserPresence] {
		t.Fatal("options alias another raw snapshot or the fixture")
	}
	if second[6].([]byte)[0] != 0x31 || fixture.Request.PinUvAuthParam[0] != 0x31 {
		t.Fatal("pinUvAuthParam aliases another raw snapshot or the fixture")
	}
	if _, present := second[8]; present {
		t.Fatal("outer raw maps alias")
	}
}

func TestGetAssertionFixtureClassifiesWireResponses(t *testing.T) {
	fixture := getAssertionFixture{}
	request := protocol.AuthenticatorGetAssertionRequest{
		RPID:           getAssertionFixtureTestRPID,
		ClientDataHash: bytes.Repeat([]byte{0x11}, 32),
	}
	valid := getAssertionFixtureResponse(t, []byte{0x01})

	t.Run("valid", func(t *testing.T) {
		response, err := fixture.getAssertion(t.Context(), getAssertionFixtureResponseDevice(valid), request)
		if err != nil {
			t.Fatal(err)
		}
		if response.Response.AuthData == nil || !response.Response.AuthData.Flags.UserPresent() {
			t.Fatalf("response authData = %#v", response.Response.AuthData)
		}
		if len(response.Fields) != 3 || !hasCBORMajorType(response.Fields[1], 5) ||
			!hasCBORMajorType(response.Fields[2], 2) || !hasCBORMajorType(response.Fields[3], 2) {
			t.Fatalf("raw response fields = %#v", response.Fields)
		}
	})

	for _, testCase := range []struct {
		name        string
		response    ctaptransport.CBORResponse
		wantMessage string
	}{
		{
			name: "CTAP status",
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
			},
			wantMessage: "authenticatorGetAssertion returned CTAP2_ERR_NO_CREDENTIALS",
		},
		{
			name: "malformed CBOR",
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       []byte{0xff},
			},
			wantMessage: "invalid authenticatorGetAssertion response CBOR",
		},
		{
			name: "typed schema",
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data: marshalGetAssertionFixture(t, map[uint64]any{
					1: false,
					2: make([]byte, 37),
					3: []byte{0x01},
				}),
			},
			wantMessage: "authenticatorGetAssertion response required credential field is not a CBOR map",
		},
		{
			name: "malformed authData",
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data: marshalGetAssertionFixture(t, protocol.AuthenticatorGetAssertionResponse{
					Credential: credential.PublicKeyCredentialDescriptor{
						Type: credential.PublicKeyCredentialTypePublicKey,
						ID:   []byte{0x01},
					},
					AuthDataRaw: []byte{0x01},
					Signature:   []byte{0x02},
				}),
			},
			wantMessage: "invalid authenticatorGetAssertion authData",
		},
		{
			name: "non-canonical",
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       nonCanonicalGetAssertionFixtureResponse(t),
			},
			wantMessage: "authenticatorGetAssertion response is not CTAP2 canonical CBOR",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := fixture.getAssertion(
				t.Context(),
				getAssertionFixtureResponseDevice(testCase.response),
				request,
			)
			var assertion *conformance.AssertionError
			if !errors.As(err, &assertion) || !strings.Contains(err.Error(), testCase.wantMessage) {
				t.Fatalf("error = %#v, want AssertionError containing %q", err, testCase.wantMessage)
			}
		})
	}

	for _, missing := range []struct {
		key  uint64
		name string
	}{
		{key: 1, name: "credential"},
		{key: 2, name: "authData"},
		{key: 3, name: "signature"},
	} {
		t.Run("missing "+missing.name, func(t *testing.T) {
			fields := map[uint64]any{
				1: map[string]any{"type": "public-key", "id": []byte{0x01}},
				2: getAssertionFixtureAuthData(),
				3: []byte{0x02},
			}
			delete(fields, missing.key)
			_, err := fixture.getAssertion(
				t.Context(),
				getAssertionFixtureResponseDevice(ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP2_OK,
					Data:       marshalGetAssertionFixture(t, fields),
				}),
				request,
			)
			var assertion *conformance.AssertionError
			want := "authenticatorGetAssertion response is missing required " + missing.name + " field"
			if !errors.As(err, &assertion) || err.Error() != want {
				t.Fatalf("error = %#v, want %q AssertionError", err, want)
			}
		})
	}

	for _, field := range []struct {
		key      uint64
		name     string
		typeName string
	}{
		{key: 1, name: "credential", typeName: "map"},
		{key: 2, name: "authData", typeName: "byte string"},
		{key: 3, name: "signature", typeName: "byte string"},
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
					1: marshalGetAssertionFixture(t, map[string]any{
						"type": "public-key",
						"id":   []byte{0x01},
					}),
					2: marshalGetAssertionFixture(t, getAssertionFixtureAuthData()),
					3: marshalGetAssertionFixture(t, []byte{0x02}),
				}
				fields[field.key] = invalid.raw
				response := marshalGetAssertionFixture(t, fields)

				_, err := fixture.getAssertion(
					t.Context(),
					getAssertionFixtureResponseDevice(ctaptransport.CBORResponse{
						StatusCode: ctaptransport.CTAP2_OK,
						Data:       response,
					}),
					request,
				)
				var assertion *conformance.AssertionError
				want := "authenticatorGetAssertion response required " + field.name +
					" field is not a CBOR " + field.typeName
				if !errors.As(err, &assertion) || err.Error() != want {
					t.Fatalf("error = %#v, want %q AssertionError", err, want)
				}
			})
		}
	}

	t.Run("transport", func(t *testing.T) {
		transportFailure := errors.New("device disconnected")
		_, err := fixture.getAssertion(t.Context(), getAssertionFixtureCBORFunc(func(
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

func TestExchangeRawGetAssertionUsesCTAP2AndValidatesResponse(t *testing.T) {
	fields := map[uint64]any{2: bytes.Repeat([]byte{0x11}, 32), 1: "raw.example"}
	wantBody, err := ctap2EncMode.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	device := getAssertionFixtureCBORFunc(func(
		_ context.Context,
		request []byte,
	) (ctaptransport.CBORResponse, error) {
		if request[0] != byte(protocol.AuthenticatorGetAssertion) || !bytes.Equal(request[1:], wantBody) {
			t.Fatalf("request = %x", request)
		}

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_MISSING_PARAMETER}, nil
	})

	_, err = exchangeRawGetAssertion(t.Context(), device, fields)
	var ctapError *ctaptransport.CTAPError
	if !errors.As(err, &ctapError) || ctapError.Command != protocol.AuthenticatorGetAssertion ||
		ctapError.StatusCode != ctaptransport.CTAP2_ERR_MISSING_PARAMETER {
		t.Fatalf("error = %#v", err)
	}

	called := false
	_, err = exchangeRawGetAssertion(t.Context(), getAssertionFixtureCBORFunc(func(
		context.Context,
		[]byte,
	) (ctaptransport.CBORResponse, error) {
		called = true

		return ctaptransport.CBORResponse{}, nil
	}), map[uint64]any{1: make(chan int)})
	if err == nil || called {
		t.Fatalf("encode error/called = %v/%v", err, called)
	}

	transportFailure := errors.New("device disconnected")
	_, err = exchangeRawGetAssertion(t.Context(), getAssertionFixtureCBORFunc(func(
		context.Context,
		[]byte,
	) (ctaptransport.CBORResponse, error) {
		return ctaptransport.CBORResponse{}, transportFailure
	}), fields)
	if !errors.Is(err, transportFailure) {
		t.Fatalf("error = %v, want transport failure", err)
	}
}

type getAssertionFixtureCBORFunc func(
	context.Context,
	[]byte,
) (ctaptransport.CBORResponse, error)

func (f getAssertionFixtureCBORFunc) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	return f(ctx, request)
}

type getAssertionFixtureDevice struct {
	t                   testing.TB
	events              *[]string
	info                protocol.AuthenticatorGetInfoResponse
	commands            []protocol.Command
	credentialID        []byte
	makeCredential      protocol.AuthenticatorMakeCredentialRequest
	getAssertionRequest protocol.AuthenticatorGetAssertionRequest
}

func newGetAssertionFixtureDevice(
	t testing.TB,
	events *[]string,
	authorized bool,
) *getAssertionFixtureDevice {
	options := map[protocol.Option]bool{}
	protocols := []protocol.PinUvAuthProtocol(nil)
	if authorized {
		options[protocol.OptionClientPIN] = false
		protocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo}
	}

	return &getAssertionFixtureDevice{
		t:            t,
		events:       events,
		credentialID: bytes.Repeat([]byte{0x91}, 16),
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:           []protocol.Version{protocol.FIDO_2_3},
			Extensions:         []extension.ExtensionIdentifier{},
			AAGUID:             uuid.UUID{},
			Options:            options,
			PinUvAuthProtocols: protocols,
			Algorithms: []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}},
		},
	}
}

func (d *getAssertionFixtureDevice) CBOR(
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
		*d.events = append(*d.events, "reset")

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.AuthenticatorGetInfo:
		*d.events = append(*d.events, "get-info")

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalGetAssertionFixture(d.t, d.info),
		}, nil
	case protocol.AuthenticatorMakeCredential:
		*d.events = append(*d.events, "make-credential")
		if err := getInfoDecMode.Unmarshal(request[1:], &d.makeCredential); err != nil {
			d.t.Fatal(err)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalGetAssertionFixture(d.t, protocol.AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AuthDataRaw:          getAssertionFixtureMakeCredentialAuthData(d.t, d.credentialID),
				AttestationStatement: map[string]any{},
			}),
		}, nil
	case protocol.AuthenticatorGetAssertion:
		*d.events = append(*d.events, "get-assertion")
		if err := getInfoDecMode.Unmarshal(request[1:], &d.getAssertionRequest); err != nil {
			d.t.Fatal(err)
		}

		return getAssertionFixtureResponse(d.t, d.credentialID), nil
	default:
		d.t.Fatalf("unexpected command %s", command)

		return ctaptransport.CBORResponse{}, nil
	}
}

func getAssertionFixtureMakeCredentialAuthData(t testing.TB, credentialID []byte) []byte {
	t.Helper()

	curve := elliptic.P256().Params()
	key := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   curve.Gx.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   curve.Gy.FillBytes(make([]byte, 32)),
	}
	authData := make([]byte, 37)
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagAttestedCredentialDataIncluded)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, byte(len(credentialID)>>8), byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, marshalGetAssertionFixture(t, key)...)

	return authData
}

func getAssertionFixtureAuthData() []byte {
	authData := make([]byte, 37)
	authData[32] = byte(protocol.AuthDataFlagUserPresent)

	return authData
}

func getAssertionFixtureResponse(t testing.TB, credentialID []byte) ctaptransport.CBORResponse {
	t.Helper()

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data: marshalGetAssertionFixture(t, protocol.AuthenticatorGetAssertionResponse{
			Credential: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   slices.Clone(credentialID),
			},
			AuthDataRaw: getAssertionFixtureAuthData(),
			Signature:   []byte{0x30, 0x00},
		}),
	}
}

func nonCanonicalGetAssertionFixtureResponse(t testing.TB) []byte {
	t.Helper()

	fields := map[uint64]any{
		1: map[string]any{"type": "public-key", "id": []byte{0x01}},
		2: getAssertionFixtureAuthData(),
		3: []byte{0x02},
	}
	encoded := []byte{0xa3}
	for _, key := range []uint64{3, 2, 1} {
		encoded = append(encoded, marshalGetAssertionFixture(t, key)...)
		encoded = append(encoded, marshalGetAssertionFixture(t, fields[key])...)
	}

	return encoded
}

func marshalGetAssertionFixture(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func getAssertionFixtureResponseDevice(
	response ctaptransport.CBORResponse,
) getAssertionFixtureCBORFunc {
	return func(_ context.Context, request []byte) (ctaptransport.CBORResponse, error) {
		if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorGetAssertion {
			return ctaptransport.CBORResponse{}, errors.New("unexpected command")
		}

		return response, nil
	}
}

func getAssertionFixtureConfig(
	events *[]string,
	provider PinUvAuthTokenProvider,
) Config {
	return Config{
		PowerCycler: func(context.Context) error {
			*events = append(*events, "power-cycle")

			return nil
		},
		TokenProvider: provider,
	}
}

func runPrepareGetAssertionFixture(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
) conformance.SuiteResult {
	t.Helper()

	return runGetAssertionFixtureTest(t, device, func(test *conformance.TestContext) {
		test.Step(conformance.Step{
			ID:   "fixture.prepare",
			Name: "Prepare fixture",
			Run: func(ctx context.Context) error {
				_, err := prepareGetAssertionFixture(ctx, test, config, getAssertionFixtureSpec{
					RPID: getAssertionFixtureTestRPID,
				})

				return err
			},
		})
	})
}

func runGetAssertionFixtureTest(
	t *testing.T,
	device ctaptransport.CBOR,
	run func(*conformance.TestContext),
) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:   "get-assertion-fixture-test",
		Name: "GetAssertion fixture test",
		Tests: []conformance.Test{{
			ID:   "get-assertion-fixture-test.case",
			Name: "GetAssertion fixture case",
			Run:  run,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertGetAssertionFixtureStatus(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertGetAssertionFixtureZeroed(t *testing.T, secret []byte) {
	t.Helper()

	if slices.ContainsFunc(secret, func(value byte) bool { return value != 0 }) {
		t.Fatal("PIN/UV token was not zeroed")
	}
}

func countGetAssertionFixtureSteps(steps []conformance.StepResult, id conformance.StepID) int {
	count := 0
	for _, step := range steps {
		if step.ID == id {
			count++
		}
	}

	return count
}
