package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	largeBlobKeySourcePath = "tests/CTAP2/Protocol/Extensions/largeBlobKey.js"
	largeBlobKeyP1RPID     = "large-blob-key-p1.ctap23-conformance.example"
	largeBlobKeyP2RPID     = "large-blob-key-p2.ctap23-conformance.example"
	largeBlobKeyF1RPID     = "large-blob-key-f1.ctap23-conformance.example"
	largeBlobKeyF2RPID     = "large-blob-key-f2.ctap23-conformance.example"
	largeBlobKeyF3RPID     = "large-blob-key-f3.ctap23-conformance.example"
	largeBlobKeyF4RPID     = "large-blob-key-f4.ctap23-conformance.example"

	TestIDLargeBlobKeyP1 conformance.TestID = "fido.ctap2.3.large-blob-key.p-1"
	TestIDLargeBlobKeyP2 conformance.TestID = "fido.ctap2.3.large-blob-key.p-2"
	TestIDLargeBlobKeyF1 conformance.TestID = "fido.ctap2.3.large-blob-key.f-1"
	TestIDLargeBlobKeyF2 conformance.TestID = "fido.ctap2.3.large-blob-key.f-2"
	TestIDLargeBlobKeyF3 conformance.TestID = "fido.ctap2.3.large-blob-key.f-3"
	TestIDLargeBlobKeyF4 conformance.TestID = "fido.ctap2.3.large-blob-key.f-4"
)

type largeBlobKeySession struct {
	info       protocol.AuthenticatorGetInfoResponse
	algorithms []credential.PublicKeyCredentialParameters
	pin        []byte
	useUV      bool
}

func (session *largeBlobKeySession) clear() {
	clear(session.pin)
	session.pin = nil
}

type largeBlobKeyMakeCredentialResult struct {
	fields   map[uint64]cbor.RawMessage
	response protocol.AuthenticatorMakeCredentialResponse
}

func largeBlobKeyTests(config Config) []conformance.Test {
	featureReference := largeBlobKeyFeatureReference()
	createReference := largeBlobKeyCreateReference()
	getReference := largeBlobKeyGetReference()
	inputReference := largeBlobKeyInputReference()
	resetRequirement := resetReference()
	powerCycleRequirement := clientPINPowerCycleReference()
	tokenReference := clientPIN2PermissionsOperationReference()
	tokenLengthReference := clientPIN2PermissionsTokenLengthReference()

	return []conformance.Test{
		largeBlobKeyTest(
			config,
			TestIDLargeBlobKeyP1,
			"P-1",
			"Fresh large-blob keys for discoverable credentials",
			"Creates two independent discoverable credentials and requires distinct fresh 32-byte large-blob keys",
			[]conformance.RequirementRef{
				featureReference,
				createReference,
				tokenReference,
				tokenLengthReference,
				resetRequirement,
				powerCycleRequirement,
			},
			func(ctx context.Context, test *conformance.TestContext, session *largeBlobKeySession) error {
				firstRequest := largeBlobKeyMakeCredentialRequest(
					"p-1-first",
					largeBlobKeyP1RPID,
					session.algorithms,
					true,
				)
				first, err := largeBlobKeyMakeCredential(ctx, test, session, firstRequest)
				if err != nil {
					return err
				}
				defer clear(first.response.LargeBlobKey)
				defer clear(first.fields[5])

				firstKey, err := largeBlobKeyRequireMakeCredentialKey(first)
				if err != nil {
					return err
				}
				defer clear(firstKey)
				if first.response.AuthData.AttestedCredentialData == nil ||
					len(first.response.AuthData.AttestedCredentialData.CredentialID) == 0 {
					return conformance.Fail("first authenticatorMakeCredential response is missing an attested credential ID")
				}

				secondRequest := largeBlobKeyMakeCredentialRequest(
					"p-1-second",
					largeBlobKeyP1RPID,
					session.algorithms,
					true,
				)
				second, err := largeBlobKeyMakeCredential(ctx, test, session, secondRequest)
				if err != nil {
					return err
				}
				defer clear(second.response.LargeBlobKey)
				defer clear(second.fields[5])

				secondKey, err := largeBlobKeyRequireMakeCredentialKey(second)
				if err != nil {
					return err
				}
				defer clear(secondKey)
				if second.response.AuthData.AttestedCredentialData == nil ||
					len(second.response.AuthData.AttestedCredentialData.CredentialID) == 0 {
					return conformance.Fail("second authenticatorMakeCredential response is missing an attested credential ID")
				}
				if bytes.Equal(
					first.response.AuthData.AttestedCredentialData.CredentialID,
					second.response.AuthData.AttestedCredentialData.CredentialID,
				) {
					return conformance.Fail("the two discoverable credentials have the same credential ID")
				}
				if bytes.Equal(firstKey, secondKey) {
					return conformance.Fail("the two discoverable credentials have the same largeBlobKey")
				}

				return nil
			},
		),
		largeBlobKeyTest(
			config,
			TestIDLargeBlobKeyP2,
			"P-2",
			"Large-blob key returned by GetAssertion",
			"Requires GetAssertion to return the exact large-blob key stored with the selected credential",
			[]conformance.RequirementRef{
				featureReference,
				createReference,
				getReference,
				tokenReference,
				tokenLengthReference,
				resetRequirement,
				powerCycleRequirement,
			},
			func(ctx context.Context, test *conformance.TestContext, session *largeBlobKeySession) error {
				created, err := largeBlobKeyMakeCredential(
					ctx,
					test,
					session,
					largeBlobKeyMakeCredentialRequest("p-2", largeBlobKeyP2RPID, session.algorithms, true),
				)
				if err != nil {
					return err
				}
				defer clear(created.response.LargeBlobKey)
				defer clear(created.fields[5])

				createdKey, err := largeBlobKeyRequireMakeCredentialKey(created)
				if err != nil {
					return err
				}
				defer clear(createdKey)
				if created.response.AuthData.AttestedCredentialData == nil ||
					len(created.response.AuthData.AttestedCredentialData.CredentialID) == 0 {
					return conformance.Fail("authenticatorMakeCredential response is missing an attested credential ID")
				}

				request := largeBlobKeyGetAssertionRequest(
					"p-2",
					largeBlobKeyP2RPID,
					created.response.AuthData.AttestedCredentialData.CredentialID,
					true,
				)
				asserted, err := largeBlobKeyGetAssertion(ctx, test, session, request)
				if err != nil {
					return err
				}
				defer clear(asserted.Response.LargeBlobKey)
				defer clear(asserted.Fields[7])

				assertedKey, err := largeBlobKeyRequireResponseKey(
					"authenticatorGetAssertion",
					asserted.Fields,
					7,
					asserted.Response.LargeBlobKey,
				)
				if err != nil {
					return err
				}
				defer clear(assertedKey)
				if !bytes.Equal(createdKey, assertedKey) {
					return conformance.Fail("authenticatorGetAssertion returned a different largeBlobKey")
				}

				return nil
			},
		),
		largeBlobKeyMakeCredentialNegativeTest(
			config,
			TestIDLargeBlobKeyF1,
			"F-1",
			"MakeCredential rejects largeBlobKey false",
			largeBlobKeyF1RPID,
			false,
			ctaptransport.CTAP2_ERR_INVALID_OPTION,
			[]conformance.RequirementRef{featureReference, inputReference, tokenReference, tokenLengthReference, resetRequirement, powerCycleRequirement},
		),
		largeBlobKeyMakeCredentialNegativeTest(
			config,
			TestIDLargeBlobKeyF2,
			"F-2",
			"MakeCredential rejects a non-boolean largeBlobKey input",
			largeBlobKeyF2RPID,
			"not-a-boolean",
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			[]conformance.RequirementRef{featureReference, inputReference, tokenReference, tokenLengthReference, resetRequirement, powerCycleRequirement},
		),
		largeBlobKeyGetAssertionNegativeTest(
			config,
			TestIDLargeBlobKeyF3,
			"F-3",
			"GetAssertion rejects largeBlobKey false",
			largeBlobKeyF3RPID,
			false,
			ctaptransport.CTAP2_ERR_INVALID_OPTION,
			[]conformance.RequirementRef{featureReference, createReference, inputReference, tokenReference, tokenLengthReference, resetRequirement, powerCycleRequirement},
		),
		largeBlobKeyGetAssertionNegativeTest(
			config,
			TestIDLargeBlobKeyF4,
			"F-4",
			"GetAssertion rejects a non-boolean largeBlobKey input",
			largeBlobKeyF4RPID,
			"not-a-boolean",
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			[]conformance.RequirementRef{featureReference, createReference, inputReference, tokenReference, tokenLengthReference, resetRequirement, powerCycleRequirement},
		),
	}
}

func largeBlobKeyTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	description string,
	references []conformance.RequirementRef,
	run func(context.Context, *conformance.TestContext, *largeBlobKeySession) error,
) conformance.Test {
	featureReference := largeBlobKeyFeatureReference()
	resetRequirement := resetReference()
	powerCycleRequirement := clientPINPowerCycleReference()

	return conformance.Test{
		ID:          id,
		Name:        name,
		Description: description,
		Source: conformance.SourceLocation{
			Path: largeBlobKeySourcePath,
			Case: marker,
		},
		References:  references,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			var session largeBlobKeySession
			if !test.Step(conformance.Step{
				ID:         "large-blob-key.applicability",
				Name:       "Check largeBlobKey applicability",
				References: []conformance.RequirementRef{featureReference},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}
					if err := largeBlobKeyApplicability(fields, info, config); err != nil {
						return err
					}
					algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
					if err != nil {
						return err
					}

					session = largeBlobKeySession{info: info, algorithms: algorithms}

					return nil
				},
			}) {
				return
			}

			test.Cleanup(largeBlobKeyCleanupStep(test, config, resetRequirement, powerCycleRequirement))
			if !test.Step(largeBlobKeyResetStep(test, config, resetRequirement, powerCycleRequirement)) {
				return
			}
			if !test.Step(conformance.Step{
				ID:   "large-blob-key.authorization",
				Name: "Prepare an exact PIN/UV protocol 2 authorization session",
				References: []conformance.RequirementRef{
					clientPIN2PermissionsOperationReference(),
					clientPIN2PermissionsTokenLengthReference(),
				},
				Run: func(ctx context.Context) error {
					return largeBlobKeyPrepareAuthorizationSession(ctx, test, config, &session)
				},
			}) {
				return
			}
			defer session.clear()

			test.Step(conformance.Step{
				ID:         conformance.StepID("large-blob-key." + marker + ".command"),
				Name:       name,
				References: references,
				Run: func(ctx context.Context) error {
					return run(ctx, test, &session)
				},
			})
		},
	}
}

func largeBlobKeyMakeCredentialNegativeTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	rpID string,
	input any,
	expected ctaptransport.StatusCode,
	references []conformance.RequirementRef,
) conformance.Test {
	return largeBlobKeyTest(
		config,
		id,
		marker,
		name,
		"Sends an explicitly encoded invalid largeBlobKey MakeCredential extension input",
		references,
		func(ctx context.Context, test *conformance.TestContext, session *largeBlobKeySession) error {
			request := largeBlobKeyMakeCredentialRequest(marker, rpID, session.algorithms, false)
			authorization, err := largeBlobKeyAuthorization(
				ctx,
				test,
				session,
				protocol.PermissionMakeCredential,
				rpID,
			)
			if err != nil {
				return err
			}
			defer clear(authorization.Value)

			request.PinUvAuthParam = ctapcrypto.Authenticate(
				protocol.PinUvAuthProtocolTwo,
				authorization.Value,
				request.ClientDataHash,
			)
			defer clear(request.PinUvAuthParam)
			request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo

			fields := ctap2WireFields("largeBlobKey MakeCredential negative", request)
			fields[6] = map[string]any{string(extension.ExtensionIdentifierLargeBlobKey): input}
			_, err = exchangeRawMakeCredential(ctx, test.CBOR(), fields)

			return expectCTAPStatus(err, expected)
		},
	)
}

func largeBlobKeyGetAssertionNegativeTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	rpID string,
	input any,
	expected ctaptransport.StatusCode,
	references []conformance.RequirementRef,
) conformance.Test {
	return largeBlobKeyTest(
		config,
		id,
		marker,
		name,
		"Creates an isolated credential and sends an explicitly encoded invalid largeBlobKey GetAssertion extension input",
		references,
		func(ctx context.Context, test *conformance.TestContext, session *largeBlobKeySession) error {
			created, err := largeBlobKeyMakeCredential(
				ctx,
				test,
				session,
				largeBlobKeyMakeCredentialRequest(marker, rpID, session.algorithms, true),
			)
			if err != nil {
				return err
			}
			defer clear(created.response.LargeBlobKey)
			defer clear(created.fields[5])
			createdKey, err := largeBlobKeyRequireMakeCredentialKey(created)
			if err != nil {
				return err
			}
			defer clear(createdKey)
			if created.response.AuthData.AttestedCredentialData == nil ||
				len(created.response.AuthData.AttestedCredentialData.CredentialID) == 0 {
				return conformance.Fail("authenticatorMakeCredential response is missing an attested credential ID")
			}

			request := largeBlobKeyGetAssertionRequest(
				marker,
				rpID,
				created.response.AuthData.AttestedCredentialData.CredentialID,
				false,
			)
			authorization, err := largeBlobKeyAuthorization(
				ctx,
				test,
				session,
				protocol.PermissionGetAssertion,
				rpID,
			)
			if err != nil {
				return err
			}
			defer clear(authorization.Value)

			request.PinUvAuthParam = ctapcrypto.Authenticate(
				protocol.PinUvAuthProtocolTwo,
				authorization.Value,
				request.ClientDataHash,
			)
			defer clear(request.PinUvAuthParam)
			request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo

			fields := ctap2WireFields("largeBlobKey GetAssertion negative", request)
			fields[4] = map[string]any{string(extension.ExtensionIdentifierLargeBlobKey): input}
			_, err = exchangeRawGetAssertion(ctx, test.CBOR(), fields)

			return expectCTAPStatus(err, expected)
		},
	)
}

func largeBlobKeyApplicability(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
) error {
	key := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
	largeBlob := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlob)
	if key && largeBlob {
		return conformance.Fail("GetInfo extensions advertises mutually exclusive largeBlobKey and largeBlob")
	}
	if !key {
		if config.Featureful && !largeBlob {
			return conformance.Fail("featureful profile advertises neither largeBlobKey nor largeBlob")
		}

		return conformance.Skip("authenticator does not advertise the largeBlobKey extension")
	}

	enabled, present, err := rawGetInfoOption(fields, protocol.OptionLargeBlobs)
	if err != nil {
		return err
	}
	if !present || !enabled {
		return conformance.Fail("largeBlobKey support requires GetInfo options.largeBlobs to be present and true")
	}
	return validateClientPINProtocolSupport(
		fields,
		info,
		config,
		protocol.PinUvAuthProtocolTwo,
	)
}

func largeBlobKeyMakeCredentialRequest(
	label string,
	rpID string,
	algorithms []credential.PublicKeyCredentialParameters,
	requested bool,
) protocol.AuthenticatorMakeCredentialRequest {
	clientDataHash := sha256.Sum256([]byte("largeBlobKey client data " + label))
	userID := sha256.Sum256([]byte("largeBlobKey user " + label))

	return protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash: clientDataHash[:],
		RP: credential.PublicKeyCredentialRpEntity{
			ID:   rpID,
			Name: "CTAP 2.3 largeBlobKey conformance",
		},
		User: credential.PublicKeyCredentialUserEntity{
			ID:          userID[:16],
			Name:        "large-blob-key-" + label,
			DisplayName: "Large blob key " + label,
		},
		PubKeyCredParams: algorithms,
		Extensions: protocol.CreateExtensionInputs{
			CreateLargeBlobKeyInput: protocol.CreateLargeBlobKeyInput{LargeBlobKey: requested},
		},
		Options: map[protocol.Option]bool{protocol.OptionResidentKeys: true},
	}
}

func largeBlobKeyGetAssertionRequest(
	label string,
	rpID string,
	credentialID []byte,
	requested bool,
) protocol.AuthenticatorGetAssertionRequest {
	clientDataHash := sha256.Sum256([]byte("largeBlobKey assertion client data " + label))

	return protocol.AuthenticatorGetAssertionRequest{
		RPID:           rpID,
		ClientDataHash: clientDataHash[:],
		AllowList: []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   slices.Clone(credentialID),
		}},
		Extensions: protocol.GetExtensionInputs{
			GetLargeBlobKeyInput: protocol.GetLargeBlobKeyInput{LargeBlobKey: requested},
		},
	}
}

func largeBlobKeyMakeCredential(
	ctx context.Context,
	test *conformance.TestContext,
	session *largeBlobKeySession,
	request protocol.AuthenticatorMakeCredentialRequest,
) (largeBlobKeyMakeCredentialResult, error) {
	authorization, err := largeBlobKeyAuthorization(
		ctx,
		test,
		session,
		protocol.PermissionMakeCredential,
		request.RP.ID,
	)
	if err != nil {
		return largeBlobKeyMakeCredentialResult{}, err
	}
	defer clear(authorization.Value)

	request.PinUvAuthParam = ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		authorization.Value,
		request.ClientDataHash,
	)
	defer clear(request.PinUvAuthParam)
	request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo

	wireResponse, err := exchangeMakeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return largeBlobKeyMakeCredentialResult{}, unexpectedCTAPStatus("authenticatorMakeCredential", err)
	}
	defer clear(wireResponse.Data)

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(wireResponse.Data, &fields); err != nil {
		return largeBlobKeyMakeCredentialResult{}, conformance.Failf(
			"invalid authenticatorMakeCredential response CBOR: %v",
			err,
		)
	}
	response, err := decodeMakeCredentialResponse(wireResponse.Data)
	if err != nil {
		return largeBlobKeyMakeCredentialResult{}, err
	}

	return largeBlobKeyMakeCredentialResult{fields: fields, response: response}, nil
}

func largeBlobKeyGetAssertion(
	ctx context.Context,
	test *conformance.TestContext,
	session *largeBlobKeySession,
	request protocol.AuthenticatorGetAssertionRequest,
) (getAssertionResponse, error) {
	authorization, err := largeBlobKeyAuthorization(
		ctx,
		test,
		session,
		protocol.PermissionGetAssertion,
		request.RPID,
	)
	if err != nil {
		return getAssertionResponse{}, err
	}
	defer clear(authorization.Value)

	request.PinUvAuthParam = ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		authorization.Value,
		request.ClientDataHash,
	)
	defer clear(request.PinUvAuthParam)
	request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo

	wireResponse, err := exchangeGetAssertion(ctx, test.CBOR(), request)
	if err != nil {
		return getAssertionResponse{}, unexpectedCTAPStatus("authenticatorGetAssertion", err)
	}
	defer clear(wireResponse.Data)

	if err := validateGetAssertionResponseRequiredFields(wireResponse.Data); err != nil {
		return getAssertionResponse{}, err
	}
	if err := validateCanonicalCTAP2Response("authenticatorGetAssertion", wireResponse.Data); err != nil {
		return getAssertionResponse{}, err
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(wireResponse.Data, &fields); err != nil {
		return getAssertionResponse{}, conformance.Failf(
			"invalid authenticatorGetAssertion response CBOR: %v",
			err,
		)
	}
	var response protocol.AuthenticatorGetAssertionResponse
	if err := getInfoDecMode.Unmarshal(wireResponse.Data, &response); err != nil {
		return getAssertionResponse{}, conformance.Failf(
			"invalid authenticatorGetAssertion response CBOR: %v",
			err,
		)
	}
	authData, err := protocol.ParseGetAssertionAuthData(response.AuthDataRaw)
	if err != nil {
		return getAssertionResponse{}, conformance.Failf(
			"invalid authenticatorGetAssertion authData: %v",
			err,
		)
	}
	response.AuthData = &authData

	return getAssertionResponse{Fields: fields, Response: response}, nil
}

func largeBlobKeyPrepareAuthorizationSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *largeBlobKeySession,
) error {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if err := largeBlobKeyPostResetProfile(fields, info); err != nil {
		return err
	}
	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		return err
	}

	session.info = info
	session.algorithms = algorithms

	restricted, _, err := rawGetInfoOption(fields, protocol.OptionNoMcGaPermissionsWithClientPin)
	if err != nil {
		return err
	}
	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	if clientPINPresent && !restricted {
		return largeBlobKeyPreparePINSession(ctx, test, config, session)
	}

	return largeBlobKeyPrepareUVSession(ctx, test, config, session, fields)
}

func largeBlobKeyPostResetProfile(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
) error {
	if !slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		return conformance.Fail("PIN/UV protocol 2 support disappeared after reset")
	}
	key := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
	largeBlob := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlob)
	if !key || largeBlob {
		return conformance.Fail("largeBlobKey support changed after reset")
	}
	largeBlobs, present, err := rawGetInfoOption(fields, protocol.OptionLargeBlobs)
	if err != nil {
		return err
	}
	if !present || !largeBlobs {
		return conformance.Fail("GetInfo options.largeBlobs is not true after reset")
	}
	pinUvAuthToken, present, err := rawGetInfoOption(fields, protocol.OptionPinUvAuthToken)
	if err != nil {
		return err
	}
	if !present || !pinUvAuthToken {
		return conformance.Fail("largeBlobKey tests require pinUvAuthToken=true after reset")
	}

	return nil
}

func largeBlobKeyPreparePINSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *largeBlobKeySession,
) error {
	if config.TemporaryPINProvider == nil {
		return errors.New("ctap23: temporary PIN provider is required for largeBlobKey tests")
	}

	request := temporaryPINRequest(session.info)
	pin, err := config.TemporaryPINProvider(ctx, request)
	if err != nil {
		clear(pin)

		return err
	}
	if err := validateTemporaryPIN(pin, request); err != nil {
		clear(pin)

		return err
	}

	keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
	if err != nil {
		clear(pin)

		return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	if err := test.Client().SetPIN(
		ctx,
		protocol.PinUvAuthProtocolTwo,
		keyAgreement,
		string(pin),
	); err != nil {
		clear(pin)

		return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		clear(pin)

		return err
	}
	if err := largeBlobKeyPostResetProfile(fields, info); err != nil {
		clear(pin)

		return err
	}
	clientPIN, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		clear(pin)

		return err
	}
	if !present || !clientPIN {
		clear(pin)

		return conformance.Fail("clientPin is not true after setting the temporary PIN")
	}

	session.info = info
	session.pin = pin
	session.useUV = false

	return nil
}

func largeBlobKeyPrepareUVSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *largeBlobKeySession,
	fields map[uint64]cbor.RawMessage,
) error {
	uv, present, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("ctap23: largeBlobKey tests require ClientPIN or built-in UV")
	}
	if !uv {
		if config.TemporaryPINProvider == nil {
			return errors.New(
				"ctap23: temporary PIN provider is required to configure built-in UV for largeBlobKey tests",
			)
		}
		if config.UVConfigurator == nil {
			return errors.New("ctap23: UV configurator is required for largeBlobKey tests")
		}

		request := temporaryPINRequest(session.info)
		pin, err := config.TemporaryPINProvider(ctx, request)
		defer clear(pin)
		if err != nil {
			return err
		}
		if err := validateTemporaryPIN(pin, request); err != nil {
			return err
		}
		if err := config.UVConfigurator(ctx, pin); err != nil {
			return err
		}

		refreshedFields, refreshed, err := readGetInfo(ctx, test.CBOR())
		if err != nil {
			return err
		}
		if err := largeBlobKeyPostResetProfile(refreshedFields, refreshed); err != nil {
			return err
		}
		uv, present, err = rawGetInfoOption(refreshedFields, protocol.OptionUserVerification)
		if err != nil {
			return err
		}
		if !present || !uv {
			return errors.New("ctap23: UV configurator completed but GetInfo uv is not true")
		}
		session.info = refreshed
	}

	session.useUV = true

	return nil
}

func largeBlobKeyAuthorization(
	ctx context.Context,
	test *conformance.TestContext,
	session *largeBlobKeySession,
	permission protocol.Permission,
	rpID string,
) (PinUvAuthToken, error) {
	var (
		token []byte
		err   error
	)
	if session.useUV {
		token, err = clientPIN2IssueUVPermissionToken(ctx, test.Client(), permission, rpID)
	} else {
		token, err = clientPIN2IssuePermissionToken(ctx, test.Client(), session.pin, permission, rpID)
	}
	if err != nil {
		clear(token)
		operation := "authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions"
		if session.useUV {
			operation = "authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions"
		}

		return PinUvAuthToken{}, unexpectedCTAPStatus(operation, err)
	}
	if err := clientPIN2ValidatePermissionToken(token); err != nil {
		clear(token)

		return PinUvAuthToken{}, err
	}

	return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, nil
}

func largeBlobKeyRequireMakeCredentialKey(
	result largeBlobKeyMakeCredentialResult,
) ([]byte, error) {
	return largeBlobKeyRequireResponseKey(
		"authenticatorMakeCredential",
		result.fields,
		5,
		result.response.LargeBlobKey,
	)
}

func largeBlobKeyRequireResponseKey(
	operation string,
	fields map[uint64]cbor.RawMessage,
	field uint64,
	typed []byte,
) ([]byte, error) {
	raw, present := fields[field]
	if !present {
		return nil, conformance.Failf("%s response is missing largeBlobKey", operation)
	}
	if len(raw) == 0 || raw[0]>>5 != 2 {
		return nil, conformance.Failf("%s response largeBlobKey is not a byte string", operation)
	}

	var decoded []byte
	if err := getInfoDecMode.Unmarshal(raw, &decoded); err != nil {
		return nil, conformance.Failf("invalid %s response largeBlobKey: %v", operation, err)
	}
	if len(decoded) != 32 {
		return nil, conformance.Failf("%s response largeBlobKey is %d bytes, want 32", operation, len(decoded))
	}
	if !bytes.Equal(decoded, typed) {
		return nil, conformance.Failf("%s typed largeBlobKey differs from wire field", operation)
	}

	return decoded, nil
}

func largeBlobKeyResetStep(
	test *conformance.TestContext,
	config Config,
	resetRequirement conformance.RequirementRef,
	powerCycleRequirement conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "large-blob-key.reset",
		Name: "Reset and rebind the authenticator",
		References: []conformance.RequirementRef{
			resetRequirement,
			powerCycleRequirement,
		},
		Run: func(ctx context.Context) error {
			return largeBlobKeyResetAndRebind(ctx, test, config)
		},
	}
}

func largeBlobKeyCleanupStep(
	test *conformance.TestContext,
	config Config,
	resetRequirement conformance.RequirementRef,
	powerCycleRequirement conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "large-blob-key.cleanup",
		Name: "Reset and rebind the authenticator after the case",
		References: []conformance.RequirementRef{
			resetRequirement,
			powerCycleRequirement,
		},
		Run: func(ctx context.Context) error {
			return largeBlobKeyResetAndRebind(ctx, test, config)
		},
	}
}

func largeBlobKeyResetAndRebind(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) error {
	if config.PowerCycler == nil {
		return errors.New("ctap23: authenticator power cycler is required for largeBlobKey tests")
	}
	if err := config.PowerCycler(ctx); err != nil {
		return err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return err
	}

	return config.PowerCycler(ctx)
}

func largeBlobKeyFeatureReference() conformance.RequirementRef {
	return largeBlobKeyReference("large-blob-key-feature-detection", conformance.RequirementConstraint)
}

func largeBlobKeyCreateReference() conformance.RequirementRef {
	return largeBlobKeyReference("make-credential-large-blob-key", conformance.RequirementMust)
}

func largeBlobKeyGetReference() conformance.RequirementRef {
	return largeBlobKeyReference("get-assertion-large-blob-key", conformance.RequirementMust)
}

func largeBlobKeyInputReference() conformance.RequirementRef {
	return largeBlobKeyReference("large-blob-key-input-validation", conformance.RequirementMust)
}

func largeBlobKeyReference(
	clause string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:12.3:" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       "12.3",
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-largeBlobKey-extension",
		Level: level,
	}
}
