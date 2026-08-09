package ctap23

import (
	"bytes"
	"context"
	"crypto/rand"
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
	largeBlobSourcePath = "tests/CTAP2/Protocol/Extensions/largeBlob.js"

	TestIDLargeBlobP1 conformance.TestID = "fido.ctap2.3.large-blob.p-1"
	TestIDLargeBlobP2 conformance.TestID = "fido.ctap2.3.large-blob.p-2"
	TestIDLargeBlobP3 conformance.TestID = "fido.ctap2.3.large-blob.p-3"
	TestIDLargeBlobP4 conformance.TestID = "fido.ctap2.3.large-blob.p-4"
	TestIDLargeBlobP5 conformance.TestID = "fido.ctap2.3.large-blob.p-5"
	TestIDLargeBlobP6 conformance.TestID = "fido.ctap2.3.large-blob.p-6"
	TestIDLargeBlobP7 conformance.TestID = "fido.ctap2.3.large-blob.p-7"
	TestIDLargeBlobF1 conformance.TestID = "fido.ctap2.3.large-blob.f-1"
	TestIDLargeBlobF2 conformance.TestID = "fido.ctap2.3.large-blob.f-2"
	TestIDLargeBlobF3 conformance.TestID = "fido.ctap2.3.large-blob.f-3"
	TestIDLargeBlobF4 conformance.TestID = "fido.ctap2.3.large-blob.f-4"
	TestIDLargeBlobF5 conformance.TestID = "fido.ctap2.3.large-blob.f-5"
)

type largeBlobPolicy int

const (
	largeBlobPolicyAny largeBlobPolicy = iota
	largeBlobPolicyDisabledByDefault
	largeBlobPolicyEnabledByDefault
)

type largeBlobSession struct {
	authorization largeBlobKeySession
}

func (session *largeBlobSession) clear() {
	session.authorization.clear()
}

type largeBlobMakeCredentialResult struct {
	fields       map[uint64]cbor.RawMessage
	response     protocol.AuthenticatorMakeCredentialResponse
	credentialID []byte
}

func (result *largeBlobMakeCredentialResult) clear() {
	clear(result.credentialID)
	result.credentialID = nil
	largeBlobClearMakeCredentialResponse(&result.response)
	clearCTAP2RawFields(result.fields)
	result.fields = nil
}

type largeBlobGetAssertionResult struct {
	fields   map[uint64]cbor.RawMessage
	response protocol.AuthenticatorGetAssertionResponse
}

func (result *largeBlobGetAssertionResult) clear() {
	largeBlobClearGetAssertionResponse(&result.response)
	clearCTAP2RawFields(result.fields)
	result.fields = nil
}

func largeBlobTests(config Config) []conformance.Test {
	featureReference := largeBlobFeatureReference()
	createReference := largeBlobCreateReference()
	getReference := largeBlobGetReference()
	inputReference := largeBlobInputReference()
	resetRequirement := resetReference()
	powerCycleRequirement := clientPINPowerCycleReference()
	authorizationReferences := []conformance.RequirementRef{
		clientPIN2PermissionsOperationReference(),
		clientPIN2PermissionsTokenLengthReference(),
	}
	lifecycleReferences := []conformance.RequirementRef{resetRequirement, powerCycleRequirement}

	return []conformance.Test{
		largeBlobTest(
			config,
			TestIDLargeBlobP1,
			"P-1",
			"MakeCredential preferred large-blob support",
			"Requests preferred direct large-blob support and requires an unsigned supported=true output",
			largeBlobPolicyAny,
			largeBlobReferences(featureReference, createReference, authorizationReferences, lifecycleReferences),
			func(ctx context.Context, test *conformance.TestContext, session *largeBlobSession) error {
				created, err := largeBlobMakeCredential(
					ctx,
					test,
					session,
					largeBlobMakeCredentialRequest("P-1", session.authorization.algorithms, extension.LargeBlobSupportPreferred),
				)
				if err != nil {
					return err
				}
				defer created.clear()

				return largeBlobRequireCreateOutput(created)
			},
		),
		largeBlobTest(
			config,
			TestIDLargeBlobP2,
			"P-2",
			"MakeCredential required large-blob support",
			"Requests required direct large-blob support and requires an unsigned supported=true output",
			largeBlobPolicyAny,
			largeBlobReferences(featureReference, createReference, authorizationReferences, lifecycleReferences),
			func(ctx context.Context, test *conformance.TestContext, session *largeBlobSession) error {
				created, err := largeBlobMakeCredential(
					ctx,
					test,
					session,
					largeBlobMakeCredentialRequest("P-2", session.authorization.algorithms, extension.LargeBlobSupportRequired),
				)
				if err != nil {
					return err
				}
				defer created.clear()

				return largeBlobRequireCreateOutput(created)
			},
		),
		largeBlobTest(
			config,
			TestIDLargeBlobP3,
			"P-3",
			"Write a direct large blob",
			"Creates an isolated capable credential and requires GetAssertion to report written=true",
			largeBlobPolicyAny,
			largeBlobReferences(featureReference, createReference, []conformance.RequirementRef{getReference}, authorizationReferences, lifecycleReferences),
			func(ctx context.Context, test *conformance.TestContext, session *largeBlobSession) error {
				created, err := largeBlobCreateCapableCredential(ctx, test, session, "P-3")
				if err != nil {
					return err
				}
				defer created.clear()

				blob, err := largeBlobRandomPayload()
				if err != nil {
					return err
				}
				defer clear(blob)
				written, err := largeBlobGetAssertion(
					ctx,
					test,
					session,
					largeBlobWriteRequest("P-3", created.credentialID, blob, true),
				)
				if err != nil {
					return err
				}
				defer written.clear()

				return largeBlobRequireWriteOutput(written, true)
			},
		),
		largeBlobTest(
			config,
			TestIDLargeBlobP4,
			"P-4",
			"Read a direct large blob",
			"Atomically provisions, writes, and reads one isolated credential and requires exact blob bytes and original size",
			largeBlobPolicyAny,
			largeBlobReferences(featureReference, createReference, []conformance.RequirementRef{getReference}, authorizationReferences, lifecycleReferences),
			func(ctx context.Context, test *conformance.TestContext, session *largeBlobSession) error {
				created, err := largeBlobCreateCapableCredential(ctx, test, session, "P-4")
				if err != nil {
					return err
				}
				defer created.clear()

				blob, err := largeBlobRandomPayload()
				if err != nil {
					return err
				}
				defer clear(blob)
				written, err := largeBlobGetAssertion(
					ctx,
					test,
					session,
					largeBlobWriteRequest("P-4", created.credentialID, blob, true),
				)
				if err != nil {
					return err
				}
				defer written.clear()
				if err := largeBlobRequireWriteOutput(written, true); err != nil {
					return err
				}

				read, err := largeBlobGetAssertion(
					ctx,
					test,
					session,
					largeBlobReadRequest("P-4", created.credentialID),
				)
				if err != nil {
					return err
				}
				defer read.clear()

				return largeBlobRequireReadOutput(read, blob, uint(len(blob)))
			},
		),
		largeBlobTest(
			config,
			TestIDLargeBlobP5,
			"P-5",
			"Write without an allowList",
			"Omits allowList and requires GetAssertion to report written=false",
			largeBlobPolicyAny,
			largeBlobReferences(featureReference, createReference, []conformance.RequirementRef{getReference}, authorizationReferences, lifecycleReferences),
			func(ctx context.Context, test *conformance.TestContext, session *largeBlobSession) error {
				created, err := largeBlobCreateCapableCredential(ctx, test, session, "P-5")
				if err != nil {
					return err
				}
				defer created.clear()

				blob, err := largeBlobRandomPayload()
				if err != nil {
					return err
				}
				defer clear(blob)
				written, err := largeBlobGetAssertion(
					ctx,
					test,
					session,
					largeBlobWriteRequest("P-5", nil, blob, false),
				)
				if err != nil {
					return err
				}
				defer written.clear()

				return largeBlobRequireWriteOutput(written, false)
			},
		),
		largeBlobDefaultPolicyTest(
			config,
			TestIDLargeBlobP6,
			"P-6",
			"Default-disabled credential rejects a write",
			largeBlobPolicyDisabledByDefault,
			false,
			largeBlobReferences(featureReference, getReference, authorizationReferences, lifecycleReferences),
		),
		largeBlobDefaultPolicyTest(
			config,
			TestIDLargeBlobP7,
			"P-7",
			"Default-enabled credential accepts a write",
			largeBlobPolicyEnabledByDefault,
			true,
			largeBlobReferences(featureReference, getReference, authorizationReferences, lifecycleReferences),
		),
		largeBlobMakeCredentialNegativeTest(
			config,
			TestIDLargeBlobF1,
			"F-1",
			"MakeCredential rejects an invalid direct large-blob map",
			map[string]any{"wrong": "123"},
			largeBlobReferences(featureReference, inputReference, authorizationReferences, lifecycleReferences),
		),
		largeBlobGetAssertionNegativeTest(
			config,
			TestIDLargeBlobF2,
			"F-2",
			"GetAssertion rejects an invalid direct large-blob map",
			map[string]any{"wrong": "123"},
			largeBlobReferences(featureReference, inputReference, authorizationReferences, lifecycleReferences),
		),
		largeBlobGetAssertionNegativeTest(
			config,
			TestIDLargeBlobF3,
			"F-3",
			"GetAssertion rejects simultaneous direct read and write",
			map[string]any{
				"read":         true,
				"write":        []byte("invalid simultaneous read and write"),
				"originalSize": uint(35),
			},
			largeBlobReferences(featureReference, inputReference, authorizationReferences, lifecycleReferences),
		),
		largeBlobGetAssertionNegativeTest(
			config,
			TestIDLargeBlobF4,
			"F-4",
			"GetAssertion rejects a non-boolean direct read",
			map[string]any{"read": "true"},
			largeBlobReferences(featureReference, inputReference, authorizationReferences, lifecycleReferences),
		),
		largeBlobGetAssertionNegativeTest(
			config,
			TestIDLargeBlobF5,
			"F-5",
			"GetAssertion rejects invalid direct write member types",
			map[string]any{"write": "123", "originalSize": "123"},
			largeBlobReferences(featureReference, inputReference, authorizationReferences, lifecycleReferences),
		),
	}
}

func largeBlobTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	description string,
	policy largeBlobPolicy,
	references []conformance.RequirementRef,
	run func(context.Context, *conformance.TestContext, *largeBlobSession) error,
) conformance.Test {
	featureReference := largeBlobFeatureReference()
	resetRequirement := resetReference()
	powerCycleRequirement := clientPINPowerCycleReference()

	return conformance.Test{
		ID:          id,
		Name:        name,
		Description: description,
		Source: conformance.SourceLocation{
			Path: largeBlobSourcePath,
			Case: marker,
		},
		References:  references,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			var session largeBlobSession
			if !test.Step(conformance.Step{
				ID:         "large-blob.applicability",
				Name:       "Check direct largeBlob applicability",
				References: []conformance.RequirementRef{featureReference},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}
					if err := largeBlobApplicability(fields, info, config, policy); err != nil {
						return err
					}
					algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
					if err != nil {
						return err
					}

					session.authorization = largeBlobKeySession{info: info, algorithms: algorithms}

					return nil
				},
			}) {
				return
			}

			test.Cleanup(largeBlobCleanupStep(test, config, resetRequirement, powerCycleRequirement))
			if !test.Step(largeBlobResetStep(test, config, resetRequirement, powerCycleRequirement)) {
				return
			}
			if !test.Step(conformance.Step{
				ID:   "large-blob.authorization",
				Name: "Prepare an exact PIN/UV protocol 2 authorization session",
				References: []conformance.RequirementRef{
					clientPIN2PermissionsOperationReference(),
					clientPIN2PermissionsTokenLengthReference(),
				},
				Run: func(ctx context.Context) error {
					return largeBlobPrepareAuthorizationSession(ctx, test, config, &session)
				},
			}) {
				return
			}
			defer session.clear()

			test.Step(conformance.Step{
				ID:         conformance.StepID("large-blob." + marker + ".command"),
				Name:       name,
				References: references,
				Run: func(ctx context.Context) error {
					return run(ctx, test, &session)
				},
			})
		},
	}
}

func largeBlobDefaultPolicyTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	policy largeBlobPolicy,
	expectedWritten bool,
	references []conformance.RequirementRef,
) conformance.Test {
	return largeBlobTest(
		config,
		id,
		marker,
		name,
		"Creates a credential without the MakeCredential extension and verifies the externally declared default policy",
		policy,
		references,
		func(ctx context.Context, test *conformance.TestContext, session *largeBlobSession) error {
			created, err := largeBlobMakeCredential(
				ctx,
				test,
				session,
				largeBlobMakeCredentialRequest(marker, session.authorization.algorithms, ""),
			)
			if err != nil {
				return err
			}
			defer created.clear()

			blob, err := largeBlobRandomPayload()
			if err != nil {
				return err
			}
			defer clear(blob)
			written, err := largeBlobGetAssertion(
				ctx,
				test,
				session,
				largeBlobWriteRequest(marker, created.credentialID, blob, true),
			)
			if err != nil {
				return err
			}
			defer written.clear()

			return largeBlobRequireWriteOutput(written, expectedWritten)
		},
	)
}

func largeBlobMakeCredentialNegativeTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	input any,
	references []conformance.RequirementRef,
) conformance.Test {
	return largeBlobTest(
		config,
		id,
		marker,
		name,
		"Sends an explicitly encoded malformed direct largeBlob MakeCredential extension input",
		largeBlobPolicyAny,
		references,
		func(ctx context.Context, test *conformance.TestContext, session *largeBlobSession) error {
			request := largeBlobMakeCredentialRequest(marker, session.authorization.algorithms, "")
			if err := largeBlobAuthorizeMakeCredential(ctx, test, session, &request); err != nil {
				return err
			}
			defer clear(request.PinUvAuthParam)

			fields := ctap2WireFields("largeBlob MakeCredential negative", request)
			defer clearCTAP2WireValue(fields)
			clearCTAP2WireValue(fields[6])
			fields[6] = map[string]any{string(extension.ExtensionIdentifierLargeBlob): input}
			response, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)
			defer clear(response.Data)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_INVALID_CBOR)
		},
	)
}

func largeBlobGetAssertionNegativeTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	input any,
	references []conformance.RequirementRef,
) conformance.Test {
	return largeBlobTest(
		config,
		id,
		marker,
		name,
		"Creates an isolated capable credential and sends an explicitly encoded malformed direct largeBlob GetAssertion extension input",
		largeBlobPolicyAny,
		references,
		func(ctx context.Context, test *conformance.TestContext, session *largeBlobSession) error {
			created, err := largeBlobCreateCapableCredential(ctx, test, session, marker)
			if err != nil {
				return err
			}
			defer created.clear()

			request := largeBlobGetAssertionRequest(marker, created.credentialID, true)
			if err := largeBlobAuthorizeGetAssertion(ctx, test, session, &request); err != nil {
				return err
			}
			defer clear(request.PinUvAuthParam)

			fields := ctap2WireFields("largeBlob GetAssertion negative", request)
			defer clearCTAP2WireValue(fields)
			clearCTAP2WireValue(fields[4])
			fields[4] = map[string]any{string(extension.ExtensionIdentifierLargeBlob): input}
			response, err := exchangeRawGetAssertion(ctx, test.CBOR(), fields)
			defer clear(response.Data)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_INVALID_CBOR)
		},
	)
}

func largeBlobApplicability(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
	policy largeBlobPolicy,
) error {
	direct := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlob)
	key := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
	if direct && key {
		return conformance.Fail("GetInfo extensions advertises mutually exclusive largeBlob and largeBlobKey")
	}
	if !direct {
		if config.Featureful && !key {
			return conformance.Fail("featureful profile advertises neither largeBlob nor largeBlobKey")
		}

		return conformance.Skip("authenticator does not advertise the direct largeBlob extension")
	}
	switch policy {
	case largeBlobPolicyAny:
	case largeBlobPolicyDisabledByDefault, largeBlobPolicyEnabledByDefault:
		if config.LargeBlobEnabledByDefault == nil {
			return conformance.Skip("largeBlobEnabledByDefault policy is not declared")
		}
		want := policy == largeBlobPolicyEnabledByDefault
		if *config.LargeBlobEnabledByDefault != want {
			return conformance.Skip("declared largeBlobEnabledByDefault policy does not match this case")
		}

	default:
		panic("unknown largeBlob policy")
	}

	return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolTwo)
}

func largeBlobMakeCredentialRequest(
	marker string,
	algorithms []credential.PublicKeyCredentialParameters,
	support extension.LargeBlobSupport,
) protocol.AuthenticatorMakeCredentialRequest {
	rpID := largeBlobRPID(marker)
	clientDataHash := sha256.Sum256([]byte("largeBlob client data " + marker))
	userID := sha256.Sum256([]byte("largeBlob user " + marker))
	request := protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash: clientDataHash[:],
		RP: credential.PublicKeyCredentialRpEntity{
			ID:   rpID,
			Name: "CTAP 2.3 direct largeBlob conformance",
		},
		User: credential.PublicKeyCredentialUserEntity{
			ID:          userID[:16],
			Name:        "large-blob-" + marker,
			DisplayName: "Large blob " + marker,
		},
		PubKeyCredParams: algorithms,
		Options:          map[protocol.Option]bool{protocol.OptionResidentKeys: true},
	}
	if support != "" {
		request.Extensions = protocol.CreateExtensionInputs{
			CreateLargeBlobInput: protocol.CreateLargeBlobInput{
				LargeBlob: protocol.CreateLargeBlobParams{Support: support},
			},
		}
	}

	return request
}

func largeBlobWriteRequest(
	marker string,
	credentialID []byte,
	blob []byte,
	includeAllowList bool,
) protocol.AuthenticatorGetAssertionRequest {
	originalSize := uint(len(blob))
	request := largeBlobGetAssertionRequest(marker, credentialID, includeAllowList)
	request.Extensions = protocol.GetExtensionInputs{
		GetLargeBlobInput: protocol.GetLargeBlobInput{
			LargeBlob: protocol.GetLargeBlobParams{
				Write:        blob,
				OriginalSize: &originalSize,
			},
		},
	}

	return request
}

func largeBlobReadRequest(marker string, credentialID []byte) protocol.AuthenticatorGetAssertionRequest {
	request := largeBlobGetAssertionRequest(marker, credentialID, true)
	request.Extensions = protocol.GetExtensionInputs{
		GetLargeBlobInput: protocol.GetLargeBlobInput{
			LargeBlob: protocol.GetLargeBlobParams{Read: true},
		},
	}

	return request
}

func largeBlobGetAssertionRequest(
	marker string,
	credentialID []byte,
	includeAllowList bool,
) protocol.AuthenticatorGetAssertionRequest {
	clientDataHash := sha256.Sum256([]byte("largeBlob assertion client data " + marker))
	request := protocol.AuthenticatorGetAssertionRequest{
		RPID:           largeBlobRPID(marker),
		ClientDataHash: clientDataHash[:],
	}
	if includeAllowList {
		request.AllowList = []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   slices.Clone(credentialID),
		}}
	}

	return request
}

func largeBlobCreateCapableCredential(
	ctx context.Context,
	test *conformance.TestContext,
	session *largeBlobSession,
	marker string,
) (largeBlobMakeCredentialResult, error) {
	created, err := largeBlobMakeCredential(
		ctx,
		test,
		session,
		largeBlobMakeCredentialRequest(marker, session.authorization.algorithms, extension.LargeBlobSupportRequired),
	)
	if err != nil {
		return largeBlobMakeCredentialResult{}, err
	}
	if err := largeBlobRequireCreateOutput(created); err != nil {
		created.clear()

		return largeBlobMakeCredentialResult{}, err
	}

	return created, nil
}

func largeBlobMakeCredential(
	ctx context.Context,
	test *conformance.TestContext,
	session *largeBlobSession,
	request protocol.AuthenticatorMakeCredentialRequest,
) (largeBlobMakeCredentialResult, error) {
	if err := largeBlobAuthorizeMakeCredential(ctx, test, session, &request); err != nil {
		return largeBlobMakeCredentialResult{}, err
	}
	defer clear(request.PinUvAuthParam)

	wireResponse, err := exchangeMakeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return largeBlobMakeCredentialResult{}, unexpectedCTAPStatus("authenticatorMakeCredential", err)
	}
	defer clear(wireResponse.Data)

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(wireResponse.Data, &fields); err != nil {
		clearCTAP2RawFields(fields)

		return largeBlobMakeCredentialResult{}, conformance.Failf("invalid authenticatorMakeCredential response CBOR: %v", err)
	}
	response, err := largeBlobDecodeMakeCredentialResponse(wireResponse.Data)
	if err != nil {
		clearCTAP2RawFields(fields)

		return largeBlobMakeCredentialResult{}, err
	}
	if response.AuthData.AttestedCredentialData == nil ||
		len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
		clearCTAP2RawFields(fields)
		largeBlobClearMakeCredentialResponse(&response)

		return largeBlobMakeCredentialResult{}, conformance.Fail("authenticatorMakeCredential response is missing an attested credential ID")
	}

	return largeBlobMakeCredentialResult{
		fields:       fields,
		response:     response,
		credentialID: slices.Clone(response.AuthData.AttestedCredentialData.CredentialID),
	}, nil
}

func largeBlobGetAssertion(
	ctx context.Context,
	test *conformance.TestContext,
	session *largeBlobSession,
	request protocol.AuthenticatorGetAssertionRequest,
) (largeBlobGetAssertionResult, error) {
	if err := largeBlobAuthorizeGetAssertion(ctx, test, session, &request); err != nil {
		return largeBlobGetAssertionResult{}, err
	}
	defer clear(request.PinUvAuthParam)

	wireResponse, err := exchangeGetAssertion(ctx, test.CBOR(), request)
	if err != nil {
		return largeBlobGetAssertionResult{}, unexpectedCTAPStatus("authenticatorGetAssertion", err)
	}
	defer clear(wireResponse.Data)

	if err := validateGetAssertionResponseRequiredFields(wireResponse.Data); err != nil {
		return largeBlobGetAssertionResult{}, err
	}
	if err := validateCanonicalCTAP2Response("authenticatorGetAssertion", wireResponse.Data); err != nil {
		return largeBlobGetAssertionResult{}, err
	}
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(wireResponse.Data, &fields); err != nil {
		clearCTAP2RawFields(fields)

		return largeBlobGetAssertionResult{}, conformance.Failf("invalid authenticatorGetAssertion response CBOR: %v", err)
	}
	var response protocol.AuthenticatorGetAssertionResponse
	if err := getInfoDecMode.Unmarshal(wireResponse.Data, &response); err != nil {
		clearCTAP2RawFields(fields)
		largeBlobClearGetAssertionResponse(&response)

		return largeBlobGetAssertionResult{}, conformance.Failf("invalid authenticatorGetAssertion response CBOR: %v", err)
	}
	authData, err := protocol.ParseGetAssertionAuthData(response.AuthDataRaw)
	if err != nil {
		clearCTAP2RawFields(fields)
		largeBlobClearGetAssertionResponse(&response)

		return largeBlobGetAssertionResult{}, conformance.Failf("invalid authenticatorGetAssertion authData: %v", err)
	}
	response.AuthData = &authData

	return largeBlobGetAssertionResult{fields: fields, response: response}, nil
}

func largeBlobDecodeMakeCredentialResponse(
	data []byte,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	if err := validateMakeCredentialResponseRequiredFields(data); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}
	if err := validateCanonicalMakeCredentialResponse(data); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	var response protocol.AuthenticatorMakeCredentialResponse
	if err := getInfoDecMode.Unmarshal(data, &response); err != nil {
		largeBlobClearMakeCredentialResponse(&response)

		return protocol.AuthenticatorMakeCredentialResponse{}, conformance.Failf(
			"invalid authenticatorMakeCredential response CBOR: %v",
			err,
		)
	}
	authData, err := protocol.ParseMakeCredentialAuthData(response.AuthDataRaw)
	if err != nil {
		largeBlobClearMakeCredentialResponse(&response)

		return protocol.AuthenticatorMakeCredentialResponse{}, conformance.Failf(
			"invalid authenticatorMakeCredential authData: %v",
			err,
		)
	}
	response.AuthData = &authData

	return response, nil
}

func largeBlobAuthorizeMakeCredential(
	ctx context.Context,
	test *conformance.TestContext,
	session *largeBlobSession,
	request *protocol.AuthenticatorMakeCredentialRequest,
) error {
	authorization, err := largeBlobKeyAuthorization(
		ctx,
		test,
		&session.authorization,
		protocol.PermissionMakeCredential,
		request.RP.ID,
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
	request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo

	return nil
}

func largeBlobAuthorizeGetAssertion(
	ctx context.Context,
	test *conformance.TestContext,
	session *largeBlobSession,
	request *protocol.AuthenticatorGetAssertionRequest,
) error {
	authorization, err := largeBlobKeyAuthorization(
		ctx,
		test,
		&session.authorization,
		protocol.PermissionGetAssertion,
		request.RPID,
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
	request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo

	return nil
}

func largeBlobRequireCreateOutput(result largeBlobMakeCredentialResult) error {
	raw, present := result.fields[6]
	if !present {
		return conformance.Fail("authenticatorMakeCredential response is missing unsigned extension outputs")
	}
	output, err := decodeLargeBlobRawOutput("authenticatorMakeCredential", raw)
	if err != nil {
		return err
	}
	defer output.clear()
	if err := requireExactLargeBlobMembers(
		"authenticatorMakeCredential",
		output.nested,
		"supported",
	); err != nil {
		return err
	}

	supportedRaw := output.nested["supported"]
	var supported bool
	if err := getInfoDecMode.Unmarshal(supportedRaw, &supported); err != nil {
		return conformance.Failf("invalid authenticatorMakeCredential largeBlob supported output: %v", err)
	}
	if !supported {
		return conformance.Fail("authenticatorMakeCredential largeBlob output supported is false")
	}
	if _, present := result.response.UnsignedExtensionOutputs[extension.ExtensionIdentifierLargeBlob]; !present {
		return conformance.Fail("typed authenticatorMakeCredential largeBlob output is absent")
	}
	var typed protocol.CreateLargeBlobOutput
	if err := getInfoDecMode.Unmarshal(output.direct(), &typed); err != nil {
		return conformance.Failf("invalid typed authenticatorMakeCredential largeBlob output: %v", err)
	}
	if !typed.Supported {
		return conformance.Fail("typed authenticatorMakeCredential largeBlob output is absent or not supported")
	}

	return nil
}

func largeBlobRequireWriteOutput(result largeBlobGetAssertionResult, expected bool) error {
	raw, present := result.fields[8]
	if !present {
		return conformance.Fail("authenticatorGetAssertion response is missing unsigned extension outputs")
	}
	output, err := decodeLargeBlobRawOutput("authenticatorGetAssertion", raw)
	if err != nil {
		return err
	}
	defer output.clear()
	if err := requireExactLargeBlobMembers(
		"authenticatorGetAssertion write",
		output.nested,
		"written",
	); err != nil {
		return err
	}

	writtenRaw := output.nested["written"]
	var written bool
	if err := getInfoDecMode.Unmarshal(writtenRaw, &written); err != nil {
		return conformance.Failf("invalid authenticatorGetAssertion largeBlob written output: %v", err)
	}
	if written != expected {
		return conformance.Failf("authenticatorGetAssertion largeBlob written is %t, want %t", written, expected)
	}
	if _, present := result.response.UnsignedExtensionOutputs[extension.ExtensionIdentifierLargeBlob]; !present {
		return conformance.Fail("typed authenticatorGetAssertion largeBlob output is absent")
	}
	var typed protocol.GetLargeBlobOutput
	typedErr := getInfoDecMode.Unmarshal(output.direct(), &typed)
	defer clear(typed.Blob)
	if typedErr != nil {
		return conformance.Failf("invalid typed authenticatorGetAssertion largeBlob output: %v", typedErr)
	}
	if typed.Written == nil || *typed.Written != expected {
		return conformance.Fail("typed authenticatorGetAssertion largeBlob write output is absent or differs from the wire")
	}
	if typed.Blob != nil || typed.OriginalSize != nil {
		return conformance.Fail("typed authenticatorGetAssertion largeBlob write output contains read members")
	}

	return nil
}

func largeBlobRequireReadOutput(
	result largeBlobGetAssertionResult,
	expectedBlob []byte,
	expectedOriginalSize uint,
) error {
	raw, present := result.fields[8]
	if !present {
		return conformance.Fail("authenticatorGetAssertion response is missing unsigned extension outputs")
	}
	output, err := decodeLargeBlobRawOutput("authenticatorGetAssertion", raw)
	if err != nil {
		return err
	}
	defer output.clear()
	if err := requireExactLargeBlobMembers(
		"authenticatorGetAssertion read",
		output.nested,
		"blob",
		"originalSize",
	); err != nil {
		return err
	}

	blobRaw := output.nested["blob"]
	if len(blobRaw) == 0 || blobRaw[0]>>5 != 2 {
		return conformance.Fail("authenticatorGetAssertion largeBlob blob output is not a byte string")
	}
	var blob []byte
	blobErr := getInfoDecMode.Unmarshal(blobRaw, &blob)
	defer clear(blob)
	if blobErr != nil {
		return conformance.Failf("invalid authenticatorGetAssertion largeBlob blob output: %v", blobErr)
	}
	if !bytes.Equal(blob, expectedBlob) {
		return conformance.Fail("authenticatorGetAssertion returned different largeBlob bytes")
	}
	originalSizeRaw := output.nested["originalSize"]
	var originalSize uint
	if err := getInfoDecMode.Unmarshal(originalSizeRaw, &originalSize); err != nil {
		return conformance.Failf("invalid authenticatorGetAssertion largeBlob originalSize output: %v", err)
	}
	if originalSize != expectedOriginalSize {
		return conformance.Failf("authenticatorGetAssertion largeBlob originalSize is %d, want %d", originalSize, expectedOriginalSize)
	}
	if _, present := result.response.UnsignedExtensionOutputs[extension.ExtensionIdentifierLargeBlob]; !present {
		return conformance.Fail("typed authenticatorGetAssertion largeBlob output is absent")
	}
	var typed protocol.GetLargeBlobOutput
	typedErr := getInfoDecMode.Unmarshal(output.direct(), &typed)
	defer clear(typed.Blob)
	if typedErr != nil {
		return conformance.Failf("invalid typed authenticatorGetAssertion largeBlob output: %v", typedErr)
	}
	if typed.Written != nil || typed.OriginalSize == nil {
		return conformance.Fail("typed authenticatorGetAssertion largeBlob read output has the wrong member combination")
	}
	if !bytes.Equal(typed.Blob, expectedBlob) || *typed.OriginalSize != expectedOriginalSize {
		return conformance.Fail("typed authenticatorGetAssertion largeBlob read output differs from the wire")
	}

	return nil
}

type decodedLargeBlobRawOutput struct {
	outputs map[string]cbor.RawMessage
	nested  map[string]cbor.RawMessage
}

func (output *decodedLargeBlobRawOutput) clear() {
	clearLargeBlobRawMessages(output.nested)
	output.nested = nil
	clearLargeBlobRawMessages(output.outputs)
	output.outputs = nil
}

// direct keeps typed DTO validation on the owned wire buffer without
// re-encoding an opaque large-blob value into another transient copy.
func (output *decodedLargeBlobRawOutput) direct() cbor.RawMessage {
	return output.outputs[string(extension.ExtensionIdentifierLargeBlob)]
}

func decodeLargeBlobRawOutput(
	operation string,
	raw cbor.RawMessage,
) (decodedLargeBlobRawOutput, error) {
	if len(raw) == 0 || raw[0]>>5 != 5 {
		return decodedLargeBlobRawOutput{}, conformance.Failf("%s unsigned extension outputs is not a map", operation)
	}
	var output decodedLargeBlobRawOutput
	if err := getInfoDecMode.Unmarshal(raw, &output.outputs); err != nil {
		output.clear()

		return decodedLargeBlobRawOutput{}, conformance.Failf("invalid %s unsigned extension outputs: %v", operation, err)
	}
	direct, present := output.outputs[string(extension.ExtensionIdentifierLargeBlob)]
	if !present {
		output.clear()

		return decodedLargeBlobRawOutput{}, conformance.Failf("%s unsigned extension outputs is missing largeBlob", operation)
	}
	for identifier := range output.outputs {
		if identifier != string(extension.ExtensionIdentifierLargeBlob) {
			output.clear()

			return decodedLargeBlobRawOutput{}, conformance.Failf(
				"%s unsigned extension outputs contains unexpected %q",
				operation,
				identifier,
			)
		}
	}
	if len(direct) == 0 || direct[0]>>5 != 5 {
		output.clear()

		return decodedLargeBlobRawOutput{}, conformance.Failf("%s largeBlob output is not a map", operation)
	}
	if err := getInfoDecMode.Unmarshal(direct, &output.nested); err != nil {
		output.clear()

		return decodedLargeBlobRawOutput{}, conformance.Failf("invalid %s largeBlob output: %v", operation, err)
	}

	return output, nil
}

func requireExactLargeBlobMembers(
	operation string,
	output map[string]cbor.RawMessage,
	required ...string,
) error {
	for member := range output {
		if !slices.Contains(required, member) {
			return conformance.Failf("%s largeBlob output contains unexpected %q", operation, member)
		}
	}
	for _, member := range required {
		if _, present := output[member]; !present {
			return conformance.Failf("%s largeBlob output is missing %s", operation, member)
		}
	}

	return nil
}

func clearLargeBlobRawMessages(values map[string]cbor.RawMessage) {
	for key, value := range values {
		clear(value)
		delete(values, key)
	}
}

func largeBlobPrepareAuthorizationSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *largeBlobSession,
) error {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if err := largeBlobPostResetProfile(fields, info); err != nil {
		return err
	}
	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		return err
	}

	session.authorization.info = info
	session.authorization.algorithms = algorithms

	restricted, _, err := rawGetInfoOption(fields, protocol.OptionNoMcGaPermissionsWithClientPin)
	if err != nil {
		return err
	}
	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	if clientPINPresent && !restricted {
		return largeBlobPreparePINSession(ctx, test, config, session)
	}

	return largeBlobPrepareUVSession(ctx, test, config, session, fields)
}

func largeBlobPostResetProfile(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
) error {
	if !slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		return conformance.Fail("PIN/UV protocol 2 support disappeared after reset")
	}
	direct := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlob)
	key := slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey)
	if !direct || key {
		return conformance.Fail("direct largeBlob support changed after reset")
	}
	pinUvAuthToken, present, err := rawGetInfoOption(fields, protocol.OptionPinUvAuthToken)
	if err != nil {
		return err
	}
	if !present || !pinUvAuthToken {
		return conformance.Fail("direct largeBlob tests require pinUvAuthToken=true after reset")
	}

	return nil
}

func largeBlobPreparePINSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *largeBlobSession,
) error {
	if config.TemporaryPINProvider == nil {
		return errors.New("ctap23: temporary PIN provider is required for direct largeBlob tests")
	}

	request := temporaryPINRequest(session.authorization.info)
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
	if err := test.Client().SetPIN(ctx, protocol.PinUvAuthProtocolTwo, keyAgreement, string(pin)); err != nil {
		clear(pin)

		return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		clear(pin)

		return err
	}
	if err := largeBlobPostResetProfile(fields, info); err != nil {
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

	session.authorization.info = info
	session.authorization.pin = pin
	session.authorization.useUV = false

	return nil
}

func largeBlobPrepareUVSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *largeBlobSession,
	fields map[uint64]cbor.RawMessage,
) error {
	uv, present, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("ctap23: direct largeBlob tests require ClientPIN or built-in UV")
	}
	if !uv {
		if config.TemporaryPINProvider == nil {
			return errors.New("ctap23: temporary PIN provider is required to configure built-in UV for direct largeBlob tests")
		}
		if config.UVConfigurator == nil {
			return errors.New("ctap23: UV configurator is required for direct largeBlob tests")
		}

		request := temporaryPINRequest(session.authorization.info)
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
		if err := largeBlobPostResetProfile(refreshedFields, refreshed); err != nil {
			return err
		}
		uv, present, err = rawGetInfoOption(refreshedFields, protocol.OptionUserVerification)
		if err != nil {
			return err
		}
		if !present || !uv {
			return errors.New("ctap23: UV configurator completed but GetInfo uv is not true")
		}
		session.authorization.info = refreshed
	}

	session.authorization.useUV = true

	return nil
}

func largeBlobResetStep(
	test *conformance.TestContext,
	config Config,
	resetRequirement conformance.RequirementRef,
	powerCycleRequirement conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "large-blob.reset",
		Name: "Reset and rebind the authenticator",
		References: []conformance.RequirementRef{
			resetRequirement,
			powerCycleRequirement,
		},
		Run: func(ctx context.Context) error {
			return largeBlobResetAndRebind(ctx, test, config)
		},
	}
}

func largeBlobCleanupStep(
	test *conformance.TestContext,
	config Config,
	resetRequirement conformance.RequirementRef,
	powerCycleRequirement conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "large-blob.cleanup",
		Name: "Reset and rebind the authenticator after the case",
		References: []conformance.RequirementRef{
			resetRequirement,
			powerCycleRequirement,
		},
		Run: func(ctx context.Context) error {
			return largeBlobResetAndRebind(ctx, test, config)
		},
	}
}

func largeBlobResetAndRebind(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) error {
	if config.PowerCycler == nil {
		return errors.New("ctap23: authenticator power cycler is required for direct largeBlob tests")
	}
	if err := config.PowerCycler(ctx); err != nil {
		return err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return err
	}

	return config.PowerCycler(ctx)
}

func largeBlobRPID(marker string) string {
	return "large-blob-" + marker + ".ctap23-conformance.example"
}

func largeBlobRandomPayload() ([]byte, error) {
	payload := make([]byte, 32)
	if _, err := rand.Read(payload); err != nil {
		clear(payload)

		return nil, err
	}

	return payload, nil
}

func largeBlobClearMakeCredentialResponse(
	response *protocol.AuthenticatorMakeCredentialResponse,
) {
	clear(response.AuthDataRaw)
	response.AuthDataRaw = nil
	clear(response.LargeBlobKey)
	response.LargeBlobKey = nil
	clearCTAP2WireValue(response.AttestationStatement)
	response.AttestationStatement = nil
	clearUnsignedExtensionOutputs(response.UnsignedExtensionOutputs)
	response.UnsignedExtensionOutputs = nil
	if response.AuthData != nil {
		clear(response.AuthData.RPIDHash)
		response.AuthData.RPIDHash = nil
		if response.AuthData.AttestedCredentialData != nil {
			clear(response.AuthData.AttestedCredentialData.CredentialID)
			response.AuthData.AttestedCredentialData.CredentialID = nil
		}
	}
	response.AuthData = nil
}

func largeBlobClearGetAssertionResponse(
	response *protocol.AuthenticatorGetAssertionResponse,
) {
	clear(response.Credential.ID)
	response.Credential.ID = nil
	clear(response.AuthDataRaw)
	response.AuthDataRaw = nil
	clear(response.Signature)
	response.Signature = nil
	clear(response.LargeBlobKey)
	response.LargeBlobKey = nil
	if response.User != nil {
		clear(response.User.ID)
		response.User.ID = nil
	}
	clearUnsignedExtensionOutputs(response.UnsignedExtensionOutputs)
	response.UnsignedExtensionOutputs = nil
	if response.AuthData != nil {
		clear(response.AuthData.RPIDHash)
		response.AuthData.RPIDHash = nil
	}
	response.AuthData = nil
}

func clearUnsignedExtensionOutputs(
	outputs map[extension.ExtensionIdentifier]any,
) {
	for identifier, output := range outputs {
		clearCTAP2WireValue(output)
		delete(outputs, identifier)
	}
}

func largeBlobReferences(
	first conformance.RequirementRef,
	second conformance.RequirementRef,
	groups ...[]conformance.RequirementRef,
) []conformance.RequirementRef {
	references := []conformance.RequirementRef{first, second}
	for _, group := range groups {
		references = append(references, group...)
	}

	return references
}

func largeBlobFeatureReference() conformance.RequirementRef {
	return largeBlobReference("large-blob-feature-detection", conformance.RequirementConstraint)
}

func largeBlobCreateReference() conformance.RequirementRef {
	return largeBlobReference("make-credential-direct-large-blob", conformance.RequirementMust)
}

func largeBlobGetReference() conformance.RequirementRef {
	return largeBlobReference("get-assertion-direct-large-blob", conformance.RequirementMust)
}

func largeBlobInputReference() conformance.RequirementRef {
	return largeBlobReference("direct-large-blob-input-validation", conformance.RequirementMust)
}

func largeBlobReference(clause string, level conformance.RequirementLevel) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID("ctap-2.3-ps-20260226:12.4:" + clause),
		Specification: conformance.SpecificationCTAP23,
		Section:       "12.4",
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-largeBlob-extension",
		Level: level,
	}
}
