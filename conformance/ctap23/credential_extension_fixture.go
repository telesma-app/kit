package ctap23

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

var credentialExtensionClientDataHash = [...]byte{
	0x82, 0x46, 0x49, 0xd1, 0xac, 0x5e, 0x22, 0x93,
	0x03, 0x57, 0xbd, 0x6f, 0x2e, 0xb5, 0x22, 0x36,
	0x8a, 0x7a, 0x10, 0xc9, 0xdc, 0xe4, 0x38, 0x6f,
	0x8b, 0x9c, 0x7d, 0x30, 0x52, 0xf0, 0x69, 0x21,
}

// credentialExtensionFixture owns the authorization and credential identifier
// for one independent MakeCredential-to-GetAssertion extension flow.
type credentialExtensionFixture struct {
	config       Config
	test         *conformance.TestContext
	make         makeCredentialFixture
	credentialID []byte
}

func prepareCredentialExtensionFixture(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	rpID string,
) (*credentialExtensionFixture, error) {
	makeCredential, err := prepareMakeCredentialFixture(ctx, test, config, rpID)
	if err != nil {
		return nil, err
	}

	return &credentialExtensionFixture{
		config: config,
		test:   test,
		make:   makeCredential,
	}, nil
}

func (f *credentialExtensionFixture) clear() {
	f.make.clear()
	clear(f.credentialID)
	f.credentialID = nil
}

func (f *credentialExtensionFixture) rememberCredential(
	response protocol.AuthenticatorMakeCredentialResponse,
) error {
	if response.AuthData == nil || response.AuthData.AttestedCredentialData == nil ||
		len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
		return conformance.Fail(
			"authenticatorMakeCredential response does not contain an attested credential ID",
		)
	}

	clear(f.credentialID)
	f.credentialID = slices.Clone(response.AuthData.AttestedCredentialData.CredentialID)

	return nil
}

// makeCredentialRaw takes ownership of fields and wipes the complete request
// tree after the command has consumed it.
func (f *credentialExtensionFixture) makeCredentialRaw(
	ctx context.Context,
	fields map[uint64]any,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	defer clearCTAP2WireValue(fields)

	wireResponse, err := exchangeRawMakeCredential(ctx, f.test.CBOR(), fields)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, unexpectedCTAPStatus(
			"authenticatorMakeCredential",
			err,
		)
	}
	defer clearCTAP2ResponseData(wireResponse)

	return decodeMakeCredentialResponse(wireResponse.Data)
}

type credentialExtensionAssertion struct {
	Fields   map[uint64]cbor.RawMessage
	Response protocol.AuthenticatorGetAssertionResponse
}

func (result *credentialExtensionAssertion) clear() {
	clearCTAP2RawFields(result.Fields)
	result.Fields = nil
	clear(result.Response.AuthDataRaw)
	result.Response.AuthDataRaw = nil
	clear(result.Response.Signature)
	result.Response.Signature = nil
	clear(result.Response.Credential.ID)
	result.Response.Credential.ID = nil
	clear(result.Response.LargeBlobKey)
	result.Response.LargeBlobKey = nil
	if result.Response.User != nil {
		clear(result.Response.User.ID)
		result.Response.User.ID = nil
	}
	for identifier, output := range result.Response.UnsignedExtensionOutputs {
		clearCTAP2WireValue(output)
		delete(result.Response.UnsignedExtensionOutputs, identifier)
	}
	result.Response.UnsignedExtensionOutputs = nil
	if result.Response.AuthData != nil {
		clear(result.Response.AuthData.RPIDHash)
		result.Response.AuthData.RPIDHash = nil
		if result.Response.AuthData.Extensions != nil {
			clear(result.Response.AuthData.Extensions.GetCredBlobOutput.CredBlob)
			result.Response.AuthData.Extensions.GetCredBlobOutput.CredBlob = nil
			clear(result.Response.AuthData.Extensions.GetHMACSecretOutput.HMACSecret)
			result.Response.AuthData.Extensions.GetHMACSecretOutput.HMACSecret = nil
		}
	}
	result.Response.AuthData = nil
	result.Response.ExtensionOutputs = nil
}

func (f *credentialExtensionFixture) getAssertion(
	ctx context.Context,
	extensions protocol.GetExtensionInputs,
	options map[protocol.Option]bool,
	allowList bool,
	authorized bool,
) (credentialExtensionAssertion, error) {
	request := protocol.AuthenticatorGetAssertionRequest{
		RPID:           f.make.Request.RP.ID,
		ClientDataHash: slices.Clone(credentialExtensionClientDataHash[:]),
		Extensions:     extensions,
		Options:        options,
	}
	defer clear(request.ClientDataHash)
	if allowList {
		request.AllowList = []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   slices.Clone(f.credentialID),
		}}
		defer clear(request.AllowList[0].ID)
	}

	if authorized {
		if err := f.authorizeGetAssertion(ctx, &request); err != nil {
			return credentialExtensionAssertion{}, err
		}
		defer clear(request.PinUvAuthParam)
	}

	wireResponse, err := exchangeGetAssertion(ctx, f.test.CBOR(), request)
	if err != nil {
		return credentialExtensionAssertion{}, unexpectedCTAPStatus(
			"authenticatorGetAssertion",
			err,
		)
	}
	defer clearCTAP2ResponseData(wireResponse)

	return decodeCredentialExtensionAssertion(wireResponse.Data)
}

func (f *credentialExtensionFixture) expectGetAssertionError(
	ctx context.Context,
	options map[protocol.Option]bool,
	allowList bool,
) error {
	request := protocol.AuthenticatorGetAssertionRequest{
		RPID:           f.make.Request.RP.ID,
		ClientDataHash: slices.Clone(credentialExtensionClientDataHash[:]),
		Options:        options,
	}
	defer clear(request.ClientDataHash)
	if allowList {
		request.AllowList = []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   slices.Clone(f.credentialID),
		}}
		defer clear(request.AllowList[0].ID)
	}

	response, err := exchangeGetAssertion(ctx, f.test.CBOR(), request)
	if err == nil {
		defer clearCTAP2ResponseData(response)
	}

	return expectAnyCTAPError(err)
}

func (f *credentialExtensionFixture) authorizeGetAssertion(
	ctx context.Context,
	request *protocol.AuthenticatorGetAssertionRequest,
) error {
	if f.config.TokenProvider == nil {
		return errors.New(
			"ctap23: PIN/UV token provider is required for extension GetAssertion tests",
		)
	}

	authorization, err := f.config.TokenProvider(ctx, f.test.Client(), PinUvAuthTokenRequest{
		Permission: protocol.PermissionGetAssertion,
		RPID:       request.RPID,
	})
	if err != nil {
		clear(authorization.Value)

		return err
	}
	defer clear(authorization.Value)
	if err := validatePinUvAuthorization(f.make.Info, authorization); err != nil {
		return err
	}
	request.PinUvAuthParam = ctapcrypto.Authenticate(
		authorization.Protocol,
		authorization.Value,
		request.ClientDataHash,
	)
	request.PinUvAuthProtocol = authorization.Protocol

	return nil
}

func decodeCredentialExtensionAssertion(data []byte) (credentialExtensionAssertion, error) {
	if err := validateGetAssertionResponseRequiredFields(data); err != nil {
		return credentialExtensionAssertion{}, err
	}
	if err := validateCanonicalCTAP2Response("authenticatorGetAssertion", data); err != nil {
		return credentialExtensionAssertion{}, err
	}

	result := credentialExtensionAssertion{}
	if err := getInfoDecMode.Unmarshal(data, &result.Fields); err != nil {
		result.clear()

		return credentialExtensionAssertion{}, conformance.Failf(
			"invalid authenticatorGetAssertion response CBOR: %v",
			err,
		)
	}
	if err := getInfoDecMode.Unmarshal(data, &result.Response); err != nil {
		result.clear()

		return credentialExtensionAssertion{}, conformance.Failf(
			"invalid authenticatorGetAssertion response CBOR: %v",
			err,
		)
	}
	authData, err := protocol.ParseGetAssertionAuthData(result.Response.AuthDataRaw)
	if err != nil {
		result.clear()

		return credentialExtensionAssertion{}, conformance.Failf(
			"invalid authenticatorGetAssertion authData: %v",
			err,
		)
	}
	result.Response.AuthData = &authData

	return result, nil
}

func (f *credentialExtensionFixture) enumerateCredential(
	ctx context.Context,
) (credentialManagementResponse, error) {
	if f.config.TokenProvider == nil {
		return credentialManagementResponse{}, errors.New(
			"ctap23: PIN/UV token provider is required for credential enumeration",
		)
	}

	authorization, err := f.config.TokenProvider(ctx, f.test.Client(), PinUvAuthTokenRequest{
		Permission: protocol.PermissionCredentialManagement,
	})
	if err != nil {
		clear(authorization.Value)

		return credentialManagementResponse{}, err
	}
	defer clear(authorization.Value)
	if err := validatePinUvAuthorization(f.make.Info, authorization); err != nil {
		return credentialManagementResponse{}, err
	}
	if authorization.Protocol != protocol.PinUvAuthProtocolTwo || len(authorization.Value) != 32 {
		return credentialManagementResponse{}, fmt.Errorf(
			"ctap23: credential-management token must be a 32-byte protocol 2 token",
		)
	}

	rpIDHash := sha256.Sum256([]byte(f.make.Request.RP.ID))
	params := protocol.CredentialManagementSubCommandParams{RPIDHash: rpIDHash[:]}
	request, err := newCredentialManagementAuthorizedRequest(
		authorization.Value,
		protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
		&params,
	)
	if err != nil {
		return credentialManagementResponse{}, fmt.Errorf(
			"ctap23: build credential enumeration request: %w",
			err,
		)
	}
	defer request.clear()

	return executeCredentialManagement(ctx, f.test.CBOR(), request.Request)
}

func clearCredentialExtensionManagementResponse(result *credentialManagementResponse) {
	clearCTAP2RawFields(result.Fields)
	result.Fields = nil
	clear(result.Response.RPIDHash)
	result.Response.RPIDHash = nil
	clear(result.Response.User.ID)
	result.Response.User.ID = nil
	clear(result.Response.CredentialID.ID)
	result.Response.CredentialID.ID = nil
	clearCTAP2WireValue(result.Response.PublicKey)
	result.Response.PublicKey = nil
	clear(result.Response.LargeBlobKey)
	result.Response.LargeBlobKey = nil
}

type credentialExtensionCase struct {
	id            conformance.TestID
	marker        string
	sourcePath    string
	name          string
	description   string
	references    []conformance.RequirementRef
	destructive   bool
	applicability func(map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse) error
	run           func(context.Context, *conformance.TestContext) error
}

func credentialExtensionTest(definition credentialExtensionCase) conformance.Test {
	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: definition.description,
		Source: conformance.SourceLocation{
			Path: definition.sourcePath,
			Case: definition.marker,
		},
		References:  definition.references,
		Destructive: definition.destructive,
		Run: func(test *conformance.TestContext) {
			if definition.applicability != nil && !test.Step(conformance.Step{
				ID:         conformance.StepID(strings.TrimSuffix(definition.sourcePath, ".js") + ".applicability"),
				Name:       "Check extension applicability before mutating authenticator state",
				References: definition.references,
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}

					return definition.applicability(fields, info)
				},
			}) {
				return
			}

			test.Step(conformance.Step{
				ID:         conformance.StepID("credential-extension." + strings.ToLower(definition.marker) + ".command"),
				Name:       definition.name,
				References: definition.references,
				Run: func(ctx context.Context) error {
					return definition.run(ctx, test)
				},
			})
		},
	}
}

func requireCredentialExtension(
	info protocol.AuthenticatorGetInfoResponse,
	identifier string,
	featureful bool,
) error {
	if slices.Contains(info.Extensions, extension.ExtensionIdentifier(identifier)) {
		return nil
	}
	if featureful {
		return conformance.Failf("featureful profile requires the %s extension", identifier)
	}

	return conformance.Skipf("authenticator does not advertise the %s extension", identifier)
}
