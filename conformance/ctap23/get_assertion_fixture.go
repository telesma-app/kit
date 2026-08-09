package ctap23

import (
	"context"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

var getAssertionFixtureClientDataHash = [...]byte{
	0xb8, 0x27, 0x71, 0x2f, 0x88, 0x3d, 0x72, 0x5f,
	0xb3, 0x5a, 0x11, 0x12, 0xb5, 0x3e, 0xd3, 0x44,
	0x82, 0xa9, 0x83, 0x0f, 0xe3, 0x85, 0x1d, 0x81,
	0x79, 0xc0, 0x1a, 0x98, 0x9e, 0x6a, 0xc2, 0x7d,
}

// getAssertionFixture owns the authorization token and a valid baseline
// request for one authenticatorGetAssertion conformance test.
type getAssertionFixture struct {
	Info                protocol.AuthenticatorGetInfoResponse
	Request             protocol.AuthenticatorGetAssertionRequest
	CredentialPublicKey cose.Key
	Authorization       PinUvAuthToken
}

type getAssertionFixtureSpec struct {
	RPID             string
	PubKeyCredParams []credential.PublicKeyCredentialParameters
}

type getAssertionResponse struct {
	Fields   map[uint64]cbor.RawMessage
	Response protocol.AuthenticatorGetAssertionResponse
}

func prepareGetAssertionFixture(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	spec getAssertionFixtureSpec,
) (getAssertionFixture, error) {
	makeCredential, err := prepareMakeCredentialFixture(ctx, test, config, spec.RPID)
	if err != nil {
		return getAssertionFixture{}, err
	}
	defer makeCredential.clear()
	if spec.PubKeyCredParams != nil {
		makeCredential.Request.PubKeyCredParams = spec.PubKeyCredParams
	}

	created, err := makeCredential.makeCredential(ctx, test.CBOR(), makeCredential.Request)
	if err != nil {
		return getAssertionFixture{}, err
	}
	makeCredential.clear()
	if created.AuthData.AttestedCredentialData == nil ||
		len(created.AuthData.AttestedCredentialData.CredentialID) == 0 {
		return getAssertionFixture{}, conformance.Fail(
			"authenticatorMakeCredential response does not contain an attested credential ID",
		)
	}

	fixture := getAssertionFixture{
		Info:                makeCredential.Info,
		CredentialPublicKey: created.AuthData.AttestedCredentialData.CredentialPublicKey,
		Request: protocol.AuthenticatorGetAssertionRequest{
			RPID:           spec.RPID,
			ClientDataHash: slices.Clone(getAssertionFixtureClientDataHash[:]),
			AllowList: []credential.PublicKeyCredentialDescriptor{{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   slices.Clone(created.AuthData.AttestedCredentialData.CredentialID),
			}},
		},
	}
	if err := fixture.refreshAuthorization(ctx, test, config, &fixture.Request); err != nil {
		return getAssertionFixture{}, err
	}

	return fixture, nil
}

func (f *getAssertionFixture) clear() {
	clear(f.Authorization.Value)
	f.Authorization.Value = nil
	clear(f.Request.PinUvAuthParam)
	f.Request.PinUvAuthParam = nil
	f.Request.PinUvAuthProtocol = 0
}

func (f *getAssertionFixture) refreshAuthorization(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	request *protocol.AuthenticatorGetAssertionRequest,
) error {
	f.clear()
	clear(request.PinUvAuthParam)
	request.PinUvAuthParam = nil
	request.PinUvAuthProtocol = 0
	if !fixtureNeedsAuthorization(f.Info) {
		return nil
	}
	if config.TokenProvider == nil {
		return fmt.Errorf(
			"ctap23: PIN/UV token provider is required for GetAssertion request tests",
		)
	}

	authorization, err := config.TokenProvider(ctx, test.Client(), PinUvAuthTokenRequest{
		Permission: protocol.PermissionGetAssertion,
		RPID:       request.RPID,
	})
	if err != nil {
		clear(authorization.Value)

		return err
	}
	if err := validatePinUvAuthorization(f.Info, authorization); err != nil {
		clear(authorization.Value)

		return err
	}
	if len(authorization.Value) != 32 {
		clear(authorization.Value)

		return fmt.Errorf(
			"ctap23: PIN/UV token provider returned a %d-byte token, want 32 bytes",
			len(authorization.Value),
		)
	}

	f.Authorization = authorization
	request.PinUvAuthParam = ctapcrypto.Authenticate(
		authorization.Protocol,
		authorization.Value,
		request.ClientDataHash,
	)
	request.PinUvAuthProtocol = authorization.Protocol

	return nil
}

func (f *getAssertionFixture) getAssertion(
	ctx context.Context,
	device ctaptransport.CBOR,
	request protocol.AuthenticatorGetAssertionRequest,
) (getAssertionResponse, error) {
	wireResponse, err := exchangeGetAssertion(ctx, device, request)
	if err != nil {
		return getAssertionResponse{}, unexpectedCTAPStatus(
			"authenticatorGetAssertion",
			err,
		)
	}

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

// rawFields returns a new decoded wire tree on every call, so an individual
// negative case can mutate the request without changing the valid fixture.
func (f *getAssertionFixture) rawFields() map[uint64]any {
	return ctap2WireFields("GetAssertion", f.Request)
}

func exchangeRawGetAssertion(
	ctx context.Context,
	device ctaptransport.CBOR,
	fields map[uint64]any,
) (ctaptransport.CBORResponse, error) {
	return exchangeGetAssertion(ctx, device, fields)
}

func exchangeGetAssertion(
	ctx context.Context,
	device ctaptransport.CBOR,
	request any,
) (ctaptransport.CBORResponse, error) {
	return exchangeCTAP2(ctx, device, protocol.AuthenticatorGetAssertion, request)
}

func validateGetAssertionResponseRequiredFields(data []byte) error {
	return validateRequiredCBORFields(
		"authenticatorGetAssertion",
		data,
		[]requiredCBORField{
			{key: 1, name: "credential", majorType: 5, typeName: "map"},
			{key: 2, name: "authData", majorType: 2, typeName: "byte string"},
			{key: 3, name: "signature", majorType: 2, typeName: "byte string"},
		},
	)
}
