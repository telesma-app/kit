package ctap23

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	makeCredentialFixtureRPName          = "CTAP 2.3 conformance"
	makeCredentialFixtureUserName        = "ctap23-conformance-user"
	makeCredentialFixtureUserDisplayName = "CTAP 2.3 conformance user"
)

var (
	makeCredentialFixtureClientDataHash = [...]byte{
		0xf7, 0x52, 0x4d, 0xc8, 0x4e, 0xa6, 0xa2, 0x53,
		0x09, 0xf7, 0x6c, 0x6e, 0x91, 0xc4, 0x95, 0x58,
		0xb9, 0x43, 0x68, 0x52, 0x28, 0xf7, 0xb8, 0x80,
		0x5c, 0x59, 0xd8, 0x72, 0xc6, 0x83, 0xa3, 0x8e,
	}
	makeCredentialFixtureUserID = [...]byte{
		0xa4, 0x63, 0x69, 0x67, 0x31, 0x8b, 0x4e, 0xcf,
		0x91, 0x99, 0x72, 0xf5, 0x35, 0xca, 0x6a, 0x98,
	}
)

// makeCredentialFixture owns the authorization token and a valid baseline
// request for one authenticatorMakeCredential conformance test.
type makeCredentialFixture struct {
	Info          protocol.AuthenticatorGetInfoResponse
	Request       protocol.AuthenticatorMakeCredentialRequest
	Authorization PinUvAuthToken
}

func prepareMakeCredentialFixture(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	rpID string,
) (makeCredentialFixture, error) {
	if config.PowerCycler == nil {
		return makeCredentialFixture{}, fmt.Errorf(
			"ctap23: authenticator power cycler is required for MakeCredential request tests",
		)
	}

	test.Cleanup(makeCredentialFixtureCleanupStep(test, config))
	if err := config.PowerCycler(ctx); err != nil {
		return makeCredentialFixture{}, err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return makeCredentialFixture{}, err
	}
	if err := config.PowerCycler(ctx); err != nil {
		return makeCredentialFixture{}, err
	}

	_, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return makeCredentialFixture{}, err
	}
	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		return makeCredentialFixture{}, err
	}

	fixture := makeCredentialFixture{
		Info: info,
		Request: protocol.AuthenticatorMakeCredentialRequest{
			ClientDataHash: slices.Clone(makeCredentialFixtureClientDataHash[:]),
			RP: credential.PublicKeyCredentialRpEntity{
				ID:   rpID,
				Name: makeCredentialFixtureRPName,
			},
			User: credential.PublicKeyCredentialUserEntity{
				ID:          slices.Clone(makeCredentialFixtureUserID[:]),
				Name:        makeCredentialFixtureUserName,
				DisplayName: makeCredentialFixtureUserDisplayName,
			},
			PubKeyCredParams: algorithms,
		},
	}
	if !fixtureNeedsAuthorization(info) {
		return fixture, nil
	}
	if config.TokenProvider == nil {
		return makeCredentialFixture{}, fmt.Errorf(
			"ctap23: PIN/UV token provider is required for MakeCredential request tests",
		)
	}

	authorization, err := config.TokenProvider(ctx, test.Client(), PinUvAuthTokenRequest{
		Permission: protocol.PermissionMakeCredential,
		RPID:       rpID,
	})
	if err != nil {
		clear(authorization.Value)

		return makeCredentialFixture{}, err
	}
	if err := validatePinUvAuthorization(info, authorization); err != nil {
		clear(authorization.Value)

		return makeCredentialFixture{}, err
	}

	fixture.Authorization = authorization
	fixture.Request.PinUvAuthParam = ctapcrypto.Authenticate(
		authorization.Protocol,
		authorization.Value,
		fixture.Request.ClientDataHash,
	)
	fixture.Request.PinUvAuthProtocol = authorization.Protocol

	return fixture, nil
}

func (f *makeCredentialFixture) clear() {
	clear(f.Authorization.Value)
	f.Authorization.Value = nil
}

func (f makeCredentialFixture) makeCredential(
	ctx context.Context,
	device ctaptransport.CBOR,
	request protocol.AuthenticatorMakeCredentialRequest,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	wireResponse, err := exchangeMakeCredential(ctx, device, request)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, unexpectedCTAPStatus(
			"authenticatorMakeCredential",
			err,
		)
	}

	return decodeMakeCredentialResponse(wireResponse.Data)
}

func decodeMakeCredentialResponse(data []byte) (protocol.AuthenticatorMakeCredentialResponse, error) {
	if err := validateMakeCredentialResponseRequiredFields(data); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}
	if err := validateCanonicalMakeCredentialResponse(data); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	var response protocol.AuthenticatorMakeCredentialResponse
	if err := getInfoDecMode.Unmarshal(data, &response); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, conformance.Failf(
			"invalid authenticatorMakeCredential response CBOR: %v",
			err,
		)
	}
	authData, err := protocol.ParseMakeCredentialAuthData(response.AuthDataRaw)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, conformance.Failf(
			"invalid authenticatorMakeCredential authData: %v",
			err,
		)
	}
	response.AuthData = &authData

	return response, nil
}

// rawFields returns a new decoded wire tree on every call, so an individual
// negative case can mutate nested request members without changing the valid
// fixture or another case.
func (f makeCredentialFixture) rawFields() map[uint64]any {
	return ctap2WireFields("MakeCredential", f.Request)
}

func exchangeRawMakeCredential(
	ctx context.Context,
	device ctaptransport.CBOR,
	fields map[uint64]any,
) (ctaptransport.CBORResponse, error) {
	return exchangeMakeCredential(ctx, device, fields)
}

func exchangeMakeCredential(
	ctx context.Context,
	device ctaptransport.CBOR,
	request any,
) (ctaptransport.CBORResponse, error) {
	return exchangeCTAP2(ctx, device, protocol.AuthenticatorMakeCredential, request)
}

func validateCanonicalMakeCredentialResponse(data []byte) error {
	return validateCanonicalCTAP2Response("authenticatorMakeCredential", data)
}

func validateMakeCredentialResponseRequiredFields(data []byte) error {
	return validateRequiredCBORFields(
		"authenticatorMakeCredential",
		data,
		[]requiredCBORField{
			{key: 1, name: "fmt", majorType: 3, typeName: "text string"},
			{key: 2, name: "authData", majorType: 2, typeName: "byte string"},
		},
	)
}

func makeCredentialResponseRequiredReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1:make-credential-response-required-members",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        "make-credential-response-required-members",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		Level:         conformance.RequirementConstraint,
	}
}

func expectAnyCTAPError(err error) error {
	if err == nil {
		return conformance.Fail("command succeeded, want a CTAP error")
	}

	var ctapError *ctaptransport.CTAPError
	if errors.As(err, &ctapError) {
		return nil
	}

	return err
}

func makeCredentialFixtureAlgorithms(
	advertised []credential.PublicKeyCredentialParameters,
) ([]credential.PublicKeyCredentialParameters, error) {
	if len(advertised) == 0 {
		return []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}}, nil
	}

	algorithms := make([]credential.PublicKeyCredentialParameters, 0, len(advertised))
	for _, algorithm := range advertised {
		if algorithm.Type == credential.PublicKeyCredentialTypePublicKey {
			algorithms = append(algorithms, algorithm)
		}
	}
	if len(algorithms) == 0 {
		return nil, conformance.Fail("GetInfo algorithms contains no public-key credential algorithm")
	}

	return algorithms, nil
}

func fixtureNeedsAuthorization(info protocol.AuthenticatorGetInfoResponse) bool {
	_, hasClientPIN := info.Options[protocol.OptionClientPIN]
	_, hasUV := info.Options[protocol.OptionUserVerification]

	return hasClientPIN || hasUV
}

func validatePinUvAuthorization(
	info protocol.AuthenticatorGetInfoResponse,
	authorization PinUvAuthToken,
) error {
	if len(authorization.Value) == 0 {
		return fmt.Errorf("ctap23: PIN/UV token provider returned an empty token")
	}
	if authorization.Protocol != protocol.PinUvAuthProtocolOne &&
		authorization.Protocol != protocol.PinUvAuthProtocolTwo {
		return fmt.Errorf(
			"ctap23: PIN/UV token provider returned unsupported protocol %d",
			authorization.Protocol,
		)
	}
	if !slices.Contains(info.PinUvAuthProtocols, authorization.Protocol) {
		return fmt.Errorf(
			"ctap23: PIN/UV token provider returned unadvertised protocol %d",
			authorization.Protocol,
		)
	}

	return nil
}

func makeCredentialFixtureCleanupStep(test *conformance.TestContext, config Config) conformance.Step {
	return conformance.Step{
		ID:         "make-credential-fixture.cleanup",
		Name:       "Reset the authenticator after the MakeCredential request test",
		References: []conformance.RequirementRef{resetReference(), clientPINPowerCycleReference()},
		Run: func(ctx context.Context) error {
			if err := config.PowerCycler(ctx); err != nil {
				return err
			}

			return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
		},
	}
}
