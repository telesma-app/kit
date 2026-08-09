package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	credentialManagementFixtureRPName           = "CTAP 2.3 credential management conformance"
	credentialManagementFixtureUserNamePrefix   = "ctap23-credential-management-user"
	credentialManagementFixtureDisplayPrefix    = "CTAP 2.3 credential management user"
	credentialManagementFixtureDeterminismLabel = "ctap23-credential-management"
)

type credentialManagementFixtureRequirements struct {
	PersistentReadOnly bool
}

// credentialManagementCredential is the exact credential state created by the
// fixture and later compared with credential-management responses.
type credentialManagementCredential struct {
	RPID           string
	RPIDHash       []byte
	ClientDataHash []byte
	Descriptor     credential.PublicKeyCredentialDescriptor
	User           credential.PublicKeyCredentialUserEntity
	PublicKey      cose.Key
	LargeBlobKey   []byte
}

// credentialManagementFixture owns its PIN, the currently borrowed
// credential-management token, and any large-blob keys returned while
// provisioning discoverable credentials.
type credentialManagementFixture struct {
	Info        protocol.AuthenticatorGetInfoResponse
	Credentials []credentialManagementCredential

	client          *client.Client
	pin             []byte
	managementToken []byte
	nextCredential  uint64
}

func prepareCredentialManagementFixture(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	requirements credentialManagementFixtureRequirements,
) (*credentialManagementFixture, error) {
	_, _, err := checkCredentialManagementApplicability(ctx, test, config, requirements)
	if err != nil {
		return nil, err
	}
	if config.PowerCycler == nil {
		return nil, errors.New("ctap23: authenticator power cycler is required for credential-management tests")
	}
	if config.TemporaryPINProvider == nil {
		return nil, errors.New("ctap23: temporary PIN provider is required for credential-management tests")
	}

	fixture := &credentialManagementFixture{client: test.Client()}
	test.Cleanup(fixture.cleanupStep(test, config))

	if err := config.PowerCycler(ctx); err != nil {
		return nil, err
	}
	if err := resetAuthenticatorForTest(ctx, fixture.client, config.Resetter); err != nil {
		return nil, err
	}

	_, fixture.Info, err = checkCredentialManagementApplicability(ctx, test, config, requirements)
	if err != nil {
		return nil, err
	}

	pinRequest := temporaryPINRequest(fixture.Info)
	fixture.pin, err = config.TemporaryPINProvider(ctx, pinRequest)
	if err != nil {
		fixture.clear()

		return nil, err
	}
	if err := validateTemporaryPIN(fixture.pin, pinRequest); err != nil {
		fixture.clear()

		return nil, err
	}

	keyAgreement, err := fixture.client.GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
	if err != nil {
		return nil, unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	if err := fixture.client.SetPIN(
		ctx,
		protocol.PinUvAuthProtocolTwo,
		keyAgreement,
		string(fixture.pin),
	); err != nil {
		return nil, unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	fields, info, err := checkCredentialManagementApplicability(
		ctx,
		test,
		config,
		requirements,
	)
	if err != nil {
		return nil, err
	}
	clientPIN, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return nil, err
	}
	if !present || !clientPIN {
		return nil, conformance.Fail("clientPin is not true after successful setPIN")
	}
	fixture.Info = info

	return fixture, nil
}

func checkCredentialManagementApplicability(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	requirements credentialManagementFixtureRequirements,
) (map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, error) {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if err := validateClientPIN2PermissionsProfile(fields, info, config); err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}

	credentialManagement, present, err := rawGetInfoOption(fields, protocol.OptionCredentialManagement)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if !present || !credentialManagement {
		if config.Featureful {
			return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Fail(
				"featureful profile requires credMgmt to be present and true",
			)
		}

		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Skip(
			"authenticator does not advertise credMgmt=true",
		)
	}

	residentKeys, present, err := rawGetInfoOption(fields, protocol.OptionResidentKeys)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if !present || !residentKeys {
		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Fail(
			"authenticator advertises credMgmt=true without rk=true",
		)
	}

	if requirements.PersistentReadOnly {
		persistentReadOnly, present, err := rawGetInfoOption(
			fields,
			protocol.OptionPersistentCredentialManagementReadOnly,
		)
		if err != nil {
			return nil, protocol.AuthenticatorGetInfoResponse{}, err
		}
		if !present || !persistentReadOnly {
			return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Skip(
				"authenticator does not advertise perCredMgmtRO=true",
			)
		}
	}

	return fields, info, nil
}

func (f *credentialManagementFixture) createDiscoverableCredential(
	ctx context.Context,
	rpID string,
) (credentialManagementCredential, error) {
	token, err := clientPIN2IssuePermissionToken(
		ctx,
		f.client,
		f.pin,
		protocol.PermissionMakeCredential,
		rpID,
	)
	if err != nil {
		clear(token)

		return credentialManagementCredential{}, unexpectedCTAPStatus(
			"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
			err,
		)
	}
	defer clear(token)
	if err := clientPIN2ValidatePermissionToken(token); err != nil {
		return credentialManagementCredential{}, err
	}

	algorithms, err := makeCredentialFixtureAlgorithms(f.Info.Algorithms)
	if err != nil {
		return credentialManagementCredential{}, err
	}

	sequence := f.nextCredential
	f.nextCredential++
	clientDataHash := credentialManagementFixtureBytes("client-data", sequence)
	userID := credentialManagementFixtureBytes("user-id", sequence)
	user := credential.PublicKeyCredentialUserEntity{
		ID:          userID,
		Name:        fmt.Sprintf("%s-%d", credentialManagementFixtureUserNamePrefix, sequence),
		DisplayName: fmt.Sprintf("%s %d", credentialManagementFixtureDisplayPrefix, sequence),
	}

	created, err := f.client.MakeCredential(
		ctx,
		protocol.PinUvAuthProtocolTwo,
		token,
		clientDataHash,
		credential.PublicKeyCredentialRpEntity{
			ID:   rpID,
			Name: credentialManagementFixtureRPName,
		},
		user,
		algorithms,
		nil,
		nil,
		map[protocol.Option]bool{protocol.OptionResidentKeys: true},
		0,
		nil,
	)
	if err != nil {
		return credentialManagementCredential{}, unexpectedCTAPStatus(
			"authenticatorMakeCredential",
			err,
		)
	}
	if created.AuthData == nil || created.AuthData.AttestedCredentialData == nil {
		clear(created.LargeBlobKey)

		return credentialManagementCredential{}, conformance.Fail(
			"authenticatorMakeCredential response does not contain attested credential data",
		)
	}
	if !created.AuthData.Flags.UserVerified() {
		clear(created.LargeBlobKey)

		return credentialManagementCredential{}, conformance.Fail(
			"PIN/UV-authenticated authenticatorMakeCredential response has UV=false",
		)
	}
	if err := validateCredentialManagementCredentialID(&created); err != nil {
		return credentialManagementCredential{}, err
	}

	rpIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(created.AuthData.RPIDHash, rpIDHash[:]) {
		clear(created.LargeBlobKey)

		return credentialManagementCredential{}, conformance.Fail(
			"authenticatorMakeCredential response rpIdHash does not match the requested RP ID",
		)
	}

	record := credentialManagementCredential{
		RPID:           rpID,
		RPIDHash:       rpIDHash[:],
		ClientDataHash: clientDataHash,
		Descriptor: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   created.AuthData.AttestedCredentialData.CredentialID,
		},
		User:         user,
		PublicKey:    created.AuthData.AttestedCredentialData.CredentialPublicKey,
		LargeBlobKey: created.LargeBlobKey,
	}
	f.Credentials = append(f.Credentials, record)

	return record, nil
}

func validateCredentialManagementCredentialID(
	created *protocol.AuthenticatorMakeCredentialResponse,
) error {
	if len(created.AuthData.AttestedCredentialData.CredentialID) != 0 {
		return nil
	}

	clear(created.LargeBlobKey)

	return conformance.Fail(
		"authenticatorMakeCredential response contains an empty credential ID",
	)
}

// refreshManagementToken replaces the fixture-owned token. The returned slice
// is borrowed until the next refresh or fixture cleanup.
func (f *credentialManagementFixture) refreshManagementToken(
	ctx context.Context,
	permission protocol.Permission,
) ([]byte, error) {
	switch permission {
	case protocol.PermissionCredentialManagement,
		protocol.PermissionPersistentCredentialManagementReadOnly:
	default:
		panic(fmt.Sprintf("credential-management token requested with permission %#x", permission))
	}

	token, err := clientPIN2IssuePermissionToken(ctx, f.client, f.pin, permission, "")
	if err != nil {
		clear(token)

		return nil, unexpectedCTAPStatus(
			"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
			err,
		)
	}
	if err := clientPIN2ValidatePermissionToken(token); err != nil {
		clear(token)

		return nil, err
	}

	clear(f.managementToken)
	f.managementToken = token

	return f.managementToken, nil
}

func (f *credentialManagementFixture) clear() {
	clear(f.pin)
	f.pin = nil
	clear(f.managementToken)
	f.managementToken = nil
	for i := range f.Credentials {
		clear(f.Credentials[i].LargeBlobKey)
		f.Credentials[i].LargeBlobKey = nil
	}
}

func (f *credentialManagementFixture) cleanupStep(
	test *conformance.TestContext,
	config Config,
) conformance.Step {
	return conformance.Step{
		ID:         "credential-management-fixture.cleanup",
		Name:       "Wipe fixture secrets, power-cycle, and reset the authenticator",
		References: []conformance.RequirementRef{clientPINPowerCycleReference(), resetReference()},
		Run: func(ctx context.Context) error {
			f.clear()
			if err := config.PowerCycler(ctx); err != nil {
				return err
			}

			return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
		},
	}
}

func credentialManagementFixtureBytes(kind string, sequence uint64) []byte {
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"%s:%s:%d",
		credentialManagementFixtureDeterminismLabel,
		kind,
		sequence,
	)))

	return digest[:]
}

// credentialManagementAuthorizedRequest owns the derived pinUvAuthParam and
// canonical subCommandParams bytes until clear is called.
type credentialManagementAuthorizedRequest struct {
	Request              protocol.AuthenticatorCredentialManagementRequest
	SubCommandParamsCBOR []byte
}

func newCredentialManagementAuthorizedRequest(
	token []byte,
	subCommand protocol.CredentialManagementSubCommand,
	params *protocol.CredentialManagementSubCommandParams,
) (credentialManagementAuthorizedRequest, error) {
	request := credentialManagementAuthorizedRequest{
		Request: protocol.AuthenticatorCredentialManagementRequest{
			SubCommand:        subCommand,
			PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
		},
	}
	authenticatedData := []byte{byte(subCommand)}
	if params != nil {
		encoded, err := ctap2EncMode.Marshal(params)
		if err != nil {
			return credentialManagementAuthorizedRequest{}, err
		}
		request.Request.SubCommandParams = *params
		request.SubCommandParamsCBOR = encoded
		authenticatedData = slices.Concat(authenticatedData, encoded)
	}
	request.Request.PinUvAuthParam = ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		authenticatedData,
	)

	return request, nil
}

func (r *credentialManagementAuthorizedRequest) clear() {
	clear(r.Request.PinUvAuthParam)
	r.Request.PinUvAuthParam = nil
	clear(r.SubCommandParamsCBOR)
	r.SubCommandParamsCBOR = nil
}

func credentialManagementContinuationRequest(
	subCommand protocol.CredentialManagementSubCommand,
) protocol.AuthenticatorCredentialManagementRequest {
	return protocol.AuthenticatorCredentialManagementRequest{SubCommand: subCommand}
}

type credentialManagementResponse struct {
	Fields   map[uint64]cbor.RawMessage
	Response protocol.AuthenticatorCredentialManagementResponse
}

func exchangeRawCredentialManagement(
	ctx context.Context,
	device ctaptransport.CBOR,
	request any,
) (ctaptransport.CBORResponse, error) {
	return exchangeCTAP2(ctx, device, protocol.AuthenticatorCredentialManagement, request)
}

func executeCredentialManagement(
	ctx context.Context,
	device ctaptransport.CBOR,
	request any,
) (credentialManagementResponse, error) {
	wireResponse, err := exchangeRawCredentialManagement(ctx, device, request)
	if err != nil {
		return credentialManagementResponse{}, unexpectedCTAPStatus(
			"authenticatorCredentialManagement",
			err,
		)
	}
	defer clear(wireResponse.Data)

	if len(wireResponse.Data) == 0 {
		return credentialManagementResponse{}, nil
	}

	return decodeCredentialManagementResponse(wireResponse.Data)
}

func executeEmptyCredentialManagement(
	ctx context.Context,
	device ctaptransport.CBOR,
	request any,
) error {
	wireResponse, err := exchangeRawCredentialManagement(ctx, device, request)
	if err != nil {
		return unexpectedCTAPStatus(
			"authenticatorCredentialManagement",
			err,
		)
	}
	defer clear(wireResponse.Data)

	if len(wireResponse.Data) != 0 {
		return conformance.Fail("authenticatorCredentialManagement returned a response body, want empty CTAP2_OK")
	}

	return nil
}

func decodeCredentialManagementResponse(data []byte) (credentialManagementResponse, error) {
	if err := validateCanonicalCTAP2Response("authenticatorCredentialManagement", data); err != nil {
		return credentialManagementResponse{}, err
	}

	result := credentialManagementResponse{}
	if err := getInfoDecMode.Unmarshal(data, &result.Fields); err != nil {
		clear(result.Fields[11])

		return result, conformance.Failf(
			"invalid authenticatorCredentialManagement response CBOR: %v",
			err,
		)
	}
	if err := getInfoDecMode.Unmarshal(data, &result.Response); err != nil {
		clear(result.Fields[11])
		clear(result.Response.LargeBlobKey)

		return result, conformance.Failf(
			"invalid authenticatorCredentialManagement response CBOR: %v",
			err,
		)
	}

	return result, nil
}
