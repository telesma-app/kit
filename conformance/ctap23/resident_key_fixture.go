package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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

type residentKeySession struct {
	config        Config
	info          protocol.AuthenticatorGetInfoResponse
	algorithms    []credential.PublicKeyCredentialParameters
	authenticated bool
}

func (session *residentKeySession) clear() {
	clearResidentKeyGetInfo(&session.info)
	session.algorithms = nil
}

type residentKeyCredential struct {
	ID          []byte
	UserID      []byte
	Name        string
	DisplayName string
	PublicKey   []byte
}

func (credential *residentKeyCredential) clear() {
	clear(credential.ID)
	credential.ID = nil
	clear(credential.UserID)
	credential.UserID = nil
	clear(credential.PublicKey)
	credential.PublicKey = nil
}

type residentKeyAssertion struct {
	CredentialType  credential.PublicKeyCredentialType
	CredentialID    []byte
	UserPresent     bool
	UserID          []byte
	UserName        string
	UserDisplayName string
	UserIcon        string
	UserFieldKeys   map[string]struct{}
	UV              bool
	NumberPresent   bool
	Number          uint
	SelectedPresent bool
	Selected        bool
}

func (assertion *residentKeyAssertion) clear() {
	clear(assertion.CredentialID)
	assertion.CredentialID = nil
	clear(assertion.UserID)
	assertion.UserID = nil
	clear(assertion.UserFieldKeys)
	assertion.UserFieldKeys = nil
}

func prepareResidentKeySession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) (residentKeySession, error) {
	if err := residentKeyResetAndRebind(ctx, test, config); err != nil {
		return residentKeySession{}, err
	}

	fields, info, err := residentKeyReadInfo(ctx, test.CBOR())
	if err != nil {
		return residentKeySession{}, err
	}
	defer clearCTAP2RawFields(fields)

	residentKeys, present, err := rawGetInfoOption(fields, protocol.OptionResidentKeys)
	if err != nil {
		clearResidentKeyGetInfo(&info)
		return residentKeySession{}, err
	}
	if !present || !residentKeys {
		clearResidentKeyGetInfo(&info)
		return residentKeySession{}, conformance.Fail("GetInfo options.rk is not true after reset")
	}
	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		clearResidentKeyGetInfo(&info)
		return residentKeySession{}, err
	}

	return residentKeySession{config: config, info: info, algorithms: algorithms}, nil
}

func (session *residentKeySession) requireUnauthenticatedDiscovery(
	fields map[uint64]cbor.RawMessage,
) error {
	for _, option := range []protocol.Option{
		protocol.OptionAlwaysUv,
		protocol.OptionClientPIN,
		protocol.OptionUserVerification,
	} {
		value, _, err := rawGetInfoOption(fields, option)
		if err != nil {
			return err
		}
		if value {
			return conformance.Skipf(
				"fresh authenticator has %s=true; unauthenticated account-discovery case is not applicable",
				option,
			)
		}
	}

	return nil
}

func (session *residentKeySession) prepareRequiredVerification(
	ctx context.Context,
	test *conformance.TestContext,
) error {
	if !slices.Contains(session.info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		return conformance.Skip("authenticator does not advertise PIN/UV protocol 2")
	}
	if session.config.TokenProvider == nil {
		return errors.New("ctap23: PIN/UV token provider is required for authenticated resident-key tests")
	}

	fields, refreshed, err := residentKeyReadInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	defer clearCTAP2RawFields(fields)
	defer clearResidentKeyGetInfo(&refreshed)

	restricted, _, err := rawGetInfoOption(fields, protocol.OptionNoMcGaPermissionsWithClientPin)
	if err != nil {
		return err
	}
	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	if clientPINPresent && !restricted {
		return session.preparePIN(ctx, test)
	}

	_, uvPresent, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return err
	}
	if !uvPresent {
		return conformance.Skip("authenticator has neither usable ClientPIN nor built-in UV for authenticated resident-key discovery")
	}

	return session.prepareUV(ctx, test, fields)
}

func (session *residentKeySession) preparePIN(
	ctx context.Context,
	test *conformance.TestContext,
) error {
	if session.config.TemporaryPINProvider == nil {
		return errors.New("ctap23: temporary PIN provider is required for authenticated resident-key tests")
	}

	request := temporaryPINRequest(session.info)
	pin, err := session.config.TemporaryPINProvider(ctx, request)
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

	fields, info, err := residentKeyReadInfo(ctx, test.CBOR())
	if err != nil {
		clear(pin)
		return err
	}
	defer clearCTAP2RawFields(fields)
	clientPIN, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		clear(pin)
		clearResidentKeyGetInfo(&info)
		return err
	}
	if !present || !clientPIN {
		clear(pin)
		clearResidentKeyGetInfo(&info)
		return conformance.Fail("clientPin is not true after setting the temporary PIN")
	}

	clearResidentKeyGetInfo(&session.info)
	session.info = info
	clear(pin)
	session.authenticated = true
	return nil
}

func (session *residentKeySession) prepareUV(
	ctx context.Context,
	test *conformance.TestContext,
	fields map[uint64]cbor.RawMessage,
) error {
	uv, _, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return err
	}
	if !uv {
		if session.config.TemporaryPINProvider == nil {
			return errors.New("ctap23: temporary PIN provider is required to configure built-in UV")
		}
		if session.config.UVConfigurator == nil {
			return errors.New("ctap23: UV configurator is required for authenticated resident-key tests")
		}

		request := temporaryPINRequest(session.info)
		pin, err := session.config.TemporaryPINProvider(ctx, request)
		defer clear(pin)
		if err != nil {
			return err
		}
		if err := validateTemporaryPIN(pin, request); err != nil {
			return err
		}
		if err := session.config.UVConfigurator(ctx, pin); err != nil {
			return err
		}

		refreshedFields, refreshed, err := residentKeyReadInfo(ctx, test.CBOR())
		if err != nil {
			return err
		}
		defer clearCTAP2RawFields(refreshedFields)
		uv, present, err := rawGetInfoOption(refreshedFields, protocol.OptionUserVerification)
		if err != nil {
			clearResidentKeyGetInfo(&refreshed)
			return err
		}
		if !present || !uv {
			clearResidentKeyGetInfo(&refreshed)
			return conformance.Fail("GetInfo options.uv is not true after UV configuration")
		}

		clearResidentKeyGetInfo(&session.info)
		session.info = refreshed
	}

	session.authenticated = true
	return nil
}

func (session *residentKeySession) useAuthorizationIfRequired(
	fields map[uint64]cbor.RawMessage,
) error {
	for _, option := range []protocol.Option{
		protocol.OptionAlwaysUv,
		protocol.OptionClientPIN,
		protocol.OptionUserVerification,
	} {
		value, _, err := rawGetInfoOption(fields, option)
		if err != nil {
			return err
		}
		if value {
			if session.config.TokenProvider == nil {
				return fmt.Errorf("ctap23: PIN/UV token provider is required when fresh GetInfo has %s=true", option)
			}
			session.authenticated = true
			return nil
		}
	}

	return nil
}

func (session *residentKeySession) authorization(
	ctx context.Context,
	test *conformance.TestContext,
	permission protocol.Permission,
	rpID string,
) (PinUvAuthToken, error) {
	if !session.authenticated {
		return PinUvAuthToken{}, nil
	}
	authorization, err := session.config.TokenProvider(ctx, test.Client(), PinUvAuthTokenRequest{
		Permission: permission,
		RPID:       rpID,
	})
	if err != nil {
		clear(authorization.Value)
		return PinUvAuthToken{}, err
	}
	if authorization.Protocol != protocol.PinUvAuthProtocolTwo {
		clear(authorization.Value)
		return PinUvAuthToken{}, fmt.Errorf(
			"ctap23: PIN/UV token provider returned protocol %d; resident-key tests require protocol 2",
			authorization.Protocol,
		)
	}
	if err := validatePinUvAuthorization(session.info, authorization); err != nil {
		clear(authorization.Value)
		return PinUvAuthToken{}, err
	}
	if err := clientPIN2ValidatePermissionToken(authorization.Value); err != nil {
		clear(authorization.Value)
		return PinUvAuthToken{}, err
	}

	return authorization, nil
}

func residentKeyMakeCredentialRequest(
	label string,
	rpID string,
	user credential.PublicKeyCredentialUserEntity,
	algorithms []credential.PublicKeyCredentialParameters,
) protocol.AuthenticatorMakeCredentialRequest {
	clientDataHash := sha256.Sum256([]byte("resident-key make credential " + label))

	return protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash: clientDataHash[:],
		RP: credential.PublicKeyCredentialRpEntity{
			ID:   rpID,
			Name: "CTAP 2.3 resident-key conformance",
		},
		User:             user,
		PubKeyCredParams: algorithms,
		Options: map[protocol.Option]bool{
			protocol.OptionResidentKeys: true,
		},
	}
}

func residentKeyMakeCredential(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
	request protocol.AuthenticatorMakeCredentialRequest,
) (residentKeyCredential, error) {
	authorization, err := session.authorization(
		ctx,
		test,
		protocol.PermissionMakeCredential,
		request.RP.ID,
	)
	if err != nil {
		return residentKeyCredential{}, err
	}
	defer clear(authorization.Value)
	if len(authorization.Value) != 0 {
		request.PinUvAuthParam = ctapcrypto.Authenticate(
			protocol.PinUvAuthProtocolTwo,
			authorization.Value,
			request.ClientDataHash,
		)
		defer clear(request.PinUvAuthParam)
		request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo
	}

	wireResponse, err := exchangeMakeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return residentKeyCredential{}, unexpectedCTAPStatus("authenticatorMakeCredential", err)
	}
	defer clear(wireResponse.Data)

	response, err := decodeMakeCredentialResponse(wireResponse.Data)
	if err != nil {
		return residentKeyCredential{}, err
	}
	defer clearResidentKeyMakeCredentialResponse(&response)
	if response.AuthData == nil || response.AuthData.AttestedCredentialData == nil ||
		len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
		return residentKeyCredential{}, conformance.Fail(
			"authenticatorMakeCredential response is missing attested credential data",
		)
	}

	publicKey, err := ctap2EncMode.Marshal(
		response.AuthData.AttestedCredentialData.CredentialPublicKey,
	)
	if err != nil {
		clear(publicKey)
		return residentKeyCredential{}, conformance.Failf("encode credential public key: %v", err)
	}

	return residentKeyCredential{
		ID:          slices.Clone(response.AuthData.AttestedCredentialData.CredentialID),
		UserID:      slices.Clone(request.User.ID),
		Name:        request.User.Name,
		DisplayName: request.User.DisplayName,
		PublicKey:   publicKey,
	}, nil
}

func residentKeyGetAssertionRequest(label string, rpID string) protocol.AuthenticatorGetAssertionRequest {
	clientDataHash := sha256.Sum256([]byte("resident-key get assertion " + label))

	return protocol.AuthenticatorGetAssertionRequest{
		RPID:           rpID,
		ClientDataHash: clientDataHash[:],
	}
}

func residentKeyGetAssertion(
	ctx context.Context,
	test *conformance.TestContext,
	session *residentKeySession,
	request protocol.AuthenticatorGetAssertionRequest,
) (residentKeyAssertion, error) {
	authorization, err := session.authorization(
		ctx,
		test,
		protocol.PermissionGetAssertion,
		request.RPID,
	)
	if err != nil {
		return residentKeyAssertion{}, err
	}
	defer clear(authorization.Value)
	if len(authorization.Value) != 0 {
		request.PinUvAuthParam = ctapcrypto.Authenticate(
			protocol.PinUvAuthProtocolTwo,
			authorization.Value,
			request.ClientDataHash,
		)
		defer clear(request.PinUvAuthParam)
		request.PinUvAuthProtocol = protocol.PinUvAuthProtocolTwo
	}
	return residentKeyGetAssertionAuthorized(ctx, test, request)
}

func residentKeyGetAssertionAuthorized(
	ctx context.Context,
	test *conformance.TestContext,
	request protocol.AuthenticatorGetAssertionRequest,
) (residentKeyAssertion, error) {
	wireResponse, err := exchangeGetAssertion(ctx, test.CBOR(), request)
	if err != nil {
		return residentKeyAssertion{}, unexpectedCTAPStatus("authenticatorGetAssertion", err)
	}
	defer clear(wireResponse.Data)

	return decodeResidentKeyAssertion("authenticatorGetAssertion", wireResponse.Data)
}

func residentKeyGetNextAssertion(
	ctx context.Context,
	test *conformance.TestContext,
) (residentKeyAssertion, error) {
	wireResponse, err := test.CBOR().CBOR(
		ctx,
		[]byte{byte(protocol.AuthenticatorGetNextAssertion)},
	)
	if err != nil {
		clear(wireResponse.Data)
		return residentKeyAssertion{}, unexpectedCTAPStatus("authenticatorGetNextAssertion", err)
	}
	defer clear(wireResponse.Data)
	wireResponse, err = ctaptransport.ValidateCBORResponse(
		protocol.AuthenticatorGetNextAssertion,
		wireResponse,
	)
	if err != nil {
		return residentKeyAssertion{}, unexpectedCTAPStatus("authenticatorGetNextAssertion", err)
	}

	return decodeResidentKeyAssertion("authenticatorGetNextAssertion", wireResponse.Data)
}

func decodeResidentKeyAssertion(operation string, data []byte) (residentKeyAssertion, error) {
	if err := validateGetAssertionResponseRequiredFields(data); err != nil {
		return residentKeyAssertion{}, err
	}
	if err := validateCanonicalCTAP2Response(operation, data); err != nil {
		return residentKeyAssertion{}, err
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(data, &fields); err != nil {
		return residentKeyAssertion{}, conformance.Failf("invalid %s response CBOR: %v", operation, err)
	}
	defer clearCTAP2RawFields(fields)

	var response protocol.AuthenticatorGetAssertionResponse
	if err := getInfoDecMode.Unmarshal(data, &response); err != nil {
		clearResidentKeyGetAssertionResponse(&response)
		return residentKeyAssertion{}, conformance.Failf("invalid %s response CBOR: %v", operation, err)
	}
	defer clearResidentKeyGetAssertionResponse(&response)
	authData, err := protocol.ParseGetAssertionAuthData(response.AuthDataRaw)
	if err != nil {
		return residentKeyAssertion{}, conformance.Failf("invalid %s authData: %v", operation, err)
	}
	response.AuthData = &authData

	assertion := residentKeyAssertion{
		CredentialType: response.Credential.Type,
		CredentialID:   slices.Clone(response.Credential.ID),
		UV:             response.AuthData.Flags.UserVerified(),
	}
	if len(assertion.CredentialID) == 0 ||
		assertion.CredentialType != credential.PublicKeyCredentialTypePublicKey {
		assertion.clear()
		return residentKeyAssertion{}, conformance.Failf(
			"%s credential descriptor is not a public-key descriptor with a nonempty ID",
			operation,
		)
	}
	if raw, present := fields[5]; present {
		if !hasCBORMajorType(raw, 0) {
			assertion.clear()
			return residentKeyAssertion{}, conformance.Failf("%s numberOfCredentials is not an unsigned integer", operation)
		}
		if err := getInfoDecMode.Unmarshal(raw, &assertion.Number); err != nil {
			assertion.clear()
			return residentKeyAssertion{}, conformance.Failf("invalid %s numberOfCredentials: %v", operation, err)
		}
		assertion.NumberPresent = true
	}
	if raw, present := fields[6]; present {
		if !hasCBORMajorType(raw, 7) {
			assertion.clear()
			return residentKeyAssertion{}, conformance.Failf("%s userSelected is not a boolean", operation)
		}
		if err := getInfoDecMode.Unmarshal(raw, &assertion.Selected); err != nil {
			assertion.clear()
			return residentKeyAssertion{}, conformance.Failf("invalid %s userSelected: %v", operation, err)
		}
		assertion.SelectedPresent = true
	}
	if raw, present := fields[4]; present {
		var userFields map[string]cbor.RawMessage
		if err := getInfoDecMode.Unmarshal(raw, &userFields); err != nil {
			assertion.clear()
			return residentKeyAssertion{}, conformance.Failf("invalid %s user entity: %v", operation, err)
		}
		defer func() {
			for key, raw := range userFields {
				clear(raw)
				delete(userFields, key)
			}
		}()
		assertion.UserPresent = true
		assertion.UserFieldKeys = make(map[string]struct{}, len(userFields))
		for key := range userFields {
			assertion.UserFieldKeys[key] = struct{}{}
		}
	}
	if response.User != nil {
		assertion.UserID = slices.Clone(response.User.ID)
		assertion.UserName = response.User.Name
		assertion.UserDisplayName = response.User.DisplayName
		assertion.UserIcon = response.User.Icon
	}

	return assertion, nil
}

func residentKeyReadInfo(
	ctx context.Context,
	device ctaptransport.CBOR,
) (map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, error) {
	response, err := device.CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		clear(response.Data)
		var ctapError *ctaptransport.CTAPError
		if errors.As(err, &ctapError) {
			return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Failf(
				"authenticatorGetInfo returned %s",
				ctapError.StatusCode,
			)
		}
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	defer clear(response.Data)
	if response.StatusCode != ctaptransport.CTAP2_OK {
		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Failf(
			"authenticatorGetInfo returned %s",
			response.StatusCode,
		)
	}

	fields, info, err := decodeGetInfoResponse(response.Data)
	if err != nil {
		clearCTAP2RawFields(fields)
		clearResidentKeyGetInfo(&info)
		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Failf(
			"invalid authenticatorGetInfo CBOR: %v",
			err,
		)
	}

	return fields, info, nil
}

func residentKeyEncryptedStoreState(
	ctx context.Context,
	test *conformance.TestContext,
) ([]byte, error) {
	fields, info, err := residentKeyReadInfo(ctx, test.CBOR())
	if err != nil {
		return nil, err
	}
	defer clearCTAP2RawFields(fields)
	defer clearResidentKeyGetInfo(&info)

	raw, present := fields[30]
	if !present {
		return nil, conformance.Skip("GetInfo does not contain encCredStoreState")
	}
	if !hasCBORMajorType(raw, 2) {
		return nil, conformance.Fail("GetInfo encCredStoreState is not a byte string")
	}
	var state []byte
	if err := getInfoDecMode.Unmarshal(raw, &state); err != nil {
		clear(state)
		return nil, conformance.Failf("invalid GetInfo encCredStoreState: %v", err)
	}
	if len(state) != 32 {
		clear(state)
		return nil, conformance.Failf("GetInfo encCredStoreState is %d bytes, want 32", len(state))
	}
	if !bytes.Equal(state, info.EncCredStoreState) {
		clear(state)
		return nil, conformance.Fail("typed encCredStoreState differs from raw field 30")
	}

	return state, nil
}

func residentKeyResetAndRebind(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) error {
	if config.PowerCycler == nil {
		return errors.New("ctap23: authenticator power cycler is required for resident-key tests")
	}
	if err := config.PowerCycler(ctx); err != nil {
		return err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return err
	}

	return config.PowerCycler(ctx)
}

func clearResidentKeyMakeCredentialResponse(response *protocol.AuthenticatorMakeCredentialResponse) {
	if response.AuthData != nil && response.AuthData.AttestedCredentialData != nil {
		clearResidentKeyCOSEKey(response.AuthData.AttestedCredentialData.CredentialPublicKey)
		response.AuthData.AttestedCredentialData.CredentialPublicKey = nil
	}
	clearMakeCredentialResponse(response)
}

func clearResidentKeyGetAssertionResponse(response *protocol.AuthenticatorGetAssertionResponse) {
	clear(response.Credential.ID)
	response.Credential.ID = nil
	if response.User != nil {
		clear(response.User.ID)
		response.User.ID = nil
	}
	clear(response.AuthDataRaw)
	response.AuthDataRaw = nil
	clear(response.Signature)
	response.Signature = nil
	clear(response.LargeBlobKey)
	response.LargeBlobKey = nil
	for identifier, output := range response.UnsignedExtensionOutputs {
		clearCTAP2WireValue(output)
		delete(response.UnsignedExtensionOutputs, identifier)
	}
	response.UnsignedExtensionOutputs = nil
	if response.AuthData != nil {
		clear(response.AuthData.RPIDHash)
		response.AuthData.RPIDHash = nil
	}
	response.AuthData = nil
	response.User = nil
	response.ExtensionOutputs = nil
}

func clearResidentKeyCOSEKey(key cose.Key) {
	for label, value := range key {
		clearCTAP2WireValue(value)
		delete(key, label)
	}
}

func clearResidentKeyGetInfo(info *protocol.AuthenticatorGetInfoResponse) {
	clear(info.EncCredStoreState)
	info.EncCredStoreState = nil
	clear(info.EncIdentifier)
	info.EncIdentifier = nil
	clear(info.PinComplexityPolicyURL)
	info.PinComplexityPolicyURL = nil
}
