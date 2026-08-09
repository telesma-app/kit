package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const hmacSecretProtocol = protocol.PinUvAuthProtocolOne
const hmacSecretProtocolOmitted = protocol.PinUvAuthProtocol(0)

type hmacSecretSession struct {
	info       protocol.AuthenticatorGetInfoResponse
	algorithms []credential.PublicKeyCredentialParameters
	pin        []byte
	protocol   protocol.PinUvAuthProtocol
	useUV      bool
	alwaysUV   bool
}

func (session *hmacSecretSession) clear() {
	clear(session.pin)
	session.pin = nil
}

type hmacSecretCredential struct {
	ID   []byte
	RPID string
}

type hmacSecretCredentialMaterial struct {
	Credential hmacSecretCredential
	FirstSalt  []byte
	SecondSalt []byte
}

func (material *hmacSecretCredentialMaterial) clear() {
	clear(material.FirstSalt)
	material.FirstSalt = nil
	clear(material.SecondSalt)
	material.SecondSalt = nil
}

type hmacSecretOutputs struct {
	First  []byte
	Second []byte
}

func (outputs *hmacSecretOutputs) clear() {
	clear(outputs.First)
	outputs.First = nil
	clear(outputs.Second)
	outputs.Second = nil
}

type hmacSecretEnvelope struct {
	input        protocol.HMACSecret
	sharedSecret []byte
}

func (envelope *hmacSecretEnvelope) clear() {
	clear(envelope.input.SaltEnc)
	envelope.input.SaltEnc = nil
	clear(envelope.input.SaltAuth)
	envelope.input.SaltAuth = nil
	clear(envelope.sharedSecret)
	envelope.sharedSecret = nil
}

func hmacSecretApplicability(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
) error {
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		return conformance.Fail("FIDO_2_3 authenticator does not advertise the mandatory hmac-secret extension")
	}

	return validateClientPINProtocolSupport(fields, info, config, hmacSecretProtocol)
}

func prepareHMACSecretSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *hmacSecretSession,
) error {
	return prepareHMACSecretSessionForProtocol(ctx, test, config, session, hmacSecretProtocol)
}

func prepareHMACSecretSessionForProtocol(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *hmacSecretSession,
	selectedProtocol protocol.PinUvAuthProtocol,
) error {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		return conformance.Fail("hmac-secret support disappeared after reset")
	}
	if !slices.Contains(info.PinUvAuthProtocols, selectedProtocol) {
		return conformance.Failf(
			"PIN/UV protocol %d support disappeared after reset",
			selectedProtocol,
		)
	}
	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		return err
	}

	session.info = info
	session.algorithms = algorithms
	session.protocol = selectedProtocol
	session.alwaysUV, _, err = rawGetInfoOption(fields, protocol.OptionAlwaysUv)
	if err != nil {
		return err
	}

	restricted, _, err := rawGetInfoOption(fields, protocol.OptionNoMcGaPermissionsWithClientPin)
	if err != nil {
		return err
	}
	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	if clientPINPresent && !restricted {
		return prepareHMACSecretPINSession(ctx, test, config, session)
	}

	return prepareHMACSecretUVSession(ctx, test, config, session, fields)
}

func prepareHMACSecretPINSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *hmacSecretSession,
) error {
	if config.TemporaryPINProvider == nil {
		return errors.New("ctap23: temporary PIN provider is required for hmac-secret tests")
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

	keyAgreement, err := test.Client().GetKeyAgreement(ctx, session.protocol)
	if err != nil {
		clear(pin)

		return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	if err := test.Client().SetPIN(ctx, session.protocol, keyAgreement, string(pin)); err != nil {
		clear(pin)

		return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	fields, info, err := readHMACSecretConfiguredProfile(ctx, test, session.protocol)
	if err != nil {
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

func prepareHMACSecretUVSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	session *hmacSecretSession,
	fields map[uint64]cbor.RawMessage,
) error {
	uv, present, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("ctap23: hmac-secret tests require ClientPIN or built-in UV")
	}
	if !uv {
		if config.TemporaryPINProvider == nil {
			return errors.New("ctap23: temporary PIN provider is required to configure built-in UV for hmac-secret tests")
		}
		if config.UVConfigurator == nil {
			return errors.New("ctap23: UV configurator is required for hmac-secret tests")
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

		fields, session.info, err = readHMACSecretConfiguredProfile(ctx, test, session.protocol)
		if err != nil {
			return err
		}
		uv, present, err = rawGetInfoOption(fields, protocol.OptionUserVerification)
		if err != nil {
			return err
		}
		if !present || !uv {
			return errors.New("ctap23: UV configurator completed but GetInfo uv is not true")
		}
	}

	session.useUV = true

	return nil
}

func readHMACSecretConfiguredProfile(
	ctx context.Context,
	test *conformance.TestContext,
	selectedProtocol protocol.PinUvAuthProtocol,
) (map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, error) {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if err := validateHMACSecretConfiguredProfile(fields, info, selectedProtocol); err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}

	return fields, info, nil
}

func validateHMACSecretConfiguredProfile(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	selectedProtocol protocol.PinUvAuthProtocol,
) error {
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		return conformance.Fail("hmac-secret support disappeared while configuring user verification")
	}
	if !slices.Contains(info.PinUvAuthProtocols, selectedProtocol) {
		return conformance.Failf(
			"PIN/UV protocol %d support disappeared while configuring user verification",
			selectedProtocol,
		)
	}
	pinUvAuthToken, present, err := rawGetInfoOption(fields, protocol.OptionPinUvAuthToken)
	if err != nil {
		return err
	}
	if !present || !pinUvAuthToken {
		return conformance.Fail("pinUvAuthToken is not true after configuring user verification")
	}

	return nil
}

func hmacSecretAuthorization(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretSession,
	permission protocol.Permission,
	rpID string,
) (PinUvAuthToken, error) {
	keyAgreement, err := test.Client().GetKeyAgreement(ctx, session.protocol)
	if err != nil {
		return PinUvAuthToken{}, unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}

	var token []byte
	if session.useUV {
		token, err = test.Client().GetPinUvAuthTokenUsingUvWithPermissions(
			ctx,
			session.protocol,
			keyAgreement,
			permission,
			rpID,
		)
	} else {
		token, err = test.Client().GetPinUvAuthTokenUsingPinWithPermissions(
			ctx,
			session.protocol,
			keyAgreement,
			string(session.pin),
			permission,
			rpID,
		)
	}
	if err != nil {
		clear(token)
		operation := "authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions"
		if session.useUV {
			operation = "authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions"
		}

		return PinUvAuthToken{}, unexpectedCTAPStatus(operation, err)
	}
	validLength := len(token) == 32
	if session.protocol == protocol.PinUvAuthProtocolOne {
		validLength = len(token) == 16 || len(token) == 32
	}
	if !validLength {
		clear(token)

		return PinUvAuthToken{}, conformance.Failf(
			"decrypted PIN/UV protocol %d pinUvAuthToken is %d bytes, want a valid protocol token",
			session.protocol,
			len(token),
		)
	}

	return PinUvAuthToken{Protocol: session.protocol, Value: token}, nil
}

func newHMACSecretEnvelope(
	ctx context.Context,
	test *conformance.TestContext,
	plaintext []byte,
	wireProtocol protocol.PinUvAuthProtocol,
) (hmacSecretEnvelope, error) {
	return newHMACSecretEnvelopeForProtocol(
		ctx,
		test,
		plaintext,
		hmacSecretProtocol,
		wireProtocol,
	)
}

func newHMACSecretEnvelopeForProtocol(
	ctx context.Context,
	test *conformance.TestContext,
	plaintext []byte,
	cryptoProtocol protocol.PinUvAuthProtocol,
	wireProtocol protocol.PinUvAuthProtocol,
) (hmacSecretEnvelope, error) {
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(cryptoProtocol)
	if err != nil {
		return hmacSecretEnvelope{}, err
	}
	authenticatorKey, err := test.Client().GetKeyAgreement(ctx, cryptoProtocol)
	if err != nil {
		return hmacSecretEnvelope{}, unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	platformKey, sharedSecret, err := pinProtocol.Encapsulate(authenticatorKey)
	if err != nil {
		clear(sharedSecret)

		return hmacSecretEnvelope{}, err
	}
	saltEnc, err := pinProtocol.Encrypt(sharedSecret, plaintext)
	if err != nil {
		clear(sharedSecret)
		clear(saltEnc)

		return hmacSecretEnvelope{}, err
	}
	saltAuth := ctapcrypto.Authenticate(cryptoProtocol, sharedSecret, saltEnc)

	return hmacSecretEnvelope{
		input: protocol.HMACSecret{
			KeyAgreement:      platformKey,
			SaltEnc:           saltEnc,
			SaltAuth:          saltAuth,
			PinUvAuthProtocol: wireProtocol,
		},
		sharedSecret: sharedSecret,
	}, nil
}

func newHMACSecretSaltEnvelope(
	ctx context.Context,
	test *conformance.TestContext,
	first []byte,
	second []byte,
	wireProtocol protocol.PinUvAuthProtocol,
) (hmacSecretEnvelope, error) {
	return newHMACSecretSaltEnvelopeForProtocol(
		ctx,
		test,
		first,
		second,
		hmacSecretProtocol,
		wireProtocol,
	)
}

func newHMACSecretSaltEnvelopeForProtocol(
	ctx context.Context,
	test *conformance.TestContext,
	first []byte,
	second []byte,
	cryptoProtocol protocol.PinUvAuthProtocol,
	wireProtocol protocol.PinUvAuthProtocol,
) (hmacSecretEnvelope, error) {
	plaintext := make([]byte, 0, len(first)+len(second))
	plaintext = append(plaintext, first...)
	plaintext = append(plaintext, second...)
	defer clear(plaintext)

	return newHMACSecretEnvelopeForProtocol(ctx, test, plaintext, cryptoProtocol, wireProtocol)
}

func hmacSecretMakeCredentialRequest(
	label string,
	rpID string,
	algorithms []credential.PublicKeyCredentialParameters,
	discoverable bool,
) protocol.AuthenticatorMakeCredentialRequest {
	clientDataHash := sha256.Sum256([]byte("hmac-secret make credential client data " + label))
	userID := sha256.Sum256([]byte("hmac-secret make credential user " + label))

	return protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash: clientDataHash[:],
		RP: credential.PublicKeyCredentialRpEntity{
			ID:   rpID,
			Name: "CTAP 2.3 hmac-secret conformance",
		},
		User: credential.PublicKeyCredentialUserEntity{
			ID:          userID[:16],
			Name:        "hmac-secret-" + label,
			DisplayName: "HMAC secret " + label,
		},
		PubKeyCredParams: algorithms,
		Extensions: protocol.CreateExtensionInputs{
			CreateCredProtectInput: protocol.CreateCredProtectInput{CredProtect: 1},
			CreateHMACSecretInput:  protocol.CreateHMACSecretInput{HMACSecret: true},
		},
		Options: map[protocol.Option]bool{protocol.OptionResidentKeys: discoverable},
	}
}

func hmacSecretCreateCredential(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretSession,
	label string,
	rpID string,
	discoverable bool,
) (hmacSecretCredential, error) {
	request := hmacSecretMakeCredentialRequest(label, rpID, session.algorithms, discoverable)
	authorization, err := hmacSecretAuthorization(
		ctx,
		test,
		session,
		protocol.PermissionMakeCredential,
		rpID,
	)
	if err != nil {
		return hmacSecretCredential{}, err
	}
	defer clear(authorization.Value)

	request.PinUvAuthParam = ctapcrypto.Authenticate(
		session.protocol,
		authorization.Value,
		request.ClientDataHash,
	)
	defer clear(request.PinUvAuthParam)
	request.PinUvAuthProtocol = session.protocol

	wireResponse, err := exchangeMakeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return hmacSecretCredential{}, unexpectedCTAPStatus("authenticatorMakeCredential", err)
	}
	defer clear(wireResponse.Data)

	response, err := decodeMakeCredentialResponse(wireResponse.Data)
	if err != nil {
		return hmacSecretCredential{}, err
	}
	defer clear(response.AuthDataRaw)
	if response.AuthData == nil || !response.AuthData.Flags.UserVerified() {
		return hmacSecretCredential{}, conformance.Fail(
			"PIN/UV-authorized authenticatorMakeCredential response has UV=false",
		)
	}
	if response.AuthData.AttestedCredentialData == nil ||
		len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
		return hmacSecretCredential{}, conformance.Fail(
			"authenticatorMakeCredential response is missing an attested credential ID",
		)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(response.AuthData.RPIDHash, rpIDHash[:]) {
		return hmacSecretCredential{}, conformance.Fail(
			"authenticatorMakeCredential response rpIdHash does not match the requested RP ID",
		)
	}
	if err := requireHMACSecretCreateOutput(response); err != nil {
		return hmacSecretCredential{}, err
	}

	return hmacSecretCredential{
		ID:   slices.Clone(response.AuthData.AttestedCredentialData.CredentialID),
		RPID: rpID,
	}, nil
}

func prepareHMACSecretCredentialMaterial(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretSession,
	marker string,
	discoverable bool,
) (hmacSecretCredentialMaterial, error) {
	label := hmacSecretLabel(marker, discoverable)
	storedCredential, err := hmacSecretCreateCredential(
		ctx,
		test,
		session,
		label,
		hmacSecretRPID(marker, discoverable),
		discoverable,
	)
	if err != nil {
		return hmacSecretCredentialMaterial{}, err
	}

	return hmacSecretCredentialMaterial{
		Credential: storedCredential,
		FirstSalt:  hmacSecretSalt(label + "-first"),
		SecondSalt: hmacSecretSalt(label + "-second"),
	}, nil
}

func requireHMACSecretCreateOutput(response protocol.AuthenticatorMakeCredentialResponse) error {
	view, err := observeMakeCredentialAuthDataExtensions(response.AuthDataRaw)
	if err != nil {
		return err
	}
	defer view.clearValues()
	if !view.Included {
		return conformance.Fail("authenticatorMakeCredential authData does not include extension data")
	}
	raw, present := view.Values[string(extension.ExtensionIdentifierHMACSecret)]
	if !present {
		return conformance.Fail("authenticatorMakeCredential authData extensions omit hmac-secret")
	}
	if !hasCBORMajorType(raw, 7) {
		return conformance.Fail("authenticatorMakeCredential hmac-secret output is not a CBOR boolean")
	}
	var value bool
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return conformance.Failf("invalid authenticatorMakeCredential hmac-secret output: %v", err)
	}
	if !value {
		return conformance.Fail("authenticatorMakeCredential hmac-secret output is false")
	}
	if response.AuthData.Extensions == nil ||
		response.AuthData.Extensions.CreateHMACSecretOutput == nil ||
		!response.AuthData.Extensions.CreateHMACSecretOutput.HMACSecret {
		return conformance.Fail("typed authenticatorMakeCredential hmac-secret output does not preserve true wire presence")
	}

	return nil
}

func hmacSecretGetAssertion(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretSession,
	credential hmacSecretCredential,
	first []byte,
	second []byte,
	wireProtocol protocol.PinUvAuthProtocol,
	verified bool,
) (hmacSecretOutputs, error) {
	envelope, err := newHMACSecretSaltEnvelopeForProtocol(
		ctx,
		test,
		first,
		second,
		session.protocol,
		wireProtocol,
	)
	if err != nil {
		return hmacSecretOutputs{}, err
	}
	defer envelope.clear()

	request := hmacSecretGetAssertionRequest(credential, envelope.input)
	if verified {
		authorization, err := hmacSecretAuthorization(
			ctx,
			test,
			session,
			protocol.PermissionGetAssertion,
			credential.RPID,
		)
		if err != nil {
			return hmacSecretOutputs{}, err
		}
		defer clear(authorization.Value)

		request.PinUvAuthParam = ctapcrypto.Authenticate(
			session.protocol,
			authorization.Value,
			request.ClientDataHash,
		)
		defer clear(request.PinUvAuthParam)
		request.PinUvAuthProtocol = session.protocol
	}

	wireResponse, err := exchangeGetAssertion(ctx, test.CBOR(), request)
	if err != nil {
		return hmacSecretOutputs{}, unexpectedCTAPStatus("authenticatorGetAssertion", err)
	}
	defer clear(wireResponse.Data)

	response, err := decodeHMACSecretGetAssertionResponse(wireResponse.Data)
	if err != nil {
		return hmacSecretOutputs{}, err
	}
	defer clearHMACSecretGetAssertionResponse(&response)
	if response.AuthData.Flags.UserVerified() != verified {
		return hmacSecretOutputs{}, conformance.Failf(
			"authenticatorGetAssertion response UV=%t, want %t",
			response.AuthData.Flags.UserVerified(),
			verified,
		)
	}
	if !bytes.Equal(response.Credential.ID, credential.ID) {
		return hmacSecretOutputs{}, conformance.Fail("authenticatorGetAssertion selected a different credential")
	}
	rpIDHash := sha256.Sum256([]byte(credential.RPID))
	if !bytes.Equal(response.AuthData.RPIDHash, rpIDHash[:]) {
		return hmacSecretOutputs{}, conformance.Fail(
			"authenticatorGetAssertion response rpIdHash does not match the requested RP ID",
		)
	}

	ciphertext, err := requireHMACSecretGetOutput(response)
	if err != nil {
		return hmacSecretOutputs{}, err
	}
	defer clear(ciphertext)

	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(session.protocol)
	if err != nil {
		return hmacSecretOutputs{}, err
	}
	decrypted, err := pinProtocol.Decrypt(envelope.sharedSecret, ciphertext)
	if err != nil {
		clear(decrypted)

		return hmacSecretOutputs{}, err
	}
	expectedLength := len(first) + len(second)
	if len(decrypted) != expectedLength {
		clear(decrypted)

		return hmacSecretOutputs{}, conformance.Failf(
			"decrypted hmac-secret output is %d bytes, want %d",
			len(decrypted),
			expectedLength,
		)
	}

	return hmacSecretOutputs{
		First:  decrypted[:len(first)],
		Second: decrypted[len(first):],
	}, nil
}

func hmacSecretGetAssertionRequest(
	storedCredential hmacSecretCredential,
	input protocol.HMACSecret,
) protocol.AuthenticatorGetAssertionRequest {
	clientDataHash := sha256.Sum256([]byte(
		"hmac-secret get assertion client data " + storedCredential.RPID,
	))

	return protocol.AuthenticatorGetAssertionRequest{
		RPID:           storedCredential.RPID,
		ClientDataHash: clientDataHash[:],
		AllowList: []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   storedCredential.ID,
		}},
		Extensions: protocol.GetExtensionInputs{
			GetHMACSecretInput: protocol.GetHMACSecretInput{HMACSecret: input},
		},
	}
}

func decodeHMACSecretGetAssertionResponse(
	data []byte,
) (protocol.AuthenticatorGetAssertionResponse, error) {
	if err := validateGetAssertionResponseRequiredFields(data); err != nil {
		return protocol.AuthenticatorGetAssertionResponse{}, err
	}
	if err := validateCanonicalCTAP2Response("authenticatorGetAssertion", data); err != nil {
		return protocol.AuthenticatorGetAssertionResponse{}, err
	}

	var response protocol.AuthenticatorGetAssertionResponse
	if err := getInfoDecMode.Unmarshal(data, &response); err != nil {
		clearHMACSecretGetAssertionResponse(&response)

		return protocol.AuthenticatorGetAssertionResponse{}, conformance.Failf(
			"invalid authenticatorGetAssertion response CBOR: %v",
			err,
		)
	}
	authData, err := protocol.ParseGetAssertionAuthData(response.AuthDataRaw)
	response.AuthData = &authData
	if err != nil {
		clearHMACSecretGetAssertionResponse(&response)

		return protocol.AuthenticatorGetAssertionResponse{}, conformance.Failf(
			"invalid authenticatorGetAssertion authData: %v",
			err,
		)
	}
	return response, nil
}

func clearHMACSecretGetAssertionResponse(
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
		if response.AuthData.AttestedCredentialData != nil {
			clear(response.AuthData.AttestedCredentialData.CredentialID)
			response.AuthData.AttestedCredentialData.CredentialID = nil
		}
		if response.AuthData.Extensions != nil {
			clear(response.AuthData.Extensions.GetCredBlobOutput.CredBlob)
			response.AuthData.Extensions.GetCredBlobOutput.CredBlob = nil
			clear(response.AuthData.Extensions.GetHMACSecretOutput.HMACSecret)
			response.AuthData.Extensions.GetHMACSecretOutput.HMACSecret = nil
		}
	}
	response.AuthData = nil
}

func requireHMACSecretGetOutput(
	response protocol.AuthenticatorGetAssertionResponse,
) ([]byte, error) {
	view, err := observeGetAssertionAuthDataExtensions(response.AuthDataRaw)
	if err != nil {
		return nil, err
	}
	defer view.clearValues()
	if !view.Included {
		return nil, conformance.Fail("authenticatorGetAssertion authData does not include extension data")
	}
	raw, present := view.Values[string(extension.ExtensionIdentifierHMACSecret)]
	if !present {
		return nil, conformance.Fail("authenticatorGetAssertion authData extensions omit hmac-secret")
	}
	if !hasCBORMajorType(raw, 2) {
		return nil, conformance.Fail("authenticatorGetAssertion hmac-secret output is not a CBOR byte string")
	}
	var value []byte
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return nil, conformance.Failf("invalid authenticatorGetAssertion hmac-secret output: %v", err)
	}
	if response.AuthData.Extensions == nil ||
		!bytes.Equal(response.AuthData.Extensions.GetHMACSecretOutput.HMACSecret, value) {
		return nil, conformance.Fail("typed authenticatorGetAssertion hmac-secret output differs from wire value")
	}

	return value, nil
}

func hmacSecretMalformedGetAssertion(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretSession,
	credential hmacSecretCredential,
	plaintext []byte,
) error {
	envelope, err := newHMACSecretEnvelopeForProtocol(
		ctx,
		test,
		plaintext,
		session.protocol,
		session.protocol,
	)
	if err != nil {
		return err
	}
	defer envelope.clear()

	request := hmacSecretGetAssertionRequest(credential, envelope.input)
	authorization, err := hmacSecretAuthorization(
		ctx,
		test,
		session,
		protocol.PermissionGetAssertion,
		credential.RPID,
	)
	if err != nil {
		return err
	}
	defer clear(authorization.Value)

	request.PinUvAuthParam = ctapcrypto.Authenticate(
		session.protocol,
		authorization.Value,
		request.ClientDataHash,
	)
	defer clear(request.PinUvAuthParam)
	request.PinUvAuthProtocol = session.protocol

	wireResponse, err := exchangeGetAssertion(ctx, test.CBOR(), request)

	return expectHMACSecretInvalidSaltResponse(wireResponse, err)
}

func expectHMACSecretInvalidSaltResponse(
	response ctaptransport.CBORResponse,
	err error,
) error {
	clear(response.Data)

	return expectCTAPStatus(err, ctaptransport.CTAP1_ERR_INVALID_PARAMETER)
}

func hmacSecretMalformedMakeCredential(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretSession,
	label string,
	rpID string,
	discoverable bool,
) error {
	request := hmacSecretMakeCredentialRequest(label, rpID, session.algorithms, discoverable)
	authorization, err := hmacSecretAuthorization(
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
		session.protocol,
		authorization.Value,
		request.ClientDataHash,
	)
	defer clear(request.PinUvAuthParam)
	request.PinUvAuthProtocol = session.protocol

	fields := ctap2WireFields("hmac-secret malformed MakeCredential", request)
	defer clearCTAP2WireValue(fields)
	clearCTAP2WireValue(fields[6])
	fields[6] = map[string]any{
		string(extension.ExtensionIdentifierHMACSecret): "not-a-boolean",
	}
	response, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)
	defer clearCTAP2ResponseData(response)

	return expectAnyCTAPError(err)
}

func hmacSecretSalt(label string) []byte {
	digest := sha256.Sum256([]byte("CTAP 2.3 hmac-secret salt " + label))

	return digest[:]
}

func hmacSecretRPID(marker string, discoverable bool) string {
	kind := "non-discoverable"
	if discoverable {
		kind = "discoverable"
	}

	return fmt.Sprintf("hmac-secret-%s-%s.ctap23-conformance.example", marker, kind)
}
