package ctap23

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
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

const credentialExtensionMetadata = `{
  "schema": 3,
  "userVerificationDetails": [[{"userVerificationMethod":"fingerprint_internal"}]],
  "keyProtection": ["tee"],
  "matcherProtection": ["tee"]
}`

type credentialExtensionStoredCredential struct {
	id                []byte
	rpID              string
	user              credential.PublicKeyCredentialUserEntity
	discoverable      bool
	credProtect       uint
	credBlob          []byte
	thirdPartyPayment bool
}

type credentialExtensionMakeRecord struct {
	rpID       string
	options    map[string]bool
	extensions map[string]cbor.RawMessage
}

type credentialExtensionGetRecord struct {
	rpID       string
	allowList  bool
	options    map[string]bool
	extensions map[string]cbor.RawMessage
}

type credentialExtensionTestDevice struct {
	t testing.TB

	info        protocol.AuthenticatorGetInfoResponse
	credentials []credentialExtensionStoredCredential
	nextID      byte

	tokenRequests []PinUvAuthTokenRequest
	tokenAliases  [][]byte
	activeTokens  map[protocol.Permission][]byte
	responseData  [][]byte
	makeRecords   []credentialExtensionMakeRecord
	getRecords    []credentialExtensionGetRecord
	cmCalls       int
	resetCalls    int
	powerCycles   int

	elevateCredProtect   bool
	omitCreateOutput     string
	omitGetOutput        string
	createOutputOverride map[string]any
	getOutputOverride    map[string]any
	uvmOutput            any
	tokenProtocol        protocol.PinUvAuthProtocol
	tokenLength          int
}

func newCredentialExtensionTestDevice(t testing.TB) *credentialExtensionTestDevice {
	return &credentialExtensionTestDevice{
		t: t,
		info: protocol.AuthenticatorGetInfoResponse{
			Versions: []protocol.Version{protocol.FIDO_2_3},
			Extensions: []extension.ExtensionIdentifier{
				extension.ExtensionIdentifierCredentialProtection,
				extension.ExtensionIdentifierCredentialBlob,
				extension.ExtensionIdentifierThirdPartyPayment,
				extension.ExtensionIdentifierUserVerificationMethod,
			},
			AAGUID: uuid.UUID{},
			Options: map[protocol.Option]bool{
				protocol.OptionClientPIN:            false,
				protocol.OptionResidentKeys:         true,
				protocol.OptionCredentialManagement: true,
				protocol.OptionAlwaysUv:             false,
			},
			MaxCredBlobLength:  64,
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Algorithms: []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}},
		},
		activeTokens:  make(map[protocol.Permission][]byte),
		tokenProtocol: protocol.PinUvAuthProtocolTwo,
		tokenLength:   32,
		uvmOutput: []any{
			[]any{uint64(0x00000002), uint64(0x0004), uint64(0x0002)},
		},
	}
}

func (d *credentialExtensionTestDevice) config() Config {
	return Config{
		Featureful: true,
		Metadata:   Metadata{StatementJSON: credentialExtensionMetadata},
		PowerCycler: func(context.Context) error {
			d.powerCycles++

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			d.reset()

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			d.tokenRequests = append(d.tokenRequests, request)
			token := bytes.Repeat([]byte{byte(len(d.tokenAliases) + 1)}, d.tokenLength)
			d.tokenAliases = append(d.tokenAliases, token)
			d.activeTokens[request.Permission] = slices.Clone(token)

			return PinUvAuthToken{Protocol: d.tokenProtocol, Value: token}, nil
		},
	}
}

func (d *credentialExtensionTestDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	d.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		d.t.Fatal("empty CBOR request")
	}

	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalGetAssertionFixture(d.t, d.info),
		}, nil
	case protocol.AuthenticatorMakeCredential:
		return d.makeCredentialResponse(request[1:]), nil
	case protocol.AuthenticatorGetAssertion:
		return d.getAssertionResponse(request[1:]), nil
	case protocol.AuthenticatorCredentialManagement:
		return d.credentialManagementResponse(request[1:]), nil
	default:
		d.t.Fatalf("unexpected command %s", protocol.Command(request[0]))

		return ctaptransport.CBORResponse{}, nil
	}
}

func (d *credentialExtensionTestDevice) response(value any) ctaptransport.CBORResponse {
	data := marshalGetAssertionFixture(d.t, value)
	d.responseData = append(d.responseData, data)

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

func (d *credentialExtensionTestDevice) makeCredentialResponse(body []byte) ctaptransport.CBORResponse {
	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatal(err)
	}
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		d.t.Fatal(err)
	}
	extensions := decodeCredentialExtensionRawMap(d.t, fields[6])
	defer clearAuthDataExtensionValues(extensions)
	options := decodeCredentialExtensionBoolMap(d.t, fields[7])
	d.makeRecords = append(d.makeRecords, credentialExtensionMakeRecord{
		rpID:       request.RP.ID,
		options:    options,
		extensions: cloneCredentialExtensionRawMap(extensions),
	})
	d.requireToken(
		protocol.PermissionMakeCredential,
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
	)

	d.nextID++
	credentialID := bytes.Repeat([]byte{0x80 + d.nextID}, 16)
	stored := credentialExtensionStoredCredential{
		id:                slices.Clone(credentialID),
		rpID:              request.RP.ID,
		user:              request.User,
		discoverable:      request.Options[protocol.OptionResidentKeys],
		credBlob:          slices.Clone(request.Extensions.CreateCredBlobInput.CredBlob),
		thirdPartyPayment: request.Extensions.CreateThirdPartyPaymentInput.ThirdPartyPayment,
	}
	if raw, present := extensions[string(extension.ExtensionIdentifierCredentialProtection)]; present {
		var requested uint
		if err := getInfoDecMode.Unmarshal(raw, &requested); err != nil {
			d.t.Fatal(err)
		}
		stored.credProtect = requested
		if d.elevateCredProtect && requested < 3 {
			stored.credProtect = 3
		}
	}
	d.credentials = append(d.credentials, stored)

	outputs := make(map[string]any)
	defer clearCTAP2WireValue(outputs)
	if _, present := extensions[string(extension.ExtensionIdentifierCredentialProtection)]; present && d.omitCreateOutput != string(extension.ExtensionIdentifierCredentialProtection) {
		outputs[string(extension.ExtensionIdentifierCredentialProtection)] = stored.credProtect
	}
	if _, present := extensions[string(extension.ExtensionIdentifierCredentialBlob)]; present && d.omitCreateOutput != string(extension.ExtensionIdentifierCredentialBlob) {
		outputs[string(extension.ExtensionIdentifierCredentialBlob)] = true
	}
	if _, present := extensions[string(extension.ExtensionIdentifierUserVerificationMethod)]; present && d.omitCreateOutput != string(extension.ExtensionIdentifierUserVerificationMethod) {
		outputs[string(extension.ExtensionIdentifierUserVerificationMethod)] = d.uvmOutput
	}
	for identifier, value := range d.createOutputOverride {
		outputs[identifier] = value
	}
	authData := getAssertionFixtureMakeCredentialAuthData(d.t, credentialID)
	if len(outputs) != 0 {
		authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
		authData = append(authData, marshalGetAssertionFixture(d.t, outputs)...)
	}

	return d.response(protocol.AuthenticatorMakeCredentialResponse{
		Format:               attestation.AttestationStatementFormatIdentifierNone,
		AuthDataRaw:          authData,
		AttestationStatement: map[string]any{},
	})
}

func (d *credentialExtensionTestDevice) getAssertionResponse(body []byte) ctaptransport.CBORResponse {
	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatal(err)
	}
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		d.t.Fatal(err)
	}
	extensions := decodeCredentialExtensionRawMap(d.t, fields[4])
	defer clearAuthDataExtensionValues(extensions)
	options := decodeCredentialExtensionBoolMap(d.t, fields[5])
	d.getRecords = append(d.getRecords, credentialExtensionGetRecord{
		rpID:       request.RPID,
		allowList:  len(request.AllowList) != 0,
		options:    options,
		extensions: cloneCredentialExtensionRawMap(extensions),
	})
	if len(request.PinUvAuthParam) != 0 {
		d.requireToken(
			protocol.PermissionGetAssertion,
			request.PinUvAuthProtocol,
			request.PinUvAuthParam,
			request.ClientDataHash,
		)
	}

	stored := d.findCredential(request)
	if stored == nil {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS}
	}
	if request.Options[protocol.OptionUserPresence] == false && len(request.PinUvAuthParam) == 0 {
		if stored.credProtect == 3 || (stored.credProtect == 2 && len(request.AllowList) == 0) {
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS}
		}
	}

	outputs := make(map[string]any)
	defer clearCTAP2WireValue(outputs)
	if _, present := extensions[string(extension.ExtensionIdentifierCredentialBlob)]; present &&
		d.omitGetOutput != string(extension.ExtensionIdentifierCredentialBlob) {
		blob := slices.Clone(stored.credBlob)
		if blob == nil {
			blob = []byte{}
		}
		outputs[string(extension.ExtensionIdentifierCredentialBlob)] = blob
	}
	if _, present := extensions[string(extension.ExtensionIdentifierThirdPartyPayment)]; present &&
		d.omitGetOutput != string(extension.ExtensionIdentifierThirdPartyPayment) {
		outputs[string(extension.ExtensionIdentifierThirdPartyPayment)] = stored.thirdPartyPayment
	}
	for identifier, value := range d.getOutputOverride {
		outputs[identifier] = value
	}
	authData := getAssertionFixtureAuthData()
	if len(outputs) != 0 {
		authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
		authData = append(authData, marshalGetAssertionFixture(d.t, outputs)...)
	}

	return d.response(protocol.AuthenticatorGetAssertionResponse{
		Credential: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   slices.Clone(stored.id),
		},
		AuthDataRaw: authData,
		Signature:   []byte{0x30, 0x00},
	})
}

func (d *credentialExtensionTestDevice) credentialManagementResponse(
	body []byte,
) ctaptransport.CBORResponse {
	d.cmCalls++
	var request protocol.AuthenticatorCredentialManagementRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatal(err)
	}
	params, err := ctap2EncMode.Marshal(&request.SubCommandParams)
	if err != nil {
		d.t.Fatal(err)
	}
	defer clear(params)
	d.requireToken(
		protocol.PermissionCredentialManagement,
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		slices.Concat([]byte{byte(request.SubCommand)}, params),
	)
	if request.SubCommand != protocol.CredentialManagementSubCommandEnumerateCredentialsBegin {
		d.t.Fatalf("credential-management subcommand = %s", request.SubCommand)
	}

	for index := range d.credentials {
		stored := &d.credentials[index]
		hash := sha256.Sum256([]byte(stored.rpID))
		if !bytes.Equal(hash[:], request.SubCommandParams.RPIDHash) || !stored.discoverable {
			continue
		}

		return d.response(protocol.AuthenticatorCredentialManagementResponse{
			User: stored.user,
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   slices.Clone(stored.id),
			},
			PublicKey:        credentialExtensionPublicKey(),
			TotalCredentials: 1,
			CredProtect:      stored.credProtect,
		})
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS}
}

func (d *credentialExtensionTestDevice) requireToken(
	permission protocol.Permission,
	protocolVersion protocol.PinUvAuthProtocol,
	actual []byte,
	authenticated []byte,
) {
	d.t.Helper()
	token := d.activeTokens[permission]
	defer clear(token)
	defer delete(d.activeTokens, permission)
	want := ctapcrypto.Authenticate(protocolVersion, token, authenticated)
	if protocolVersion != d.tokenProtocol || !bytes.Equal(actual, want) {
		d.t.Fatalf("permission %#x authorization = %x, want exact protocol %d %x", permission, actual, d.tokenProtocol, want)
	}
}

func cloneCredentialExtensionRawMap(
	values map[string]cbor.RawMessage,
) map[string]cbor.RawMessage {
	if values == nil {
		return nil
	}

	result := make(map[string]cbor.RawMessage, len(values))
	for identifier, value := range values {
		result[identifier] = slices.Clone(value)
	}

	return result
}

func (d *credentialExtensionTestDevice) findCredential(
	request protocol.AuthenticatorGetAssertionRequest,
) *credentialExtensionStoredCredential {
	for index := range d.credentials {
		stored := &d.credentials[index]
		if stored.rpID != request.RPID {
			continue
		}
		if len(request.AllowList) == 0 {
			if stored.discoverable {
				return stored
			}

			continue
		}
		for _, descriptor := range request.AllowList {
			if bytes.Equal(stored.id, descriptor.ID) {
				return stored
			}
		}
	}

	return nil
}

func (d *credentialExtensionTestDevice) reset() {
	d.resetCalls++
	for index := range d.credentials {
		clear(d.credentials[index].id)
		clear(d.credentials[index].user.ID)
		clear(d.credentials[index].credBlob)
	}
	d.credentials = nil
}

func (d *credentialExtensionTestDevice) assertOwnedBuffersWiped(t testing.TB) {
	t.Helper()
	for index, token := range d.tokenAliases {
		if slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
			t.Fatalf("token alias %d was not wiped: %x", index, token)
		}
	}
	for index, data := range d.responseData {
		if slices.ContainsFunc(data, func(value byte) bool { return value != 0 }) {
			t.Fatalf("response Data alias %d was not wiped: %x", index, data)
		}
	}
}

func decodeCredentialExtensionRawMap(
	t testing.TB,
	raw cbor.RawMessage,
) map[string]cbor.RawMessage {
	t.Helper()
	if raw == nil {
		return nil
	}
	var result map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}

	return result
}

func decodeCredentialExtensionBoolMap(
	t testing.TB,
	raw cbor.RawMessage,
) map[string]bool {
	t.Helper()
	if raw == nil {
		return nil
	}
	var result map[string]bool
	if err := getInfoDecMode.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}

	return result
}

func credentialExtensionPublicKey() cose.Key {
	curve := elliptic.P256().Params()

	return cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   curve.Gx.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   curve.Gy.FillBytes(make([]byte, 32)),
	}
}

func runCredentialExtensionTest(
	t *testing.T,
	device *credentialExtensionTestDevice,
	test conformance.Test,
) conformance.SuiteResult {
	t.Helper()
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "credential-extension-test",
		Name:  "Credential extension test",
		Tests: []conformance.Test{test},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func requireCredentialExtensionPassed(t testing.TB, result conformance.SuiteResult) {
	t.Helper()
	if result.Status != conformance.StatusPassed || len(result.Tests) != 1 ||
		result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
}

func TestCredentialExtensionFixtureAcceptsProtocolOneTokenLengths(t *testing.T) {
	for _, tokenLength := range []int{16, 32} {
		t.Run(fmt.Sprintf("%d bytes", tokenLength), func(t *testing.T) {
			device := newCredentialExtensionTestDevice(t)
			device.tokenProtocol = protocol.PinUvAuthProtocolOne
			device.tokenLength = tokenLength
			device.info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{
				protocol.PinUvAuthProtocolOne,
			}
			config := device.config()
			result := runCredentialExtensionTest(t, device, thirdPartyPaymentTests(config)[1])
			requireCredentialExtensionPassed(t, result)
			device.assertOwnedBuffersWiped(t)
		})
	}
	for _, testCase := range []struct {
		name        string
		protocol    protocol.PinUvAuthProtocol
		tokenLength int
	}{
		{name: "protocol one short", protocol: protocol.PinUvAuthProtocolOne, tokenLength: 15},
		{name: "protocol one long", protocol: protocol.PinUvAuthProtocolOne, tokenLength: 48},
		{name: "protocol two short", protocol: protocol.PinUvAuthProtocolTwo, tokenLength: 16},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newCredentialExtensionTestDevice(t)
			device.tokenProtocol = testCase.protocol
			device.tokenLength = testCase.tokenLength
			device.info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{testCase.protocol}
			config := device.config()
			result := runCredentialExtensionTest(t, device, thirdPartyPaymentTests(config)[1])
			if result.Status != conformance.StatusError {
				t.Fatalf("status = %s, want environment error", result.Status)
			}
			device.assertOwnedBuffersWiped(t)
		})
	}
}

func TestCredentialExtensionFixtureClassifiesMissingEnvironmentAndApplicability(t *testing.T) {
	device := newCredentialExtensionTestDevice(t)
	test := credBlobTests(Config{Featureful: true})[1]
	result := runCredentialExtensionTest(t, device, test)
	if result.Status != conformance.StatusError {
		t.Fatalf("missing environment status = %s, want error", result.Status)
	}
	if device.resetCalls != 0 {
		t.Fatalf("missing environment reset calls = %d", device.resetCalls)
	}

	device = newCredentialExtensionTestDevice(t)
	device.info.Extensions = slices.DeleteFunc(
		device.info.Extensions,
		func(identifier extension.ExtensionIdentifier) bool {
			return identifier == extension.ExtensionIdentifierCredentialBlob
		},
	)
	config := device.config()
	config.Featureful = false
	result = runCredentialExtensionTest(t, device, credBlobTests(config)[1])
	if result.Status != conformance.StatusSkipped || device.resetCalls != 0 {
		t.Fatalf("inapplicable result/reset = %s/%d", result.Status, device.resetCalls)
	}
}

func TestCredentialExtensionFixtureWipesPartialDecodedResponses(t *testing.T) {
	fields := map[uint64]cbor.RawMessage{
		1: marshalGetAssertionFixture(t, map[string]any{"id": []byte{0x41}}),
		2: marshalGetAssertionFixture(t, []byte{0x42}),
	}
	response := protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: []byte{0x43},
		Signature:   []byte{0x44},
		Credential: credential.PublicKeyCredentialDescriptor{
			ID: []byte{0x45},
		},
	}
	fieldAliases := []cbor.RawMessage{fields[1], fields[2]}
	dataAlias := response.AuthDataRaw
	signatureAlias := response.Signature
	credentialAlias := response.Credential.ID
	result := credentialExtensionAssertion{Fields: fields, Response: response}
	result.clear()
	for index, alias := range append(fieldAliases, dataAlias, signatureAlias, credentialAlias) {
		if slices.ContainsFunc(alias, func(value byte) bool { return value != 0 }) {
			t.Fatalf("retained partial response alias %d was not wiped: %x", index, alias)
		}
	}
}

func TestCredentialExtensionTestDeviceSanity(t *testing.T) {
	device := newCredentialExtensionTestDevice(t)
	if device.info.MaxCredBlobLength != 64 || len(device.info.Extensions) != 4 {
		t.Fatalf("device info = %#v", device.info)
	}
	if credentialExtensionPublicKey()[cose.KeyParameterAlg] != cose.AlgorithmES256 {
		t.Fatalf("test public key = %#v", credentialExtensionPublicKey())
	}
}

var _ ctaptransport.CBOR = (*credentialExtensionTestDevice)(nil)
