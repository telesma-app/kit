package ctap23

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestHMACSecretApplicabilityRequiresFeatureAndClassifiesProtocolOneProfile(t *testing.T) {
	fields := map[uint64]cbor.RawMessage{2: {0x81, 0x6b}}
	supported := protocol.AuthenticatorGetInfoResponse{
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
	}
	if err := hmacSecretApplicability(fields, supported, Config{}); err != nil {
		t.Fatalf("supported profile: %v", err)
	}

	missingFeature := supported
	missingFeature.Extensions = nil
	var failure *conformance.AssertionError
	if err := hmacSecretApplicability(fields, missingFeature, Config{}); err == nil || !errors.As(err, &failure) {
		t.Fatalf("missing hmac-secret error = %T %v, want conformance failure", err, err)
	}

	missingProtocol := supported
	missingProtocol.PinUvAuthProtocols = nil
	var skip *conformance.SkipError
	if err := hmacSecretApplicability(fields, missingProtocol, Config{}); err == nil || !errors.As(err, &skip) {
		t.Fatalf("non-featureful error = %T %v, want skip", err, err)
	}
	if err := hmacSecretApplicability(fields, missingProtocol, Config{
		Featureful: true,
		Transport:  AuthenticatorTransportNFC,
	}); err == nil || !errors.As(err, &skip) {
		t.Fatalf("featureful NFC error = %T %v, want skip", err, err)
	}
	if err := hmacSecretApplicability(fields, missingProtocol, Config{
		Featureful: true,
		Transport:  AuthenticatorTransportHID,
	}); err == nil || !errors.As(err, &failure) {
		t.Fatalf("featureful HID error = %T %v, want conformance failure", err, err)
	}
	if err := hmacSecretApplicability(fields, missingProtocol, Config{
		Featureful: true,
		Transport:  "future",
	}); err == nil || errors.As(err, &failure) || errors.As(err, &skip) {
		t.Fatalf("unknown transport error = %T %v, want execution error", err, err)
	}
}

func TestHMACSecretRequestAndSecretBufferContracts(t *testing.T) {
	request := hmacSecretMakeCredentialRequest(
		"fixture",
		"fixture.ctap23-conformance.example",
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		true,
	)
	if !request.Options[protocol.OptionResidentKeys] ||
		!request.Extensions.CreateHMACSecretInput.HMACSecret ||
		request.Extensions.CreateCredProtectInput.CredProtect != 1 {
		t.Fatalf("MakeCredential request = %#v", request)
	}
	if len(request.ClientDataHash) != 32 || len(request.User.ID) != 16 {
		t.Fatalf("deterministic request hash/user lengths = %d/%d", len(request.ClientDataHash), len(request.User.ID))
	}

	firstSalt := hmacSecretSalt("fixture")
	secondSalt := hmacSecretSalt("fixture")
	otherSalt := hmacSecretSalt("other")
	if len(firstSalt) != 32 || !bytes.Equal(firstSalt, secondSalt) || bytes.Equal(firstSalt, otherSalt) {
		t.Fatal("deterministic salt contract is not preserved")
	}
	clear(firstSalt)
	clear(secondSalt)
	clear(otherSalt)

	plaintext := bytes.Repeat([]byte{0x71}, 64)
	outputs := hmacSecretOutputs{First: plaintext[:32], Second: plaintext[32:]}
	outputs.clear()
	if !bytes.Equal(plaintext, make([]byte, len(plaintext))) || outputs.First != nil || outputs.Second != nil {
		t.Fatal("hmac-secret outputs were not wiped and released")
	}

	envelope := hmacSecretEnvelope{
		input: protocol.HMACSecret{
			SaltEnc:           bytes.Repeat([]byte{0x72}, 32),
			SaltAuth:          bytes.Repeat([]byte{0x73}, 16),
			PinUvAuthProtocol: hmacSecretProtocol,
		},
		sharedSecret: bytes.Repeat([]byte{0x74}, 32),
	}
	saltEnc := envelope.input.SaltEnc
	saltAuth := envelope.input.SaltAuth
	sharedSecret := envelope.sharedSecret
	envelope.clear()
	if envelope.input.PinUvAuthProtocol != hmacSecretProtocol {
		t.Fatal("clearing secret material changed the public protocol selection")
	}
	if !allZeroHMACSecret(saltEnc) || !allZeroHMACSecret(saltAuth) || !allZeroHMACSecret(sharedSecret) {
		t.Fatal("encrypted HMAC fixture material was not wiped")
	}
}

func TestHMACSecretProtocolOneWirePresenceFollowsSource(t *testing.T) {
	storedCredential := hmacSecretCredential{
		ID:   []byte{0x01},
		RPID: "fixture.ctap23-conformance.example",
	}
	tests := []struct {
		name         string
		wireProtocol protocol.PinUvAuthProtocol
		wantPresent  bool
	}{
		{name: "implicit", wireProtocol: hmacSecretProtocolOmitted},
		{name: "explicit", wireProtocol: hmacSecretProtocol, wantPresent: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := hmacSecretGetAssertionRequest(storedCredential, protocol.HMACSecret{
				SaltEnc:           bytes.Repeat([]byte{0x61}, 32),
				SaltAuth:          bytes.Repeat([]byte{0x62}, 16),
				PinUvAuthProtocol: test.wireProtocol,
			})
			fields := ctap2WireFields("hmac-secret protocol field test", request)
			defer clearCTAP2WireValue(fields)

			extensions, ok := fields[4].(map[string]any)
			if !ok {
				t.Fatalf("extensions = %T, want map", fields[4])
			}
			hmacInput, ok := extensions[string(extension.ExtensionIdentifierHMACSecret)].(map[uint64]any)
			if !ok {
				t.Fatalf("hmac-secret input = %T, want integer-keyed map", extensions[string(extension.ExtensionIdentifierHMACSecret)])
			}
			value, present := hmacInput[4]
			if present != test.wantPresent {
				t.Fatalf("pinUvAuthProtocol present = %t, want %t", present, test.wantPresent)
			}
			if test.wantPresent && value != uint64(hmacSecretProtocol) {
				t.Fatalf("pinUvAuthProtocol = %#v, want %d", value, hmacSecretProtocol)
			}
		})
	}
}

func TestExpectHMACSecretInvalidSaltResponseWipesUnexpectedSuccess(t *testing.T) {
	data := bytes.Repeat([]byte{0x71}, 64)
	response := ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       data,
	}
	if err := expectHMACSecretInvalidSaltResponse(response, nil); err == nil {
		t.Fatal("unexpected success was accepted")
	}
	if !allZeroHMACSecret(data) {
		t.Fatal("unexpected successful hmac-secret response data was not wiped")
	}
}

func TestHMACSecretCasesExecuteProtocolOneTranscripts(t *testing.T) {
	tests := []struct {
		id                       conformance.TestID
		wantDiscoverable         []bool
		wantProtocolFieldPresent []bool
	}{
		{id: TestIDHMACSecretP1, wantDiscoverable: []bool{false, true}},
		{
			id:                       TestIDHMACSecretP2,
			wantDiscoverable:         []bool{false, true},
			wantProtocolFieldPresent: []bool{false, false, true, false, false, true},
		},
		{
			id:                       TestIDHMACSecretP3,
			wantDiscoverable:         []bool{false, true},
			wantProtocolFieldPresent: []bool{true, true, true, true},
		},
		{id: TestIDHMACSecretF1, wantDiscoverable: []bool{false, true}},
		{
			id:                       TestIDHMACSecretF2,
			wantDiscoverable:         []bool{false, true},
			wantProtocolFieldPresent: []bool{true, true},
		},
		{
			id:                       TestIDHMACSecretF3,
			wantDiscoverable:         []bool{false, true},
			wantProtocolFieldPresent: []bool{true, true},
		},
	}

	for _, testCase := range tests {
		t.Run(string(testCase.id), func(t *testing.T) {
			device := newHMACSecretExecutionDevice(t)
			result := runHMACSecretExecutionTest(t, device, hmacSecretExecutionConfig(device), testCase.id)

			assertHMACSecretExecutionStatus(t, result, conformance.StatusPassed)
			if !slices.Equal(device.discoverableRequests, testCase.wantDiscoverable) {
				t.Fatalf("discoverable requests = %v, want %v", device.discoverableRequests, testCase.wantDiscoverable)
			}
			if !slices.Equal(device.protocolFieldPresent, testCase.wantProtocolFieldPresent) {
				t.Fatalf("hmac-secret key 4 presence = %v, want %v", device.protocolFieldPresent, testCase.wantProtocolFieldPresent)
			}
			if device.base.setPINCalls != 1 {
				t.Fatalf("setPIN calls = %d, want 1", device.base.setPINCalls)
			}
			if device.permissionTokenCalls == 0 {
				t.Fatal("case did not obtain a PIN/UV protocol 1 permission token")
			}
			if device.powerCycles != 4 || device.resets != 2 {
				t.Fatalf("power cycles/resets = %d/%d, want 4/2", device.powerCycles, device.resets)
			}
		})
	}
}

func TestHMACSecretAlwaysUVSkipsNoUVCasesAfterLifecycleSetup(t *testing.T) {
	for _, id := range []conformance.TestID{TestIDHMACSecretP2, TestIDHMACSecretP3} {
		t.Run(string(id), func(t *testing.T) {
			device := newHMACSecretExecutionDevice(t)
			device.alwaysUV = true
			result := runHMACSecretExecutionTest(t, device, hmacSecretExecutionConfig(device), id)

			assertHMACSecretExecutionStatus(t, result, conformance.StatusSkipped)
			if len(device.discoverableRequests) != 0 || len(device.protocolFieldPresent) != 0 {
				t.Fatalf("skipped case mutated credential state: mc=%v ga=%v", device.discoverableRequests, device.protocolFieldPresent)
			}
			if device.powerCycles != 4 || device.resets != 2 {
				t.Fatalf("power cycles/resets = %d/%d, want 4/2", device.powerCycles, device.resets)
			}
		})
	}
}

func TestHMACSecretEnvironmentFailureDoesNotMutateAuthenticator(t *testing.T) {
	device := newHMACSecretExecutionDevice(t)
	result := runHMACSecretExecutionTest(t, device, Config{}, TestIDHMACSecretP1)

	assertHMACSecretExecutionStatus(t, result, conformance.StatusError)
	if device.resets != 0 || device.powerCycles != 0 || device.base.setPINCalls != 0 ||
		len(device.discoverableRequests) != 0 {
		t.Fatalf("environment failure mutated authenticator: resets=%d cycles=%d setPIN=%d mc=%v",
			device.resets, device.powerCycles, device.base.setPINCalls, device.discoverableRequests)
	}
}

func TestHMACSecretMalformedMakeCredentialClassifiesAllResponseKinds(t *testing.T) {
	tests := []struct {
		name       string
		mode       hmacSecretNegativeMode
		wantStatus conformance.Status
	}{
		{name: "ctap-error", mode: hmacSecretNegativeCTAPError, wantStatus: conformance.StatusPassed},
		{name: "unexpected-success", mode: hmacSecretNegativeSuccess, wantStatus: conformance.StatusFailed},
		{name: "transport-error", mode: hmacSecretNegativeTransportError, wantStatus: conformance.StatusError},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			device := newHMACSecretExecutionDevice(t)
			device.makeCredentialNegative = testCase.mode
			result := runHMACSecretExecutionTest(
				t,
				device,
				hmacSecretExecutionConfig(device),
				TestIDHMACSecretF1,
			)

			assertHMACSecretExecutionStatus(t, result, testCase.wantStatus)
			if testCase.mode != hmacSecretNegativeCTAPError && !allZeroHMACSecret(device.retainedResponseData) {
				t.Fatal("malformed MakeCredential response data was retained")
			}
		})
	}
}

func TestHMACSecretMalformedGetAssertionRequiresExactStatus(t *testing.T) {
	for _, id := range []conformance.TestID{TestIDHMACSecretF2, TestIDHMACSecretF3} {
		t.Run(string(id)+"/exact", func(t *testing.T) {
			device := newHMACSecretExecutionDevice(t)
			result := runHMACSecretExecutionTest(t, device, hmacSecretExecutionConfig(device), id)
			assertHMACSecretExecutionStatus(t, result, conformance.StatusPassed)
		})
		t.Run(string(id)+"/wrong", func(t *testing.T) {
			device := newHMACSecretExecutionDevice(t)
			device.invalidSaltStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			result := runHMACSecretExecutionTest(t, device, hmacSecretExecutionConfig(device), id)
			assertHMACSecretExecutionStatus(t, result, conformance.StatusFailed)
		})
	}
}

func TestHMACSecretAuthorizationAccepts16ByteTokenAndRejectsOtherLengths(t *testing.T) {
	for _, testCase := range []struct {
		length     int
		wantStatus conformance.Status
	}{
		{length: 16, wantStatus: conformance.StatusPassed},
		{length: 48, wantStatus: conformance.StatusFailed},
		{length: 32, wantStatus: conformance.StatusPassed},
	} {
		t.Run(fmt.Sprintf("%d", testCase.length), func(t *testing.T) {
			device := newHMACSecretExecutionDevice(t)
			device.tokenLength = testCase.length
			result := runHMACSecretExecutionTest(
				t,
				device,
				hmacSecretExecutionConfig(device),
				TestIDHMACSecretP1,
			)

			assertHMACSecretExecutionStatus(t, result, testCase.wantStatus)
		})
	}
}

func TestHMACSecretMalformedWireBuffersAreWiped(t *testing.T) {
	request := hmacSecretMakeCredentialRequest(
		"wipe",
		"wipe.ctap23-conformance.example",
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		true,
	)
	request.PinUvAuthParam = bytes.Repeat([]byte{0x51}, 16)
	fields := ctap2WireFields("hmac-secret malformed wire wipe", request)
	retainedPINParam := fields[8].([]byte)
	fields[6] = map[string]any{
		string(extension.ExtensionIdentifierHMACSecret): []byte{0x61, 0x62, 0x63},
	}
	retainedExtension := fields[6].(map[string]any)[string(extension.ExtensionIdentifierHMACSecret)].([]byte)

	clearCTAP2WireValue(fields)

	if !allZeroHMACSecret(retainedPINParam) || !allZeroHMACSecret(retainedExtension) {
		t.Fatal("malformed MakeCredential wire fields retained cloned secret buffers")
	}
}

func TestClearHMACSecretGetAssertionResponseWipesAllRetainedBuffers(t *testing.T) {
	credentialID := bytes.Repeat([]byte{0x41}, 16)
	authDataRaw := bytes.Repeat([]byte{0x42}, 37)
	signature := bytes.Repeat([]byte{0x43}, 16)
	largeBlobKey := bytes.Repeat([]byte{0x44}, 32)
	userID := bytes.Repeat([]byte{0x45}, 16)
	rpIDHash := bytes.Repeat([]byte{0x46}, 32)
	hmacOutput := bytes.Repeat([]byte{0x47}, 64)
	credBlob := bytes.Repeat([]byte{0x48}, 16)
	unsignedOutput := bytes.Repeat([]byte{0x49}, 16)
	response := protocol.AuthenticatorGetAssertionResponse{
		Credential:   credential.PublicKeyCredentialDescriptor{ID: credentialID},
		AuthDataRaw:  authDataRaw,
		Signature:    signature,
		LargeBlobKey: largeBlobKey,
		User:         &credential.PublicKeyCredentialUserEntity{ID: userID},
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierLargeBlob: unsignedOutput,
		},
		AuthData: &protocol.GetAssertionAuthData{
			RPIDHash: rpIDHash,
			Extensions: &protocol.GetExtensionOutputs{
				GetCredBlobOutput:   protocol.GetCredBlobOutput{CredBlob: credBlob},
				GetHMACSecretOutput: protocol.GetHMACSecretOutput{HMACSecret: hmacOutput},
			},
		},
	}

	clearHMACSecretGetAssertionResponse(&response)

	for name, retained := range map[string][]byte{
		"credential ID":   credentialID,
		"authData":        authDataRaw,
		"signature":       signature,
		"largeBlobKey":    largeBlobKey,
		"user ID":         userID,
		"RP ID hash":      rpIDHash,
		"HMAC output":     hmacOutput,
		"credBlob":        credBlob,
		"unsigned output": unsignedOutput,
	} {
		if !allZeroHMACSecret(retained) {
			t.Fatalf("%s retained: %x", name, retained)
		}
	}
	if response.AuthData != nil || response.User.ID != nil || response.Credential.ID != nil ||
		response.AuthDataRaw != nil || response.Signature != nil || response.LargeBlobKey != nil ||
		response.UnsignedExtensionOutputs != nil {
		t.Fatalf("cleared response retained live references: %#v", response)
	}
}

func TestDecodeHMACSecretGetAssertionResponseRejectsPartialAndInvalidAuthData(t *testing.T) {
	partial, err := ctap2EncMode.Marshal(map[uint64]any{
		1: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   bytes.Repeat([]byte{0x51}, 16),
		},
		2: bytes.Repeat([]byte{0x52}, 37),
		3: bytes.Repeat([]byte{0x53}, 16),
		4: "not-a-user-entity",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHMACSecretGetAssertionResponse(partial); err == nil {
		t.Fatal("partial GetAssertion response decode was accepted")
	}

	invalidAuthData, err := ctap2EncMode.Marshal(map[uint64]any{
		1: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   bytes.Repeat([]byte{0x61}, 16),
		},
		2: []byte{0x62},
		3: bytes.Repeat([]byte{0x63}, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHMACSecretGetAssertionResponse(invalidAuthData); err == nil {
		t.Fatal("GetAssertion response with invalid authData was accepted")
	}
}

func TestRequireHMACSecretOutputsUsesRawPresenceTypeAndCanonicalValue(t *testing.T) {
	makeCredential := hmacSecretMakeCredentialResponse(t, true)
	if err := requireHMACSecretCreateOutput(makeCredential); err != nil {
		t.Fatal(err)
	}
	makeCredential = hmacSecretMakeCredentialResponse(t, false)
	if err := requireHMACSecretCreateOutput(makeCredential); err == nil {
		t.Fatal("accepted false MakeCredential hmac-secret output")
	}

	want := bytes.Repeat([]byte{0x51}, 32)
	getAssertion := hmacSecretGetAssertionResponse(t, want)
	got, err := requireHMACSecretGetOutput(getAssertion)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("GetAssertion hmac-secret output = %x, want %x", got, want)
	}

	getAssertion.AuthData.Extensions.GetHMACSecretOutput.HMACSecret[0] ^= 0xff
	if _, err := requireHMACSecretGetOutput(getAssertion); err == nil {
		t.Fatal("accepted typed GetAssertion output that differs from the wire")
	}
}

func hmacSecretMakeCredentialResponse(
	t testing.TB,
	value bool,
) protocol.AuthenticatorMakeCredentialResponse {
	t.Helper()

	authData := getAssertionFixtureMakeCredentialAuthData(t, bytes.Repeat([]byte{0x41}, 32))
	authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
	authData = append(authData, marshalGetAssertionFixture(t, map[string]any{"hmac-secret": value})...)
	parsed, err := protocol.ParseMakeCredentialAuthData(authData)
	if err != nil {
		t.Fatal(err)
	}

	return protocol.AuthenticatorMakeCredentialResponse{AuthDataRaw: authData, AuthData: &parsed}
}

func hmacSecretGetAssertionResponse(
	t testing.TB,
	value []byte,
) protocol.AuthenticatorGetAssertionResponse {
	t.Helper()

	authData := getAssertionFixtureAuthData()
	authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
	authData = append(authData, marshalGetAssertionFixture(t, map[string]any{"hmac-secret": value})...)
	parsed, err := protocol.ParseGetAssertionAuthData(authData)
	if err != nil {
		t.Fatal(err)
	}

	return protocol.AuthenticatorGetAssertionResponse{AuthDataRaw: authData, AuthData: &parsed}
}

func allZeroHMACSecret(value []byte) bool {
	return bytes.Equal(value, make([]byte, len(value)))
}

type hmacSecretNegativeMode uint8

const (
	hmacSecretNegativeCTAPError hmacSecretNegativeMode = iota
	hmacSecretNegativeSuccess
	hmacSecretNegativeTransportError
)

type hmacSecretExecutionCredential struct {
	id              []byte
	rpID            string
	discoverable    bool
	withoutUVSecret []byte
	withUVSecret    []byte
}

type hmacSecretExecutionDevice struct {
	t                      testing.TB
	base                   *clientPIN1NewPINDevice
	credentials            map[string]hmacSecretExecutionCredential
	currentToken           []byte
	currentPermission      protocol.Permission
	currentRPID            string
	tokenLength            int
	tokenSequence          byte
	permissionTokenCalls   int
	discoverableRequests   []bool
	protocolFieldPresent   []bool
	makeCredentialNegative hmacSecretNegativeMode
	invalidSaltStatus      ctaptransport.StatusCode
	retainedResponseData   []byte
	alwaysUV               bool
	powerCycles            int
	resets                 int
	makeCredentialSequence byte
	advertisedProtocols    []protocol.PinUvAuthProtocol
	hmacSecretMCSupported  bool
	makeCredUvNotRqd       bool
	makeCredentialRecords  []hmacSecretExecutionRecord
	getAssertionRecords    []hmacSecretExecutionRecord
	protocolTwoIVs         [][]byte
}

type hmacSecretExecutionRecord struct {
	protocol     protocol.PinUvAuthProtocol
	discoverable bool
	verified     bool
	makeOutput   bool
	saltLength   int
}

func newHMACSecretExecutionDevice(t testing.TB) *hmacSecretExecutionDevice {
	t.Helper()

	return &hmacSecretExecutionDevice{
		t:                 t,
		base:              newClientPIN1NewPINDevice(t),
		credentials:       make(map[string]hmacSecretExecutionCredential),
		tokenLength:       16,
		invalidSaltStatus: ctaptransport.CTAP1_ERR_INVALID_PARAMETER,
		advertisedProtocols: []protocol.PinUvAuthProtocol{
			protocol.PinUvAuthProtocolOne,
		},
	}
}

func (device *hmacSecretExecutionDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		device.t.Fatal("empty CTAP request")
	}

	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		return device.getInfoResponse(), nil
	case protocol.AuthenticatorClientPIN:
		return device.clientPINResponse(request[1:])
	case protocol.AuthenticatorMakeCredential:
		return device.makeCredentialResponse(request[1:])
	case protocol.AuthenticatorGetAssertion:
		return device.getAssertionResponse(request[1:])
	default:
		device.t.Fatalf("unexpected hmac-secret command %s", protocol.Command(request[0]))

		return ctaptransport.CBORResponse{}, nil
	}
}

func (device *hmacSecretExecutionDevice) getInfoResponse() ctaptransport.CBORResponse {
	response := device.base.getInfoResponse()
	var info protocol.AuthenticatorGetInfoResponse
	if err := getInfoDecMode.Unmarshal(response.Data, &info); err != nil {
		device.t.Fatal(err)
	}
	clear(response.Data)
	info.PinUvAuthProtocols = slices.Clone(device.advertisedProtocols)
	if device.hmacSecretMCSupported {
		info.Extensions = append(info.Extensions, extension.ExtensionIdentifierHMACSecretMC)
	}
	if device.alwaysUV {
		info.Options[protocol.OptionAlwaysUv] = true
	}
	if device.makeCredUvNotRqd {
		info.Options[protocol.OptionMakeCredentialUvNotRequired] = true
	}

	return device.base.success(info)
}

func (device *hmacSecretExecutionDevice) clientPINResponse(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	var request protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatalf("decode hmac-secret ClientPIN request: %v", err)
	}
	if !slices.Contains(device.advertisedProtocols, request.PinUvAuthProtocol) {
		device.t.Fatalf("ClientPIN protocol = %d, advertised %v", request.PinUvAuthProtocol, device.advertisedProtocols)
	}
	device.base.clientPINProtocols = append(device.base.clientPINProtocols, request.PinUvAuthProtocol)

	switch request.SubCommand {
	case protocol.ClientPINSubCommandGetKeyAgreement:
		return device.base.success(map[uint64]any{1: device.base.publicKey}), nil
	case protocol.ClientPINSubCommandSetPIN:
		device.base.setPINCalls++
		sharedSecret := device.sharedSecret(request.PinUvAuthProtocol, request.KeyAgreement)
		defer clear(sharedSecret)
		wantAuth := ctapcrypto.Authenticate(request.PinUvAuthProtocol, sharedSecret, request.NewPinEnc)
		defer clear(wantAuth)
		if !bytes.Equal(request.PinUvAuthParam, wantAuth) {
			device.t.Fatal("setPIN pinUvAuthParam does not authenticate newPinEnc")
		}
		plaintext := device.decrypt(request.PinUvAuthProtocol, sharedSecret, request.NewPinEnc)
		defer clear(plaintext)
		length := bytes.IndexByte(plaintext, 0)
		if length < 0 {
			device.t.Fatal("setPIN plaintext has no zero padding")
		}
		clear(device.base.pin)
		device.base.pin = slices.Clone(plaintext[:length])

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions:
		return device.permissionTokenResponse(request)
	default:
		device.t.Fatalf("unexpected hmac-secret ClientPIN subcommand %s", request.SubCommand)

		return ctaptransport.CBORResponse{}, nil
	}
}

func (device *hmacSecretExecutionDevice) permissionTokenResponse(
	request protocol.AuthenticatorClientPINRequest,
) (ctaptransport.CBORResponse, error) {
	device.permissionTokenCalls++
	if request.Permissions != protocol.PermissionMakeCredential &&
		request.Permissions != protocol.PermissionGetAssertion {
		device.t.Fatalf("permission-token permission = %s", request.Permissions)
	}
	if request.RPID == "" {
		device.t.Fatal("permission token is not RP-scoped")
	}

	sharedSecret := device.sharedSecret(request.PinUvAuthProtocol, request.KeyAgreement)
	decryptedPINHash := device.decrypt(request.PinUvAuthProtocol, sharedSecret, request.PinHashEnc)
	if !bytes.Equal(decryptedPINHash, device.base.pinHash()) {
		device.t.Fatal("permission-token PIN hash does not match the configured PIN")
	}
	clear(decryptedPINHash)

	clear(device.currentToken)
	device.tokenSequence++
	tokenLength := device.tokenLength
	if request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo {
		tokenLength = 32
	}
	device.currentToken = bytes.Repeat([]byte{0x80 + device.tokenSequence}, tokenLength)
	device.currentPermission = request.Permissions
	device.currentRPID = request.RPID
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(request.PinUvAuthProtocol)
	if err != nil {
		device.t.Fatal(err)
	}
	encrypted, err := pinProtocol.Encrypt(sharedSecret, device.currentToken)
	clear(sharedSecret)
	if err != nil {
		device.t.Fatal(err)
	}

	return device.base.success(map[uint64]any{2: encrypted}), nil
}

func (device *hmacSecretExecutionDevice) makeCredentialResponse(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatalf("decode hmac-secret MakeCredential fields: %v", err)
	}
	defer clearCTAP2RawFields(fields)

	var options map[protocol.Option]bool
	if raw := fields[7]; raw != nil {
		if err := getInfoDecMode.Unmarshal(raw, &options); err != nil {
			device.t.Fatal(err)
		}
	}
	discoverable := options[protocol.OptionResidentKeys]
	device.discoverableRequests = append(device.discoverableRequests, discoverable)
	var clientDataHash []byte
	if err := getInfoDecMode.Unmarshal(fields[1], &clientDataHash); err != nil {
		device.t.Fatal(err)
	}
	defer clear(clientDataHash)
	var rp credential.PublicKeyCredentialRpEntity
	if err := getInfoDecMode.Unmarshal(fields[2], &rp); err != nil {
		device.t.Fatal(err)
	}
	var authParam []byte
	if raw := fields[8]; raw != nil {
		if err := getInfoDecMode.Unmarshal(raw, &authParam); err != nil {
			device.t.Fatal(err)
		}
		defer clear(authParam)
	}
	var authProtocol protocol.PinUvAuthProtocol
	if raw := fields[9]; raw != nil {
		if err := getInfoDecMode.Unmarshal(raw, &authProtocol); err != nil {
			device.t.Fatal(err)
		}
	}
	if len(authParam) != 0 {
		device.requirePermissionAuthorization(
			protocol.PermissionMakeCredential,
			rp.ID,
			clientDataHash,
			authProtocol,
			authParam,
		)
	}

	var extensions map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[6], &extensions); err != nil {
		device.t.Fatalf("decode hmac-secret MakeCredential extensions: %v", err)
	}
	defer clearAuthDataExtensionValues(extensions)
	hmacInput, present := extensions[string(extension.ExtensionIdentifierHMACSecret)]
	mcInput, mcPresent := extensions[string(extension.ExtensionIdentifierHMACSecretMC)]
	if !present {
		if mcPresent {
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_MISSING_PARAMETER}, nil
		}
		device.t.Fatal("MakeCredential omitted hmac-secret")
	}
	if !hasCBORMajorType(hmacInput, 7) {
		return device.malformedMakeCredentialResponse()
	}
	var hmacEnabled bool
	if err := getInfoDecMode.Unmarshal(hmacInput, &hmacEnabled); err != nil || !hmacEnabled {
		return device.malformedMakeCredentialResponse()
	}

	var mcEnvelope protocol.HMACSecret
	if mcPresent {
		if err := getInfoDecMode.Unmarshal(mcInput, &mcEnvelope); err != nil {
			return device.malformedMakeCredentialResponse()
		}
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatalf("decode hmac-secret MakeCredential request: %v", err)
	}
	if !request.Extensions.CreateHMACSecretInput.HMACSecret {
		device.t.Fatalf("MakeCredential extensions = %#v", request.Extensions)
	}
	verified := len(request.PinUvAuthParam) != 0

	var saltPlaintext []byte
	var sharedSecret []byte
	if mcPresent {
		sharedSecret = device.validateHMACEnvelope(mcEnvelope)
		defer clear(sharedSecret)
		saltPlaintext = device.decrypt(mcEnvelope.PinUvAuthProtocol, sharedSecret, mcEnvelope.SaltEnc)
		defer clear(saltPlaintext)
		if len(saltPlaintext) != 32 && len(saltPlaintext) != 64 {
			return ctaptransport.CBORResponse{StatusCode: device.invalidSaltStatus}, nil
		}
	}
	recordProtocol := request.PinUvAuthProtocol
	if mcPresent {
		recordProtocol = mcEnvelope.PinUvAuthProtocol
	}
	device.makeCredentialRecords = append(device.makeCredentialRecords, hmacSecretExecutionRecord{
		protocol:     recordProtocol,
		discoverable: discoverable,
		verified:     verified,
		makeOutput:   mcPresent,
		saltLength:   len(saltPlaintext),
	})

	device.makeCredentialSequence++
	credentialIDHash := sha256.Sum256([]byte(fmt.Sprintf(
		"hmac-secret credential %d %s",
		device.makeCredentialSequence,
		request.RP.ID,
	)))
	credentialID := slices.Clone(credentialIDHash[:16])
	withoutUVHash := sha256.Sum256([]byte(fmt.Sprintf(
		"hmac-secret credential %d without UV %s", device.makeCredentialSequence, request.RP.ID,
	)))
	withUVHash := sha256.Sum256([]byte(fmt.Sprintf(
		"hmac-secret credential %d with UV %s", device.makeCredentialSequence, request.RP.ID,
	)))
	device.credentials[string(credentialID)] = hmacSecretExecutionCredential{
		id:              credentialID,
		rpID:            request.RP.ID,
		discoverable:    discoverable,
		withoutUVSecret: slices.Clone(withoutUVHash[:]),
		withUVSecret:    slices.Clone(withUVHash[:]),
	}

	authData := clientPIN1NewPINMakeCredentialAuthData(
		device.t,
		protocol.AuthDataFlagUserPresent,
		credentialID,
	)
	if verified {
		authData[32] |= byte(protocol.AuthDataFlagUserVerified)
	}
	rpIDHash := sha256.Sum256([]byte(request.RP.ID))
	copy(authData, rpIDHash[:])
	authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
	extensionOutputs := map[string]any{
		string(extension.ExtensionIdentifierHMACSecret): true,
	}
	if mcPresent {
		stored := device.credentials[string(credentialID)]
		output := device.hmacOutputs(stored, verified, saltPlaintext)
		defer clear(output)
		pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(mcEnvelope.PinUvAuthProtocol)
		if err != nil {
			device.t.Fatal(err)
		}
		ciphertext, err := pinProtocol.Encrypt(sharedSecret, output)
		if err != nil {
			device.t.Fatal(err)
		}
		defer clear(ciphertext)
		extensionOutputs[string(extension.ExtensionIdentifierHMACSecretMC)] = ciphertext
	}
	authData = append(authData, hmacSecretExtensionsEncoding(device.t, extensionOutputs)...)

	return device.base.success(map[uint64]any{
		1: "none",
		2: authData,
		3: map[string]any{},
	}), nil
}

func (device *hmacSecretExecutionDevice) malformedMakeCredentialResponse() (
	ctaptransport.CBORResponse,
	error,
) {
	switch device.makeCredentialNegative {
	case hmacSecretNegativeCTAPError:
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_INVALID_CBOR}, nil
	case hmacSecretNegativeSuccess:
		device.retainedResponseData = bytes.Repeat([]byte{0x91}, 32)

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       device.retainedResponseData,
		}, nil
	case hmacSecretNegativeTransportError:
		device.retainedResponseData = bytes.Repeat([]byte{0x92}, 32)

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       device.retainedResponseData,
		}, errors.New("scripted hmac-secret MakeCredential transport failure")
	default:
		panic("unknown hmac-secret negative mode")
	}
}

func (device *hmacSecretExecutionDevice) getAssertionResponse(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatalf("decode hmac-secret GetAssertion fields: %v", err)
	}
	defer clearCTAP2RawFields(fields)
	var rawExtensions map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[4], &rawExtensions); err != nil {
		device.t.Fatal(err)
	}
	defer clearAuthDataExtensionValues(rawExtensions)
	var rawInput map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(
		rawExtensions[string(extension.ExtensionIdentifierHMACSecret)],
		&rawInput,
	); err != nil {
		device.t.Fatal(err)
	}
	_, protocolPresent := rawInput[4]
	device.protocolFieldPresent = append(device.protocolFieldPresent, protocolPresent)
	clearCTAP2RawFields(rawInput)

	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatalf("decode hmac-secret GetAssertion request: %v", err)
	}
	if len(request.AllowList) != 1 {
		device.t.Fatalf("allowList length = %d, want 1", len(request.AllowList))
	}
	stored, present := device.credentials[string(request.AllowList[0].ID)]
	if !present || stored.rpID != request.RPID {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS}, nil
	}

	verified := len(request.PinUvAuthParam) != 0
	if verified {
		device.requirePermissionAuthorization(
			protocol.PermissionGetAssertion,
			request.RPID,
			request.ClientDataHash,
			request.PinUvAuthProtocol,
			request.PinUvAuthParam,
		)
	}
	input := request.Extensions.GetHMACSecretInput.HMACSecret
	selectedProtocol := input.PinUvAuthProtocol
	if selectedProtocol == hmacSecretProtocolOmitted {
		selectedProtocol = protocol.PinUvAuthProtocolOne
	}
	if !slices.Contains(device.advertisedProtocols, selectedProtocol) {
		device.t.Fatalf("hmac-secret protocol = %d, advertised %v", selectedProtocol, device.advertisedProtocols)
	}
	validatedInput := input
	validatedInput.PinUvAuthProtocol = selectedProtocol
	sharedSecret := device.validateHMACEnvelope(validatedInput)
	plaintext := device.decrypt(selectedProtocol, sharedSecret, input.SaltEnc)
	defer clear(plaintext)
	if len(plaintext) != 32 && len(plaintext) != 64 {
		clear(sharedSecret)

		return ctaptransport.CBORResponse{StatusCode: device.invalidSaltStatus}, nil
	}

	output := device.hmacOutputs(stored, verified, plaintext)
	defer clear(output)
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(selectedProtocol)
	if err != nil {
		device.t.Fatal(err)
	}
	ciphertext, err := pinProtocol.Encrypt(sharedSecret, output)
	clear(sharedSecret)
	if err != nil {
		device.t.Fatal(err)
	}
	defer clear(ciphertext)
	device.getAssertionRecords = append(device.getAssertionRecords, hmacSecretExecutionRecord{
		protocol:     selectedProtocol,
		discoverable: stored.discoverable,
		verified:     verified,
		saltLength:   len(plaintext),
	})

	flags := protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagExtensionDataIncluded
	if verified {
		flags |= protocol.AuthDataFlagUserVerified
	}
	authData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte(request.RPID))
	copy(authData, rpIDHash[:])
	authData[32] = byte(flags)
	authData = append(authData, hmacSecretExtensionEncoding(device.t, ciphertext)...)

	return device.base.success(map[uint64]any{
		1: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   stored.id,
		},
		2: authData,
		3: []byte{0x30, 0x00},
	}), nil
}

func (device *hmacSecretExecutionDevice) requirePermissionAuthorization(
	permission protocol.Permission,
	rpID string,
	clientDataHash []byte,
	protocolNumber protocol.PinUvAuthProtocol,
	authParam []byte,
) {
	device.t.Helper()
	if device.currentPermission != permission || device.currentRPID != rpID {
		device.t.Fatalf(
			"authorization scope = %s/%q, want %s/%q",
			device.currentPermission,
			device.currentRPID,
			permission,
			rpID,
		)
	}
	want := ctapcrypto.Authenticate(protocolNumber, device.currentToken, clientDataHash)
	defer clear(want)
	if !slices.Contains(device.advertisedProtocols, protocolNumber) || !bytes.Equal(authParam, want) {
		device.t.Fatalf("authorization = %d/%x, want advertised protocol/%x", protocolNumber, authParam, want)
	}
}

func (device *hmacSecretExecutionDevice) validateHMACEnvelope(input protocol.HMACSecret) []byte {
	device.t.Helper()
	if !slices.Contains(device.advertisedProtocols, input.PinUvAuthProtocol) {
		device.t.Fatalf("hmac-secret envelope protocol = %d, advertised %v", input.PinUvAuthProtocol, device.advertisedProtocols)
	}
	sharedSecret := device.sharedSecret(input.PinUvAuthProtocol, input.KeyAgreement)
	wantSaltAuth := ctapcrypto.Authenticate(input.PinUvAuthProtocol, sharedSecret, input.SaltEnc)
	defer clear(wantSaltAuth)
	if !bytes.Equal(input.SaltAuth, wantSaltAuth) {
		clear(sharedSecret)
		device.t.Fatal("hmac-secret envelope saltAuth does not authenticate saltEnc")
	}
	if input.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo {
		if len(input.SaltEnc) < 16 {
			clear(sharedSecret)
			device.t.Fatal("protocol 2 saltEnc omits the 16-byte IV")
		}
		iv := slices.Clone(input.SaltEnc[:16])
		for _, previous := range device.protocolTwoIVs {
			if bytes.Equal(previous, iv) {
				clear(iv)
				clear(sharedSecret)
				device.t.Fatal("protocol 2 reused an hmac-secret IV")
			}
		}
		device.protocolTwoIVs = append(device.protocolTwoIVs, iv)
	}

	return sharedSecret
}

func (device *hmacSecretExecutionDevice) hmacOutputs(
	stored hmacSecretExecutionCredential,
	verified bool,
	salts []byte,
) []byte {
	secret := stored.withoutUVSecret
	if verified {
		secret = stored.withUVSecret
	}
	output := make([]byte, 0, len(salts))
	for offset := 0; offset < len(salts); offset += sha256.Size {
		mac := hmac.New(sha256.New, secret)
		mac.Write(salts[offset : offset+sha256.Size])
		output = mac.Sum(output)
	}

	return output
}

func (device *hmacSecretExecutionDevice) sharedSecret(
	selectedProtocol protocol.PinUvAuthProtocol,
	platformKey cose.Key,
) []byte {
	device.t.Helper()
	publicKey, err := platformKey.P256PublicKey()
	if err != nil {
		device.t.Fatal(err)
	}
	z, err := device.base.privateKey.ECDH(publicKey)
	if err != nil {
		device.t.Fatal(err)
	}
	defer clear(z)
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(selectedProtocol)
	if err != nil {
		device.t.Fatal(err)
	}
	sharedSecret, err := pinProtocol.KDF(z)
	if err != nil {
		device.t.Fatal(err)
	}

	return sharedSecret
}

func (device *hmacSecretExecutionDevice) decrypt(
	selectedProtocol protocol.PinUvAuthProtocol,
	sharedSecret []byte,
	ciphertext []byte,
) []byte {
	device.t.Helper()
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(selectedProtocol)
	if err != nil {
		device.t.Fatal(err)
	}
	plaintext, err := pinProtocol.Decrypt(sharedSecret, ciphertext)
	if err != nil {
		device.t.Fatal(err)
	}

	return plaintext
}

func (device *hmacSecretExecutionDevice) reset() {
	device.resets++
	device.base.reset()
	clear(device.currentToken)
	device.currentToken = nil
	device.currentPermission = 0
	device.currentRPID = ""
	for key, stored := range device.credentials {
		clear(stored.id)
		clear(stored.withoutUVSecret)
		clear(stored.withUVSecret)
		delete(device.credentials, key)
	}
	for _, iv := range device.protocolTwoIVs {
		clear(iv)
	}
	device.protocolTwoIVs = nil
}

func hmacSecretExtensionEncoding(t testing.TB, value any) []byte {
	t.Helper()

	return hmacSecretExtensionsEncoding(t, map[string]any{
		string(extension.ExtensionIdentifierHMACSecret): value,
	})
}

func hmacSecretExtensionsEncoding(t testing.TB, values map[string]any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func boolToUint(value bool) uint8 {
	if value {
		return 1
	}

	return 0
}

func hmacSecretExecutionConfig(device *hmacSecretExecutionDevice) Config {
	return Config{
		PowerCycler: func(context.Context) error {
			device.powerCycles++

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			device.reset()

			return nil
		},
		TemporaryPINProvider: func(context.Context, TemporaryPINRequest) ([]byte, error) {
			return []byte("1234"), nil
		},
	}
}

func runHMACSecretExecutionTest(
	t *testing.T,
	device *hmacSecretExecutionDevice,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range hmacSecretTests(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("hmac-secret test %q not found", id)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "hmac-secret-execution-test",
		Name:  "HMAC secret execution test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertHMACSecretExecutionStatus(
	t testing.TB,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()
	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}
