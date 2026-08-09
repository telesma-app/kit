package ctap23

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestLargeBlobKeyCasesPassWithIndependentLifecycleAndScopedTokens(t *testing.T) {
	want := []struct {
		id          conformance.TestID
		marker      string
		permissions []protocol.Permission
		rpIDs       []string
		operations  []string
	}{
		{TestIDLargeBlobKeyP1, "P-1", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionMakeCredential}, []string{largeBlobKeyP1RPID, largeBlobKeyP1RPID}, []string{"token:1", "makeCredential", "token:1", "makeCredential"}},
		{TestIDLargeBlobKeyP2, "P-2", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{largeBlobKeyP2RPID, largeBlobKeyP2RPID}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobKeyF1, "F-1", []protocol.Permission{protocol.PermissionMakeCredential}, []string{largeBlobKeyF1RPID}, []string{"token:1", "makeCredential"}},
		{TestIDLargeBlobKeyF2, "F-2", []protocol.Permission{protocol.PermissionMakeCredential}, []string{largeBlobKeyF2RPID}, []string{"token:1", "makeCredential"}},
		{TestIDLargeBlobKeyF3, "F-3", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{largeBlobKeyF3RPID, largeBlobKeyF3RPID}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
		{TestIDLargeBlobKeyF4, "F-4", []protocol.Permission{protocol.PermissionMakeCredential, protocol.PermissionGetAssertion}, []string{largeBlobKeyF4RPID, largeBlobKeyF4RPID}, []string{"token:1", "makeCredential", "token:2", "getAssertion"}},
	}

	for index, expected := range want {
		t.Run(expected.marker, func(t *testing.T) {
			environment := &largeBlobKeyTestEnvironment{}
			device := &largeBlobKeyTestDevice{t: t, marker: expected.marker, environment: environment}
			environment.device = device
			config := environment.config(t)

			result := runLargeBlobKeyTest(t, device, config, index)
			if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
				t.Fatalf("result = %#v, want passed", result)
			}
			testResult := result.Tests[0]
			if testResult.ID != expected.id || testResult.Source.Path != largeBlobKeySourcePath || testResult.Source.Case != expected.marker {
				t.Fatalf("source mapping = %#v", testResult)
			}
			if !testResult.Destructive || len(testResult.References) < 6 || testResult.References[0].Section != "12.3" {
				t.Fatalf("metadata = %#v", testResult)
			}
			if len(testResult.Steps) != 5 || testResult.Steps[0].ID != "large-blob-key.applicability" || testResult.Steps[1].ID != "large-blob-key.reset" || testResult.Steps[2].ID != "large-blob-key.authorization" || testResult.Steps[4].ID != "large-blob-key.cleanup" {
				t.Fatalf("steps = %#v", testResult.Steps)
			}
			for _, step := range testResult.Steps {
				if step.Status != conformance.StatusPassed {
					t.Fatalf("step = %#v, want passed", step)
				}
			}

			wantLifecycle := []string{
				"power-cycle", "reset", "power-cycle",
				"power-cycle", "reset", "power-cycle",
			}
			if !slices.Equal(environment.events, wantLifecycle) {
				t.Fatalf("lifecycle = %v, want %v", environment.events, wantLifecycle)
			}
			if !slices.Equal(device.pinUV.permissionScopes, expected.permissions) || !slices.Equal(device.pinUV.permissionRPIDs, expected.rpIDs) {
				t.Fatalf("token scopes = %v/%v, want %v/%v", device.pinUV.permissionScopes, device.pinUV.permissionRPIDs, expected.permissions, expected.rpIDs)
			}
			if !slices.Equal(device.operations, expected.operations) {
				t.Fatalf("authorization/command operations = %v, want %v", device.operations, expected.operations)
			}
			if environment.genericTokenProviderCalled {
				t.Fatal("generic TokenProvider was called")
			}
			if device.pinUV.setPINCalls != 1 || !device.pinUV.permissionWiresExact {
				t.Fatalf("exact P2 setup/token transcript = setPIN %d, exact %t", device.pinUV.setPINCalls, device.pinUV.permissionWiresExact)
			}
			if device.getInfoCalls != 3 {
				t.Fatalf("GetInfo calls = %d, want pre-reset, post-reset, and post-SetPIN reads", device.getInfoCalls)
			}
			for requestIndex, pinProtocol := range device.pinUV.pinProtocols {
				if pinProtocol != protocol.PinUvAuthProtocolTwo {
					t.Fatalf("ClientPIN request %d used protocol %d, want 2", requestIndex, pinProtocol)
				}
			}
			if !slices.Equal(device.advertisedProtocols, []protocol.PinUvAuthProtocol{
				protocol.PinUvAuthProtocolOne,
				protocol.PinUvAuthProtocolTwo,
			}) {
				t.Fatalf("advertised PIN/UV protocols = %v, want [1 2]", device.advertisedProtocols)
			}
			for pinIndex, pin := range environment.pins {
				if !allZeroLargeBlobKey(pin) {
					t.Fatalf("temporary PIN %d was not wiped: %x", pinIndex, pin)
				}
			}
			for tokenIndex, token := range device.tokenSecretBuffers {
				if !allZeroLargeBlobKey(token) {
					t.Fatalf("authenticator token %d was not wiped by cleanup: %x", tokenIndex, token)
				}
			}
			for responseIndex, responseData := range device.responseData {
				if !allZeroLargeBlobKey(responseData) {
					t.Fatalf("response buffer %d containing largeBlobKey was not wiped: %x", responseIndex, responseData)
				}
			}
			if device.makeCredentialCalls != len(slices.DeleteFunc(slices.Clone(expected.permissions), func(permission protocol.Permission) bool {
				return permission != protocol.PermissionMakeCredential
			})) {
				t.Fatalf("MakeCredential calls = %d", device.makeCredentialCalls)
			}
		})
	}
}

func TestLargeBlobKeyUsesExactProtocolTwoUVFallback(t *testing.T) {
	environment := &largeBlobKeyTestEnvironment{}
	device := &largeBlobKeyTestDevice{
		t:           t,
		marker:      "P-2",
		environment: environment,
		forceUV:     true,
	}
	environment.device = device

	result := runLargeBlobKeyTest(t, device, environment.config(t), 1)
	if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
	if environment.genericTokenProviderCalled {
		t.Fatal("generic TokenProvider was called")
	}
	if environment.uvConfiguratorCalls != 1 || device.pinUV.setPINCalls != 0 {
		t.Fatalf("UV/PIN setup calls = %d/%d, want 1/0", environment.uvConfiguratorCalls, device.pinUV.setPINCalls)
	}
	if device.getInfoCalls != 3 {
		t.Fatalf("GetInfo calls = %d, want pre-reset, post-reset, and post-UV reads", device.getInfoCalls)
	}
	if !slices.Equal(device.pinUV.permissionScopes, []protocol.Permission{
		protocol.PermissionMakeCredential,
		protocol.PermissionGetAssertion,
	}) || !slices.Equal(device.pinUV.permissionRPIDs, []string{
		largeBlobKeyP2RPID,
		largeBlobKeyP2RPID,
	}) {
		t.Fatalf("UV token scopes = %v/%v", device.pinUV.permissionScopes, device.pinUV.permissionRPIDs)
	}
	if !device.pinUV.permissionWiresExact || !device.pinUV.permissionCryptoExact {
		t.Fatal("UV permission-token transcript did not use exact protocol-2 wire/crypto")
	}
	for index, pinProtocol := range device.pinUV.pinProtocols {
		if pinProtocol != protocol.PinUvAuthProtocolTwo {
			t.Fatalf("UV ClientPIN request %d used protocol %d, want 2", index, pinProtocol)
		}
	}
	for _, pin := range environment.pins {
		if !allZeroLargeBlobKey(pin) {
			t.Fatalf("UV setup PIN was not wiped: %x", pin)
		}
	}
	for _, token := range device.tokenSecretBuffers {
		if !allZeroLargeBlobKey(token) {
			t.Fatalf("UV token was not wiped by cleanup: %x", token)
		}
	}
}

func TestLargeBlobKeyFailsWhenProtocolTwoDisappearsAfterReset(t *testing.T) {
	environment := &largeBlobKeyTestEnvironment{}
	device := &largeBlobKeyTestDevice{
		t:                t,
		marker:           "P-1",
		environment:      environment,
		dropP2AfterReset: true,
	}
	environment.device = device

	result := runLargeBlobKeyTest(t, device, environment.config(t), 0)
	if result.Status != conformance.StatusFailed || result.Tests[0].Status != conformance.StatusFailed {
		t.Fatalf("result = %#v, want failed", result)
	}
	if len(result.Tests[0].Steps) != 4 || result.Tests[0].Steps[2].ID != "large-blob-key.authorization" ||
		result.Tests[0].Steps[2].Status != conformance.StatusFailed || device.getInfoCalls != 2 {
		t.Fatalf("post-reset confirmation = steps %#v, GetInfo calls %d", result.Tests[0].Steps, device.getInfoCalls)
	}
	if len(environment.pins) != 0 || environment.genericTokenProviderCalled {
		t.Fatal("post-reset P2 failure touched authorization providers")
	}
}

func TestLargeBlobKeyApplicabilityUsesRawGetInfo(t *testing.T) {
	tests := []struct {
		name       string
		featureful bool
		extensions []string
		options    map[string]any
		protocols  []uint
		status     conformance.Status
	}{
		{
			name:       "non-featureful missing extension skips",
			extensions: nil,
			options:    map[string]any{string(protocol.OptionLargeBlobs): true},
			status:     conformance.StatusSkipped,
		},
		{
			name:       "featureful missing both extensions fails",
			featureful: true,
			extensions: nil,
			options:    map[string]any{string(protocol.OptionLargeBlobs): true},
			status:     conformance.StatusFailed,
		},
		{
			name: "mutually exclusive extensions fail",
			extensions: []string{
				string(extension.ExtensionIdentifierLargeBlobKey),
				string(extension.ExtensionIdentifierLargeBlob),
			},
			options: map[string]any{string(protocol.OptionLargeBlobs): true},
			status:  conformance.StatusFailed,
		},
		{
			name:       "missing largeBlobs option fails",
			extensions: []string{string(extension.ExtensionIdentifierLargeBlobKey)},
			status:     conformance.StatusFailed,
		},
		{
			name:       "false largeBlobs option fails",
			extensions: []string{string(extension.ExtensionIdentifierLargeBlobKey)},
			options:    map[string]any{string(protocol.OptionLargeBlobs): false},
			status:     conformance.StatusFailed,
		},
		{
			name:       "non-boolean largeBlobs option fails",
			extensions: []string{string(extension.ExtensionIdentifierLargeBlobKey)},
			options:    map[string]any{string(protocol.OptionLargeBlobs): "true"},
			status:     conformance.StatusFailed,
		},
		{
			name:       "non-featureful missing protocol two skips",
			extensions: []string{string(extension.ExtensionIdentifierLargeBlobKey)},
			options:    map[string]any{string(protocol.OptionLargeBlobs): true},
			protocols:  []uint{uint(protocol.PinUvAuthProtocolOne)},
			status:     conformance.StatusSkipped,
		},
		{
			name:       "featureful missing protocol two fails",
			featureful: true,
			extensions: []string{string(extension.ExtensionIdentifierLargeBlobKey)},
			options:    map[string]any{string(protocol.OptionLargeBlobs): true},
			protocols:  []uint{uint(protocol.PinUvAuthProtocolOne)},
			status:     conformance.StatusFailed,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			fields := largeBlobKeyTestInfoFields()
			fields[2] = testCase.extensions
			if testCase.options == nil {
				delete(fields, 4)
			} else {
				fields[4] = testCase.options
			}
			if testCase.protocols != nil {
				fields[6] = testCase.protocols
			}
			transport := newScriptedCBORTransport(t, scriptedCBORExchange{
				request: []byte{byte(protocol.AuthenticatorGetInfo)},
				response: ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP2_OK,
					Data:       marshalLargeBlobKeyTest(t, fields),
				},
			})
			environment := &largeBlobKeyTestEnvironment{}
			config := environment.config(t)
			config.Featureful = testCase.featureful

			result := runLargeBlobKeyTest(t, transport, config, 0)
			if result.Status != testCase.status || result.Tests[0].Status != testCase.status {
				t.Fatalf("result = %#v, want %s", result, testCase.status)
			}
			if len(result.Tests[0].Steps) != 1 || len(environment.events) != 0 || len(environment.pins) != 0 || environment.genericTokenProviderCalled {
				t.Fatalf("inapplicable case touched lifecycle or authorization: %#v, events=%v pins=%d generic=%t", result.Tests[0].Steps, environment.events, len(environment.pins), environment.genericTokenProviderCalled)
			}
		})
	}
}

func TestLargeBlobKeyRequiresResponseWirePresenceLengthFreshnessAndEquality(t *testing.T) {
	tests := []struct {
		name   string
		index  int
		mutate func(*largeBlobKeyTestDevice)
	}{
		{"MakeCredential field absent", 0, func(device *largeBlobKeyTestDevice) { device.omitMakeCredentialKey = true }},
		{"MakeCredential field wrong length", 0, func(device *largeBlobKeyTestDevice) { device.makeCredentialKeyLength = 31 }},
		{"MakeCredential keys reused", 0, func(device *largeBlobKeyTestDevice) { device.reuseMakeCredentialKey = true }},
		{"GetAssertion field absent", 1, func(device *largeBlobKeyTestDevice) { device.omitGetAssertionKey = true }},
		{"GetAssertion key differs", 1, func(device *largeBlobKeyTestDevice) { device.changeGetAssertionKey = true }},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			environment := &largeBlobKeyTestEnvironment{}
			marker := []string{"P-1", "P-2"}[testCase.index]
			device := &largeBlobKeyTestDevice{t: t, marker: marker, environment: environment}
			environment.device = device
			testCase.mutate(device)

			result := runLargeBlobKeyTest(t, device, environment.config(t), testCase.index)
			if result.Status != conformance.StatusFailed || result.Tests[0].Status != conformance.StatusFailed {
				t.Fatalf("result = %#v, want failed", result)
			}
		})
	}
}

func TestLargeBlobKeyClassifiesStatusAndTransportErrors(t *testing.T) {
	t.Run("wrong status fails", func(t *testing.T) {
		environment := &largeBlobKeyTestEnvironment{}
		device := &largeBlobKeyTestDevice{
			t:              t,
			marker:         "F-1",
			environment:    environment,
			negativeStatus: ctaptransport.CTAP1_ERR_INVALID_PARAMETER,
		}
		environment.device = device

		result := runLargeBlobKeyTest(t, device, environment.config(t), 2)
		if result.Status != conformance.StatusFailed || result.Tests[0].Status != conformance.StatusFailed {
			t.Fatalf("result = %#v, want failed", result)
		}
	})

	t.Run("transport error remains execution error", func(t *testing.T) {
		environment := &largeBlobKeyTestEnvironment{}
		device := &largeBlobKeyTestDevice{
			t:            t,
			marker:       "P-1",
			environment:  environment,
			commandError: errors.New("device disconnected"),
		}
		environment.device = device

		result := runLargeBlobKeyTest(t, device, environment.config(t), 0)
		if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
			t.Fatalf("result = %#v, want error", result)
		}
	})
}

type largeBlobKeyTestEnvironment struct {
	events                     []string
	pins                       [][]byte
	device                     *largeBlobKeyTestDevice
	genericTokenProviderCalled bool
	uvConfiguratorCalls        int
}

func (environment *largeBlobKeyTestEnvironment) config(t *testing.T) Config {
	t.Helper()

	return Config{
		Featureful: true,
		PowerCycler: func(context.Context) error {
			environment.events = append(environment.events, "power-cycle")

			return nil
		},
		Resetter: func(_ context.Context, ctapClient *client.Client) error {
			if ctapClient == nil {
				t.Fatal("resetter received nil client")
			}
			environment.events = append(environment.events, "reset")
			if environment.device != nil {
				environment.device.resetSecurityState()
			}

			return nil
		},
		TokenProvider: func(context.Context, *client.Client, PinUvAuthTokenRequest) (PinUvAuthToken, error) {
			environment.genericTokenProviderCalled = true

			return PinUvAuthToken{}, errors.New("generic token provider must not be called")
		},
		TemporaryPINProvider: func(context.Context, TemporaryPINRequest) ([]byte, error) {
			pin := []byte("123456")
			environment.pins = append(environment.pins, pin)

			return pin, nil
		},
		UVConfigurator: func(_ context.Context, pin []byte) error {
			if !bytes.Equal(pin, []byte("123456")) {
				t.Fatalf("UV configurator PIN = %q", pin)
			}
			environment.uvConfiguratorCalls++
			environment.device.ensurePINUV()
			environment.device.pinUV.uvConfigured = true

			return nil
		},
	}
}

type largeBlobKeyTestDevice struct {
	t                       testing.TB
	marker                  string
	environment             *largeBlobKeyTestEnvironment
	pinUV                   *clientPIN2UVPermissionsAuthenticator
	advertisedProtocols     []protocol.PinUvAuthProtocol
	tokenSecretBuffers      [][]byte
	operations              []string
	forceUV                 bool
	dropP2AfterReset        bool
	resetCalls              int
	getInfoCalls            int
	makeCredentialCalls     int
	credentials             map[string][]byte
	omitMakeCredentialKey   bool
	makeCredentialKeyLength int
	reuseMakeCredentialKey  bool
	omitGetAssertionKey     bool
	changeGetAssertionKey   bool
	negativeStatus          ctaptransport.StatusCode
	commandError            error
	tokenTransportError     bool
	responseData            [][]byte
}

func (device *largeBlobKeyTestDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		device.t.Fatal("empty CBOR request")
	}

	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		device.ensurePINUV()
		device.getInfoCalls++
		device.advertisedProtocols = []protocol.PinUvAuthProtocol{
			protocol.PinUvAuthProtocolOne,
			protocol.PinUvAuthProtocolTwo,
		}
		fields := largeBlobKeyTestInfoFields()
		if device.dropP2AfterReset && device.resetCalls != 0 {
			fields[6] = []uint{uint(protocol.PinUvAuthProtocolOne)}
		}
		options := fields[4].(map[string]any)
		if device.forceUV {
			delete(options, string(protocol.OptionClientPIN))
			options[string(protocol.OptionUserVerification)] = device.pinUV.uvConfigured
		} else {
			options[string(protocol.OptionClientPIN)] = len(device.pinUV.pin) != 0
		}
		options[string(protocol.OptionPinUvAuthToken)] = true

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalLargeBlobKeyTest(device.t, fields),
		}, nil
	case protocol.AuthenticatorClientPIN:
		return device.clientPIN(ctx, request)
	case protocol.AuthenticatorMakeCredential:
		return device.makeCredential(request[1:])
	case protocol.AuthenticatorGetAssertion:
		return device.getAssertion(request[1:])
	default:
		device.t.Fatalf("unexpected command %s", protocol.Command(request[0]))

		return ctaptransport.CBORResponse{}, nil
	}
}

func (device *largeBlobKeyTestDevice) ensurePINUV() {
	device.t.Helper()
	if device.pinUV == nil {
		test, ok := device.t.(*testing.T)
		if !ok {
			device.t.Fatal("largeBlobKey test device requires *testing.T")
		}
		device.pinUV = newClientPIN2UVPermissionsAuthenticator(test)
	}
}

func (device *largeBlobKeyTestDevice) clientPIN(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	device.ensurePINUV()

	var body protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
		device.t.Fatal(err)
	}
	if device.tokenTransportError &&
		(body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions ||
			body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions) {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected during permission-token request")
	}
	response, err := device.pinUV.CBOR(ctx, request)
	if err != nil {
		return response, err
	}
	if body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions ||
		body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions {
		token := device.pinUV.issuedTokens[body.Permissions]
		device.tokenSecretBuffers = append(device.tokenSecretBuffers, token)
		device.operations = append(device.operations, fmt.Sprintf("token:%d", body.Permissions))
	}

	return response, nil
}

func (device *largeBlobKeyTestDevice) resetSecurityState() {
	device.ensurePINUV()
	device.resetCalls++
	clear(device.pinUV.pin)
	device.pinUV.pin = nil
	for _, token := range device.pinUV.issuedTokens {
		clear(token)
	}
	device.pinUV.issuedTokens = make(map[protocol.Permission][]byte)
	device.pinUV.activeToken = nil
	device.pinUV.activePermission = protocol.PermissionNone
	device.pinUV.uvConfigured = false
}

func (device *largeBlobKeyTestDevice) makeCredential(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	device.makeCredentialCalls++
	device.operations = append(device.operations, "makeCredential")
	if device.commandError != nil {
		return ctaptransport.CBORResponse{}, device.commandError
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatal(err)
	}
	if device.marker == "F-1" || device.marker == "F-2" {
		device.requireRawExtensionInput(fields, 6)
		device.requireRawAuthorization(
			fields,
			1,
			8,
			9,
			protocol.PermissionMakeCredential,
			largeBlobKeyRPIDForMarker(device.marker),
		)

		return ctaptransport.CBORResponse{StatusCode: device.expectedNegativeStatus()}, nil
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatal(err)
	}
	if !request.Extensions.LargeBlobKey || !request.Options[protocol.OptionResidentKeys] {
		device.t.Fatalf("MakeCredential extension/options = %#v/%#v", request.Extensions, request.Options)
	}
	device.requireAuthorization(
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
		protocol.PermissionMakeCredential,
		request.RP.ID,
	)

	credentialID := []byte{0xa0, byte(device.makeCredentialCalls)}
	keyLength := device.makeCredentialKeyLength
	if keyLength == 0 {
		keyLength = 32
	}
	keyByte := byte(0x40 + device.makeCredentialCalls)
	if device.reuseMakeCredentialKey {
		keyByte = 0x40
	}
	key := bytes.Repeat([]byte{keyByte}, keyLength)
	if device.credentials == nil {
		device.credentials = make(map[string][]byte)
	}
	device.credentials[string(credentialID)] = slices.Clone(key)

	response := map[uint64]any{
		1: string(attestation.AttestationStatementFormatIdentifierNone),
		2: getAssertionFixtureMakeCredentialAuthData(device.t, credentialID),
		3: map[string]any{},
	}
	if !device.omitMakeCredentialKey {
		response[5] = key
	}

	data := marshalLargeBlobKeyTest(device.t, response)
	device.responseData = append(device.responseData, data)

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       data,
	}, nil
}

func (device *largeBlobKeyTestDevice) getAssertion(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	device.operations = append(device.operations, "getAssertion")
	if device.commandError != nil {
		return ctaptransport.CBORResponse{}, device.commandError
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatal(err)
	}
	if device.marker == "F-3" || device.marker == "F-4" {
		device.requireRawExtensionInput(fields, 4)
		device.requireRawAuthorization(
			fields,
			2,
			6,
			7,
			protocol.PermissionGetAssertion,
			largeBlobKeyRPIDForMarker(device.marker),
		)

		return ctaptransport.CBORResponse{StatusCode: device.expectedNegativeStatus()}, nil
	}

	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatal(err)
	}
	if !request.Extensions.LargeBlobKey || len(request.AllowList) != 1 {
		device.t.Fatalf("GetAssertion extension/allowList = %#v/%#v", request.Extensions, request.AllowList)
	}
	device.requireAuthorization(
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
		protocol.PermissionGetAssertion,
		request.RPID,
	)

	credentialID := request.AllowList[0].ID
	key, present := device.credentials[string(credentialID)]
	if !present {
		device.t.Fatalf("unknown credential ID %x", credentialID)
	}
	if device.changeGetAssertionKey {
		key = bytes.Repeat([]byte{0xee}, 32)
	}
	response := map[uint64]any{
		1: map[string]any{"type": string(request.AllowList[0].Type), "id": credentialID},
		2: getAssertionFixtureAuthData(),
		3: []byte{0x30, 0x00},
	}
	if !device.omitGetAssertionKey {
		response[7] = key
	}

	data := marshalLargeBlobKeyTest(device.t, response)
	device.responseData = append(device.responseData, data)

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       data,
	}, nil
}

func (device *largeBlobKeyTestDevice) requireRawExtensionInput(
	fields map[uint64]cbor.RawMessage,
	field uint64,
) {
	device.t.Helper()

	rawExtensions, present := fields[field]
	if !present {
		device.t.Fatalf("request is missing extension map field %d", field)
	}
	var extensions map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(rawExtensions, &extensions); err != nil {
		device.t.Fatal(err)
	}
	raw, present := extensions[string(extension.ExtensionIdentifierLargeBlobKey)]
	if !present {
		device.t.Fatal("request is missing explicitly encoded largeBlobKey input")
	}
	var value any
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		device.t.Fatal(err)
	}
	if device.marker == "F-1" || device.marker == "F-3" {
		if value != false {
			device.t.Fatalf("largeBlobKey input = %#v, want false", value)
		}
	} else if _, ok := value.(string); !ok {
		device.t.Fatalf("largeBlobKey input = %#v, want non-boolean", value)
	}
}

func (device *largeBlobKeyTestDevice) requireAuthorization(
	protocolVersion protocol.PinUvAuthProtocol,
	parameter []byte,
	clientDataHash []byte,
	permission protocol.Permission,
	rpID string,
) {
	device.t.Helper()
	if protocolVersion != protocol.PinUvAuthProtocolTwo {
		device.t.Fatalf("pinUvAuthProtocol = %d, want 2", protocolVersion)
	}
	device.ensurePINUV()
	if len(device.pinUV.permissionScopes) == 0 || len(device.pinUV.permissionRPIDs) == 0 {
		device.t.Fatal("command issued without a token")
	}
	index := len(device.pinUV.permissionScopes) - 1
	if device.pinUV.permissionScopes[index] != permission || device.pinUV.permissionRPIDs[index] != rpID {
		device.t.Fatalf(
			"token scope = %d/%q, want permission %d RP %q",
			device.pinUV.permissionScopes[index],
			device.pinUV.permissionRPIDs[index],
			permission,
			rpID,
		)
	}
	token := device.pinUV.issuedTokens[permission]
	if len(token) != 32 {
		device.t.Fatalf("issued token = %x, want 32 bytes", token)
	}
	expected := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, clientDataHash)
	defer clear(expected)
	if !bytes.Equal(parameter, expected) {
		device.t.Fatalf("pinUvAuthParam = %x, want %x", parameter, expected)
	}
}

func (device *largeBlobKeyTestDevice) requireRawAuthorization(
	fields map[uint64]cbor.RawMessage,
	clientDataHashField uint64,
	parameterField uint64,
	protocolField uint64,
	permission protocol.Permission,
	rpID string,
) {
	device.t.Helper()

	var clientDataHash []byte
	if err := getInfoDecMode.Unmarshal(fields[clientDataHashField], &clientDataHash); err != nil {
		device.t.Fatal(err)
	}
	var parameter []byte
	if err := getInfoDecMode.Unmarshal(fields[parameterField], &parameter); err != nil {
		device.t.Fatal(err)
	}
	var protocolVersion protocol.PinUvAuthProtocol
	if err := getInfoDecMode.Unmarshal(fields[protocolField], &protocolVersion); err != nil {
		device.t.Fatal(err)
	}
	device.requireAuthorization(
		protocolVersion,
		parameter,
		clientDataHash,
		permission,
		rpID,
	)
}

func largeBlobKeyRPIDForMarker(marker string) string {
	switch marker {
	case "P-1":
		return largeBlobKeyP1RPID
	case "P-2":
		return largeBlobKeyP2RPID
	case "F-1":
		return largeBlobKeyF1RPID
	case "F-2":
		return largeBlobKeyF2RPID
	case "F-3":
		return largeBlobKeyF3RPID
	case "F-4":
		return largeBlobKeyF4RPID
	default:
		panic("unknown largeBlobKey marker " + marker)
	}
}

func (device *largeBlobKeyTestDevice) expectedNegativeStatus() ctaptransport.StatusCode {
	if device.negativeStatus != ctaptransport.CTAP2_OK {
		return device.negativeStatus
	}
	if device.marker == "F-1" || device.marker == "F-3" {
		return ctaptransport.CTAP2_ERR_INVALID_OPTION
	}

	return ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE
}

func largeBlobKeyTestInfoFields() map[uint64]any {
	return map[uint64]any{
		1: []string{"FIDO_2_1"},
		2: []string{string(extension.ExtensionIdentifierLargeBlobKey)},
		3: make([]byte, 16),
		4: map[string]any{
			string(protocol.OptionLargeBlobs):       true,
			string(protocol.OptionPinUvAuthToken):   true,
			string(protocol.OptionClientPIN):        false,
			string(protocol.OptionUserVerification): false,
		},
		6: []uint{
			uint(protocol.PinUvAuthProtocolOne),
			uint(protocol.PinUvAuthProtocolTwo),
		},
		10: []map[string]any{{
			"type": "public-key",
			"alg":  int64(-7),
		}},
	}
}

func marshalLargeBlobKeyTest(t testing.TB, value any) []byte {
	t.Helper()

	data, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func runLargeBlobKeyTest(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	index int,
) conformance.SuiteResult {
	t.Helper()

	tests := largeBlobKeyTests(config)
	if index < 0 || index >= len(tests) {
		t.Fatalf("test index %d is out of range", index)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "large-blob-key-test",
		Name:  "largeBlobKey test",
		Tests: []conformance.Test{tests[index]},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func allZeroLargeBlobKey(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}

	return true
}

func TestLargeBlobKeyTemporaryPINProviderFailuresRemainExecutionErrors(t *testing.T) {
	environment := &largeBlobKeyTestEnvironment{}
	device := &largeBlobKeyTestDevice{t: t, marker: "P-1", environment: environment}
	environment.device = device
	config := environment.config(t)
	providerError := errors.New("temporary PIN unavailable")
	config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
		return nil, providerError
	}

	result := runLargeBlobKeyTest(t, device, config, 0)
	if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
		t.Fatalf("result = %#v, want error", result)
	}
}

func TestLargeBlobKeyExactProtocolTwoSetupAndTokenClassification(t *testing.T) {
	tests := []struct {
		name   string
		status conformance.Status
		mutate func(*largeBlobKeyTestDevice)
	}{
		{
			name:   "SetPIN CTAP status is a conformance failure",
			status: conformance.StatusFailed,
			mutate: func(device *largeBlobKeyTestDevice) {
				device.ensurePINUV()
				device.pinUV.setPINStatus = ctaptransport.CTAP2_ERR_OPERATION_DENIED
			},
		},
		{
			name:   "permission token CTAP status is a conformance failure",
			status: conformance.StatusFailed,
			mutate: func(device *largeBlobKeyTestDevice) {
				device.ensurePINUV()
				device.pinUV.permissionTokenStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
			},
		},
		{
			name:   "permission token wrong length is a conformance failure",
			status: conformance.StatusFailed,
			mutate: func(device *largeBlobKeyTestDevice) {
				device.ensurePINUV()
				device.pinUV.permissionTokenLength = 16
			},
		},
		{
			name:   "permission token transport error remains an execution error",
			status: conformance.StatusError,
			mutate: func(device *largeBlobKeyTestDevice) {
				device.tokenTransportError = true
			},
		},
		{
			name:   "setup transport error remains an execution error",
			status: conformance.StatusError,
			mutate: func(device *largeBlobKeyTestDevice) {
				device.ensurePINUV()
				device.pinUV.transportErrorCommand = protocol.AuthenticatorClientPIN
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			environment := &largeBlobKeyTestEnvironment{}
			device := &largeBlobKeyTestDevice{t: t, marker: "P-1", environment: environment}
			environment.device = device
			testCase.mutate(device)

			result := runLargeBlobKeyTest(t, device, environment.config(t), 0)
			if result.Status != testCase.status || result.Tests[0].Status != testCase.status {
				t.Fatalf("result = %#v, want %s", result, testCase.status)
			}
			if environment.genericTokenProviderCalled {
				t.Fatal("generic TokenProvider was called")
			}
			for _, pin := range environment.pins {
				if !allZeroLargeBlobKey(pin) {
					t.Fatalf("temporary PIN was not wiped after failure: %x", pin)
				}
			}
		})
	}
}
