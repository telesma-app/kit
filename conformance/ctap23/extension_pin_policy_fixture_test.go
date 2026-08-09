package ctap23

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

type extensionPINPolicyMakeCredentialRecord struct {
	rpID      string
	extension extension.ExtensionIdentifier
}

type extensionPINPolicyDevice struct {
	*authenticatorConfigDevice

	makeCredentialStatus ctaptransport.StatusCode
	outputPresent        *bool
	outputValue          any
	outputRaw            []byte
	absentGetInfoFields  map[uint64]bool
	complexityAfterReset *bool
	tokenProtocol        protocol.PinUvAuthProtocol
	tokenError           error
	transferredToken     []byte
	expectedToken        []byte
	tokenRequests        []PinUvAuthTokenRequest
	makeCredentials      []extensionPINPolicyMakeCredentialRecord
	responseDataAliases  [][]byte
}

func newExtensionPINPolicyDevice(t *testing.T) *extensionPINPolicyDevice {
	t.Helper()

	token := bytes.Repeat([]byte{0x5d}, 32)

	return &extensionPINPolicyDevice{
		authenticatorConfigDevice: newAuthenticatorConfigDevice(t),
		tokenProtocol:             protocol.PinUvAuthProtocolTwo,
		transferredToken:          token,
		expectedToken:             slices.Clone(token),
		absentGetInfoFields:       make(map[uint64]bool),
	}
}

func (device *extensionPINPolicyDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if len(request) == 0 {
		device.t.Fatal("empty request")
	}
	if protocol.Command(request[0]) == protocol.AuthenticatorGetInfo &&
		len(device.absentGetInfoFields) != 0 {
		response := device.authenticatorConfigDevice.getInfoResponse()
		var fields map[uint64]any
		if err := getInfoDecMode.Unmarshal(response.Data, &fields); err != nil {
			device.t.Fatal(err)
		}
		for key := range device.absentGetInfoFields {
			delete(fields, key)
		}
		response.Data = marshalGetAssertionFixture(device.t, fields)

		return ctaptransport.ValidateCBORResponse(protocol.AuthenticatorGetInfo, response)
	}
	if protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
		return device.authenticatorConfigDevice.CBOR(ctx, request)
	}
	if device.transportErrorCommand == protocol.AuthenticatorMakeCredential {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected")
	}
	if device.makeCredentialStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.ValidateCBORResponse(
			protocol.AuthenticatorMakeCredential,
			ctaptransport.CBORResponse{StatusCode: device.makeCredentialStatus},
		)
	}

	response := device.makeCredentialResponse(request[1:])

	return ctaptransport.ValidateCBORResponse(protocol.AuthenticatorMakeCredential, response)
}

func (device *extensionPINPolicyDevice) makeCredentialResponse(
	body []byte,
) ctaptransport.CBORResponse {
	device.t.Helper()

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatal(err)
	}
	for _, key := range []uint64{1, 2, 3, 4, 6, 8, 9} {
		if fields[key] == nil {
			device.t.Fatalf("authenticatorMakeCredential field %d is absent", key)
		}
	}
	if len(fields) != 7 || fields[5] != nil || fields[7] != nil || fields[10] != nil || fields[11] != nil {
		device.t.Fatalf("authenticatorMakeCredential fields = %#v", fields)
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatal(err)
	}
	if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
		device.t.Fatalf("MakeCredential pinUvAuthProtocol = %d", request.PinUvAuthProtocol)
	}
	wantAuth := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		device.expectedToken,
		request.ClientDataHash,
	)
	defer clear(wantAuth)
	if !bytes.Equal(request.PinUvAuthParam, wantAuth) {
		device.t.Fatal("MakeCredential pinUvAuthParam does not authenticate clientDataHash")
	}

	var rawExtensions map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[6], &rawExtensions); err != nil {
		device.t.Fatal(err)
	}
	if len(rawExtensions) != 1 {
		device.t.Fatalf("MakeCredential extensions = %#v", rawExtensions)
	}
	var extensionID extension.ExtensionIdentifier
	for name, raw := range rawExtensions {
		extensionID = extension.ExtensionIdentifier(name)
		var input bool
		if err := getInfoDecMode.Unmarshal(raw, &input); err != nil || !input {
			device.t.Fatalf("MakeCredential extension %q = %x: %v", name, raw, err)
		}
	}
	if extensionID != extension.ExtensionIdentifierMinPinLength &&
		extensionID != extension.ExtensionIdentifierPinComplexityPolicy {
		device.t.Fatalf("unexpected extension %q", extensionID)
	}
	device.makeCredentials = append(device.makeCredentials, extensionPINPolicyMakeCredentialRecord{
		rpID:      request.RP.ID,
		extension: extensionID,
	})

	present := slices.Contains(device.configuredRPIDs, request.RP.ID)
	if device.outputPresent != nil {
		present = *device.outputPresent
	}
	authData := getAssertionFixtureMakeCredentialAuthData(device.t, []byte{0x91, 0x92})
	if present || device.outputRaw != nil {
		authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
		rawOutput := device.outputRaw
		if rawOutput == nil {
			value := device.outputValue
			if value == nil {
				if extensionID == extension.ExtensionIdentifierMinPinLength {
					value = device.minPINLength
				} else {
					value = device.complexityPolicy
				}
			}
			rawOutput = marshalGetAssertionFixture(device.t, map[string]any{
				string(extensionID): value,
			})
		}
		authData = append(authData, rawOutput...)
	}

	response := ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data: marshalGetAssertionFixture(device.t, map[uint64]any{
			1: "none",
			2: authData,
			3: map[string]any{},
		}),
	}
	device.responseDataAliases = append(device.responseDataAliases, response.Data)

	return response
}

func extensionPINPolicyConfig(
	device *extensionPINPolicyDevice,
	pin []byte,
) Config {
	config := authenticatorConfigConfig(device.authenticatorConfigDevice, pin)
	resetter := config.Resetter
	config.Resetter = func(ctx context.Context, ctapClient *client.Client) error {
		if err := resetter(ctx, ctapClient); err != nil {
			return err
		}
		if device.complexityAfterReset != nil {
			device.complexityPolicy = *device.complexityAfterReset
		}

		return nil
	}
	config.TokenProvider = func(
		_ context.Context,
		_ *client.Client,
		request PinUvAuthTokenRequest,
	) (PinUvAuthToken, error) {
		device.tokenRequests = append(device.tokenRequests, request)
		if device.tokenError != nil {
			return PinUvAuthToken{}, device.tokenError
		}

		return PinUvAuthToken{
			Protocol: device.tokenProtocol,
			Value:    device.transferredToken,
		}, nil
	}

	return config
}

func runExtensionPINPolicyTest(
	t *testing.T,
	device ctaptransport.CBOR,
	test conformance.Test,
) conformance.TestResult {
	t.Helper()

	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "extension-pin-policy-test",
		Name:  "Extension PIN policy test",
		Tests: []conformance.Test{test},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result.Tests[0]
}

func assertExtensionPINPolicyConfigRequest(
	t *testing.T,
	device *extensionPINPolicyDevice,
	wantRPID string,
) {
	t.Helper()
	if len(device.requests) != 1 ||
		device.requests[0].subCommand != protocol.ConfigSubCommandSetMinPINLength ||
		len(device.requests[0].params) != 1 {
		t.Fatalf("authenticatorConfig requests = %#v", device.requests)
	}
	var rpIDs []string
	if err := getInfoDecMode.Unmarshal(device.requests[0].params[2], &rpIDs); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rpIDs, []string{wantRPID}) {
		t.Fatalf("configured RP IDs = %v, want [%s]", rpIDs, wantRPID)
	}
}

func assertExtensionPINPolicyLifecycleAndSecrets(
	t *testing.T,
	device *extensionPINPolicyDevice,
	pin []byte,
) {
	t.Helper()
	if device.powerCycles != 2 || device.resets != 2 ||
		device.authenticatorConfigDevice.tokenRequests != 1 {
		t.Fatalf(
			"power cycles = %d, resets = %d, config token requests = %d",
			device.powerCycles,
			device.resets,
			device.authenticatorConfigDevice.tokenRequests,
		)
	}
	if !device.setPINWireExact || !device.pinAuthenticator.permissionWiresExact ||
		!slices.Equal(
			device.pinAuthenticator.permissionScopes,
			[]protocol.Permission{protocol.PermissionAuthenticatorConfiguration},
		) || !slices.Equal(device.pinAuthenticator.permissionRPIDs, []string{""}) {
		t.Fatalf("configuration authorization transcript = %#v", device.pinAuthenticator)
	}
	assertAuthenticatorConfigZeroed(t, pin)
	assertAuthenticatorConfigZeroed(t, device.transferredToken)
	for _, data := range device.responseDataAliases {
		assertMakeCredentialFixtureBytesCleared(t, "extension PIN policy response", data)
	}
}

func nonCanonicalExtensionPINPolicyOutput(name string, encodedValue byte) []byte {
	output := []byte{0xa1, 0x78, byte(len(name))}
	output = append(output, name...)
	output = append(output, encodedValue)

	return output
}

var _ ctaptransport.CBOR = (*extensionPINPolicyDevice)(nil)
