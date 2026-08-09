package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestLargeBlobs1Definitions(t *testing.T) {
	tests := largeBlobs1Tests(Config{})
	want := []struct {
		id          conformance.TestID
		marker      string
		destructive bool
		sections    []string
	}{
		{id: TestIDLargeBlobs1P1, marker: "P-1", sections: []string{"6.10.1", "6.4"}},
		{id: TestIDLargeBlobs1P2, marker: "P-2", sections: []string{"6.10.1", "6.10.2"}},
		{id: TestIDLargeBlobs1P3, marker: "P-3", destructive: true, sections: []string{"6.10.1", "6.10.2", "6.6"}},
		{id: TestIDLargeBlobs1P4, marker: "P-4", destructive: true, sections: []string{"6.10.1", "6.10.2", "6.5.7", "6.6"}},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != largeBlobs1SourcePath ||
			test.Source.Case != want[index].marker || test.Destructive != want[index].destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		for _, section := range want[index].sections {
			if !slices.ContainsFunc(test.References, func(reference conformance.RequirementRef) bool {
				return reference.Section == section && reference.Specification == conformance.SpecificationCTAP23
			}) {
				t.Errorf("test %d is missing CTAP 2.3 section %s", index, section)
			}
		}
	}
}

func TestLargeBlobs1P1CapacityAndApplicability(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		maximum    uint
		options    map[protocol.Option]bool
		featureful bool
		want       conformance.Status
	}{
		{
			name:    "maximum absent",
			options: largeBlobs1TestOptions(true, true),
			want:    conformance.StatusPassed,
		},
		{
			name:    "minimum capacity",
			maximum: 1024,
			options: largeBlobs1TestOptions(true, true),
			want:    conformance.StatusPassed,
		},
		{
			name:    "capacity below minimum",
			maximum: 1023,
			options: largeBlobs1TestOptions(true, true),
			want:    conformance.StatusFailed,
		},
		{
			name:       "featureful profile requires support",
			options:    largeBlobs1TestOptions(false, true),
			featureful: true,
			want:       conformance.StatusFailed,
		},
		{
			name:    "large blobs unsupported",
			options: largeBlobs1TestOptions(false, true),
			want:    conformance.StatusSkipped,
		},
		{
			name:    "discoverable credentials unsupported",
			options: largeBlobs1TestOptions(true, false),
			want:    conformance.StatusSkipped,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newLargeBlobs1TestDevice(t)
			device.info.MaxSerializedLargeBlobArray = testCase.maximum
			device.info.Options = testCase.options

			result := runLargeBlobs1Test(t, device, Config{Featureful: testCase.featureful}, TestIDLargeBlobs1P1)
			assertLargeBlobs1Status(t, result, testCase.want)
			if len(device.requests) != 0 || device.resetCalls != 0 {
				t.Fatalf("LargeBlobs requests/resets = %d/%d, want 0/0", len(device.requests), device.resetCalls)
			}
		})
	}
}

func TestLargeBlobs1P2ExactZeroLengthWireAndResponse(t *testing.T) {
	device := newLargeBlobs1TestDevice(t)
	result := runLargeBlobs1Test(t, device, Config{}, TestIDLargeBlobs1P2)
	assertLargeBlobs1Status(t, result, conformance.StatusPassed)
	if len(device.requests) != 1 || len(device.requestFields) != 1 {
		t.Fatalf("requests = %d/%d, want 1/1", len(device.requests), len(device.requestFields))
	}

	request := device.requests[0]
	fields := device.requestFields[0]
	if request.Get == nil || *request.Get != 0 || request.Offset != 0 || request.Set != nil {
		t.Fatalf("request = %#v", request)
	}
	for _, key := range []uint64{1, 3} {
		var value uint64
		raw, present := fields[key]
		if !present {
			t.Fatalf("request field %d is absent", key)
		}
		if err := getInfoDecMode.Unmarshal(raw, &value); err != nil || value != 0 {
			t.Fatalf("request field %d = %x/%d, error %v", key, raw, value, err)
		}
	}
}

func TestLargeBlobs1P2RejectsMissingOrNonemptyByteString(t *testing.T) {
	for _, testCase := range []struct {
		name string
		data []byte
	}{
		{name: "missing", data: largeBlobs1TestMarshal(t, map[uint64]any{})},
		{name: "null", data: largeBlobs1TestMarshal(t, map[uint64]any{1: nil})},
		{name: "wrong type", data: largeBlobs1TestMarshal(t, map[uint64]any{1: ""})},
		{name: "nonempty", data: largeBlobs1TestMarshal(t, map[uint64]any{1: []byte{0x01}})},
		{name: "noncanonical empty byte string", data: []byte{0xa1, 0x01, 0x58, 0x00}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newLargeBlobs1TestDevice(t)
			device.zeroReadResponse = testCase.data
			device.zeroReadResponseSet = true

			result := runLargeBlobs1Test(t, device, Config{}, TestIDLargeBlobs1P2)
			assertLargeBlobs1Status(t, result, conformance.StatusFailed)
		})
	}
}

func TestLargeBlobs1P2ClassifiesCommandAndTransportErrors(t *testing.T) {
	t.Run("CTAP status", func(t *testing.T) {
		device := newLargeBlobs1TestDevice(t)
		device.largeBlobsStatus = ctaptransport.CTAP1_ERR_INVALID_PARAMETER

		result := runLargeBlobs1Test(t, device, Config{}, TestIDLargeBlobs1P2)
		assertLargeBlobs1Status(t, result, conformance.StatusFailed)
	})

	t.Run("transport", func(t *testing.T) {
		device := newLargeBlobs1TestDevice(t)
		device.largeBlobsError = errors.New("device disconnected")

		result := runLargeBlobs1Test(t, device, Config{}, TestIDLargeBlobs1P2)
		assertLargeBlobs1Status(t, result, conformance.StatusError)
	})
}

func TestLargeBlobs1P3ResetsAndReadsExactInitialArray(t *testing.T) {
	var events []string
	device := newLargeBlobs1TestDevice(t)
	device.events = &events
	config := largeBlobs1TestConfig(&events)

	result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P3)
	assertLargeBlobs1Status(t, result, conformance.StatusPassed)
	if !slices.Equal(events, []string{"power-cycle", "reset", "power-cycle", "get"}) {
		t.Fatalf("events = %v", events)
	}
	if device.resetCalls != 1 || len(device.requests) != 1 {
		t.Fatalf("resets/requests = %d/%d, want 1/1", device.resetCalls, len(device.requests))
	}
	request := device.requests[0]
	if request.Get == nil || *request.Get <= 17 || *request.Get > 100 || request.Offset != 0 {
		t.Fatalf("request = %#v", request)
	}
}

func TestLargeBlobs1P3RejectsCorruptInitialArray(t *testing.T) {
	var events []string
	device := newLargeBlobs1TestDevice(t)
	device.events = &events
	device.corruptAfterReset = true

	result := runLargeBlobs1Test(t, device, largeBlobs1TestConfig(&events), TestIDLargeBlobs1P3)
	assertLargeBlobs1Status(t, result, conformance.StatusFailed)
}

func TestLargeBlobs1P3RequiresPowerCycleBoundary(t *testing.T) {
	device := newLargeBlobs1TestDevice(t)
	result := runLargeBlobs1Test(t, device, Config{}, TestIDLargeBlobs1P3)
	assertLargeBlobs1Status(t, result, conformance.StatusError)
	if device.resetCalls != 0 || len(device.requests) != 0 {
		t.Fatalf("resets/requests = %d/%d, want 0/0", device.resetCalls, len(device.requests))
	}
}

func TestLargeBlobs1P4ExactProtocolTwoWriteReadAndCleanup(t *testing.T) {
	var events []string
	device := newLargeBlobs1TestDevice(t)
	device.events = &events
	pin := []byte("123456")
	config := largeBlobs1TestConfig(&events)
	config.TemporaryPINProvider = func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
		events = append(events, "temporary-pin")
		if request.MinCodePoints != 4 || request.MaxCodePoints != 63 {
			t.Fatalf("temporary PIN request = %#v", request)
		}

		return pin, nil
	}

	result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P4)
	assertLargeBlobs1Status(t, result, conformance.StatusPassed)
	assertLargeBlobs1Zeroed(t, pin)
	if device.resetCalls != 2 {
		t.Fatalf("reset calls = %d, want setup and cleanup", device.resetCalls)
	}
	if !slices.Equal(events, []string{
		"power-cycle", "reset", "power-cycle", "temporary-pin",
		"get-key-agreement", "set-pin", "get-key-agreement", "pin-token",
		"set", "get", "get", "power-cycle", "reset",
	}) {
		t.Fatalf("events = %v", events)
	}
	assertLargeBlobs1ProtocolTwoTranscript(t, device, 1, false)
	assertLargeBlobs1ExactWrite(t, device)
	assertLargeBlobs1TokenSecretsCleared(t, device)
}

func TestLargeBlobs1P4UsesBuiltInUVWhenClientPINIsAbsent(t *testing.T) {
	var events []string
	device := newLargeBlobs1TestDevice(t)
	device.events = &events
	delete(device.info.Options, protocol.OptionClientPIN)
	device.info.Options[protocol.OptionUserVerification] = false
	device.pinUV.uvConfigured = true
	pin := []byte("654321")
	var configuratorPIN []byte
	config := largeBlobs1TestConfig(&events)
	config.TemporaryPINProvider = func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
		events = append(events, "temporary-pin")
		if request.MinCodePoints != 4 || request.MaxCodePoints != 63 {
			t.Fatalf("temporary PIN request = %#v", request)
		}

		return pin, nil
	}
	config.UVConfigurator = func(_ context.Context, borrowedPIN []byte) error {
		events = append(events, "uv-config")
		if !bytes.Equal(borrowedPIN, []byte("654321")) {
			t.Fatalf("UV configurator PIN = %q", borrowedPIN)
		}
		configuratorPIN = borrowedPIN
		device.info.Options[protocol.OptionUserVerification] = true

		return nil
	}

	result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P4)
	assertLargeBlobs1Status(t, result, conformance.StatusPassed)
	assertLargeBlobs1Zeroed(t, pin)
	assertLargeBlobs1Zeroed(t, configuratorPIN)
	if !slices.Equal(events, []string{
		"power-cycle", "reset", "power-cycle", "temporary-pin", "uv-config",
		"get-key-agreement", "uv-token", "set", "get", "get", "power-cycle", "reset",
	}) {
		t.Fatalf("events = %v", events)
	}
	assertLargeBlobs1ProtocolTwoTranscript(t, device, 0, true)
	assertLargeBlobs1ExactWrite(t, device)
	assertLargeBlobs1TokenSecretsCleared(t, device)
}

func TestLargeBlobs1P4SkipsWithoutProtocolTwoBeforeReset(t *testing.T) {
	var events []string
	device := newLargeBlobs1TestDevice(t)
	device.info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne}
	config := largeBlobs1TestConfig(&events)

	result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P4)
	assertLargeBlobs1Status(t, result, conformance.StatusSkipped)
	if device.resetCalls != 0 || len(events) != 0 || len(device.pinUV.pinProtocols) != 0 {
		t.Fatalf("unsupported P-4 mutated state: resets=%d events=%v protocols=%v", device.resetCalls, events, device.pinUV.pinProtocols)
	}
}

func assertLargeBlobs1ExactWrite(t *testing.T, device *largeBlobs1TestDevice) {
	t.Helper()

	if !device.setAuthorizationExact {
		t.Fatal("set authorization was not exact protocol-2 LargeBlobs authentication")
	}
	if len(device.lastSet) < 36 || len(device.lastSet) > 116 {
		t.Fatalf("serialized length = %d, want 36..116", len(device.lastSet))
	}
	payload := device.lastSet[:len(device.lastSet)-16]
	digest := sha256.Sum256(payload)
	if !bytes.Equal(device.lastSet[len(payload):], digest[:16]) {
		t.Fatal("serialized value does not end in the truncated payload digest")
	}
	clear(digest[:])

	if len(device.requests) != 3 {
		t.Fatalf("requests = %d, want set/full get/sliced get", len(device.requests))
	}
	setRequest, fullRequest, sliceRequest := device.requests[0], device.requests[1], device.requests[2]
	if setRequest.Get != nil || setRequest.Length != uint(len(device.lastSet)) ||
		setRequest.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
		t.Fatalf("set request = %#v", setRequest)
	}
	if fullRequest.Get == nil || *fullRequest.Get != uint(len(device.lastSet)) || fullRequest.Offset != 0 {
		t.Fatalf("full read request = %#v", fullRequest)
	}
	wantOffset := uint(len(device.lastSet) / 4)
	wantLength := uint(len(device.lastSet) / 2)
	if sliceRequest.Get == nil || *sliceRequest.Get != wantLength || sliceRequest.Offset != wantOffset {
		t.Fatalf("slice request = %#v, want offset/length %d/%d", sliceRequest, wantOffset, wantLength)
	}
}

func TestLargeBlobs1P4EnvironmentAndCommandFailures(t *testing.T) {
	t.Run("missing temporary PIN provider", func(t *testing.T) {
		var events []string
		device := newLargeBlobs1TestDevice(t)

		result := runLargeBlobs1Test(t, device, largeBlobs1TestConfig(&events), TestIDLargeBlobs1P4)
		assertLargeBlobs1Status(t, result, conformance.StatusError)
		if device.resetCalls != 2 {
			t.Fatalf("reset calls = %d, want setup and cleanup", device.resetCalls)
		}
	})

	t.Run("temporary PIN provider error clears returned PIN", func(t *testing.T) {
		var events []string
		device := newLargeBlobs1TestDevice(t)
		pin := []byte("123456")
		config := largeBlobs1TestConfig(&events)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
			return pin, errors.New("PIN entry canceled")
		}

		result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P4)
		assertLargeBlobs1Status(t, result, conformance.StatusError)
		assertLargeBlobs1Zeroed(t, pin)
	})

	t.Run("permission-token CTAP status is failure", func(t *testing.T) {
		var events []string
		device := newLargeBlobs1TestDevice(t)
		device.pinUV.permissionTokenStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
		pin := []byte("123456")
		config := largeBlobs1TestConfig(&events)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) { return pin, nil }

		result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P4)
		assertLargeBlobs1Status(t, result, conformance.StatusFailed)
		assertLargeBlobs1Zeroed(t, pin)
		if device.resetCalls != 2 {
			t.Fatalf("reset calls = %d, want setup and cleanup", device.resetCalls)
		}
	})

	t.Run("large-blob CTAP status is failure and cleanup runs", func(t *testing.T) {
		var events []string
		device := newLargeBlobs1TestDevice(t)
		device.largeBlobsStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
		pin := []byte("123456")
		config := largeBlobs1TestConfig(&events)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) { return pin, nil }

		result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P4)
		assertLargeBlobs1Status(t, result, conformance.StatusFailed)
		assertLargeBlobs1Zeroed(t, pin)
		if device.resetCalls != 2 {
			t.Fatalf("reset calls = %d, want setup and cleanup", device.resetCalls)
		}
	})

	t.Run("UV configurator error clears PIN", func(t *testing.T) {
		var events []string
		device := newLargeBlobs1TestDevice(t)
		delete(device.info.Options, protocol.OptionClientPIN)
		device.info.Options[protocol.OptionUserVerification] = false
		pin := []byte("123456")
		config := largeBlobs1TestConfig(&events)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) { return pin, nil }
		config.UVConfigurator = func(context.Context, []byte) error { return errors.New("UV enrollment canceled") }

		result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P4)
		assertLargeBlobs1Status(t, result, conformance.StatusError)
		assertLargeBlobs1Zeroed(t, pin)
	})

	t.Run("large-blob transport failure is error", func(t *testing.T) {
		var events []string
		device := newLargeBlobs1TestDevice(t)
		device.largeBlobsError = errors.New("device disconnected")
		pin := []byte("123456")
		config := largeBlobs1TestConfig(&events)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) { return pin, nil }

		result := runLargeBlobs1Test(t, device, config, TestIDLargeBlobs1P4)
		assertLargeBlobs1Status(t, result, conformance.StatusError)
		assertLargeBlobs1Zeroed(t, pin)
	})
}

func TestLargeBlobs1WriteStateClear(t *testing.T) {
	state := largeBlobs1WriteState{
		payload:    bytes.Repeat([]byte{0x11}, 20),
		serialized: bytes.Repeat([]byte{0x22}, 36),
		readback:   bytes.Repeat([]byte{0x33}, 36),
		fragment:   bytes.Repeat([]byte{0x44}, 18),
	}
	values := [][]byte{state.payload, state.serialized, state.readback, state.fragment}
	state.clear()
	for _, value := range values {
		assertLargeBlobs1Zeroed(t, value)
	}
}

func assertLargeBlobs1ProtocolTwoTranscript(
	t *testing.T,
	device *largeBlobs1TestDevice,
	wantSetPINCalls int,
	wantUV bool,
) {
	t.Helper()

	if !slices.Equal(device.info.PinUvAuthProtocols, []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	}) {
		t.Fatalf("advertised PIN/UV protocols = %v", device.info.PinUvAuthProtocols)
	}
	for index, pinProtocol := range device.pinUV.pinProtocols {
		if pinProtocol != protocol.PinUvAuthProtocolTwo {
			t.Fatalf("ClientPIN request %d used protocol %d, want 2", index, pinProtocol)
		}
	}
	wantClientPINRequests := 3
	if wantUV {
		wantClientPINRequests = 1
	}
	if len(device.pinUV.pinProtocols) != wantClientPINRequests {
		t.Fatalf("ClientPIN requests = %d, want %d", len(device.pinUV.pinProtocols), wantClientPINRequests)
	}
	if device.pinUV.setPINCalls != wantSetPINCalls {
		t.Fatalf("setPIN calls = %d, want %d", device.pinUV.setPINCalls, wantSetPINCalls)
	}
	permissions := device.pinUV.clientPIN2PermissionsAuthenticator.permissionScopes
	rpIDs := device.pinUV.clientPIN2PermissionsAuthenticator.permissionRPIDs
	if !slices.Equal(permissions, []protocol.Permission{protocol.PermissionLargeBlobWrite}) ||
		!slices.Equal(rpIDs, []string{""}) {
		t.Fatalf("permission scopes/RP IDs = %v/%q", permissions, rpIDs)
	}
	if !device.pinUV.permissionWiresExact {
		t.Fatal("permission token request did not use the exact protocol-2 wire shape")
	}
	if wantUV && !device.pinUV.permissionCryptoExact {
		t.Fatal("UV permission token transcript did not use exact protocol-2 crypto")
	}
}

func assertLargeBlobs1TokenSecretsCleared(t *testing.T, device *largeBlobs1TestDevice) {
	t.Helper()

	for index, secret := range device.tokenSecretBuffers {
		for _, value := range secret {
			if value != 0 {
				t.Fatalf("token secret %d was not cleared", index)
			}
		}
	}
}

type largeBlobs1TestDevice struct {
	t *testing.T

	info                  protocol.AuthenticatorGetInfoResponse
	pinUV                 *clientPIN2UVPermissionsAuthenticator
	serialized            []byte
	requests              []protocol.AuthenticatorLargeBlobsRequest
	requestFields         []map[uint64]cbor.RawMessage
	lastSet               []byte
	token                 []byte
	setAuthorizationExact bool
	resetCalls            int
	events                *[]string
	corruptAfterReset     bool
	zeroReadResponse      []byte
	zeroReadResponseSet   bool
	largeBlobsStatus      ctaptransport.StatusCode
	largeBlobsError       error
	tokenSecretBuffers    [][]byte
}

func newLargeBlobs1TestDevice(t *testing.T) *largeBlobs1TestDevice {
	t.Helper()
	initial := largeBlobs1InitialSerializedArray()
	options := largeBlobs1TestOptions(true, true)
	options[protocol.OptionClientPIN] = false
	options[protocol.OptionPinUvAuthToken] = true

	return &largeBlobs1TestDevice{
		t: t,
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:           []protocol.Version{protocol.FIDO_2_3},
			AAGUID:             uuid.Nil,
			Options:            options,
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne, protocol.PinUvAuthProtocolTwo},
		},
		pinUV:            newClientPIN2UVPermissionsAuthenticator(t),
		serialized:       slices.Clone(initial[:]),
		largeBlobsStatus: ctaptransport.CTAP2_OK,
	}
}

func (device *largeBlobs1TestDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		device.t.Fatal("empty request")
	}

	switch command := protocol.Command(request[0]); command {
	case protocol.AuthenticatorGetInfo:
		return largeBlobs1TestSuccess(device.t, device.info), nil
	case protocol.AuthenticatorReset:
		device.resetCalls++
		device.event("reset")
		device.resetPINUVState()
		initial := largeBlobs1InitialSerializedArray()
		device.serialized = slices.Clone(initial[:])
		if device.corruptAfterReset {
			device.serialized[len(device.serialized)-1] ^= 0xff
		}

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.AuthenticatorLargeBlobs:
		return device.largeBlobs(request[1:])
	case protocol.AuthenticatorClientPIN:
		return device.clientPIN(ctx, request)
	default:
		device.t.Fatalf("unexpected command %s", command)

		return ctaptransport.CBORResponse{}, nil
	}
}

func (device *largeBlobs1TestDevice) clientPIN(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	var body protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
		device.t.Fatal(err)
	}
	switch body.SubCommand {
	case protocol.ClientPINSubCommandGetKeyAgreement:
		device.event("get-key-agreement")
	case protocol.ClientPINSubCommandSetPIN:
		device.event("set-pin")
	case protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions:
		device.event("pin-token")
	case protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions:
		device.event("uv-token")
	default:
		device.t.Fatalf("unexpected ClientPIN subcommand %d", body.SubCommand)
	}

	response, err := device.pinUV.CBOR(ctx, request)
	if err != nil {
		return response, err
	}
	if body.SubCommand == protocol.ClientPINSubCommandSetPIN {
		device.info.Options[protocol.OptionClientPIN] = true
	}
	if body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions ||
		body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions {
		token := device.pinUV.issuedTokens[protocol.PermissionLargeBlobWrite]
		device.token = token
		device.tokenSecretBuffers = append(device.tokenSecretBuffers, token)
	}

	return response, nil
}

func (device *largeBlobs1TestDevice) resetPINUVState() {
	clear(device.pinUV.pin)
	device.pinUV.pin = nil
	for _, token := range device.pinUV.issuedTokens {
		clear(token)
	}
	device.pinUV.issuedTokens = make(map[protocol.Permission][]byte)
	device.pinUV.activeToken = nil
	device.pinUV.activePermission = protocol.PermissionNone
	device.token = nil
	if _, present := device.info.Options[protocol.OptionClientPIN]; present {
		device.info.Options[protocol.OptionClientPIN] = false
	}
	if _, present := device.info.Options[protocol.OptionUserVerification]; present {
		device.info.Options[protocol.OptionUserVerification] = false
	}
}

func (device *largeBlobs1TestDevice) largeBlobs(body []byte) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if device.largeBlobsError != nil {
		return ctaptransport.CBORResponse{}, device.largeBlobsError
	}
	if device.largeBlobsStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{}, &ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorLargeBlobs,
			StatusCode: device.largeBlobsStatus,
		}
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatal(err)
	}
	var request protocol.AuthenticatorLargeBlobsRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		device.t.Fatal(err)
	}
	device.requestFields = append(device.requestFields, fields)
	device.requests = append(device.requests, request)

	if request.Set != nil {
		device.event("set")
		device.lastSet = slices.Clone(request.Set)
		device.setAuthorizationExact = device.validSetAuthorization(request)
		device.serialized = slices.Clone(request.Set)

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	}

	device.event("get")
	if request.Get == nil {
		device.t.Fatal("LargeBlobs request contains neither get nor set")
	}
	if device.zeroReadResponseSet && request.Offset == 0 && *request.Get == 0 {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: device.zeroReadResponse}, nil
	}

	start := min(int(request.Offset), len(device.serialized))
	end := min(start+int(*request.Get), len(device.serialized))
	return largeBlobs1TestSuccess(device.t, map[uint64]any{1: slices.Clone(device.serialized[start:end])}), nil
}

func (device *largeBlobs1TestDevice) validSetAuthorization(request protocol.AuthenticatorLargeBlobsRequest) bool {
	device.t.Helper()
	if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo || len(device.token) != 32 ||
		request.Get != nil || request.Offset != 0 || request.Length != uint(len(request.Set)) {
		return false
	}

	message := bytes.Repeat([]byte{0xff}, 32)
	message = append(message, 0x0c, 0x00)
	var offset [4]byte
	binary.LittleEndian.PutUint32(offset[:], uint32(request.Offset))
	message = append(message, offset[:]...)
	digest := sha256.Sum256(request.Set)
	message = append(message, digest[:]...)
	expected := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, device.token, message)
	valid := bytes.Equal(request.PinUvAuthParam, expected)
	clear(message)
	clear(digest[:])
	clear(expected)

	return valid
}

func (device *largeBlobs1TestDevice) event(name string) {
	if device.events != nil {
		*device.events = append(*device.events, name)
	}
}

func largeBlobs1TestOptions(largeBlobs, residentKeys bool) map[protocol.Option]bool {
	return map[protocol.Option]bool{
		protocol.OptionLargeBlobs:   largeBlobs,
		protocol.OptionResidentKeys: residentKeys,
	}
}

func largeBlobs1TestConfig(events *[]string) Config {
	return Config{
		PowerCycler: func(context.Context) error {
			*events = append(*events, "power-cycle")

			return nil
		},
	}
}

func runLargeBlobs1Test(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	testID conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	tests := largeBlobs1Tests(config)
	index := slices.IndexFunc(tests, func(test conformance.Test) bool { return test.ID == testID })
	if index < 0 {
		t.Fatalf("unknown test ID %q", testID)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "large-blobs-1-test",
		Name:  "LargeBlobs 1 test",
		Tests: []conformance.Test{tests[index]},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertLargeBlobs1Status(t testing.TB, result conformance.SuiteResult, want conformance.Status) {
	t.Helper()
	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertLargeBlobs1Zeroed(t testing.TB, value []byte) {
	t.Helper()
	if slices.ContainsFunc(value, func(current byte) bool { return current != 0 }) {
		t.Fatal("owned buffer was not cleared")
	}
}

func largeBlobs1TestMarshal(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func largeBlobs1TestSuccess(t testing.TB, value any) ctaptransport.CBORResponse {
	t.Helper()

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       largeBlobs1TestMarshal(t, value),
	}
}

var _ ctaptransport.CBOR = (*largeBlobs1TestDevice)(nil)
