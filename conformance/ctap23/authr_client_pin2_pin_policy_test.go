package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"golang.org/x/text/unicode/norm"
)

func TestAuthrClientPIN2PinPolicyDefinitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrClientPIN2PinPolicyP1, "P-1"},
		{TestIDAuthrClientPIN2PinPolicyF1, "F-1"},
		{TestIDAuthrClientPIN2PinPolicyF2, "F-2"},
		{TestIDAuthrClientPIN2PinPolicyF3, "F-3"},
		{TestIDAuthrClientPIN2PinPolicyF4, "F-4"},
		{TestIDAuthrClientPIN2PinPolicyF5, "F-5"},
	}
	tests := authrClientPIN2PinPolicyTests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrClientPIN2PinPolicySourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive || len(test.References) < 8 ||
			!slices.Contains(test.References, clientPIN2KeyAgreementProtocolTwoReference()) {
			t.Fatalf("test %d = %#v", index, test)
		}
	}
}

func TestAuthrClientPIN2PinPolicyCasesPassWithExactPINs(t *testing.T) {
	rocketPIN := clientPIN2PinPolicyRocketPIN(t, 3)
	defer clear(rocketPIN)
	for _, testCase := range []struct {
		id            conformance.TestID
		wantPIN       []byte
		wantStatus    ctaptransport.StatusCode
		wantGetInfo   int
		wantProvider  bool
		customMaximum uint
	}{
		{
			id:           TestIDAuthrClientPIN2PinPolicyP1,
			wantPIN:      []byte("12345"),
			wantGetInfo:  3,
			wantProvider: true,
		},
		{
			id:          TestIDAuthrClientPIN2PinPolicyF1,
			wantPIN:     bytes.Repeat([]byte{'A'}, 3),
			wantStatus:  ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo: 2,
		},
		{
			id:          TestIDAuthrClientPIN2PinPolicyF2,
			wantPIN:     bytes.Repeat([]byte{'A'}, 64),
			wantStatus:  ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo: 2,
		},
		{
			id:          TestIDAuthrClientPIN2PinPolicyF3,
			wantPIN:     bytes.Repeat([]byte{'A'}, 64),
			wantStatus:  ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo: 2,
		},
		{
			id:            TestIDAuthrClientPIN2PinPolicyF4,
			wantPIN:       bytes.Repeat([]byte{'A'}, 13),
			wantStatus:    ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo:   3,
			customMaximum: 12,
		},
		{
			id:            TestIDAuthrClientPIN2PinPolicyF4,
			wantPIN:       bytes.Repeat([]byte{'A'}, 64),
			wantStatus:    ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo:   3,
			customMaximum: 63,
		},
		{
			id:          TestIDAuthrClientPIN2PinPolicyF5,
			wantPIN:     rocketPIN,
			wantStatus:  ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo: 3,
		},
	} {
		t.Run(string(testCase.id), func(t *testing.T) {
			events := []string{}
			device := newClientPIN2PinPolicyDevice(t, &events)
			device.info.MaxPINLength = testCase.customMaximum
			device.setPINStatus = testCase.wantStatus
			device.wantPIN = slices.Clone(testCase.wantPIN)
			config, lifecycle := clientPIN2PinPolicyConfig(t, &events)

			result := runClientPIN2PinPolicyTest(t, device, config, testCase.id)

			assertClientPIN2PinPolicyStatus(t, result, conformance.StatusPassed)
			if device.getInfoCalls != testCase.wantGetInfo || device.setPINCalls != 1 ||
				device.getKeyAgreementCalls != 1 {
				t.Fatalf("device calls = %#v", device)
			}
			if lifecycle.providerCalled != testCase.wantProvider {
				t.Fatalf("provider called = %t, want %t", lifecycle.providerCalled, testCase.wantProvider)
			}
			assertClientPIN2PinPolicyLifecycle(t, result, events, true)
			if lifecycle.pin != nil {
				assertClientPIN2PinPolicyZeroed(t, lifecycle.pin)
			}
			if len(device.lastNewPINEnc) != 80 || len(device.lastPinUvAuthParam) != 32 {
				t.Fatalf(
					"protocol 2 setPIN lengths = newPinEnc %d, pinUvAuthParam %d",
					len(device.lastNewPINEnc),
					len(device.lastPinUvAuthParam),
				)
			}
		})
	}
}

func TestAuthrClientPIN2PinPolicyP1RequestsAdvertisedInteriorRange(t *testing.T) {
	events := []string{}
	device := newClientPIN2PinPolicyDevice(t, &events)
	device.info.MinPINLength = 8
	device.info.MaxPINLength = 12
	device.wantPIN = []byte("123456789")
	config, lifecycle := clientPIN2PinPolicyConfig(t, &events)

	result := runClientPIN2PinPolicyTest(t, device, config, TestIDAuthrClientPIN2PinPolicyP1)

	assertClientPIN2PinPolicyStatus(t, result, conformance.StatusPassed)
	if lifecycle.request != (TemporaryPINRequest{MinCodePoints: 9, MaxCodePoints: 12}) {
		t.Fatalf("temporary PIN request = %#v", lifecycle.request)
	}
	assertClientPIN2PinPolicyZeroed(t, lifecycle.pin)
}

func TestAuthrClientPIN2PinPolicyF5SendsExact64ByteRocketVector(t *testing.T) {
	rocketPIN := clientPIN2PinPolicyRocketPIN(t, 16)
	defer clear(rocketPIN)
	events := []string{}
	device := newClientPIN2PinPolicyDevice(t, &events)
	device.info.MinPINLength = 17
	device.info.MaxPINLength = 63
	device.setPINStatus = ctaptransport.StatusCode(0x37)
	device.wantPIN = rocketPIN
	config, _ := clientPIN2PinPolicyConfig(t, &events)

	result := runClientPIN2PinPolicyTest(t, device, config, TestIDAuthrClientPIN2PinPolicyF5)

	assertClientPIN2PinPolicyStatus(t, result, conformance.StatusPassed)
	if device.setPINStatus != ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION {
		t.Fatalf("setPIN status = %#x, want exact PIN_POLICY_VIOLATION 0x37", device.setPINStatus)
	}
	if device.getKeyAgreementCalls != 1 || device.setPINCalls != 1 {
		t.Fatalf("device calls = %#v", device)
	}
	if len(device.lastNewPINEnc) != 80 || len(device.lastPinUvAuthParam) != 32 {
		t.Fatalf(
			"protocol 2 setPIN lengths = newPinEnc %d, pinUvAuthParam %d",
			len(device.lastNewPINEnc),
			len(device.lastPinUvAuthParam),
		)
	}
	assertClientPIN2PinPolicyLifecycle(t, result, events, true)
}

func TestAuthrClientPIN2PinPolicyPreflightSkipsAndFailsBeforeMutation(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		id          conformance.TestID
		minimum     uint
		maximum     uint
		protocols   []protocol.PinUvAuthProtocol
		featureful  bool
		provider    bool
		wantStatus  conformance.Status
		wantMessage string
	}{
		{
			name:       "P1 equal effective bounds",
			id:         TestIDAuthrClientPIN2PinPolicyP1,
			minimum:    12,
			maximum:    12,
			provider:   true,
			wantStatus: conformance.StatusSkipped,
		},
		{
			name:       "P1 minimum exceeds maximum",
			id:         TestIDAuthrClientPIN2PinPolicyP1,
			minimum:    12,
			maximum:    8,
			provider:   true,
			wantStatus: conformance.StatusFailed,
		},
		{
			name:       "P1 missing provider",
			id:         TestIDAuthrClientPIN2PinPolicyP1,
			minimum:    4,
			provider:   false,
			wantStatus: conformance.StatusError,
		},
		{
			name:       "F4 maxPINLength absent",
			id:         TestIDAuthrClientPIN2PinPolicyF4,
			minimum:    4,
			wantStatus: conformance.StatusSkipped,
		},
		{
			name:       "F4 invalid maxPINLength",
			id:         TestIDAuthrClientPIN2PinPolicyF4,
			minimum:    4,
			maximum:    7,
			wantStatus: conformance.StatusFailed,
		},
		{
			name:        "F5 rocket vector exceeds raw helper capacity",
			id:          TestIDAuthrClientPIN2PinPolicyF5,
			minimum:     18,
			maximum:     63,
			wantStatus:  conformance.StatusSkipped,
			wantMessage: "the minPINLength-1 rocket vector is 68 UTF-8 bytes and cannot be represented by the shared 64-byte raw PIN helper",
		},
		{
			name:       "protocol 2 absent non-featureful",
			id:         TestIDAuthrClientPIN2PinPolicyF1,
			minimum:    4,
			protocols:  []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name:       "protocol 2 absent featureful",
			id:         TestIDAuthrClientPIN2PinPolicyF1,
			minimum:    4,
			protocols:  []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			featureful: true,
			wantStatus: conformance.StatusFailed,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			events := []string{}
			device := newClientPIN2PinPolicyDevice(t, &events)
			device.info.MinPINLength = testCase.minimum
			device.info.MaxPINLength = testCase.maximum
			if testCase.protocols != nil {
				device.info.PinUvAuthProtocols = testCase.protocols
			}
			config, lifecycle := clientPIN2PinPolicyConfig(t, &events)
			config.Featureful = testCase.featureful
			if !testCase.provider {
				config.TemporaryPINProvider = nil
			}

			result := runClientPIN2PinPolicyTest(t, device, config, testCase.id)

			assertClientPIN2PinPolicyStatus(t, result, testCase.wantStatus)
			if testCase.wantMessage != "" {
				last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
				if last.Message != testCase.wantMessage {
					t.Fatalf("skip message = %q, want %q", last.Message, testCase.wantMessage)
				}
			}
			if lifecycle.powerCycles != 0 || lifecycle.resets != 0 ||
				device.getKeyAgreementCalls != 0 || device.setPINCalls != 0 || lifecycle.providerCalled {
				t.Fatalf("mutation occurred: lifecycle=%#v device=%#v", lifecycle, device)
			}
		})
	}
}

func TestAuthrClientPIN2PinPolicyRawGetInfoTypesFailBeforeMutation(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		field uint64
		value any
	}{
		{name: "minPINLength text", field: 13, value: "4"},
		{name: "maxPINLength text", field: 29, value: "12"},
		{name: "maxPINLength negative", field: 29, value: int64(-1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			events := []string{}
			device := newClientPIN2PinPolicyDevice(t, &events)
			device.getInfoMutate = func(fields map[uint64]any) {
				fields[testCase.field] = testCase.value
			}
			config, lifecycle := clientPIN2PinPolicyConfig(t, &events)

			result := runClientPIN2PinPolicyTest(t, device, config, TestIDAuthrClientPIN2PinPolicyF4)

			assertClientPIN2PinPolicyStatus(t, result, conformance.StatusFailed)
			if lifecycle.powerCycles != 0 || lifecycle.resets != 0 || device.setPINCalls != 0 {
				t.Fatalf("mutation occurred: lifecycle=%#v device=%#v", lifecycle, device)
			}
		})
	}
}

func TestAuthrClientPIN2PinPolicyStatusClassification(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		id         conformance.TestID
		status     ctaptransport.StatusCode
		err        error
		wantPIN    []byte
		wantStatus conformance.Status
	}{
		{
			name:       "P1 CTAP error",
			id:         TestIDAuthrClientPIN2PinPolicyP1,
			status:     ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantPIN:    []byte("12345"),
			wantStatus: conformance.StatusFailed,
		},
		{
			name:       "F1 unexpected OK",
			id:         TestIDAuthrClientPIN2PinPolicyF1,
			wantPIN:    bytes.Repeat([]byte{'A'}, 3),
			wantStatus: conformance.StatusFailed,
		},
		{
			name:       "F2 wrong CTAP status",
			id:         TestIDAuthrClientPIN2PinPolicyF2,
			status:     ctaptransport.CTAP2_ERR_PIN_INVALID,
			wantPIN:    bytes.Repeat([]byte{'A'}, 64),
			wantStatus: conformance.StatusFailed,
		},
		{
			name:       "F3 transport error",
			id:         TestIDAuthrClientPIN2PinPolicyF3,
			err:        errors.New("device disconnected"),
			wantPIN:    bytes.Repeat([]byte{'A'}, 64),
			wantStatus: conformance.StatusError,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			events := []string{}
			device := newClientPIN2PinPolicyDevice(t, &events)
			device.setPINStatus = testCase.status
			device.setPINError = testCase.err
			device.wantPIN = testCase.wantPIN
			config, lifecycle := clientPIN2PinPolicyConfig(t, &events)

			result := runClientPIN2PinPolicyTest(t, device, config, testCase.id)

			assertClientPIN2PinPolicyStatus(t, result, testCase.wantStatus)
			if lifecycle.pin != nil {
				assertClientPIN2PinPolicyZeroed(t, lifecycle.pin)
			}
			assertClientPIN2PinPolicyLifecycle(t, result, events, true)
		})
	}
}

func TestAuthrClientPIN2PinPolicyEnvironmentAndProviderFailures(t *testing.T) {
	t.Run("missing power cycler", func(t *testing.T) {
		events := []string{}
		device := newClientPIN2PinPolicyDevice(t, &events)
		config, lifecycle := clientPIN2PinPolicyConfig(t, &events)
		config.PowerCycler = nil

		result := runClientPIN2PinPolicyTest(t, device, config, TestIDAuthrClientPIN2PinPolicyF1)

		assertClientPIN2PinPolicyStatus(t, result, conformance.StatusError)
		if lifecycle.resets != 0 || device.setPINCalls != 0 {
			t.Fatalf("lifecycle/device = %#v/%#v", lifecycle, device)
		}
	})

	for _, testCase := range []struct {
		name string
		pin  []byte
		err  error
	}{
		{name: "provider error", pin: []byte("12345"), err: errors.New("PIN interaction canceled")},
		{name: "non-NFC PIN", pin: []byte("Cafe\u0301123")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			events := []string{}
			device := newClientPIN2PinPolicyDevice(t, &events)
			config, lifecycle := clientPIN2PinPolicyConfig(t, &events)
			lifecycle.pin = testCase.pin
			config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
				lifecycle.providerCalled = true

				return lifecycle.pin, testCase.err
			}

			result := runClientPIN2PinPolicyTest(t, device, config, TestIDAuthrClientPIN2PinPolicyP1)

			assertClientPIN2PinPolicyStatus(t, result, conformance.StatusError)
			assertClientPIN2PinPolicyZeroed(t, lifecycle.pin)
			if device.setPINCalls != 0 {
				t.Fatal("setPIN ran after provider failure")
			}
			assertClientPIN2PinPolicyLifecycle(t, result, events, false)
		})
	}
}

func TestAuthrClientPIN2PinPolicyCleanupFailureIsVisible(t *testing.T) {
	events := []string{}
	device := newClientPIN2PinPolicyDevice(t, &events)
	device.wantPIN = []byte("12345")
	config, lifecycle := clientPIN2PinPolicyConfig(t, &events)
	cleanupFailure := errors.New("cleanup rebind failed")
	config.PowerCycler = func(context.Context) error {
		lifecycle.powerCycles++
		events = append(events, "power-cycle")
		if lifecycle.powerCycles == 2 {
			return cleanupFailure
		}

		return nil
	}

	result := runClientPIN2PinPolicyTest(t, device, config, TestIDAuthrClientPIN2PinPolicyP1)

	assertClientPIN2PinPolicyStatus(t, result, conformance.StatusError)
	last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if last.ID != "client-pin2-pin-policy.cleanup" || last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
	assertClientPIN2PinPolicyZeroed(t, lifecycle.pin)
}

type clientPIN2PinPolicyDevice struct {
	t                    testing.TB
	events               *[]string
	info                 protocol.AuthenticatorGetInfoResponse
	authenticatorPrivate *ecdh.PrivateKey
	authenticatorKey     cose.Key
	getInfoMutate        func(map[uint64]any)
	getInfoCalls         int
	getKeyAgreementCalls int
	setPINCalls          int
	setPINStatus         ctaptransport.StatusCode
	setPINError          error
	wantPIN              []byte
	lastNewPINEnc        []byte
	lastPinUvAuthParam   []byte
}

func newClientPIN2PinPolicyDevice(
	t testing.TB,
	events *[]string,
) *clientPIN2PinPolicyDevice {
	t.Helper()
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	return &clientPIN2PinPolicyDevice{
		t:                    t,
		events:               events,
		authenticatorPrivate: privateKey,
		authenticatorKey:     key,
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:           []protocol.Version{protocol.FIDO_2_3},
			Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
			AAGUID:             uuid.MustParse("d8ac1945-9029-4a79-af0b-d7181bf54da8"),
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			MinPINLength:       4,
		},
	}
}

func (device *clientPIN2PinPolicyDevice) CBOR(
	_ context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if len(request) == 0 {
		device.t.Fatal("empty request")
	}
	command := protocol.Command(request[0])
	switch command {
	case protocol.AuthenticatorGetInfo:
		device.getInfoCalls++
		*device.events = append(*device.events, "get-info")

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       device.getInfoResponse(),
		}, nil
	case protocol.AuthenticatorClientPIN:
		var body protocol.AuthenticatorClientPINRequest
		if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
			device.t.Fatal(err)
		}
		if body.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
			device.t.Fatalf("protocol = %d, want 2", body.PinUvAuthProtocol)
		}
		switch body.SubCommand {
		case protocol.ClientPINSubCommandGetKeyAgreement:
			device.getKeyAgreementCalls++
			*device.events = append(*device.events, "get-key-agreement")

			return ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data: marshalClientPINRetryFixture(device.t, map[uint64]any{
					1: device.authenticatorKey,
				}),
			}, nil
		case protocol.ClientPINSubCommandSetPIN:
			device.setPINCalls++
			*device.events = append(*device.events, "set-pin")
			device.verifySetPINWire(request[1:], body)
			if device.setPINError != nil {
				return ctaptransport.CBORResponse{}, device.setPINError
			}
			if device.setPINStatus != ctaptransport.CTAP2_OK {
				return ctaptransport.ValidateCBORResponse(
					protocol.AuthenticatorClientPIN,
					ctaptransport.CBORResponse{StatusCode: device.setPINStatus},
				)
			}

			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
		default:
			device.t.Fatalf("unexpected ClientPIN subcommand %s", body.SubCommand)
		}
	default:
		device.t.Fatalf("unexpected command %s", command)
	}

	return ctaptransport.CBORResponse{}, nil
}

func (device *clientPIN2PinPolicyDevice) getInfoResponse() []byte {
	device.t.Helper()
	encoded := marshalClientPINRetryFixture(device.t, device.info)
	if device.getInfoMutate == nil {
		return encoded
	}
	var fields map[uint64]any
	if err := getInfoDecMode.Unmarshal(encoded, &fields); err != nil {
		device.t.Fatal(err)
	}
	device.getInfoMutate(fields)

	return marshalClientPINRetryFixture(device.t, fields)
}

func (device *clientPIN2PinPolicyDevice) verifySetPINWire(
	raw []byte,
	body protocol.AuthenticatorClientPINRequest,
) {
	device.t.Helper()
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &fields); err != nil {
		device.t.Fatal(err)
	}
	if len(fields) != 5 {
		device.t.Fatalf("setPIN field count = %d, want 5", len(fields))
	}
	for key := uint64(1); key <= 5; key++ {
		if _, present := fields[key]; !present {
			device.t.Fatalf("setPIN is missing field %d", key)
		}
	}
	if len(body.NewPinEnc) != 80 {
		device.t.Fatalf("protocol 2 newPinEnc length = %d, want 80", len(body.NewPinEnc))
	}
	if len(body.PinUvAuthParam) != 32 {
		device.t.Fatalf("protocol 2 pinUvAuthParam length = %d, want 32", len(body.PinUvAuthParam))
	}
	device.lastNewPINEnc = slices.Clone(body.NewPinEnc)
	device.lastPinUvAuthParam = slices.Clone(body.PinUvAuthParam)

	platformPublicKey, err := body.KeyAgreement.P256PublicKey()
	if err != nil {
		device.t.Fatal(err)
	}
	z, err := device.authenticatorPrivate.ECDH(platformPublicKey)
	if err != nil {
		device.t.Fatal(err)
	}
	defer clear(z)
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolTwo)
	if err != nil {
		device.t.Fatal(err)
	}
	sharedSecret, err := pinProtocol.KDF(z)
	if err != nil {
		device.t.Fatal(err)
	}
	defer clear(sharedSecret)
	wantAuthParam := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, sharedSecret, body.NewPinEnc)
	defer clear(wantAuthParam)
	if !bytes.Equal(body.PinUvAuthParam, wantAuthParam) {
		device.t.Fatal("invalid protocol 2 setPIN pinUvAuthParam")
	}
	plaintext, err := pinProtocol.Decrypt(sharedSecret, body.NewPinEnc)
	if err != nil {
		device.t.Fatal(err)
	}
	defer clear(plaintext)
	if len(plaintext) != 64 || len(device.wantPIN) == 0 ||
		!bytes.Equal(plaintext[:len(device.wantPIN)], device.wantPIN) ||
		slices.ContainsFunc(plaintext[len(device.wantPIN):], func(value byte) bool { return value != 0 }) {
		device.t.Fatal("setPIN plaintext does not match the exact deterministic PIN")
	}
}

type clientPIN2PinPolicyLifecycle struct {
	powerCycles    int
	resets         int
	providerCalled bool
	request        TemporaryPINRequest
	pin            []byte
}

func clientPIN2PinPolicyConfig(
	t testing.TB,
	events *[]string,
) (Config, *clientPIN2PinPolicyLifecycle) {
	t.Helper()
	lifecycle := &clientPIN2PinPolicyLifecycle{}

	return Config{
		PowerCycler: func(context.Context) error {
			lifecycle.powerCycles++
			*events = append(*events, "power-cycle")

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			lifecycle.resets++
			*events = append(*events, "reset")

			return nil
		},
		TemporaryPINProvider: func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
			lifecycle.providerCalled = true
			lifecycle.request = request
			lifecycle.pin = make([]byte, request.MinCodePoints)
			for index := range lifecycle.pin {
				lifecycle.pin[index] = byte('1' + index%9)
			}

			return lifecycle.pin, nil
		},
	}, lifecycle
}

func runClientPIN2PinPolicyTest(
	t *testing.T,
	device *clientPIN2PinPolicyDevice,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()
	var selected conformance.Test
	for _, test := range authrClientPIN2PinPolicyTests(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("test %q not found", id)
	}
	runner, err := conformance.NewRunner(device, options.WithTransport(device))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "authr-client-pin2-pin-policy-test",
		Name:  "ClientPIN2 PIN policy test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertClientPIN2PinPolicyStatus(
	t testing.TB,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()
	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertClientPIN2PinPolicyLifecycle(
	t testing.TB,
	result conformance.SuiteResult,
	events []string,
	wantSetPIN bool,
) {
	t.Helper()
	firstPowerCycle := slices.Index(events, "power-cycle")
	firstReset := slices.Index(events, "reset")
	setPIN := slices.Index(events, "set-pin")
	if firstPowerCycle < 0 || firstReset != firstPowerCycle+1 ||
		wantSetPIN && setPIN < firstReset || !wantSetPIN && setPIN >= 0 ||
		len(events) < 2 || events[len(events)-2] != "power-cycle" || events[len(events)-1] != "reset" {
		t.Fatalf("events = %v", events)
	}
	if countGetAssertionFixtureSteps(result.Tests[0].Steps, "client-pin2-pin-policy.cleanup") != 1 {
		t.Fatalf("cleanup steps = %#v", result.Tests[0].Steps)
	}
}

func assertClientPIN2PinPolicyZeroed(t testing.TB, pin []byte) {
	t.Helper()
	if slices.ContainsFunc(pin, func(value byte) bool { return value != 0 }) {
		t.Fatal("PIN buffer was not zeroed")
	}
}

func clientPIN2PinPolicyRocketPIN(t testing.TB, codePoints int) []byte {
	t.Helper()
	pin := make([]byte, codePoints*len(clientPIN2PinPolicyRocket))
	for offset := 0; offset < len(pin); offset += len(clientPIN2PinPolicyRocket) {
		copy(pin[offset:], clientPIN2PinPolicyRocket[:])
	}
	if !utf8.Valid(pin) || !norm.NFC.IsNormal(pin) || utf8.RuneCount(pin) != codePoints ||
		len(pin) == utf8.RuneCount(pin) {
		t.Fatal("invalid rocket PIN fixture")
	}

	return pin
}

var _ ctaptransport.CBOR = (*clientPIN2PinPolicyDevice)(nil)
