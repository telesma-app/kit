package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN1PinPolicyDefinitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrClientPIN1PinPolicyP1, "P-1"},
		{TestIDAuthrClientPIN1PinPolicyF1, "F-1"},
		{TestIDAuthrClientPIN1PinPolicyF2, "F-2"},
		{TestIDAuthrClientPIN1PinPolicyF3, "F-3"},
		{TestIDAuthrClientPIN1PinPolicyF4, "F-4"},
	}
	tests := authrClientPIN1PinPolicyTests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrClientPIN1PinPolicySourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive || len(test.References) < 8 {
			t.Fatalf("test %d = %#v", index, test)
		}
	}
}

func TestAuthrClientPIN1PinPolicyCasesPassWithExactPINs(t *testing.T) {
	for _, testCase := range []struct {
		id            conformance.TestID
		wantLength    int
		wantStatus    ctaptransport.StatusCode
		wantGetInfo   int
		wantProvider  bool
		customMaximum uint
	}{
		{
			id:           TestIDAuthrClientPIN1PinPolicyP1,
			wantLength:   5,
			wantGetInfo:  3,
			wantProvider: true,
		},
		{
			id:          TestIDAuthrClientPIN1PinPolicyF1,
			wantLength:  3,
			wantStatus:  ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo: 2,
		},
		{
			id:          TestIDAuthrClientPIN1PinPolicyF2,
			wantLength:  64,
			wantStatus:  ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo: 2,
		},
		{
			id:          TestIDAuthrClientPIN1PinPolicyF3,
			wantLength:  64,
			wantStatus:  ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo: 2,
		},
		{
			id:            TestIDAuthrClientPIN1PinPolicyF4,
			wantLength:    13,
			wantStatus:    ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantGetInfo:   3,
			customMaximum: 12,
		},
	} {
		t.Run(string(testCase.id), func(t *testing.T) {
			events := []string{}
			device := newClientPIN1PinPolicyDevice(t, &events)
			device.info.MaxPINLength = testCase.customMaximum
			device.setPINStatus = testCase.wantStatus
			device.wantPINLength = testCase.wantLength
			config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)

			result := runClientPIN1PinPolicyTest(t, device, config, testCase.id)

			assertClientPIN1PinPolicyStatus(t, result, conformance.StatusPassed)
			if device.getInfoCalls != testCase.wantGetInfo || device.setPINCalls != 1 ||
				device.getKeyAgreementCalls != 1 {
				t.Fatalf("device calls = %#v", device)
			}
			if lifecycle.providerCalled != testCase.wantProvider {
				t.Fatalf("provider called = %t, want %t", lifecycle.providerCalled, testCase.wantProvider)
			}
			assertClientPIN1PinPolicyLifecycle(t, result, events)
			if lifecycle.pin != nil {
				assertClientPIN1PinPolicyZeroed(t, lifecycle.pin)
			}
		})
	}
}

func TestAuthrClientPIN1PinPolicyP1RequestsAdvertisedInteriorRange(t *testing.T) {
	events := []string{}
	device := newClientPIN1PinPolicyDevice(t, &events)
	device.info.MinPINLength = 8
	device.info.MaxPINLength = 12
	device.wantPINLength = 9
	config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)

	result := runClientPIN1PinPolicyTest(t, device, config, TestIDAuthrClientPIN1PinPolicyP1)

	assertClientPIN1PinPolicyStatus(t, result, conformance.StatusPassed)
	if lifecycle.request != (TemporaryPINRequest{MinCodePoints: 9, MaxCodePoints: 12}) {
		t.Fatalf("temporary PIN request = %#v", lifecycle.request)
	}
	assertClientPIN1PinPolicyZeroed(t, lifecycle.pin)
}

func TestAuthrClientPIN1PinPolicyPreflightSkipsAndFailsBeforeMutation(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		id         conformance.TestID
		minimum    uint
		maximum    uint
		wantStatus conformance.Status
	}{
		{
			name:       "P1 equal effective bounds",
			id:         TestIDAuthrClientPIN1PinPolicyP1,
			minimum:    12,
			maximum:    12,
			wantStatus: conformance.StatusSkipped,
		},
		{
			name:       "P1 minimum exceeds maximum",
			id:         TestIDAuthrClientPIN1PinPolicyP1,
			minimum:    12,
			maximum:    8,
			wantStatus: conformance.StatusFailed,
		},
		{
			name:       "F4 maxPINLength absent",
			id:         TestIDAuthrClientPIN1PinPolicyF4,
			minimum:    4,
			wantStatus: conformance.StatusSkipped,
		},
		{
			name:       "F4 invalid maxPINLength",
			id:         TestIDAuthrClientPIN1PinPolicyF4,
			minimum:    4,
			maximum:    7,
			wantStatus: conformance.StatusFailed,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			events := []string{}
			device := newClientPIN1PinPolicyDevice(t, &events)
			device.info.MinPINLength = testCase.minimum
			device.info.MaxPINLength = testCase.maximum
			config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)

			result := runClientPIN1PinPolicyTest(t, device, config, testCase.id)

			assertClientPIN1PinPolicyStatus(t, result, testCase.wantStatus)
			if lifecycle.powerCycles != 0 || lifecycle.resets != 0 ||
				device.getKeyAgreementCalls != 0 || device.setPINCalls != 0 || lifecycle.providerCalled {
				t.Fatalf("mutation occurred: lifecycle=%#v device=%#v", lifecycle, device)
			}
		})
	}
}

func TestAuthrClientPIN1PinPolicyStatusClassification(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		id         conformance.TestID
		status     ctaptransport.StatusCode
		err        error
		wantStatus conformance.Status
	}{
		{
			name:       "P1 CTAP error",
			id:         TestIDAuthrClientPIN1PinPolicyP1,
			status:     ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			wantStatus: conformance.StatusFailed,
		},
		{
			name:       "F1 unexpected OK",
			id:         TestIDAuthrClientPIN1PinPolicyF1,
			wantStatus: conformance.StatusFailed,
		},
		{
			name:       "F2 wrong CTAP status",
			id:         TestIDAuthrClientPIN1PinPolicyF2,
			status:     ctaptransport.CTAP2_ERR_PIN_INVALID,
			wantStatus: conformance.StatusFailed,
		},
		{
			name:       "F3 transport error",
			id:         TestIDAuthrClientPIN1PinPolicyF3,
			err:        errors.New("device disconnected"),
			wantStatus: conformance.StatusError,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			events := []string{}
			device := newClientPIN1PinPolicyDevice(t, &events)
			device.setPINStatus = testCase.status
			device.setPINError = testCase.err
			if testCase.id == TestIDAuthrClientPIN1PinPolicyP1 {
				device.wantPINLength = 5
			} else if testCase.id == TestIDAuthrClientPIN1PinPolicyF1 {
				device.wantPINLength = 3
			} else {
				device.wantPINLength = 64
			}
			config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)

			result := runClientPIN1PinPolicyTest(t, device, config, testCase.id)

			assertClientPIN1PinPolicyStatus(t, result, testCase.wantStatus)
			if lifecycle.pin != nil {
				assertClientPIN1PinPolicyZeroed(t, lifecycle.pin)
			}
			assertClientPIN1PinPolicyLifecycle(t, result, events)
		})
	}
}

func TestAuthrClientPIN1PinPolicyEnvironmentAndProviderFailures(t *testing.T) {
	t.Run("missing power cycler", func(t *testing.T) {
		events := []string{}
		device := newClientPIN1PinPolicyDevice(t, &events)
		config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)
		config.PowerCycler = nil

		result := runClientPIN1PinPolicyTest(t, device, config, TestIDAuthrClientPIN1PinPolicyF1)

		assertClientPIN1PinPolicyStatus(t, result, conformance.StatusError)
		if lifecycle.resets != 0 || device.setPINCalls != 0 {
			t.Fatalf("lifecycle/device = %#v/%#v", lifecycle, device)
		}
	})

	t.Run("missing provider", func(t *testing.T) {
		events := []string{}
		device := newClientPIN1PinPolicyDevice(t, &events)
		config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)
		config.TemporaryPINProvider = nil

		result := runClientPIN1PinPolicyTest(t, device, config, TestIDAuthrClientPIN1PinPolicyP1)

		assertClientPIN1PinPolicyStatus(t, result, conformance.StatusError)
		if lifecycle.powerCycles != 0 || lifecycle.resets != 0 || device.setPINCalls != 0 {
			t.Fatalf("lifecycle/device = %#v/%#v", lifecycle, device)
		}
	})

	t.Run("provider error wipes returned PIN", func(t *testing.T) {
		events := []string{}
		device := newClientPIN1PinPolicyDevice(t, &events)
		config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)
		lifecycle.pin = []byte("12345")
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
			return lifecycle.pin, errors.New("PIN interaction canceled")
		}

		result := runClientPIN1PinPolicyTest(t, device, config, TestIDAuthrClientPIN1PinPolicyP1)

		assertClientPIN1PinPolicyStatus(t, result, conformance.StatusError)
		assertClientPIN1PinPolicyZeroed(t, lifecycle.pin)
		if device.setPINCalls != 0 {
			t.Fatal("setPIN ran after provider failure")
		}
	})

	t.Run("non-NFC provider PIN is rejected and wiped", func(t *testing.T) {
		events := []string{}
		device := newClientPIN1PinPolicyDevice(t, &events)
		config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)
		lifecycle.pin = []byte("Cafe\u0301123")
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
			return lifecycle.pin, nil
		}

		result := runClientPIN1PinPolicyTest(t, device, config, TestIDAuthrClientPIN1PinPolicyP1)

		assertClientPIN1PinPolicyStatus(t, result, conformance.StatusError)
		assertClientPIN1PinPolicyZeroed(t, lifecycle.pin)
		if device.setPINCalls != 0 {
			t.Fatal("setPIN ran for non-NFC PIN")
		}
	})
}

func TestAuthrClientPIN1PinPolicyCleanupFailureIsVisible(t *testing.T) {
	events := []string{}
	device := newClientPIN1PinPolicyDevice(t, &events)
	device.wantPINLength = 5
	config, lifecycle := clientPIN1PinPolicyConfig(t, device, &events)
	cleanupFailure := errors.New("cleanup rebind failed")
	config.PowerCycler = func(context.Context) error {
		lifecycle.powerCycles++
		events = append(events, "power-cycle")
		if lifecycle.powerCycles == 2 {
			return cleanupFailure
		}

		return nil
	}

	result := runClientPIN1PinPolicyTest(t, device, config, TestIDAuthrClientPIN1PinPolicyP1)

	assertClientPIN1PinPolicyStatus(t, result, conformance.StatusError)
	last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if last.ID != "client-pin1-pin-policy.cleanup" || last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
	assertClientPIN1PinPolicyZeroed(t, lifecycle.pin)
}

type clientPIN1PinPolicyDevice struct {
	t                    testing.TB
	events               *[]string
	info                 protocol.AuthenticatorGetInfoResponse
	authenticatorPrivate *ecdh.PrivateKey
	authenticatorKey     cose.Key
	getInfoCalls         int
	getKeyAgreementCalls int
	setPINCalls          int
	setPINStatus         ctaptransport.StatusCode
	setPINError          error
	wantPINLength        int
}

func newClientPIN1PinPolicyDevice(
	t testing.TB,
	events *[]string,
) *clientPIN1PinPolicyDevice {
	t.Helper()
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	return &clientPIN1PinPolicyDevice{
		t:                    t,
		events:               events,
		authenticatorPrivate: privateKey,
		authenticatorKey:     key,
		info: protocol.AuthenticatorGetInfoResponse{
			Versions:           []protocol.Version{protocol.FIDO_2_3},
			Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
			AAGUID:             uuid.MustParse("db82ed3e-c50b-493c-92fc-1df203c86a20"),
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			MinPINLength:       4,
		},
	}
}

func (device *clientPIN1PinPolicyDevice) CBOR(
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
			Data:       marshalClientPINRetryFixture(device.t, device.info),
		}, nil
	case protocol.AuthenticatorClientPIN:
		var body protocol.AuthenticatorClientPINRequest
		if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
			device.t.Fatal(err)
		}
		if body.PinUvAuthProtocol != protocol.PinUvAuthProtocolOne {
			device.t.Fatalf("protocol = %d, want 1", body.PinUvAuthProtocol)
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
			device.verifySetPIN(body)
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

func (device *clientPIN1PinPolicyDevice) verifySetPIN(
	body protocol.AuthenticatorClientPINRequest,
) {
	device.t.Helper()
	platformPublicKey, err := body.KeyAgreement.P256PublicKey()
	if err != nil {
		device.t.Fatal(err)
	}
	z, err := device.authenticatorPrivate.ECDH(platformPublicKey)
	if err != nil {
		device.t.Fatal(err)
	}
	defer clear(z)
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolOne)
	if err != nil {
		device.t.Fatal(err)
	}
	sharedSecret, err := pinProtocol.KDF(z)
	if err != nil {
		device.t.Fatal(err)
	}
	defer clear(sharedSecret)
	wantAuthParam := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolOne, sharedSecret, body.NewPinEnc)
	defer clear(wantAuthParam)
	if !bytes.Equal(body.PinUvAuthParam, wantAuthParam) {
		device.t.Fatal("invalid setPIN pinUvAuthParam")
	}
	plaintext, err := pinProtocol.Decrypt(sharedSecret, body.NewPinEnc)
	if err != nil {
		device.t.Fatal(err)
	}
	defer clear(plaintext)
	if len(plaintext) != 64 {
		device.t.Fatalf("setPIN plaintext length = %d", len(plaintext))
	}
	if device.wantPINLength == 64 {
		if !bytes.Equal(plaintext, bytes.Repeat([]byte{'A'}, 64)) {
			device.t.Fatal("64-byte policy PIN is not deterministic ASCII")
		}

		return
	}
	if device.wantPINLength == 0 {
		device.t.Fatal("test did not configure the expected PIN length")
	}
	if !slices.ContainsFunc(plaintext[:device.wantPINLength], func(value byte) bool { return value != 'A' }) &&
		!slices.ContainsFunc(plaintext[device.wantPINLength:], func(value byte) bool { return value != 0 }) {
		return
	}
	if device.wantPINLength == 5 && bytes.Equal(plaintext[:5], []byte("12345")) &&
		!slices.ContainsFunc(plaintext[5:], func(value byte) bool { return value != 0 }) {
		return
	}
	if device.wantPINLength == 9 && bytes.Equal(plaintext[:9], []byte("123456789")) &&
		!slices.ContainsFunc(plaintext[9:], func(value byte) bool { return value != 0 }) {
		return
	}
	device.t.Fatal("setPIN plaintext does not match the exact deterministic PIN")
}

type clientPIN1PinPolicyLifecycle struct {
	powerCycles    int
	resets         int
	providerCalled bool
	request        TemporaryPINRequest
	pin            []byte
}

func clientPIN1PinPolicyConfig(
	t testing.TB,
	device *clientPIN1PinPolicyDevice,
	events *[]string,
) (Config, *clientPIN1PinPolicyLifecycle) {
	t.Helper()
	lifecycle := &clientPIN1PinPolicyLifecycle{}
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

func runClientPIN1PinPolicyTest(
	t *testing.T,
	device *clientPIN1PinPolicyDevice,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()
	var selected conformance.Test
	for _, test := range authrClientPIN1PinPolicyTests(config) {
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
		ID:    "authr-client-pin1-pin-policy-test",
		Name:  "ClientPIN1 PIN policy test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertClientPIN1PinPolicyStatus(
	t testing.TB,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()
	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertClientPIN1PinPolicyLifecycle(
	t testing.TB,
	result conformance.SuiteResult,
	events []string,
) {
	t.Helper()
	firstPowerCycle := slices.Index(events, "power-cycle")
	firstReset := slices.Index(events, "reset")
	setPIN := slices.Index(events, "set-pin")
	if firstPowerCycle < 0 || firstReset != firstPowerCycle+1 || setPIN < firstReset ||
		len(events) < 2 || events[len(events)-2] != "power-cycle" || events[len(events)-1] != "reset" {
		t.Fatalf("events = %v", events)
	}
	if countGetAssertionFixtureSteps(result.Tests[0].Steps, "client-pin1-pin-policy.cleanup") != 1 {
		t.Fatalf("cleanup steps = %#v", result.Tests[0].Steps)
	}
}

func assertClientPIN1PinPolicyZeroed(t testing.TB, pin []byte) {
	t.Helper()
	if slices.ContainsFunc(pin, func(value byte) bool { return value != 0 }) {
		t.Fatal("PIN buffer was not zeroed")
	}
}

var _ ctaptransport.CBOR = (*clientPIN1PinPolicyDevice)(nil)
