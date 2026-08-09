package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/crypto/protocolone"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN1GetRetriesSourceMappingAndReferences(t *testing.T) {
	tests := authrClientPIN1GetRetriesTests(Config{})
	want := []struct {
		id          conformance.TestID
		marker      string
		destructive bool
	}{
		{id: TestIDAuthrClientPIN1GetRetriesP1, marker: "P-1", destructive: true},
		{id: TestIDAuthrClientPIN1GetRetriesP2, marker: "P-2", destructive: true},
		{id: TestIDAuthrClientPIN1GetRetriesP3, marker: "P-3", destructive: true},
		{id: TestIDAuthrClientPIN1GetRetriesP4, marker: "P-4"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != authrClientPIN1GetRetriesSourcePath || test.Source.Case != expected.marker {
			t.Errorf("test %d mapping = (%q, %q, %q), want (%q, %q, %q)",
				index,
				test.ID,
				test.Source.Path,
				test.Source.Case,
				expected.id,
				authrClientPIN1GetRetriesSourcePath,
				expected.marker,
			)
		}
		if test.Destructive != expected.destructive {
			t.Errorf("test %q destructive = %t, want %t", test.ID, test.Destructive, expected.destructive)
		}
		for _, reference := range test.References {
			if reference.ID == "" || reference.Specification == "" || reference.Section == "" || reference.Clause == "" || reference.URL == "" || reference.Level == "" {
				t.Errorf("test %q has incomplete reference %#v", test.ID, reference)
			}
		}
	}

	anchors := []string{
		"#pin-entry-and-user-verification-retries-counters",
		"#pinRetries",
		"#getRetries",
		"#settingNewPin",
		"#getPinToken",
		"#authenticatorMakeCredential",
		"#message-encoding",
	}
	all := slices.Concat(tests[0].References, tests[1].References, tests[2].References, tests[3].References)
	for _, anchor := range anchors {
		if !slices.ContainsFunc(all, func(reference conformance.RequirementRef) bool {
			return strings.HasSuffix(reference.URL, anchor)
		}) {
			t.Errorf("references do not include %s", anchor)
		}
	}
	getRetriesReference := clientPINGetRetriesReference()
	if getRetriesReference.Level != conformance.RequirementConstraint || !strings.HasSuffix(getRetriesReference.URL, "#getRetries") {
		t.Fatalf("GetRetries reference = %#v", getRetriesReference)
	}
	if clientPINMaximumRetriesReference().Level != conformance.RequirementMust {
		t.Fatalf("maximum retries reference = %#v", clientPINMaximumRetriesReference())
	}
}

func TestAuthrClientPIN1GetRetriesP1PassesAndCleansUp(t *testing.T) {
	device := newClientPIN1RetryDevice(t, 8)
	config, lifecycle := clientPIN1RetryConfig(t, device)

	result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
	assertClientPIN1RetryResultStatus(t, result, conformance.StatusPassed)
	assertClientPIN1RetryCleanup(t, result, lifecycle)
	if device.getRetriesCalls != 1 {
		t.Fatalf("getRetries calls = %d, want 1", device.getRetriesCalls)
	}
}

func TestAuthrClientPIN1GetRetriesP2DecrementsAndRestoresCounter(t *testing.T) {
	device := newClientPIN1RetryDevice(
		t,
		8,
		ctaptransport.CTAP2_ERR_PIN_INVALID,
		ctaptransport.CTAP2_ERR_PIN_INVALID,
		ctaptransport.CTAP2_OK,
	)
	config, lifecycle := clientPIN1RetryConfig(t, device)

	result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP2)
	assertClientPIN1RetryResultStatus(t, result, conformance.StatusPassed)
	assertClientPIN1RetryCleanup(t, result, lifecycle)
	if !device.makeCredentialCalled {
		t.Fatal("MakeCredential was not called with the valid legacy token")
	}
	if device.retries != device.maximumRetries {
		t.Fatalf("retries = %d, want restored %d", device.retries, device.maximumRetries)
	}
}

func TestAuthrClientPIN1GetRetriesP2RejectsIncorrectCounterTransitions(t *testing.T) {
	t.Run("incorrect PINs do not decrement twice", func(t *testing.T) {
		device := newClientPIN1RetryDevice(
			t,
			8,
			ctaptransport.CTAP2_ERR_PIN_INVALID,
			ctaptransport.CTAP2_ERR_PIN_INVALID,
			ctaptransport.CTAP2_OK,
		)
		device.decrementRetriesOnInvalidPIN = false
		config, lifecycle := clientPIN1RetryConfig(t, device)

		result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP2)
		assertClientPIN1RetryResultStatus(t, result, conformance.StatusFailed)
		assertClientPIN1RetryCleanup(t, result, lifecycle)
	})

	t.Run("valid PIN does not restore counter", func(t *testing.T) {
		device := newClientPIN1RetryDevice(
			t,
			8,
			ctaptransport.CTAP2_ERR_PIN_INVALID,
			ctaptransport.CTAP2_ERR_PIN_INVALID,
			ctaptransport.CTAP2_OK,
		)
		device.restoreRetriesOnValidPIN = false
		config, lifecycle := clientPIN1RetryConfig(t, device)

		result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP2)
		assertClientPIN1RetryResultStatus(t, result, conformance.StatusFailed)
		assertClientPIN1RetryCleanup(t, result, lifecycle)
		if !device.makeCredentialCalled {
			t.Fatal("MakeCredential was not reached before the restoration check")
		}
	})
}

func TestAuthrClientPIN1GetRetriesP3UsesCounterDependentThirdStatus(t *testing.T) {
	for _, test := range []struct {
		name       string
		maximum    uint
		thirdError ctaptransport.StatusCode
	}{
		{name: "transient auth block", maximum: 8, thirdError: ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED},
		{name: "counter exhausted", maximum: 3, thirdError: ctaptransport.CTAP2_ERR_PIN_BLOCKED},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := newClientPIN1RetryDevice(
				t,
				test.maximum,
				ctaptransport.CTAP2_ERR_PIN_INVALID,
				ctaptransport.CTAP2_ERR_PIN_INVALID,
				test.thirdError,
			)
			config, lifecycle := clientPIN1RetryConfig(t, device)

			result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP3)
			assertClientPIN1RetryResultStatus(t, result, conformance.StatusPassed)
			assertClientPIN1RetryCleanup(t, result, lifecycle)
		})
	}
}

func TestAuthrClientPIN1GetRetriesP4SkipsWithoutEnvironmentOrHardware(t *testing.T) {
	device := newClientPIN1RetryDevice(t, 8)

	result := runClientPIN1GetRetriesTest(t, device, Config{}, TestIDAuthrClientPIN1GetRetriesP4)
	assertClientPIN1RetryResultStatus(t, result, conformance.StatusSkipped)
	if device.commands != 0 {
		t.Fatalf("commands = %d, want none", device.commands)
	}
	if len(result.Tests[0].Steps) != 1 || result.Tests[0].Steps[0].ID != "client-pin1.p4-disabled" {
		t.Fatalf("steps = %#v, want the source skip only", result.Tests[0].Steps)
	}
}

func TestAuthrClientPIN1GetRetriesSupportClassificationPrecedesMutation(t *testing.T) {
	for _, test := range []struct {
		name             string
		configureDevice  func(*clientPIN1RetryDevice)
		configureProfile func(*Config)
		want             conformance.Status
	}{
		{
			name: "clientPin absent",
			configureDevice: func(device *clientPIN1RetryDevice) {
				device.clientPINPresent = false
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "protocol absent non-featureful",
			configureDevice: func(device *clientPIN1RetryDevice) {
				device.protocolOneSupported = false
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "protocol absent featureful HID",
			configureDevice: func(device *clientPIN1RetryDevice) {
				device.protocolOneSupported = false
			},
			configureProfile: func(config *Config) {
				config.Featureful = true
				config.Transport = AuthenticatorTransportHID
			},
			want: conformance.StatusFailed,
		},
		{
			name: "protocol absent featureful NFC",
			configureDevice: func(device *clientPIN1RetryDevice) {
				device.protocolOneSupported = false
			},
			configureProfile: func(config *Config) {
				config.Featureful = true
				config.Transport = AuthenticatorTransportNFC
			},
			want: conformance.StatusSkipped,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := newClientPIN1RetryDevice(t, 8)
			test.configureDevice(device)
			config, lifecycle := clientPIN1RetryConfig(t, device)
			if test.configureProfile != nil {
				test.configureProfile(&config)
			}

			result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
			assertClientPIN1RetryResultStatus(t, result, test.want)
			if lifecycle.powerCycles != 0 || lifecycle.resets != 0 || lifecycle.pinProvided {
				t.Fatalf("lifecycle = %#v, want no mutation", lifecycle)
			}
		})
	}
}

func TestAuthrClientPIN1GetRetriesRequiresLifecycleCallbacks(t *testing.T) {
	for _, missing := range []string{"power cycler", "PIN provider"} {
		t.Run(missing, func(t *testing.T) {
			device := newClientPIN1RetryDevice(t, 8)
			config, lifecycle := clientPIN1RetryConfig(t, device)
			switch missing {
			case "power cycler":
				config.PowerCycler = nil
			case "PIN provider":
				config.TemporaryPINProvider = nil
			}

			result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
			assertClientPIN1RetryResultStatus(t, result, conformance.StatusError)
			if lifecycle.powerCycles != 0 || lifecycle.resets != 0 {
				t.Fatalf("lifecycle = %#v, want no mutation", lifecycle)
			}
		})
	}
}

func TestAuthrClientPIN1GetRetriesClassifiesBodyAndSetupFailuresAndStillCleansUp(t *testing.T) {
	t.Run("counter above maximum", func(t *testing.T) {
		device := newClientPIN1RetryDevice(t, 9)
		config, lifecycle := clientPIN1RetryConfig(t, device)

		result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
		assertClientPIN1RetryResultStatus(t, result, conformance.StatusFailed)
		assertClientPIN1RetryCleanup(t, result, lifecycle)
	})

	t.Run("counter transport failure", func(t *testing.T) {
		device := newClientPIN1RetryDevice(t, 8)
		device.getRetriesError = errors.New("device disconnected")
		config, lifecycle := clientPIN1RetryConfig(t, device)

		result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
		assertClientPIN1RetryResultStatus(t, result, conformance.StatusError)
		assertClientPIN1RetryCleanup(t, result, lifecycle)
	})

	t.Run("set PIN CTAP status", func(t *testing.T) {
		device := newClientPIN1RetryDevice(t, 8)
		device.setPINStatus = ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION
		config, lifecycle := clientPIN1RetryConfig(t, device)

		result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
		assertClientPIN1RetryResultStatus(t, result, conformance.StatusFailed)
		assertClientPIN1RetryCleanup(t, result, lifecycle)
	})

	t.Run("unexpected third PIN status", func(t *testing.T) {
		device := newClientPIN1RetryDevice(
			t,
			8,
			ctaptransport.CTAP2_ERR_PIN_INVALID,
			ctaptransport.CTAP2_ERR_PIN_INVALID,
			ctaptransport.CTAP2_ERR_PIN_BLOCKED,
		)
		config, lifecycle := clientPIN1RetryConfig(t, device)

		result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP3)
		assertClientPIN1RetryResultStatus(t, result, conformance.StatusFailed)
		assertClientPIN1RetryCleanup(t, result, lifecycle)
	})
}

func TestAuthrClientPIN1GetRetriesRejectsAndZerosInvalidProvidedPIN(t *testing.T) {
	device := newClientPIN1RetryDevice(t, 8)
	config, lifecycle := clientPIN1RetryConfig(t, device)
	lifecycle.pin = []byte("123")
	config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
		lifecycle.pinProvided = true

		return lifecycle.pin, nil
	}

	result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
	assertClientPIN1RetryResultStatus(t, result, conformance.StatusError)
	assertZeroedClientPIN1PIN(t, lifecycle.pin)
	if lifecycle.powerCycles != 1 || lifecycle.resets != 1 {
		t.Fatalf("lifecycle = %#v, want completed initial reset only", lifecycle)
	}
}

func TestAuthrClientPIN1GetRetriesZerosProvidedPINWhenProviderReturnsError(t *testing.T) {
	device := newClientPIN1RetryDevice(t, 8)
	config, lifecycle := clientPIN1RetryConfig(t, device)
	lifecycle.pin = []byte("7351")
	config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
		lifecycle.pinProvided = true

		return lifecycle.pin, errors.New("PIN interaction failed")
	}

	result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
	assertClientPIN1RetryResultStatus(t, result, conformance.StatusError)
	assertZeroedClientPIN1PIN(t, lifecycle.pin)
	if lifecycle.powerCycles != 1 || lifecycle.resets != 1 {
		t.Fatalf("lifecycle = %#v, want completed initial reset only", lifecycle)
	}
}

func TestAuthrClientPIN1GetRetriesReportsCleanupFailureAndZerosPIN(t *testing.T) {
	device := newClientPIN1RetryDevice(t, 8)
	config, lifecycle := clientPIN1RetryConfig(t, device)
	config.PowerCycler = func(context.Context) error {
		lifecycle.powerCycles++
		if lifecycle.powerCycles == 2 {
			return errors.New("rebind failed")
		}

		return nil
	}

	result := runClientPIN1GetRetriesTest(t, device, config, TestIDAuthrClientPIN1GetRetriesP1)
	assertClientPIN1RetryResultStatus(t, result, conformance.StatusError)
	last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if last.ID != "client-pin1.cleanup" || last.Status != conformance.StatusError || last.Message != "rebind failed" {
		t.Fatalf("cleanup = %#v", last)
	}
	assertZeroedClientPIN1PIN(t, lifecycle.pin)
}

type clientPIN1RetryLifecycle struct {
	powerCycles int
	resets      int
	pinProvided bool
	pin         []byte
}

func clientPIN1RetryConfig(
	t *testing.T,
	device *clientPIN1RetryDevice,
) (Config, *clientPIN1RetryLifecycle) {
	t.Helper()

	lifecycle := &clientPIN1RetryLifecycle{}
	return Config{
		PowerCycler: func(context.Context) error {
			lifecycle.powerCycles++

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			lifecycle.resets++
			device.reset()

			return nil
		},
		TemporaryPINProvider: func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
			if request != (TemporaryPINRequest{MinCodePoints: 4, MaxCodePoints: 63}) {
				t.Fatalf("temporary PIN request = %#v", request)
			}
			lifecycle.pinProvided = true
			lifecycle.pin = []byte("7351")

			return lifecycle.pin, nil
		},
	}, lifecycle
}

func runClientPIN1GetRetriesTest(
	t *testing.T,
	device *clientPIN1RetryDevice,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrClientPIN1GetRetriesTests(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("test %q not found", id)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), conformance.Suite{
		ID:    "client-pin1-get-retries-test",
		Name:  "client PIN 1 get retries test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertClientPIN1RetryResultStatus(t *testing.T, result conformance.SuiteResult, want conformance.Status) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %q", result, want)
	}
}

func assertClientPIN1RetryCleanup(
	t *testing.T,
	result conformance.SuiteResult,
	lifecycle *clientPIN1RetryLifecycle,
) {
	t.Helper()

	last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if last.ID != "client-pin1.cleanup" || last.Status != conformance.StatusPassed {
		t.Fatalf("cleanup = %#v, want passed cleanup", last)
	}
	if lifecycle.powerCycles != 2 || lifecycle.resets != 2 {
		t.Fatalf("lifecycle = %#v, want two power cycles and resets", lifecycle)
	}
	assertZeroedClientPIN1PIN(t, lifecycle.pin)
}

func assertZeroedClientPIN1PIN(t *testing.T, pin []byte) {
	t.Helper()

	if slices.ContainsFunc(pin, func(value byte) bool { return value != 0 }) {
		t.Fatalf("temporary PIN was not zeroed")
	}
}

type clientPIN1RetryDevice struct {
	t                            *testing.T
	privateKey                   *ecdh.PrivateKey
	publicKey                    cose.Key
	maximumRetries               uint
	retries                      uint
	tokenStatuses                []ctaptransport.StatusCode
	tokenStatusIndex             int
	clientPINPresent             bool
	protocolOneSupported         bool
	getRetriesCalls              int
	getRetriesError              error
	setPINStatus                 ctaptransport.StatusCode
	makeCredentialCalled         bool
	commands                     int
	decrementRetriesOnInvalidPIN bool
	restoreRetriesOnValidPIN     bool
}

func newClientPIN1RetryDevice(
	t *testing.T,
	maximumRetries uint,
	tokenStatuses ...ctaptransport.StatusCode,
) *clientPIN1RetryDevice {
	t.Helper()

	privateKeyBytes := make([]byte, 32)
	privateKeyBytes[len(privateKeyBytes)-1] = 1
	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	return &clientPIN1RetryDevice{
		t:                            t,
		privateKey:                   privateKey,
		publicKey:                    publicKey,
		maximumRetries:               maximumRetries,
		retries:                      maximumRetries,
		tokenStatuses:                tokenStatuses,
		clientPINPresent:             true,
		protocolOneSupported:         true,
		decrementRetriesOnInvalidPIN: true,
		restoreRetriesOnValidPIN:     true,
	}
}

func (d *clientPIN1RetryDevice) CBOR(ctx context.Context, request []byte) (ctaptransport.CBORResponse, error) {
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	d.commands++
	if len(request) == 0 {
		d.t.Fatal("empty CTAP request")
	}

	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		return d.getInfoResponse(), nil
	case protocol.AuthenticatorClientPIN:
		return d.clientPINResponse(request[1:])
	case protocol.AuthenticatorMakeCredential:
		return d.makeCredentialResponse(request[1:])
	default:
		d.t.Fatalf("unexpected command %s", protocol.Command(request[0]))
		return ctaptransport.CBORResponse{}, nil
	}
}

func (d *clientPIN1RetryDevice) reset() {
	d.retries = d.maximumRetries
	d.tokenStatusIndex = 0
}

func (d *clientPIN1RetryDevice) getInfoResponse() ctaptransport.CBORResponse {
	options := map[string]bool{}
	if d.clientPINPresent {
		options[string(protocol.OptionClientPIN)] = false
	}
	protocols := []uint{}
	if d.protocolOneSupported {
		protocols = append(protocols, uint(protocol.PinUvAuthProtocolOne))
	}

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data: marshalClientPIN1Fixture(d.t, map[int]any{
			1:  []string{string(protocol.FIDO_2_3)},
			2:  []string{"hmac-secret"},
			3:  make([]byte, 16),
			4:  options,
			6:  protocols,
			10: []map[string]any{{"type": "public-key", "alg": -7}},
			13: uint(4),
			29: uint(63),
		}),
	}
}

func (d *clientPIN1RetryDevice) clientPINResponse(body []byte) (ctaptransport.CBORResponse, error) {
	var request protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatalf("decode ClientPIN request: %v", err)
	}
	if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolOne {
		d.t.Fatalf("pinUvAuthProtocol = %d, want 1", request.PinUvAuthProtocol)
	}

	switch request.SubCommand {
	case protocol.ClientPINSubCommandGetPINRetries:
		d.getRetriesCalls++
		if d.getRetriesError != nil {
			return ctaptransport.CBORResponse{}, d.getRetriesError
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalClientPIN1Fixture(d.t, map[int]any{3: d.retries}),
		}, nil
	case protocol.ClientPINSubCommandGetKeyAgreement:
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       clientPIN1Response(d.t, d.publicKey),
		}, nil
	case protocol.ClientPINSubCommandSetPIN:
		if d.setPINStatus != ctaptransport.CTAP2_OK {
			return d.ctapError(d.setPINStatus)
		}

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.ClientPINSubCommandGetPinToken:
		return d.pinTokenResponse(request)
	default:
		d.t.Fatalf("unexpected ClientPIN subcommand %s", request.SubCommand)
		return ctaptransport.CBORResponse{}, nil
	}
}

func (d *clientPIN1RetryDevice) pinTokenResponse(
	request protocol.AuthenticatorClientPINRequest,
) (ctaptransport.CBORResponse, error) {
	if d.tokenStatusIndex >= len(d.tokenStatuses) {
		d.t.Fatalf("unexpected getPinToken attempt %d", d.tokenStatusIndex+1)
	}
	status := d.tokenStatuses[d.tokenStatusIndex]
	d.tokenStatusIndex++
	if status != ctaptransport.CTAP2_OK {
		if d.decrementRetriesOnInvalidPIN && d.retries > 0 {
			d.retries--
		}

		return d.ctapError(status)
	}

	sharedSecret := d.sharedSecret(request.KeyAgreement)
	encryptedToken, err := protocolone.Encrypt(sharedSecret, clientPIN1RetryToken)
	if err != nil {
		d.t.Fatal(err)
	}
	if d.restoreRetriesOnValidPIN {
		d.retries = d.maximumRetries
	}

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       marshalClientPIN1Fixture(d.t, map[int]any{2: encryptedToken}),
	}, nil
}

func (d *clientPIN1RetryDevice) makeCredentialResponse(body []byte) (ctaptransport.CBORResponse, error) {
	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatalf("decode MakeCredential request: %v", err)
	}
	expected := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolOne,
		clientPIN1RetryToken,
		request.ClientDataHash,
	)
	if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolOne || !bytes.Equal(request.PinUvAuthParam, expected) {
		d.t.Fatalf("MakeCredential did not authenticate with the protocol 1 token")
	}
	d.makeCredentialCalled = true

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data: marshalClientPIN1Fixture(d.t, map[int]any{
			1: "none",
			2: make([]byte, 37),
			3: map[string]any{},
		}),
	}, nil
}

func (d *clientPIN1RetryDevice) sharedSecret(platformKey cose.Key) []byte {
	publicKey, err := platformKey.P256PublicKey()
	if err != nil {
		d.t.Fatal(err)
	}
	z, err := d.privateKey.ECDH(publicKey)
	if err != nil {
		d.t.Fatal(err)
	}

	return protocolone.KDF(z)
}

func (d *clientPIN1RetryDevice) ctapError(
	status ctaptransport.StatusCode,
) (ctaptransport.CBORResponse, error) {
	return ctaptransport.CBORResponse{}, &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorClientPIN,
		StatusCode: status,
	}
}

var clientPIN1RetryToken = bytes.Repeat([]byte{0x42}, 32)
