package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/crypto/protocolone"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN1NewPINDefinitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrClientPIN1NewPINP1, "P-1"},
		{TestIDAuthrClientPIN1NewPINP2, "P-2"},
		{TestIDAuthrClientPIN1NewPINP3, "P-3"},
		{TestIDAuthrClientPIN1NewPINP4, "P-4"},
		{TestIDAuthrClientPIN1NewPINP5, "P-5"},
		{TestIDAuthrClientPIN1NewPINP6, "P-6"},
		{TestIDAuthrClientPIN1NewPINF1, "F-1"},
	}
	tests := authrClientPIN1NewPINTests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != authrClientPIN1NewPINSourcePath ||
			test.Source.Case != expected.marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		if len(test.References) < 7 || test.References[2] != clientPIN1KeyAgreementProtocolOneReference() {
			t.Fatalf("references for %s = %#v", test.ID, test.References)
		}
	}
}

func TestAuthrClientPIN1NewPINCases(t *testing.T) {
	cases := []struct {
		id              conformance.TestID
		setPIN          int
		changePIN       int
		legacyTokens    int
		permissionToken int
		makeCredential  int
		getAssertion    int
		setMinPINLength int
	}{
		{id: TestIDAuthrClientPIN1NewPINP1, setPIN: 1},
		{id: TestIDAuthrClientPIN1NewPINP2, setPIN: 1, changePIN: 1},
		{id: TestIDAuthrClientPIN1NewPINP3, setPIN: 1, legacyTokens: 1},
		{id: TestIDAuthrClientPIN1NewPINP4, setPIN: 1, legacyTokens: 1, makeCredential: 1},
		{id: TestIDAuthrClientPIN1NewPINP5, setPIN: 1, legacyTokens: 2, makeCredential: 1, getAssertion: 1},
		{id: TestIDAuthrClientPIN1NewPINP6, setPIN: 1, changePIN: 1, permissionToken: 1, setMinPINLength: 1},
		{id: TestIDAuthrClientPIN1NewPINF1, setPIN: 1, legacyTokens: 1, permissionToken: 1, setMinPINLength: 1},
	}

	for _, testCase := range cases {
		t.Run(string(testCase.id), func(t *testing.T) {
			device := newClientPIN1NewPINDevice(t)
			config, lifecycle := clientPIN1NewPINConfig(t, device)

			result := runClientPIN1NewPINTest(t, device, config, testCase.id)

			assertClientPIN1NewPINStatus(t, result, conformance.StatusPassed)
			assertClientPIN1NewPINLifecycle(t, result, lifecycle)
			if device.setPINCalls != testCase.setPIN || device.changePINCalls != testCase.changePIN ||
				device.legacyTokenCalls != testCase.legacyTokens ||
				device.permissionTokenCalls != testCase.permissionToken ||
				device.makeCredentialCalls != testCase.makeCredential ||
				device.getAssertionCalls != testCase.getAssertion ||
				device.setMinPINLengthCalls != testCase.setMinPINLength {
				t.Fatalf("device calls = %#v", device)
			}
			if slices.ContainsFunc(device.clientPINProtocols, func(value protocol.PinUvAuthProtocol) bool {
				return value != protocol.PinUvAuthProtocolOne
			}) {
				t.Fatalf("ClientPIN protocols = %v, want only protocol 1", device.clientPINProtocols)
			}
			if testCase.changePIN != 0 && !device.changedToDifferentPIN {
				t.Fatal("ChangePIN did not use a distinct PIN")
			}
			if testCase.id == TestIDAuthrClientPIN1NewPINF1 && !device.forceAtLegacyToken {
				t.Fatal("F-1 did not call getPinToken while forcePINChange was true")
			}
			if want := clientPIN1NewPINWantEvents(testCase.id); !slices.Equal(device.events, want) {
				t.Fatalf("events = %v, want %v", device.events, want)
			}
		})
	}
}

func TestAuthrClientPIN1NewPINSetMinApplicability(t *testing.T) {
	profileCases := []struct {
		name   string
		status conformance.Status
		mutate func(*clientPIN1NewPINDevice)
	}{
		{
			name:   "setMinPINLength absent",
			status: conformance.StatusSkipped,
			mutate: func(device *clientPIN1NewPINDevice) {
				device.setMinPINLengthSupported = false
			},
		},
		{
			name:   "setMinPINLength false",
			status: conformance.StatusSkipped,
			mutate: func(device *clientPIN1NewPINDevice) {
				device.setMinPINLengthEnabled = false
			},
		},
		{
			name:   "authnrCfg absent",
			status: conformance.StatusFailed,
			mutate: func(device *clientPIN1NewPINDevice) {
				device.authenticatorConfigSupported = false
			},
		},
		{
			name:   "authnrCfg false",
			status: conformance.StatusFailed,
			mutate: func(device *clientPIN1NewPINDevice) {
				device.authenticatorConfigEnabled = false
			},
		},
		{
			name:   "pinUvAuthToken absent",
			status: conformance.StatusFailed,
			mutate: func(device *clientPIN1NewPINDevice) {
				device.pinUvAuthTokenSupported = false
			},
		},
		{
			name:   "pinUvAuthToken false",
			status: conformance.StatusFailed,
			mutate: func(device *clientPIN1NewPINDevice) {
				device.pinUvAuthTokenEnabled = false
			},
		},
		{
			name:   "authenticatorConfigCommands absent",
			status: conformance.StatusFailed,
			mutate: func(device *clientPIN1NewPINDevice) {
				device.authenticatorConfigCommands = nil
			},
		},
		{
			name:   "authenticatorConfigCommands lacks setMinPINLength",
			status: conformance.StatusFailed,
			mutate: func(device *clientPIN1NewPINDevice) {
				device.authenticatorConfigCommands = []protocol.ConfigSubCommand{
					protocol.ConfigSubCommandToggleAlwaysUv,
				}
			},
		},
	}

	for _, id := range []conformance.TestID{
		TestIDAuthrClientPIN1NewPINP6,
		TestIDAuthrClientPIN1NewPINF1,
	} {
		for _, testCase := range profileCases {
			t.Run(string(id)+"/"+testCase.name, func(t *testing.T) {
				device := newClientPIN1NewPINDevice(t)
				testCase.mutate(device)
				config, lifecycle := clientPIN1NewPINConfig(t, device)
				config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
					t.Fatal("inapplicable configuration profile requested a PIN")

					return nil, nil
				}

				result := runClientPIN1NewPINTest(t, device, config, id)

				assertClientPIN1NewPINStatus(t, result, testCase.status)
				if lifecycle.powerCycles != 0 || lifecycle.resets != 0 || lifecycle.pin != nil ||
					device.setPINCalls != 0 || device.permissionTokenCalls != 0 ||
					device.setMinPINLengthCalls != 0 {
					t.Fatalf("inapplicable case mutated state: lifecycle=%#v device=%#v", lifecycle, device)
				}
				if !slices.Equal(device.events, []string{"get-info", "get-info"}) {
					t.Fatalf("events = %v", device.events)
				}
			})
		}
	}
}

func TestAuthrClientPIN1NewPINLegacyMCGAApplicability(t *testing.T) {
	for _, id := range []conformance.TestID{
		TestIDAuthrClientPIN1NewPINP4,
		TestIDAuthrClientPIN1NewPINP5,
	} {
		t.Run(string(id), func(t *testing.T) {
			device := newClientPIN1NewPINDevice(t)
			device.noMcGaPermissionsWithClientPIN = true
			config, lifecycle := clientPIN1NewPINConfig(t, device)
			config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
				t.Fatal("inapplicable legacy MC/GA case requested a PIN")

				return nil, nil
			}

			result := runClientPIN1NewPINTest(t, device, config, id)

			assertClientPIN1NewPINStatus(t, result, conformance.StatusSkipped)
			if lifecycle.powerCycles != 0 || lifecycle.resets != 0 || lifecycle.pin != nil ||
				device.setPINCalls != 0 || device.legacyTokenCalls != 0 ||
				device.makeCredentialCalls != 0 || device.getAssertionCalls != 0 {
				t.Fatalf("inapplicable case mutated state: lifecycle=%#v device=%#v", lifecycle, device)
			}
			if !slices.Equal(device.events, []string{"get-info", "get-info"}) {
				t.Fatalf("events = %v", device.events)
			}
		})
	}
}

func TestAuthrClientPIN1NewPINValidatesTokenAndUVResponses(t *testing.T) {
	t.Run("P-3 accepts 16-byte token", func(t *testing.T) {
		device := newClientPIN1NewPINDevice(t)
		device.legacyToken = bytes.Repeat([]byte{0x31}, 16)
		config, lifecycle := clientPIN1NewPINConfig(t, device)

		result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINP3)

		assertClientPIN1NewPINStatus(t, result, conformance.StatusPassed)
		assertClientPIN1NewPINLifecycle(t, result, lifecycle)
	})

	t.Run("P-3 rejects invalid token length", func(t *testing.T) {
		device := newClientPIN1NewPINDevice(t)
		device.legacyToken = bytes.Repeat([]byte{0x31}, 48)
		config, lifecycle := clientPIN1NewPINConfig(t, device)

		result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINP3)

		assertClientPIN1NewPINStatus(t, result, conformance.StatusFailed)
		assertClientPIN1NewPINLifecycle(t, result, lifecycle)
	})

	t.Run("P-4 MakeCredential UV", func(t *testing.T) {
		device := newClientPIN1NewPINDevice(t)
		device.makeCredentialFlags = protocol.AuthDataFlagUserPresent
		config, lifecycle := clientPIN1NewPINConfig(t, device)

		result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINP4)

		assertClientPIN1NewPINStatus(t, result, conformance.StatusFailed)
		assertClientPIN1NewPINLifecycle(t, result, lifecycle)
	})

	t.Run("P-5 GetAssertion UV", func(t *testing.T) {
		device := newClientPIN1NewPINDevice(t)
		device.getAssertionFlags = protocol.AuthDataFlagUserPresent
		config, lifecycle := clientPIN1NewPINConfig(t, device)

		result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINP5)

		assertClientPIN1NewPINStatus(t, result, conformance.StatusFailed)
		assertClientPIN1NewPINLifecycle(t, result, lifecycle)
	})
}

func TestAuthrClientPIN1NewPINP6RequiresForcePINChangeToClear(t *testing.T) {
	device := newClientPIN1NewPINDevice(t)
	device.retainForcePINChangeAfterChange = true
	config, lifecycle := clientPIN1NewPINConfig(t, device)

	result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINP6)

	assertClientPIN1NewPINStatus(t, result, conformance.StatusFailed)
	assertClientPIN1NewPINLifecycle(t, result, lifecycle)
	if device.changePINCalls != 1 || !device.changedToDifferentPIN || !device.forceAtPostChangeGetInfo {
		t.Fatalf("ChangePIN force-change regression was not exercised: %#v", device)
	}
}

func TestAuthrClientPIN1NewPINF1RequiresExactPINInvalid(t *testing.T) {
	for _, status := range []ctaptransport.StatusCode{
		ctaptransport.CTAP2_OK,
		ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
	} {
		t.Run(status.String(), func(t *testing.T) {
			device := newClientPIN1NewPINDevice(t)
			device.forcedLegacyStatus = &status
			config, lifecycle := clientPIN1NewPINConfig(t, device)

			result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINF1)

			assertClientPIN1NewPINStatus(t, result, conformance.StatusFailed)
			assertClientPIN1NewPINLifecycle(t, result, lifecycle)
		})
	}
}

func TestAuthrClientPIN1NewPINSetupAndBodyFailuresStillCleanUp(t *testing.T) {
	t.Run("missing power cycler", func(t *testing.T) {
		device := newClientPIN1NewPINDevice(t)
		config, lifecycle := clientPIN1NewPINConfig(t, device)
		config.PowerCycler = nil

		result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINP1)

		assertClientPIN1NewPINStatus(t, result, conformance.StatusError)
		if lifecycle.powerCycles != 0 || lifecycle.resets != 0 || device.setPINCalls != 0 {
			t.Fatalf("lifecycle/device = %#v/%#v", lifecycle, device)
		}
	})

	t.Run("ChangePIN CTAP status", func(t *testing.T) {
		device := newClientPIN1NewPINDevice(t)
		device.changePINStatus = ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION
		config, lifecycle := clientPIN1NewPINConfig(t, device)

		result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINP2)

		assertClientPIN1NewPINStatus(t, result, conformance.StatusFailed)
		assertClientPIN1NewPINLifecycle(t, result, lifecycle)
	})

	t.Run("cleanup failure", func(t *testing.T) {
		cleanupFailure := errors.New("rebind failed")
		device := newClientPIN1NewPINDevice(t)
		config, lifecycle := clientPIN1NewPINConfig(t, device)
		config.PowerCycler = func(context.Context) error {
			lifecycle.powerCycles++
			device.events = append(device.events, "power-cycle")
			if lifecycle.powerCycles == 2 {
				return cleanupFailure
			}

			return nil
		}

		result := runClientPIN1NewPINTest(t, device, config, TestIDAuthrClientPIN1NewPINP1)

		assertClientPIN1NewPINStatus(t, result, conformance.StatusError)
		last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
		if last.ID != "client-pin1.cleanup" || last.Message != cleanupFailure.Error() {
			t.Fatalf("cleanup = %#v", last)
		}
		assertClientPIN1NewPINSecretWiped(t, lifecycle.pin, "temporary PIN")
	})
}

type clientPIN1NewPINLifecycle struct {
	powerCycles int
	resets      int
	pin         []byte
}

func clientPIN1NewPINConfig(
	t *testing.T,
	device *clientPIN1NewPINDevice,
) (Config, *clientPIN1NewPINLifecycle) {
	t.Helper()

	lifecycle := &clientPIN1NewPINLifecycle{}
	return Config{
		PowerCycler: func(context.Context) error {
			lifecycle.powerCycles++
			device.events = append(device.events, "power-cycle")

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			lifecycle.resets++
			device.events = append(device.events, "reset")
			device.reset()

			return nil
		},
		TemporaryPINProvider: func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
			if request != (TemporaryPINRequest{MinCodePoints: 4, MaxCodePoints: 63}) {
				t.Fatalf("temporary PIN request = %#v", request)
			}
			lifecycle.pin = []byte("7351")

			return lifecycle.pin, nil
		},
	}, lifecycle
}

func runClientPIN1NewPINTest(
	t *testing.T,
	device *clientPIN1NewPINDevice,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrClientPIN1NewPINTests(config) {
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
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "client-pin1-new-pin-test",
		Name:  "ClientPIN protocol 1 new PIN test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertClientPIN1NewPINLifecycle(
	t *testing.T,
	result conformance.SuiteResult,
	lifecycle *clientPIN1NewPINLifecycle,
) {
	t.Helper()

	if lifecycle.powerCycles != 2 || lifecycle.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 2/2", lifecycle.powerCycles, lifecycle.resets)
	}
	if countClientPIN1NewPINSteps(result.Tests[0].Steps, "client-pin1.cleanup") != 1 {
		t.Fatalf("steps = %#v", result.Tests[0].Steps)
	}
	last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if last.ID != "client-pin1.cleanup" || last.Status != conformance.StatusPassed {
		t.Fatalf("cleanup = %#v", last)
	}
	assertClientPIN1NewPINSecretWiped(t, lifecycle.pin, "temporary PIN")
}

func assertClientPIN1NewPINStatus(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertClientPIN1NewPINSecretWiped(t *testing.T, secret []byte, name string) {
	t.Helper()

	if len(secret) != 0 && slices.ContainsFunc(secret, func(value byte) bool { return value != 0 }) {
		t.Fatalf("%s was not wiped", name)
	}
}

func countClientPIN1NewPINSteps(steps []conformance.StepResult, id conformance.StepID) int {
	count := 0
	for _, step := range steps {
		if step.ID == id {
			count++
		}
	}

	return count
}

func clientPIN1NewPINWantEvents(id conformance.TestID) []string {
	getKeyAgreement := "client-pin:" + protocol.ClientPINSubCommandGetKeyAgreement.String()
	setPIN := "client-pin:" + protocol.ClientPINSubCommandSetPIN.String()
	changePIN := "client-pin:" + protocol.ClientPINSubCommandChangePIN.String()
	getPINToken := "client-pin:" + protocol.ClientPINSubCommandGetPinToken.String()
	getPermissionToken := "client-pin:" +
		protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions.String()

	events := []string{"get-info"}
	if id == TestIDAuthrClientPIN1NewPINP4 || id == TestIDAuthrClientPIN1NewPINP5 ||
		id == TestIDAuthrClientPIN1NewPINP6 || id == TestIDAuthrClientPIN1NewPINF1 {
		events = append(events, "get-info")
	}
	events = append(events, "power-cycle", "reset", "get-info", getKeyAgreement, setPIN)
	switch id {
	case TestIDAuthrClientPIN1NewPINP1:
	case TestIDAuthrClientPIN1NewPINP2:
		events = append(events, getKeyAgreement, changePIN)
	case TestIDAuthrClientPIN1NewPINP3:
		events = append(events, getKeyAgreement, getPINToken)
	case TestIDAuthrClientPIN1NewPINP4:
		events = append(events, getKeyAgreement, getPINToken, "make-credential")
	case TestIDAuthrClientPIN1NewPINP5:
		events = append(
			events,
			getKeyAgreement,
			getPINToken,
			"make-credential",
			getKeyAgreement,
			getPINToken,
			"get-assertion",
		)
	case TestIDAuthrClientPIN1NewPINP6:
		events = append(
			events,
			getKeyAgreement,
			getPermissionToken,
			"set-min-pin-length",
			getKeyAgreement,
			changePIN,
			"get-info",
		)
	case TestIDAuthrClientPIN1NewPINF1:
		events = append(
			events,
			getKeyAgreement,
			getPermissionToken,
			"set-min-pin-length",
			getKeyAgreement,
			getPINToken,
		)
	default:
		panic("unknown ClientPIN1 NewPIN test ID")
	}

	return append(events, "power-cycle", "reset")
}

type clientPIN1NewPINDevice struct {
	t                               testing.TB
	privateKey                      *ecdh.PrivateKey
	publicKey                       cose.Key
	setMinPINLengthSupported        bool
	setMinPINLengthEnabled          bool
	authenticatorConfigSupported    bool
	authenticatorConfigEnabled      bool
	pinUvAuthTokenSupported         bool
	pinUvAuthTokenEnabled           bool
	authenticatorConfigCommands     []protocol.ConfigSubCommand
	noMcGaPermissionsWithClientPIN  bool
	pin                             []byte
	forcePINChange                  bool
	retainForcePINChangeAfterChange bool
	legacyToken                     []byte
	configToken                     []byte
	credentialID                    []byte
	hasCredential                   bool
	makeCredentialFlags             protocol.AuthDataFlag
	getAssertionFlags               protocol.AuthDataFlag
	forcedLegacyStatus              *ctaptransport.StatusCode
	changePINStatus                 ctaptransport.StatusCode
	events                          []string
	clientPINProtocols              []protocol.PinUvAuthProtocol
	setPINCalls                     int
	changePINCalls                  int
	legacyTokenCalls                int
	permissionTokenCalls            int
	makeCredentialCalls             int
	getAssertionCalls               int
	setMinPINLengthCalls            int
	changedToDifferentPIN           bool
	forceAtLegacyToken              bool
	forceAtPostChangeGetInfo        bool
}

func newClientPIN1NewPINDevice(t testing.TB) *clientPIN1NewPINDevice {
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

	return &clientPIN1NewPINDevice{
		t:                            t,
		privateKey:                   privateKey,
		publicKey:                    publicKey,
		setMinPINLengthSupported:     true,
		setMinPINLengthEnabled:       true,
		authenticatorConfigSupported: true,
		authenticatorConfigEnabled:   true,
		pinUvAuthTokenSupported:      true,
		pinUvAuthTokenEnabled:        true,
		authenticatorConfigCommands: []protocol.ConfigSubCommand{
			protocol.ConfigSubCommandSetMinPINLength,
		},
		legacyToken:         bytes.Repeat([]byte{0x42}, 32),
		configToken:         bytes.Repeat([]byte{0x64}, 32),
		credentialID:        bytes.Repeat([]byte{0x81}, 16),
		makeCredentialFlags: protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified,
		getAssertionFlags:   protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified,
	}
}

func (d *clientPIN1NewPINDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	d.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		d.t.Fatal("empty CTAP request")
	}

	switch protocol.Command(request[0]) {
	case protocol.AuthenticatorGetInfo:
		d.events = append(d.events, "get-info")

		return d.getInfoResponse(), nil
	case protocol.AuthenticatorClientPIN:
		return d.clientPINResponse(request[1:])
	case protocol.AuthenticatorMakeCredential:
		d.events = append(d.events, "make-credential")

		return d.makeCredentialResponse(request[1:])
	case protocol.AuthenticatorGetAssertion:
		d.events = append(d.events, "get-assertion")

		return d.getAssertionResponse(request[1:])
	case protocol.AuthenticatorConfig:
		d.events = append(d.events, "set-min-pin-length")

		return d.configResponse(request[1:])
	default:
		d.t.Fatalf("unexpected command %s", protocol.Command(request[0]))

		return ctaptransport.CBORResponse{}, nil
	}
}

func (d *clientPIN1NewPINDevice) reset() {
	clear(d.pin)
	d.pin = nil
	d.forcePINChange = false
	d.hasCredential = false
}

func (d *clientPIN1NewPINDevice) getInfoResponse() ctaptransport.CBORResponse {
	if d.changePINCalls != 0 {
		d.forceAtPostChangeGetInfo = d.forcePINChange
	}
	options := map[protocol.Option]bool{
		protocol.OptionClientPIN: d.pin != nil,
	}
	if d.setMinPINLengthSupported {
		options[protocol.OptionSetMinPINLength] = d.setMinPINLengthEnabled
	}
	if d.authenticatorConfigSupported {
		options[protocol.OptionAuthenticatorConfig] = d.authenticatorConfigEnabled
	}
	if d.pinUvAuthTokenSupported {
		options[protocol.OptionPinUvAuthToken] = d.pinUvAuthTokenEnabled
	}
	if d.noMcGaPermissionsWithClientPIN {
		options[protocol.OptionNoMcGaPermissionsWithClientPin] = true
	}

	return d.success(protocol.AuthenticatorGetInfoResponse{
		Versions:           []protocol.Version{protocol.FIDO_2_3},
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		AAGUID:             uuid.Nil,
		Options:            options,
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Algorithms: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		MinPINLength:                4,
		MaxPINLength:                63,
		ForcePINChange:              d.forcePINChange,
		AuthenticatorConfigCommands: slices.Clone(d.authenticatorConfigCommands),
	})
}

func (d *clientPIN1NewPINDevice) clientPINResponse(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	var request protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatalf("decode ClientPIN request: %v", err)
	}
	d.clientPINProtocols = append(d.clientPINProtocols, request.PinUvAuthProtocol)
	if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolOne {
		d.t.Fatalf("pinUvAuthProtocol = %d, want 1", request.PinUvAuthProtocol)
	}
	d.events = append(d.events, "client-pin:"+request.SubCommand.String())

	switch request.SubCommand {
	case protocol.ClientPINSubCommandGetKeyAgreement:
		return d.success(map[uint64]any{1: d.publicKey}), nil
	case protocol.ClientPINSubCommandSetPIN:
		d.setPINCalls++

		return d.setPINResponse(request), nil
	case protocol.ClientPINSubCommandChangePIN:
		d.changePINCalls++
		if d.changePINStatus != ctaptransport.CTAP2_OK {
			return d.clientPINError(d.changePINStatus)
		}

		return d.validateClientPINResponse(d.changePINResponse(request))
	case protocol.ClientPINSubCommandGetPinToken:
		d.legacyTokenCalls++
		d.forceAtLegacyToken = d.forcePINChange

		return d.validateClientPINResponse(d.tokenResponse(request, false))
	case protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions:
		d.permissionTokenCalls++

		return d.validateClientPINResponse(d.tokenResponse(request, true))
	default:
		d.t.Fatalf("unexpected ClientPIN subcommand %s", request.SubCommand)

		return ctaptransport.CBORResponse{}, nil
	}
}

func (d *clientPIN1NewPINDevice) validateClientPINResponse(
	response ctaptransport.CBORResponse,
) (ctaptransport.CBORResponse, error) {
	if response.StatusCode != ctaptransport.CTAP2_OK {
		return d.clientPINError(response.StatusCode)
	}

	return response, nil
}

func (d *clientPIN1NewPINDevice) clientPINError(
	status ctaptransport.StatusCode,
) (ctaptransport.CBORResponse, error) {
	return ctaptransport.CBORResponse{}, &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorClientPIN,
		StatusCode: status,
	}
}

func (d *clientPIN1NewPINDevice) setPINResponse(
	request protocol.AuthenticatorClientPINRequest,
) ctaptransport.CBORResponse {
	sharedSecret := d.sharedSecret(request.KeyAgreement)
	d.requireAuthParam(sharedSecret, request.NewPinEnc, request.PinUvAuthParam, "setPIN")
	d.pin = d.decryptPIN(sharedSecret, request.NewPinEnc)

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
}

func (d *clientPIN1NewPINDevice) changePINResponse(
	request protocol.AuthenticatorClientPINRequest,
) ctaptransport.CBORResponse {
	sharedSecret := d.sharedSecret(request.KeyAgreement)
	d.requireAuthParam(
		sharedSecret,
		slices.Concat(request.NewPinEnc, request.PinHashEnc),
		request.PinUvAuthParam,
		"changePIN",
	)
	if !bytes.Equal(d.decrypt(sharedSecret, request.PinHashEnc), d.pinHash()) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID}
	}

	newPIN := d.decryptPIN(sharedSecret, request.NewPinEnc)
	d.changedToDifferentPIN = !bytes.Equal(d.pin, newPIN)
	clear(d.pin)
	d.pin = newPIN
	if !d.retainForcePINChangeAfterChange {
		d.forcePINChange = false
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
}

func (d *clientPIN1NewPINDevice) tokenResponse(
	request protocol.AuthenticatorClientPINRequest,
	withPermissions bool,
) ctaptransport.CBORResponse {
	if !withPermissions && d.forcePINChange {
		if d.forcedLegacyStatus == nil {
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID}
		}
		if *d.forcedLegacyStatus != ctaptransport.CTAP2_OK {
			return ctaptransport.CBORResponse{StatusCode: *d.forcedLegacyStatus}
		}
	}
	if withPermissions && (request.Permissions != protocol.PermissionAuthenticatorConfiguration || request.RPID != "") {
		d.t.Fatalf("permission token scope = %s/%q", request.Permissions, request.RPID)
	}

	sharedSecret := d.sharedSecret(request.KeyAgreement)
	if !bytes.Equal(d.decrypt(sharedSecret, request.PinHashEnc), d.pinHash()) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID}
	}
	token := d.legacyToken
	if withPermissions {
		token = d.configToken
	}
	encrypted, err := protocolone.Encrypt(sharedSecret, token)
	if err != nil {
		d.t.Fatal(err)
	}

	return d.success(map[uint64]any{2: encrypted})
}

func (d *clientPIN1NewPINDevice) makeCredentialResponse(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	d.makeCredentialCalls++

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatalf("decode MakeCredential request: %v", err)
	}
	d.requirePINTokenAuth(
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
		"MakeCredential",
	)
	if request.RP.ID != clientPINRetryRPID {
		d.t.Fatalf("MakeCredential RP ID = %q", request.RP.ID)
	}
	d.hasCredential = true

	return d.success(protocol.AuthenticatorMakeCredentialResponse{
		Format: attestation.AttestationStatementFormatIdentifierNone,
		AuthDataRaw: clientPIN1NewPINMakeCredentialAuthData(
			d.t,
			d.makeCredentialFlags,
			d.credentialID,
		),
		AttestationStatement: map[string]any{},
	}), nil
}

func (d *clientPIN1NewPINDevice) getAssertionResponse(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	d.getAssertionCalls++

	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		d.t.Fatalf("decode GetAssertion request: %v", err)
	}
	d.requirePINTokenAuth(
		request.PinUvAuthProtocol,
		request.PinUvAuthParam,
		request.ClientDataHash,
		"GetAssertion",
	)
	if !d.hasCredential || request.RPID != clientPINRetryRPID || len(request.AllowList) != 1 ||
		!bytes.Equal(request.AllowList[0].ID, d.credentialID) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS}, nil
	}

	return d.success(protocol.AuthenticatorGetAssertionResponse{
		Credential: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   d.credentialID,
		},
		AuthDataRaw: clientPIN1NewPINGetAssertionAuthData(d.getAssertionFlags),
		Signature:   []byte{0x30, 0x00},
	}), nil
}

func (d *clientPIN1NewPINDevice) configResponse(
	body []byte,
) (ctaptransport.CBORResponse, error) {
	d.setMinPINLengthCalls++

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		d.t.Fatalf("decode authenticatorConfig request: %v", err)
	}
	var subCommand protocol.ConfigSubCommand
	if err := getInfoDecMode.Unmarshal(fields[1], &subCommand); err != nil {
		d.t.Fatal(err)
	}
	var params protocol.SetMinPINLengthConfigSubCommandParams
	if err := getInfoDecMode.Unmarshal(fields[2], &params); err != nil {
		d.t.Fatal(err)
	}
	var pinUvAuthProtocol protocol.PinUvAuthProtocol
	if err := getInfoDecMode.Unmarshal(fields[3], &pinUvAuthProtocol); err != nil {
		d.t.Fatal(err)
	}
	var pinUvAuthParam []byte
	if err := getInfoDecMode.Unmarshal(fields[4], &pinUvAuthParam); err != nil {
		d.t.Fatal(err)
	}
	if subCommand != protocol.ConfigSubCommandSetMinPINLength || !params.ForceChangePIN ||
		pinUvAuthProtocol != protocol.PinUvAuthProtocolOne {
		d.t.Fatalf("setMinPINLength request = %s/%#v/%d", subCommand, params, pinUvAuthProtocol)
	}
	message := slices.Concat(
		bytes.Repeat([]byte{0xff}, 32),
		[]byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)},
		[]byte(fields[2]),
	)
	want := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolOne, d.configToken, message)
	if !bytes.Equal(pinUvAuthParam, want) {
		d.t.Fatalf("setMinPINLength pinUvAuthParam = %x, want %x", pinUvAuthParam, want)
	}
	d.forcePINChange = true

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
}

func (d *clientPIN1NewPINDevice) requirePINTokenAuth(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthParam []byte,
	clientDataHash []byte,
	operation string,
) {
	d.t.Helper()
	want := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolOne,
		d.legacyToken,
		clientDataHash,
	)
	if pinUvAuthProtocol != protocol.PinUvAuthProtocolOne || !bytes.Equal(pinUvAuthParam, want) {
		d.t.Fatalf("%s authorization = %d/%x, want protocol 1/%x", operation, pinUvAuthProtocol, pinUvAuthParam, want)
	}
}

func (d *clientPIN1NewPINDevice) requireAuthParam(
	sharedSecret []byte,
	message []byte,
	authParam []byte,
	operation string,
) {
	d.t.Helper()
	want := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolOne, sharedSecret, message)
	if !bytes.Equal(authParam, want) {
		d.t.Fatalf("%s pinUvAuthParam = %x, want %x", operation, authParam, want)
	}
}

func (d *clientPIN1NewPINDevice) pinHash() []byte {
	hash := sha256.Sum256(d.pin)

	return hash[:16]
}

func (d *clientPIN1NewPINDevice) decryptPIN(sharedSecret []byte, ciphertext []byte) []byte {
	d.t.Helper()
	plaintext := d.decrypt(sharedSecret, ciphertext)
	length := bytes.IndexByte(plaintext, 0)
	if length < 0 {
		d.t.Fatal("encrypted PIN has no zero padding")
	}
	pin := slices.Clone(plaintext[:length])
	clear(plaintext)

	return pin
}

func (d *clientPIN1NewPINDevice) decrypt(sharedSecret []byte, ciphertext []byte) []byte {
	d.t.Helper()
	plaintext, err := protocolone.Decrypt(sharedSecret, ciphertext)
	if err != nil {
		d.t.Fatal(err)
	}

	return plaintext
}

func (d *clientPIN1NewPINDevice) sharedSecret(platformKey cose.Key) []byte {
	d.t.Helper()
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

func (d *clientPIN1NewPINDevice) success(value any) ctaptransport.CBORResponse {
	d.t.Helper()
	data, err := ctap2EncMode.Marshal(value)
	if err != nil {
		d.t.Fatal(err)
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

func clientPIN1NewPINMakeCredentialAuthData(
	t testing.TB,
	flags protocol.AuthDataFlag,
	credentialID []byte,
) []byte {
	t.Helper()

	curve := elliptic.P256().Params()
	key := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   curve.Gx.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   curve.Gy.FillBytes(make([]byte, 32)),
	}
	authData := make([]byte, 37)
	authData[32] = byte(flags | protocol.AuthDataFlagAttestedCredentialDataIncluded)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, byte(len(credentialID)>>8), byte(len(credentialID)))
	authData = append(authData, credentialID...)
	encodedKey, err := ctap2EncMode.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	authData = append(authData, encodedKey...)

	return authData
}

func clientPIN1NewPINGetAssertionAuthData(flags protocol.AuthDataFlag) []byte {
	authData := make([]byte, 37)
	authData[32] = byte(flags)

	return authData
}
