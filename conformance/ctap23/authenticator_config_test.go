package ctap23

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthenticatorConfigDefinitions(t *testing.T) {
	tests := authenticatorConfigTests(Config{})
	want := []struct {
		id      conformance.TestID
		marker  string
		section string
	}{
		{id: TestIDAuthenticatorConfigP1, marker: "P-1", section: "6.11.1"},
		{id: TestIDAuthenticatorConfigP2, marker: "P-2", section: "6.11.2"},
		{id: TestIDAuthenticatorConfigP3, marker: "P-3", section: "6.11.4"},
		{id: TestIDAuthenticatorConfigP4, marker: "P-4", section: "6.11.4"},
		{id: TestIDAuthenticatorConfigP5, marker: "P-5", section: "6.11.4"},
		{id: TestIDAuthenticatorConfigP6, marker: "P-6", section: "6.11.4"},
		{id: TestIDAuthenticatorConfigP7, marker: "P-7", section: "6.11.5"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != authenticatorConfigSourcePath ||
			test.Source.Case != expected.marker || !test.Destructive {
			t.Errorf("test[%d] = %#v", index, test)
		}
		if len(test.References) != 2 || test.References[0].Section != "6.11" ||
			test.References[1].Section != expected.section {
			t.Errorf("test[%d] references = %#v", index, test.References)
		}
	}
}

func TestAuthenticatorConfigCasesUseExactProtocolTwoWireAndCleanup(t *testing.T) {
	cases := []struct {
		index      int
		subCommand protocol.ConfigSubCommand
		assert     func(*testing.T, map[uint64]cbor.RawMessage)
	}{
		{index: 0, subCommand: protocol.ConfigSubCommandEnableEnterpriseAttestation, assert: assertNoAuthenticatorConfigParams},
		{index: 1, subCommand: protocol.ConfigSubCommandToggleAlwaysUv, assert: assertNoAuthenticatorConfigParams},
		{index: 2, subCommand: protocol.ConfigSubCommandSetMinPINLength, assert: func(t *testing.T, params map[uint64]cbor.RawMessage) {
			assertAuthenticatorConfigUintParam(t, params, 1, 5)
		}},
		{index: 3, subCommand: protocol.ConfigSubCommandSetMinPINLength, assert: func(t *testing.T, params map[uint64]cbor.RawMessage) {
			if len(params) != 1 {
				t.Fatalf("params = %#v", params)
			}
			var rpIDs []string
			if err := getInfoDecMode.Unmarshal(params[2], &rpIDs); err != nil {
				t.Fatal(err)
			}
			want := []string{"config-rp-0.example", "config-rp-1.example"}
			if !slices.Equal(rpIDs, want) {
				t.Fatalf("RP IDs = %v, want %v", rpIDs, want)
			}
		}},
		{index: 4, subCommand: protocol.ConfigSubCommandSetMinPINLength, assert: func(t *testing.T, params map[uint64]cbor.RawMessage) {
			assertAuthenticatorConfigBoolParam(t, params, 3)
		}},
		{index: 5, subCommand: protocol.ConfigSubCommandSetMinPINLength, assert: func(t *testing.T, params map[uint64]cbor.RawMessage) {
			assertAuthenticatorConfigBoolParam(t, params, 4)
		}},
		{index: 6, subCommand: protocol.ConfigSubCommandEnableLongTouchForReset, assert: assertNoAuthenticatorConfigParams},
	}

	for _, testCase := range cases {
		t.Run(authenticatorConfigTests(Config{})[testCase.index].Source.Case, func(t *testing.T) {
			device := newAuthenticatorConfigDevice(t)
			pin := []byte("1234")
			result := runAuthenticatorConfigTest(t, device, authenticatorConfigConfig(device, pin), testCase.index)
			if result.Status != conformance.StatusPassed {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
			if len(device.requests) != 1 || device.requests[0].subCommand != testCase.subCommand {
				t.Fatalf("requests = %#v", device.requests)
			}
			testCase.assert(t, device.requests[0].params)
			if device.powerCycles != 2 || device.resets != 2 || device.tokenRequests != 1 {
				t.Fatalf(
					"power cycles = %d, resets = %d, token requests = %d",
					device.powerCycles,
					device.resets,
					device.tokenRequests,
				)
			}
			if !slices.Equal(device.pinRequests, []TemporaryPINRequest{{
				MinCodePoints: protocol.DefaultMinPINCodePoints,
				MaxCodePoints: protocol.DefaultMinPINCodePoints,
			}}) {
				t.Fatalf("temporary PIN requests = %#v", device.pinRequests)
			}
			if device.pinAuthenticator.setPINCalls != 1 ||
				!device.pinAuthenticator.permissionWiresExact ||
				!slices.Equal(
					device.pinAuthenticator.permissionScopes,
					[]protocol.Permission{protocol.PermissionAuthenticatorConfiguration},
				) ||
				!slices.Equal(device.pinAuthenticator.permissionRPIDs, []string{""}) {
				t.Fatalf("ClientPIN transcript = %#v", device.pinAuthenticator)
			}
			if !device.setPINWireExact ||
				!slices.Equal(device.clientPINSubCommands, []protocol.ClientPINSubCommand{
					protocol.ClientPINSubCommandGetKeyAgreement,
					protocol.ClientPINSubCommandSetPIN,
					protocol.ClientPINSubCommandGetKeyAgreement,
					protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
				}) {
				t.Fatalf(
					"ClientPIN subcommands = %v, exact SetPIN wire = %t",
					device.clientPINSubCommands,
					device.setPINWireExact,
				)
			}
			for _, selected := range device.pinAuthenticator.pinProtocols {
				if selected != protocol.PinUvAuthProtocolTwo {
					t.Fatalf("ClientPIN selected protocol %d, want 2", selected)
				}
			}
			assertAuthenticatorConfigZeroed(t, pin)
			if device.pinAuthenticator.pin != nil {
				t.Fatalf("authenticator retained PIN after cleanup: %x", device.pinAuthenticator.pin)
			}
		})
	}
}

func TestAuthenticatorConfigApplicabilityAndFeaturefulProfile(t *testing.T) {
	cases := []struct {
		name       string
		index      int
		featureful bool
		mutate     func(*authenticatorConfigDevice)
		want       conformance.Status
	}{
		{
			name: "authnrCfg absent skips",
			mutate: func(device *authenticatorConfigDevice) {
				device.absentOptions[string(protocol.OptionAuthenticatorConfig)] = true
			},
			want: conformance.StatusSkipped,
		},
		{
			name:       "authnrCfg false fails featureful profile",
			featureful: true,
			mutate: func(device *authenticatorConfigDevice) {
				device.optionOverrides[string(protocol.OptionAuthenticatorConfig)] = false
			},
			want: conformance.StatusFailed,
		},
		{
			name:       "featureful profile requires toggle",
			featureful: true,
			mutate: func(device *authenticatorConfigDevice) {
				device.commands = slices.DeleteFunc(device.commands, func(command protocol.ConfigSubCommand) bool {
					return command == protocol.ConfigSubCommandToggleAlwaysUv
				})
			},
			want: conformance.StatusFailed,
		},
		{
			name: "authnrCfg wrong type fails",
			mutate: func(device *authenticatorConfigDevice) {
				device.optionOverrides[string(protocol.OptionAuthenticatorConfig)] = uint64(1)
			},
			want: conformance.StatusFailed,
		},
		{
			name: "enterprise option absent skips",
			mutate: func(device *authenticatorConfigDevice) {
				device.absentOptions[string(protocol.OptionEnterpriseAttestation)] = true
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "enterprise command absent fails",
			mutate: func(device *authenticatorConfigDevice) {
				device.commands = slices.Delete(device.commands, 0, 1)
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "toggle command absent skips",
			index: 1,
			mutate: func(device *authenticatorConfigDevice) {
				device.commands = slices.DeleteFunc(device.commands, func(command protocol.ConfigSubCommand) bool {
					return command == protocol.ConfigSubCommandToggleAlwaysUv
				})
			},
			want: conformance.StatusSkipped,
		},
		{
			name:  "set minimum false skips",
			index: 2,
			mutate: func(device *authenticatorConfigDevice) {
				device.optionOverrides[string(protocol.OptionSetMinPINLength)] = false
			},
			want: conformance.StatusSkipped,
		},
		{
			name:  "set minimum requires PIN or passcode",
			index: 2,
			mutate: func(device *authenticatorConfigDevice) {
				device.absentOptions[string(protocol.OptionClientPIN)] = true
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "minimum RP IDs require extension",
			index: 3,
			mutate: func(device *authenticatorConfigDevice) {
				device.extensions = slices.DeleteFunc(device.extensions, func(identifier extension.ExtensionIdentifier) bool {
					return identifier == extension.ExtensionIdentifierMinPinLength
				})
			},
			want: conformance.StatusSkipped,
		},
		{
			name:  "minimum RP IDs require positive maximum",
			index: 3,
			mutate: func(device *authenticatorConfigDevice) {
				device.maxRPIDs = 0
			},
			want: conformance.StatusSkipped,
		},
		{
			name:  "force change requires configured PIN",
			index: 4,
			mutate: func(device *authenticatorConfigDevice) {
				device.clientPIN = false
			},
			want: conformance.StatusSkipped,
		},
		{
			name:  "complexity policy requires extension",
			index: 5,
			mutate: func(device *authenticatorConfigDevice) {
				device.extensions = slices.DeleteFunc(device.extensions, func(identifier extension.ExtensionIdentifier) bool {
					return identifier == extension.ExtensionIdentifierPinComplexityPolicy
				})
			},
			want: conformance.StatusSkipped,
		},
		{
			name:  "long touch requires GetInfo field",
			index: 6,
			mutate: func(device *authenticatorConfigDevice) {
				device.longTouchPresent = false
			},
			want: conformance.StatusSkipped,
		},
		{
			name:  "long touch requires command",
			index: 6,
			mutate: func(device *authenticatorConfigDevice) {
				device.commands = slices.DeleteFunc(device.commands, func(command protocol.ConfigSubCommand) bool {
					return command == protocol.ConfigSubCommandEnableLongTouchForReset
				})
			},
			want: conformance.StatusSkipped,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthenticatorConfigDevice(t)
			testCase.mutate(device)
			config := authenticatorConfigConfig(device, []byte("1234"))
			config.Featureful = testCase.featureful
			result := runAuthenticatorConfigTest(t, device, config, testCase.index)
			if result.Status != testCase.want {
				t.Fatalf("status = %s, want %s; steps = %#v", result.Status, testCase.want, result.Steps)
			}
			if device.powerCycles != 0 || device.resets != 0 || device.tokenRequests != 0 {
				t.Fatalf("unsupported case mutated environment: %#v", device)
			}
		})
	}
}

func TestAuthenticatorConfigRejectsInvalidCommandsWireType(t *testing.T) {
	device := newAuthenticatorConfigDevice(t)
	device.fieldOverrides[31] = []any{"toggleAlwaysUv"}
	result := runAuthenticatorConfigTest(
		t,
		device,
		authenticatorConfigConfig(device, []byte("1234")),
		0,
	)
	if result.Status != conformance.StatusFailed {
		t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
	}
}

func TestAuthenticatorConfigCommandAndEnvironmentErrorsAreClassifiedAndCleanedUp(t *testing.T) {
	cases := []struct {
		name           string
		mutate         func(*authenticatorConfigDevice, *Config)
		pinTransferred bool
		want           conformance.Status
	}{
		{
			name: "CTAP status is failure",
			mutate: func(device *authenticatorConfigDevice, _ *Config) {
				device.configStatus = ctaptransport.CTAP2_ERR_INVALID_OPTION
			},
			pinTransferred: true,
			want:           conformance.StatusFailed,
		},
		{
			name: "transport error is execution error",
			mutate: func(device *authenticatorConfigDevice, _ *Config) {
				device.transportErrorCommand = protocol.AuthenticatorConfig
			},
			pinTransferred: true,
			want:           conformance.StatusError,
		},
		{
			name: "temporary PIN provider error is execution error",
			mutate: func(_ *authenticatorConfigDevice, config *Config) {
				config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
					return nil, errors.New("interaction canceled")
				}
			},
			want: conformance.StatusError,
		},
		{
			name: "missing temporary PIN provider is execution error",
			mutate: func(_ *authenticatorConfigDevice, config *Config) {
				config.TemporaryPINProvider = nil
			},
			want: conformance.StatusError,
		},
		{
			name: "set PIN CTAP status is failure",
			mutate: func(device *authenticatorConfigDevice, _ *Config) {
				device.pinAuthenticator.setPINStatus = ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION
			},
			pinTransferred: true,
			want:           conformance.StatusFailed,
		},
		{
			name: "permission token CTAP status is failure",
			mutate: func(device *authenticatorConfigDevice, _ *Config) {
				device.pinAuthenticator.permissionTokenStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
			},
			pinTransferred: true,
			want:           conformance.StatusFailed,
		},
		{
			name: "cleanup reset error is execution error",
			mutate: func(device *authenticatorConfigDevice, _ *Config) {
				device.resetErrorAt = 2
			},
			pinTransferred: true,
			want:           conformance.StatusError,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthenticatorConfigDevice(t)
			pin := []byte("1234")
			config := authenticatorConfigConfig(device, pin)
			testCase.mutate(device, &config)
			result := runAuthenticatorConfigTest(t, device, config, 0)
			if result.Status != testCase.want {
				t.Fatalf("status = %s, want %s; steps = %#v", result.Status, testCase.want, result.Steps)
			}
			if device.powerCycles != 2 || device.resets != 2 {
				t.Fatalf("power cycles = %d, resets = %d", device.powerCycles, device.resets)
			}
			if testCase.pinTransferred {
				assertAuthenticatorConfigZeroed(t, pin)

				return
			}
			if !bytes.Equal(pin, []byte("1234")) {
				t.Fatal("untransferred PIN changed when the provider returned an error")
			}
		})
	}
}

func TestAuthenticatorConfigToggleOperationDeniedSemantics(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		before bool
		want   conformance.Status
	}{
		{name: "enabled remains enabled", before: true, want: conformance.StatusPassed},
		{name: "disabled denial fails", before: false, want: conformance.StatusFailed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthenticatorConfigDevice(t)
			device.alwaysUVAfterToken = new(bool)
			*device.alwaysUVAfterToken = testCase.before
			device.denyToggle = true
			result := runAuthenticatorConfigTest(
				t,
				device,
				authenticatorConfigConfig(device, []byte("1234")),
				1,
			)
			if result.Status != testCase.want {
				t.Fatalf("status = %s, want %s; steps = %#v", result.Status, testCase.want, result.Steps)
			}
		})
	}
}

func TestAuthenticatorConfigRefreshDetectsMissingStateChanges(t *testing.T) {
	for _, index := range []int{0, 1, 2, 4, 5, 6} {
		t.Run(authenticatorConfigTests(Config{})[index].Source.Case, func(t *testing.T) {
			device := newAuthenticatorConfigDevice(t)
			device.suppressMutation = true
			result := runAuthenticatorConfigTest(
				t,
				device,
				authenticatorConfigConfig(device, []byte("1234")),
				index,
			)
			if result.Status != conformance.StatusFailed {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
		})
	}
}

func TestAuthenticatorConfigRequiresAdvertisedProtocolTwoBeforeMutation(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		featureful bool
		want       conformance.Status
	}{
		{name: "non-featureful profile skips", want: conformance.StatusSkipped},
		{name: "featureful profile fails", featureful: true, want: conformance.StatusFailed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthenticatorConfigDevice(t)
			device.pinProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne}
			config := authenticatorConfigConfig(device, []byte("1234"))
			config.Featureful = testCase.featureful
			result := runAuthenticatorConfigTest(t, device, config, 0)
			if result.Status != testCase.want {
				t.Fatalf("status = %s, want %s; steps = %#v", result.Status, testCase.want, result.Steps)
			}
			if device.powerCycles != 0 || device.resets != 0 || device.tokenRequests != 0 {
				t.Fatalf("unsupported protocol mutated environment: %#v", device)
			}
		})
	}
}

func TestAuthenticatorConfigRejectsWrongProtocolTwoTokenLengthAndCleansUp(t *testing.T) {
	device := newAuthenticatorConfigDevice(t)
	device.pinAuthenticator.permissionTokenLength = 16
	pin := []byte("1234")
	result := runAuthenticatorConfigTest(t, device, authenticatorConfigConfig(device, pin), 0)
	if result.Status != conformance.StatusFailed {
		t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
	}
	if device.powerCycles != 2 || device.resets != 2 || len(device.pinAuthenticator.issuedTokens) != 0 {
		t.Fatalf("cleanup state = %#v", device)
	}
	assertAuthenticatorConfigZeroed(t, pin)
}

func TestAuthenticatorConfigRejectsPINLongerThanResetMinimum(t *testing.T) {
	device := newAuthenticatorConfigDevice(t)
	pin := []byte("12345")
	result := runAuthenticatorConfigTest(t, device, authenticatorConfigConfig(device, pin), 2)
	if result.Status != conformance.StatusError {
		t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
	}
	if !slices.Equal(device.pinRequests, []TemporaryPINRequest{{
		MinCodePoints: protocol.DefaultMinPINCodePoints,
		MaxCodePoints: protocol.DefaultMinPINCodePoints,
	}}) {
		t.Fatalf("temporary PIN requests = %#v", device.pinRequests)
	}
	if device.pinAuthenticator.setPINCalls != 0 || device.tokenRequests != 0 || len(device.requests) != 0 {
		t.Fatalf("invalid environment PIN reached CTAP: %#v", device)
	}
	assertAuthenticatorConfigZeroed(t, pin)
}

func TestAuthenticatorConfigUsesForcedUVFallbackWithoutClientPIN(t *testing.T) {
	device := newAuthenticatorConfigDevice(t)
	device.clientPINPresent = false
	device.clientPIN = false
	device.uvPresent = true
	device.uvConfigured = true
	device.uvAuthenticator.uvConfigured = true
	pin := []byte("1234")
	result := runAuthenticatorConfigTest(t, device, authenticatorConfigConfig(device, pin), 0)
	if result.Status != conformance.StatusPassed {
		t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
	}
	if device.uvConfigCalls != 1 ||
		!slices.Equal(device.pinRequests, []TemporaryPINRequest{{
			MinCodePoints: protocol.DefaultMinPINCodePoints,
			MaxCodePoints: 63,
		}}) {
		t.Fatalf("UV preparation = calls %d, PIN requests %#v", device.uvConfigCalls, device.pinRequests)
	}
	if !device.uvAuthenticator.permissionWiresExact ||
		!slices.Equal(
			device.uvAuthenticator.permissionScopes,
			[]protocol.Permission{protocol.PermissionAuthenticatorConfiguration},
		) ||
		!slices.Equal(device.uvAuthenticator.permissionRPIDs, []string{""}) ||
		device.uvAuthenticator.setPINCalls != 0 {
		t.Fatalf("UV ClientPIN transcript = %#v", device.uvAuthenticator)
	}
	if !slices.Equal(device.clientPINSubCommands, []protocol.ClientPINSubCommand{
		protocol.ClientPINSubCommandGetKeyAgreement,
		protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
	}) {
		t.Fatalf("UV ClientPIN subcommands = %v", device.clientPINSubCommands)
	}
	for _, selected := range device.uvAuthenticator.pinProtocols {
		if selected != protocol.PinUvAuthProtocolTwo {
			t.Fatalf("UV ClientPIN selected protocol %d, want 2", selected)
		}
	}
	assertAuthenticatorConfigZeroed(t, pin)
}

func TestAuthenticatorConfigUVFallbackErrorsAreClassifiedAndCleanedUp(t *testing.T) {
	for _, testCase := range []struct {
		name           string
		mutate         func(*Config)
		pinTransferred bool
	}{
		{
			name: "missing UV configurator",
			mutate: func(config *Config) {
				config.UVConfigurator = nil
			},
		},
		{
			name: "UV configurator error",
			mutate: func(config *Config) {
				config.UVConfigurator = func(context.Context, []byte) error {
					return errors.New("UV enrollment canceled")
				}
			},
			pinTransferred: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthenticatorConfigDevice(t)
			device.clientPINPresent = false
			device.clientPIN = false
			device.uvPresent = true
			pin := []byte("1234")
			config := authenticatorConfigConfig(device, pin)
			testCase.mutate(&config)
			result := runAuthenticatorConfigTest(t, device, config, 0)
			if result.Status != conformance.StatusError {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
			if device.powerCycles != 2 || device.resets != 2 || device.tokenRequests != 0 {
				t.Fatalf("cleanup state = %#v", device)
			}
			if testCase.pinTransferred {
				assertAuthenticatorConfigZeroed(t, pin)
			} else if !bytes.Equal(pin, []byte("1234")) {
				t.Fatal("untransferred PIN changed")
			}
		})
	}
}

type authenticatorConfigRequestRecord struct {
	subCommand protocol.ConfigSubCommand
	params     map[uint64]cbor.RawMessage
}

type authenticatorConfigDevice struct {
	t *testing.T

	pinAuthenticator *clientPIN2PermissionsAuthenticator
	uvAuthenticator  *clientPIN2UVPermissionsAuthenticator

	commands         []protocol.ConfigSubCommand
	extensions       []extension.ExtensionIdentifier
	optionOverrides  map[string]any
	absentOptions    map[string]bool
	fieldOverrides   map[uint64]any
	pinProtocols     []protocol.PinUvAuthProtocol
	longTouchPresent bool
	maxRPIDs         uint

	clientPINPresent      bool
	clientPIN             bool
	uvPresent             bool
	uvConfigured          bool
	enterprise            bool
	alwaysUV              bool
	alwaysUVAfterToken    *bool
	minPINLength          uint
	forcePINChange        bool
	complexityPolicy      bool
	longTouch             bool
	configuredRPIDs       []string
	suppressMutation      bool
	denyToggle            bool
	configStatus          ctaptransport.StatusCode
	transportErrorCommand protocol.Command

	powerCycles   int
	resets        int
	resetErrorAt  int
	tokenRequests int
	uvConfigCalls int
	requests      []authenticatorConfigRequestRecord
	pinRequests   []TemporaryPINRequest

	clientPINSubCommands []protocol.ClientPINSubCommand
	setPINWireExact      bool
}

func newAuthenticatorConfigDevice(t *testing.T) *authenticatorConfigDevice {
	t.Helper()

	pinAuthenticator := newClientPIN2PermissionsAuthenticator(t)
	uvAuthenticator := newClientPIN2UVPermissionsAuthenticator(t)

	return &authenticatorConfigDevice{
		t:                t,
		pinAuthenticator: pinAuthenticator,
		uvAuthenticator:  uvAuthenticator,
		commands: []protocol.ConfigSubCommand{
			protocol.ConfigSubCommandEnableEnterpriseAttestation,
			protocol.ConfigSubCommandToggleAlwaysUv,
			protocol.ConfigSubCommandSetMinPINLength,
			protocol.ConfigSubCommandEnableLongTouchForReset,
		},
		extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierMinPinLength,
			extension.ExtensionIdentifierPinComplexityPolicy,
		},
		optionOverrides: make(map[string]any),
		absentOptions:   make(map[string]bool),
		fieldOverrides:  make(map[uint64]any),
		pinProtocols: []protocol.PinUvAuthProtocol{
			protocol.PinUvAuthProtocolOne,
			protocol.PinUvAuthProtocolTwo,
		},
		longTouchPresent: true,
		maxRPIDs:         2,
		clientPINPresent: true,
		clientPIN:        true,
		minPINLength:     protocol.DefaultMinPINCodePoints,
		setPINWireExact:  true,
	}
}

func (device *authenticatorConfigDevice) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.t.Helper()
	if len(request) == 0 {
		device.t.Fatal("empty request")
	}

	command := protocol.Command(request[0])
	if command == device.transportErrorCommand {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected")
	}
	var response ctaptransport.CBORResponse
	switch command {
	case protocol.AuthenticatorGetInfo:
		response = device.getInfoResponse()
	case protocol.AuthenticatorClientPIN:
		return device.clientPINResponse(ctx, request)
	case protocol.AuthenticatorConfig:
		response = device.authenticatorConfigResponse(request[1:])
	default:
		device.t.Fatalf("unexpected command %s", command)
	}

	return ctaptransport.ValidateCBORResponse(command, response)
}

func (device *authenticatorConfigDevice) clientPINResponse(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	var body protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
		device.t.Fatal(err)
	}
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		device.t.Fatal(err)
	}
	device.clientPINSubCommands = append(device.clientPINSubCommands, body.SubCommand)
	if body.SubCommand == protocol.ClientPINSubCommandSetPIN {
		device.setPINWireExact = device.setPINWireExact &&
			body.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
			fields[1] != nil &&
			fields[2] != nil &&
			fields[3] != nil &&
			fields[4] != nil &&
			fields[5] != nil &&
			fields[6] == nil &&
			fields[9] == nil &&
			fields[10] == nil &&
			len(fields) == 5
	}

	var (
		response ctaptransport.CBORResponse
		err      error
	)
	if device.clientPINPresent {
		response, err = device.pinAuthenticator.CBOR(ctx, request)
	} else {
		response, err = device.uvAuthenticator.CBOR(ctx, request)
	}
	if err != nil || response.StatusCode != ctaptransport.CTAP2_OK {
		return response, err
	}

	switch body.SubCommand {
	case protocol.ClientPINSubCommandSetPIN:
		device.clientPIN = true
	case protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions:
		device.tokenRequests++
		if device.alwaysUVAfterToken != nil {
			device.alwaysUV = *device.alwaysUVAfterToken
		}
	default:
	}

	return response, nil
}

func (device *authenticatorConfigDevice) getInfoResponse() ctaptransport.CBORResponse {
	options := map[string]any{
		string(protocol.OptionAuthenticatorConfig):   true,
		string(protocol.OptionEnterpriseAttestation): device.enterprise,
		string(protocol.OptionAlwaysUv):              device.alwaysUV,
		string(protocol.OptionSetMinPINLength):       true,
		string(protocol.OptionPinUvAuthToken):        true,
	}
	if device.clientPINPresent {
		options[string(protocol.OptionClientPIN)] = device.clientPIN
	}
	if device.uvPresent {
		options[string(protocol.OptionUserVerification)] = device.uvConfigured
	}
	for option := range device.absentOptions {
		delete(options, option)
	}
	for option, value := range device.optionOverrides {
		options[option] = value
	}

	fields := map[uint64]any{
		1:  []string{string(protocol.FIDO_2_3)},
		2:  device.extensions,
		4:  options,
		5:  uint(1024),
		6:  device.pinProtocols,
		12: device.forcePINChange,
		16: device.maxRPIDs,
		27: device.complexityPolicy,
		31: device.commands,
	}
	if device.clientPINPresent {
		fields[13] = device.minPINLength
	}
	if device.uvPresent {
		fields[18] = protocol.UserVerifyPasscodeInternal
	}
	if device.longTouchPresent {
		fields[24] = device.longTouch
	}
	for key, value := range device.fieldOverrides {
		fields[key] = value
	}
	data, err := ctap2EncMode.Marshal(fields)
	if err != nil {
		device.t.Fatal(err)
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

func (device *authenticatorConfigDevice) authenticatorConfigResponse(body []byte) ctaptransport.CBORResponse {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		device.t.Fatal(err)
	}
	wantFieldCount := 3
	if _, present := fields[2]; present {
		wantFieldCount = 4
	}
	if len(fields) != wantFieldCount {
		device.t.Fatalf("authenticatorConfig fields = %#v", fields)
	}
	var subCommand protocol.ConfigSubCommand
	if err := getInfoDecMode.Unmarshal(fields[1], &subCommand); err != nil {
		device.t.Fatal(err)
	}
	var pinProtocol protocol.PinUvAuthProtocol
	if err := getInfoDecMode.Unmarshal(fields[3], &pinProtocol); err != nil {
		device.t.Fatal(err)
	}
	if pinProtocol != protocol.PinUvAuthProtocolTwo {
		device.t.Fatalf("pinUvAuthProtocol = %d", pinProtocol)
	}
	var authParam []byte
	if err := getInfoDecMode.Unmarshal(fields[4], &authParam); err != nil {
		device.t.Fatal(err)
	}
	message := slices.Concat(
		bytes.Repeat([]byte{0xff}, 32),
		[]byte{byte(protocol.AuthenticatorConfig), byte(subCommand)},
		fields[2],
	)
	wantAuth := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, device.configurationToken(), message)
	defer clear(wantAuth)
	if !bytes.Equal(authParam, wantAuth) {
		device.t.Fatal("pinUvAuthParam does not authenticate the exact request")
	}

	var params map[uint64]cbor.RawMessage
	if rawParams, present := fields[2]; present {
		if err := getInfoDecMode.Unmarshal(rawParams, &params); err != nil {
			device.t.Fatal(err)
		}
	}
	device.requests = append(device.requests, authenticatorConfigRequestRecord{
		subCommand: subCommand,
		params:     params,
	})
	if device.configStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: device.configStatus}
	}
	if subCommand == protocol.ConfigSubCommandToggleAlwaysUv && device.denyToggle {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_OPERATION_DENIED}
	}
	if !device.suppressMutation {
		device.apply(subCommand, params)
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
}

func (device *authenticatorConfigDevice) configurationToken() []byte {
	if device.clientPINPresent {
		return device.pinAuthenticator.issuedTokens[protocol.PermissionAuthenticatorConfiguration]
	}

	return device.uvAuthenticator.activeToken
}

func (device *authenticatorConfigDevice) apply(
	subCommand protocol.ConfigSubCommand,
	params map[uint64]cbor.RawMessage,
) {
	switch subCommand {
	case protocol.ConfigSubCommandEnableEnterpriseAttestation:
		device.enterprise = true
	case protocol.ConfigSubCommandToggleAlwaysUv:
		device.alwaysUV = !device.alwaysUV
	case protocol.ConfigSubCommandSetMinPINLength:
		if raw := params[1]; raw != nil {
			var minimum uint
			if err := getInfoDecMode.Unmarshal(raw, &minimum); err != nil {
				device.t.Fatal(err)
			}
			if minimum > uint(utf8.RuneCount(device.pinAuthenticator.pin)) && device.clientPIN {
				device.forcePINChange = true
			}
			device.minPINLength = minimum
		}
		if raw := params[2]; raw != nil {
			if err := getInfoDecMode.Unmarshal(raw, &device.configuredRPIDs); err != nil {
				device.t.Fatal(err)
			}
		}
		if raw := params[3]; raw != nil {
			if err := getInfoDecMode.Unmarshal(raw, &device.forcePINChange); err != nil {
				device.t.Fatal(err)
			}
		}
		if raw := params[4]; raw != nil {
			if err := getInfoDecMode.Unmarshal(raw, &device.complexityPolicy); err != nil {
				device.t.Fatal(err)
			}
		}
	case protocol.ConfigSubCommandEnableLongTouchForReset:
		device.longTouch = true
	default:
		device.t.Fatalf("unexpected subcommand 0x%x", subCommand)
	}
}

func (device *authenticatorConfigDevice) reset() error {
	device.resets++
	if device.resetErrorAt == device.resets {
		return errors.New("reset interaction failed")
	}
	device.pinAuthenticator.clientPIN2NewPINAuthenticator.reset()
	for permission, token := range device.pinAuthenticator.issuedTokens {
		clear(token)
		delete(device.pinAuthenticator.issuedTokens, permission)
	}
	device.uvAuthenticator.reset()
	device.clientPIN = false
	device.uvConfigured = false
	device.enterprise = false
	device.alwaysUV = false
	device.minPINLength = protocol.DefaultMinPINCodePoints
	device.forcePINChange = false
	device.complexityPolicy = false
	device.longTouch = false
	device.configuredRPIDs = nil

	return nil
}

func authenticatorConfigConfig(device *authenticatorConfigDevice, pin []byte) Config {
	return Config{
		PowerCycler: func(context.Context) error {
			device.powerCycles++

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			return device.reset()
		},
		TemporaryPINProvider: func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
			device.pinRequests = append(device.pinRequests, request)

			return pin, nil
		},
		UVConfigurator: func(context.Context, []byte) error {
			device.uvConfigCalls++
			device.uvConfigured = true
			device.uvAuthenticator.uvConfigured = true

			return nil
		},
	}
}

func runAuthenticatorConfigTest(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	index int,
) conformance.TestResult {
	t.Helper()
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "authenticator-config-test",
		Name:  "AuthenticatorConfig test",
		Tests: []conformance.Test{authenticatorConfigTests(config)[index]},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result.Tests[0]
}

func assertNoAuthenticatorConfigParams(t *testing.T, params map[uint64]cbor.RawMessage) {
	t.Helper()
	if params != nil {
		t.Fatalf("params = %#v, want absent", params)
	}
}

func assertAuthenticatorConfigUintParam(
	t *testing.T,
	params map[uint64]cbor.RawMessage,
	key uint64,
	want uint,
) {
	t.Helper()
	if len(params) != 1 {
		t.Fatalf("params = %#v", params)
	}
	var got uint
	if err := getInfoDecMode.Unmarshal(params[key], &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("params[%d] = %d, want %d", key, got, want)
	}
}

func assertAuthenticatorConfigBoolParam(
	t *testing.T,
	params map[uint64]cbor.RawMessage,
	key uint64,
) {
	t.Helper()
	if len(params) != 1 {
		t.Fatalf("params = %#v", params)
	}
	var got bool
	if err := getInfoDecMode.Unmarshal(params[key], &got); err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatalf("params[%d] = false, want true", key)
	}
}

func assertAuthenticatorConfigZeroed(t *testing.T, value []byte) {
	t.Helper()
	for index, b := range value {
		if b != 0 {
			t.Fatalf("secret byte %d was not cleared", index)
		}
	}
}

var _ ctaptransport.CBOR = (*authenticatorConfigDevice)(nil)
