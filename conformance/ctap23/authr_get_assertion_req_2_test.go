package ctap23

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrGetAssertionReq2Definitions(t *testing.T) {
	want := []struct {
		id         conformance.TestID
		marker     string
		references []conformance.RequirementRef
	}{
		{
			id:     TestIDAuthrGetAssertionReq2P1,
			marker: "P-1",
			references: []conformance.RequirementRef{
				authrGetAssertionReq1CommandReference(),
				authrGetAssertionReq2Reference("6.2", "get-assertion-options", "getassert-input-parameters"),
				authrGetAssertionReq2Reference("6.2.2", "unknown-options-treated-as-absent", "op-getassert-step-options"),
				authrGetAssertionReq2Reference("6.2", "get-assertion-response-auth-data", "authenticatorGetAssertion"),
				ctapMessageEncodingReference(),
			},
		},
		{
			id:     TestIDAuthrGetAssertionReq2P2,
			marker: "P-2",
			references: []conformance.RequirementRef{
				authrGetAssertionReq1CommandReference(),
				authrGetAssertionReq2Reference("6.2", "get-assertion-options", "getassert-input-parameters"),
				authrGetAssertionReq2Reference("6.2.2", "up-option-sets-auth-data-flag", "op-getassert-step-up"),
				authrGetAssertionReq2Reference("6.2", "get-assertion-response-auth-data", "authenticatorGetAssertion"),
				ctapMessageEncodingReference(),
			},
		},
		{
			id:     TestIDAuthrGetAssertionReq2P3,
			marker: "P-3",
			references: []conformance.RequirementRef{
				authrGetAssertionReq1CommandReference(),
				authrGetAssertionReq2Reference("6.2", "get-assertion-options", "getassert-input-parameters"),
				authrGetAssertionReq2Reference("6.2.2", "uv-option-sets-auth-data-flag", "op-getassert-step-performBuiltInUv"),
				authrGetAssertionReq2Reference("6.2", "get-assertion-response-auth-data", "authenticatorGetAssertion"),
				ctapMessageEncodingReference(),
			},
		},
	}

	tests := authrGetAssertionReq2Tests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != authrGetAssertionReq2SourcePath ||
			test.Source.Case != expected.marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		if !slices.Equal(test.References, expected.references) {
			t.Fatalf("references for %s = %#v, want %#v", test.ID, test.References, expected.references)
		}
	}
}

func TestAuthrGetAssertionReq2P1SendsUnknownOptionWithAllowListAndAuthorization(t *testing.T) {
	device := newAuthrGetAssertionReq2Device(t)
	lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)

	result := runAuthrGetAssertionReq2Test(t, device, lifecycle.config(), TestIDAuthrGetAssertionReq2P1)

	assertAuthrGetAssertionReq2Status(t, result, conformance.StatusPassed)
	assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, 1, 1)
	assertAuthrGetAssertionReq2Request(
		t,
		device.getAssertionRequest,
		map[string]bool{"makeTea": true},
		true,
	)
}

func TestAuthrGetAssertionReq2P2ApplicabilityAndUPFlag(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options authrGetAssertionReq2InfoOptions
	}{
		{name: "options absent", options: authrGetAssertionReq2AbsentOptions()},
		{name: "up absent", options: authrGetAssertionReq2Options(map[string]any{
			string(protocol.OptionClientPIN): false,
		})},
		{name: "up true", options: authrGetAssertionReq2Options(map[string]any{
			string(protocol.OptionClientPIN):    false,
			string(protocol.OptionUserPresence): true,
		})},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrGetAssertionReq2Device(t)
			device.infoOptions = append(device.infoOptions, testCase.options)
			device.responseFlags = protocol.AuthDataFlagUserPresent
			lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)

			result := runAuthrGetAssertionReq2Test(
				t,
				device,
				lifecycle.config(),
				TestIDAuthrGetAssertionReq2P2,
			)

			assertAuthrGetAssertionReq2Status(t, result, conformance.StatusPassed)
			assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, 2, 1)
			assertAuthrGetAssertionReq2Request(
				t,
				device.getAssertionRequest,
				map[string]bool{string(protocol.OptionUserPresence): true},
				true,
			)
		})
	}
}

func TestAuthrGetAssertionReq2P2SkipsLateWhenUPIsFalse(t *testing.T) {
	device := newAuthrGetAssertionReq2Device(t)
	device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
		string(protocol.OptionClientPIN):    false,
		string(protocol.OptionUserPresence): false,
	}))
	lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)

	result := runAuthrGetAssertionReq2Test(t, device, lifecycle.config(), TestIDAuthrGetAssertionReq2P2)

	assertAuthrGetAssertionReq2Status(t, result, conformance.StatusSkipped)
	assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, 2, 0)
	if device.getAssertionRequest != nil {
		t.Fatalf("GetAssertion request = %x, want none", device.getAssertionRequest)
	}
}

func TestAuthrGetAssertionReq2P3UsesConfiguredUVWithoutCallbacks(t *testing.T) {
	device := newAuthrGetAssertionReq2Device(t)
	device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
		string(protocol.OptionClientPIN):        false,
		string(protocol.OptionUserVerification): true,
	}))
	device.responseFlags = protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified
	lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)

	result := runAuthrGetAssertionReq2Test(t, device, lifecycle.config(), TestIDAuthrGetAssertionReq2P3)

	assertAuthrGetAssertionReq2Status(t, result, conformance.StatusPassed)
	assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, 2, 1)
	if lifecycle.pinRequests != 0 || lifecycle.uvConfigurations != 0 {
		t.Fatalf("PIN requests/UV configurations = %d/%d, want 0/0", lifecycle.pinRequests, lifecycle.uvConfigurations)
	}
	assertAuthrGetAssertionReq2Request(
		t,
		device.getAssertionRequest,
		map[string]bool{string(protocol.OptionUserVerification): true},
		false,
	)
}

func TestAuthrGetAssertionReq2P3ConfiguresUVAndWipesPIN(t *testing.T) {
	device := newAuthrGetAssertionReq2Device(t)
	device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
		string(protocol.OptionClientPIN):        false,
		string(protocol.OptionUserVerification): false,
	}))
	device.responseFlags = protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified
	lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)

	result := runAuthrGetAssertionReq2Test(t, device, lifecycle.config(), TestIDAuthrGetAssertionReq2P3)

	assertAuthrGetAssertionReq2Status(t, result, conformance.StatusPassed)
	assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, 3, 1)
	if lifecycle.pinRequests != 1 || lifecycle.uvConfigurations != 1 ||
		lifecycle.pinRequest != (TemporaryPINRequest{MinCodePoints: 6, MaxCodePoints: 12}) {
		t.Fatalf(
			"PIN requests/configurations/request = %d/%d/%#v",
			lifecycle.pinRequests,
			lifecycle.uvConfigurations,
			lifecycle.pinRequest,
		)
	}
	assertAuthrGetAssertionReq2PINWiped(t, lifecycle.pin)
	assertAuthrGetAssertionReq2Request(
		t,
		device.getAssertionRequest,
		map[string]bool{string(protocol.OptionUserVerification): true},
		false,
	)
}

func TestAuthrGetAssertionReq2P3SkipsLateWhenUVIsAbsent(t *testing.T) {
	device := newAuthrGetAssertionReq2Device(t)
	device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
		string(protocol.OptionClientPIN): false,
	}))
	lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)

	result := runAuthrGetAssertionReq2Test(t, device, lifecycle.config(), TestIDAuthrGetAssertionReq2P3)

	assertAuthrGetAssertionReq2Status(t, result, conformance.StatusSkipped)
	assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, 2, 0)
	if lifecycle.pinRequests != 0 || lifecycle.uvConfigurations != 0 || device.getAssertionRequest != nil {
		t.Fatalf(
			"PIN requests/UV configurations/GetAssertion = %d/%d/%x",
			lifecycle.pinRequests,
			lifecycle.uvConfigurations,
			device.getAssertionRequest,
		)
	}
}

func TestAuthrGetAssertionReq2RejectsMalformedRawGetInfoOptions(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		id      conformance.TestID
		options authrGetAssertionReq2InfoOptions
	}{
		{name: "P2 options null", id: TestIDAuthrGetAssertionReq2P2, options: authrGetAssertionReq2Options(nil)},
		{name: "P2 options wrong type", id: TestIDAuthrGetAssertionReq2P2, options: authrGetAssertionReq2Options([]any{})},
		{name: "P2 up null", id: TestIDAuthrGetAssertionReq2P2, options: authrGetAssertionReq2Options(map[string]any{string(protocol.OptionUserPresence): nil})},
		{name: "P2 up wrong type", id: TestIDAuthrGetAssertionReq2P2, options: authrGetAssertionReq2Options(map[string]any{string(protocol.OptionUserPresence): "true"})},
		{name: "P3 options null", id: TestIDAuthrGetAssertionReq2P3, options: authrGetAssertionReq2Options(nil)},
		{name: "P3 options wrong type", id: TestIDAuthrGetAssertionReq2P3, options: authrGetAssertionReq2Options([]any{})},
		{name: "P3 uv null", id: TestIDAuthrGetAssertionReq2P3, options: authrGetAssertionReq2Options(map[string]any{string(protocol.OptionUserVerification): nil})},
		{name: "P3 uv wrong type", id: TestIDAuthrGetAssertionReq2P3, options: authrGetAssertionReq2Options(map[string]any{string(protocol.OptionUserVerification): "true"})},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrGetAssertionReq2Device(t)
			device.infoOptions = append(device.infoOptions, testCase.options)
			lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)

			result := runAuthrGetAssertionReq2Test(t, device, lifecycle.config(), testCase.id)

			assertAuthrGetAssertionReq2Status(t, result, conformance.StatusFailed)
			assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, 2, 0)
			if device.getAssertionRequest != nil {
				t.Fatalf("GetAssertion request = %x, want none", device.getAssertionRequest)
			}
		})
	}
}

func TestAuthrGetAssertionReq2P3ConfigurationGapsAreErrorsAndWipePIN(t *testing.T) {
	providerFailure := errors.New("PIN provider failed")
	configuratorFailure := errors.New("UV configurator failed")
	for _, testCase := range []struct {
		name          string
		configure     func(*authrGetAssertionReq2Lifecycle, *Config)
		refresh       *authrGetAssertionReq2InfoOptions
		wantPIN       bool
		wantConfigure bool
	}{
		{name: "missing PIN provider", configure: func(_ *authrGetAssertionReq2Lifecycle, config *Config) {
			config.TemporaryPINProvider = nil
		}},
		{name: "missing UV configurator", configure: func(_ *authrGetAssertionReq2Lifecycle, config *Config) {
			config.UVConfigurator = nil
		}},
		{name: "provider error", wantPIN: true, configure: func(lifecycle *authrGetAssertionReq2Lifecycle, _ *Config) {
			lifecycle.pinProviderError = providerFailure
		}},
		{name: "invalid PIN", wantPIN: true, configure: func(lifecycle *authrGetAssertionReq2Lifecycle, _ *Config) {
			lifecycle.pinValue = []byte("123")
		}},
		{name: "configurator error", wantPIN: true, wantConfigure: true, configure: func(lifecycle *authrGetAssertionReq2Lifecycle, _ *Config) {
			lifecycle.uvConfiguratorError = configuratorFailure
		}},
		{name: "refresh uv absent", wantPIN: true, wantConfigure: true, refresh: authrGetAssertionReq2OptionsPtr(map[string]any{
			string(protocol.OptionClientPIN): false,
		})},
		{name: "refresh uv false", wantPIN: true, wantConfigure: true, refresh: authrGetAssertionReq2OptionsPtr(map[string]any{
			string(protocol.OptionClientPIN):        false,
			string(protocol.OptionUserVerification): false,
		})},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrGetAssertionReq2Device(t)
			device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
				string(protocol.OptionClientPIN):        false,
				string(protocol.OptionUserVerification): false,
			}))
			lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)
			lifecycle.refreshOptions = testCase.refresh
			config := lifecycle.config()
			if testCase.configure != nil {
				testCase.configure(lifecycle, &config)
			}

			result := runAuthrGetAssertionReq2Test(t, device, config, TestIDAuthrGetAssertionReq2P3)

			assertAuthrGetAssertionReq2Status(t, result, conformance.StatusError)
			wantGetInfo := 2
			if testCase.wantConfigure && testCase.refresh != nil {
				wantGetInfo = 3
			}
			assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, wantGetInfo, 0)
			if (lifecycle.pinRequests != 0) != testCase.wantPIN {
				t.Fatalf("PIN requests = %d, wantPIN %v", lifecycle.pinRequests, testCase.wantPIN)
			}
			if (lifecycle.uvConfigurations != 0) != testCase.wantConfigure {
				t.Fatalf("UV configurations = %d, want %v", lifecycle.uvConfigurations, testCase.wantConfigure)
			}
			if testCase.wantPIN {
				assertAuthrGetAssertionReq2PINWiped(t, lifecycle.pin)
			}
		})
	}
}

func TestAuthrGetAssertionReq2P3RejectsMalformedRefreshedUVAndWipesPIN(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		options authrGetAssertionReq2InfoOptions
	}{
		{name: "options null", options: authrGetAssertionReq2Options(nil)},
		{name: "options wrong type", options: authrGetAssertionReq2Options([]any{})},
		{name: "uv null", options: authrGetAssertionReq2Options(map[string]any{
			string(protocol.OptionUserVerification): nil,
		})},
		{name: "uv wrong type", options: authrGetAssertionReq2Options(map[string]any{
			string(protocol.OptionUserVerification): []any{},
		})},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrGetAssertionReq2Device(t)
			device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
				string(protocol.OptionClientPIN):        false,
				string(protocol.OptionUserVerification): false,
			}))
			lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)
			lifecycle.refreshOptions = &testCase.options

			result := runAuthrGetAssertionReq2Test(
				t,
				device,
				lifecycle.config(),
				TestIDAuthrGetAssertionReq2P3,
			)

			assertAuthrGetAssertionReq2Status(t, result, conformance.StatusFailed)
			assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, 3, 0)
			assertAuthrGetAssertionReq2PINWiped(t, lifecycle.pin)
		})
	}
}

func TestAuthrGetAssertionReq2CommandFailuresAndResponseFlags(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	for _, testCase := range []struct {
		name       string
		id         conformance.TestID
		flags      protocol.AuthDataFlag
		status     ctaptransport.StatusCode
		err        error
		wantStatus conformance.Status
	}{
		{name: "CTAP status", id: TestIDAuthrGetAssertionReq2P1, status: ctaptransport.CTAP2_ERR_NO_CREDENTIALS, wantStatus: conformance.StatusFailed},
		{name: "transport error", id: TestIDAuthrGetAssertionReq2P1, err: transportFailure, wantStatus: conformance.StatusError},
		{name: "UP flag false", id: TestIDAuthrGetAssertionReq2P2, flags: 0, wantStatus: conformance.StatusFailed},
		{name: "UV flag false", id: TestIDAuthrGetAssertionReq2P3, flags: protocol.AuthDataFlagUserPresent, wantStatus: conformance.StatusFailed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrGetAssertionReq2Device(t)
			device.getAssertionStatus = testCase.status
			device.getAssertionError = testCase.err
			device.responseFlags = testCase.flags
			switch testCase.id {
			case TestIDAuthrGetAssertionReq2P2:
				device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
					string(protocol.OptionUserPresence): true,
				}))
			case TestIDAuthrGetAssertionReq2P3:
				device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
					string(protocol.OptionUserVerification): true,
				}))
			}
			lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)

			result := runAuthrGetAssertionReq2Test(t, device, lifecycle.config(), testCase.id)

			assertAuthrGetAssertionReq2Status(t, result, testCase.wantStatus)
			wantGetInfo := 1
			if testCase.id != TestIDAuthrGetAssertionReq2P1 {
				wantGetInfo = 2
			}
			assertAuthrGetAssertionReq2StandardLifecycle(t, device, lifecycle, wantGetInfo, 1)
		})
	}
}

func TestAuthrGetAssertionReq2CleanupFailureIsVisibleAndSecretsAreWiped(t *testing.T) {
	cleanupFailure := errors.New("cleanup power cycle failed")
	device := newAuthrGetAssertionReq2Device(t)
	device.infoOptions = append(device.infoOptions, authrGetAssertionReq2Options(map[string]any{
		string(protocol.OptionClientPIN):        false,
		string(protocol.OptionUserVerification): false,
	}))
	device.responseFlags = protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified
	lifecycle := newAuthrGetAssertionReq2Lifecycle(t, device)
	lifecycle.cleanupFailure = cleanupFailure

	result := runAuthrGetAssertionReq2Test(t, device, lifecycle.config(), TestIDAuthrGetAssertionReq2P3)

	assertAuthrGetAssertionReq2Status(t, result, conformance.StatusError)
	assertAuthrGetAssertionReq2TokensWiped(t, lifecycle.tokens)
	assertAuthrGetAssertionReq2PINWiped(t, lifecycle.pin)
	if lifecycle.powerCycles != 3 || device.resets != 1 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/1", lifecycle.powerCycles, device.resets)
	}
	steps := result.Tests[0].Steps
	last := steps[len(steps)-1]
	if last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusError ||
		last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
}

type authrGetAssertionReq2InfoOptions struct {
	present bool
	value   any
}

func authrGetAssertionReq2Options(value any) authrGetAssertionReq2InfoOptions {
	return authrGetAssertionReq2InfoOptions{present: true, value: value}
}

func authrGetAssertionReq2OptionsPtr(value any) *authrGetAssertionReq2InfoOptions {
	options := authrGetAssertionReq2Options(value)

	return &options
}

func authrGetAssertionReq2AbsentOptions() authrGetAssertionReq2InfoOptions {
	return authrGetAssertionReq2InfoOptions{}
}

type authrGetAssertionReq2Lifecycle struct {
	t                   testing.TB
	device              *authrGetAssertionReq2Device
	powerCycles         int
	tokens              [][]byte
	cleanupFailure      error
	pinRequests         int
	pinRequest          TemporaryPINRequest
	pin                 []byte
	pinValue            []byte
	pinProviderError    error
	uvConfigurations    int
	uvConfiguratorError error
	refreshOptions      *authrGetAssertionReq2InfoOptions
}

func newAuthrGetAssertionReq2Lifecycle(
	t testing.TB,
	device *authrGetAssertionReq2Device,
) *authrGetAssertionReq2Lifecycle {
	return &authrGetAssertionReq2Lifecycle{
		t:        t,
		device:   device,
		pinValue: []byte("123456"),
	}
}

func (l *authrGetAssertionReq2Lifecycle) config() Config {
	return Config{
		PowerCycler: func(context.Context) error {
			l.powerCycles++
			if l.powerCycles == 3 && l.cleanupFailure != nil {
				return l.cleanupFailure
			}

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			wantPermissions := []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionGetAssertion,
			}
			if len(l.tokens) >= len(wantPermissions) ||
				request.Permission != wantPermissions[len(l.tokens)] ||
				request.RPID != authrGetAssertionReq2RPID {
				l.t.Fatalf("token request %d = %#v", len(l.tokens), request)
			}
			if len(l.tokens) == 1 && slices.ContainsFunc(
				l.tokens[0],
				func(value byte) bool { return value != 0 },
			) {
				l.t.Fatal("MakeCredential token was not wiped before GetAssertion authorization")
			}

			token := bytes.Repeat([]byte{byte(0x91 + len(l.tokens))}, 32)
			l.tokens = append(l.tokens, token)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    token,
			}, nil
		},
		TemporaryPINProvider: func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
			l.pinRequests++
			l.pinRequest = request
			l.pin = slices.Clone(l.pinValue)

			return l.pin, l.pinProviderError
		},
		UVConfigurator: func(_ context.Context, pin []byte) error {
			l.uvConfigurations++
			if !bytes.Equal(pin, l.pinValue) {
				l.t.Fatalf("UV configurator PIN = %q, want %q", pin, l.pinValue)
			}
			if l.uvConfiguratorError != nil {
				return l.uvConfiguratorError
			}
			if l.refreshOptions != nil {
				l.device.infoOptions = append(l.device.infoOptions, *l.refreshOptions)
			} else {
				l.device.infoOptions = append(l.device.infoOptions, authrGetAssertionReq2Options(map[string]any{
					string(protocol.OptionClientPIN):        false,
					string(protocol.OptionUserVerification): true,
				}))
			}

			return nil
		},
	}
}

type authrGetAssertionReq2Device struct {
	t                      testing.TB
	commands               []protocol.Command
	resets                 int
	credentialID           []byte
	getInfoCalls           int
	infoOptions            []authrGetAssertionReq2InfoOptions
	getAssertionStatus     ctaptransport.StatusCode
	getAssertionError      error
	getAssertionRequest    []byte
	responseFlags          protocol.AuthDataFlag
	makeCredentialRequests int
}

func newAuthrGetAssertionReq2Device(t testing.TB) *authrGetAssertionReq2Device {
	t.Helper()

	return &authrGetAssertionReq2Device{
		t:            t,
		credentialID: bytes.Repeat([]byte{0xa2}, 16),
		infoOptions: []authrGetAssertionReq2InfoOptions{authrGetAssertionReq2Options(map[string]any{
			string(protocol.OptionClientPIN): false,
		})},
		responseFlags: protocol.AuthDataFlagUserPresent,
	}
}

func (d *authrGetAssertionReq2Device) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	d.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		d.t.Fatal("empty request")
	}

	command := protocol.Command(request[0])
	d.commands = append(d.commands, command)
	switch command {
	case protocol.AuthenticatorReset:
		if len(request) != 1 {
			d.t.Fatalf("reset request = %x", request)
		}
		d.resets++

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.AuthenticatorGetInfo:
		if len(request) != 1 {
			d.t.Fatalf("GetInfo request = %x", request)
		}
		options := d.infoOptions[len(d.infoOptions)-1]
		if d.getInfoCalls < len(d.infoOptions) {
			options = d.infoOptions[d.getInfoCalls]
		}
		d.getInfoCalls++
		fields := map[uint64]any{
			1: []protocol.Version{protocol.FIDO_2_3},
			2: []extension.ExtensionIdentifier{},
			3: uuid.UUID{},
			6: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			10: []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}},
			13: uint(6),
			29: uint(12),
		}
		if options.present {
			fields[4] = options.value
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       authrGetAssertionReq2Marshal(d.t, fields),
		}, nil
	case protocol.AuthenticatorMakeCredential:
		d.makeCredentialRequests++

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: authrGetAssertionReq2Marshal(d.t, protocol.AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AuthDataRaw:          authrGetAssertionReq2MakeCredentialAuthData(d.t, d.credentialID),
				AttestationStatement: map[string]any{},
			}),
		}, nil
	case protocol.AuthenticatorGetAssertion:
		d.getAssertionRequest = slices.Clone(request)
		if d.getAssertionError != nil {
			return ctaptransport.CBORResponse{}, d.getAssertionError
		}

		response := ctaptransport.CBORResponse{StatusCode: d.getAssertionStatus}
		if response.StatusCode == ctaptransport.CTAP2_OK {
			response.Data = authrGetAssertionReq2Marshal(
				d.t,
				protocol.AuthenticatorGetAssertionResponse{
					Credential: credential.PublicKeyCredentialDescriptor{
						Type: credential.PublicKeyCredentialTypePublicKey,
						ID:   d.credentialID,
					},
					AuthDataRaw: authrGetAssertionReq2AuthData(d.responseFlags),
					Signature:   []byte{0x30, 0x00},
				},
			)
		}

		return response, nil
	default:
		d.t.Fatalf("unexpected command 0x%02x", byte(command))

		return ctaptransport.CBORResponse{}, nil
	}
}

func runAuthrGetAssertionReq2Test(
	t *testing.T,
	device *authrGetAssertionReq2Device,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrGetAssertionReq2Tests(config) {
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
		ID:    "authr-get-assertion-req-2-test",
		Name:  "Authr GetAssertion Req 2 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrGetAssertionReq2StandardLifecycle(
	t testing.TB,
	device *authrGetAssertionReq2Device,
	lifecycle *authrGetAssertionReq2Lifecycle,
	wantGetInfo int,
	wantGetAssertion int,
) {
	t.Helper()

	if lifecycle.powerCycles != 3 || device.resets != 2 || device.makeCredentialRequests != 1 ||
		device.getInfoCalls != wantGetInfo {
		t.Fatalf(
			"power cycles/resets/MakeCredential/GetInfo = %d/%d/%d/%d, want 3/2/1/%d",
			lifecycle.powerCycles,
			device.resets,
			device.makeCredentialRequests,
			device.getInfoCalls,
			wantGetInfo,
		)
	}
	getAssertionCount := 0
	for _, command := range device.commands {
		if command == protocol.AuthenticatorGetAssertion {
			getAssertionCount++
		}
	}
	if getAssertionCount != wantGetAssertion {
		t.Fatalf("GetAssertion calls = %d, want %d; commands = %v", getAssertionCount, wantGetAssertion, device.commands)
	}
	assertAuthrGetAssertionReq2TokensWiped(t, lifecycle.tokens)
}

func assertAuthrGetAssertionReq2Request(
	t testing.TB,
	request []byte,
	wantOptions map[string]bool,
	wantAuthorization bool,
) {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorGetAssertion {
		t.Fatalf("request = %x", request)
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		t.Fatal(err)
	}
	wantKeys := []uint64{1, 2, 3, 5}
	if wantAuthorization {
		wantKeys = append(wantKeys, 6, 7)
	}
	slices.Sort(wantKeys)
	gotKeys := make([]uint64, 0, len(fields))
	for key := range fields {
		gotKeys = append(gotKeys, key)
	}
	slices.Sort(gotKeys)
	if !slices.Equal(gotKeys, wantKeys) {
		t.Fatalf("GetAssertion keys = %v, want %v", gotKeys, wantKeys)
	}
	if fields[1][0]>>5 != 3 || fields[2][0]>>5 != 2 || fields[3][0]>>5 != 4 ||
		fields[5][0]>>5 != 5 {
		t.Fatalf("required/options major types = %x/%x/%x/%x", fields[1], fields[2], fields[3], fields[5])
	}
	var options map[string]bool
	if err := getInfoDecMode.Unmarshal(fields[5], &options); err != nil {
		t.Fatal(err)
	}
	if len(options) != len(wantOptions) {
		t.Fatalf("options = %#v, want %#v", options, wantOptions)
	}
	for name, value := range wantOptions {
		if options[name] != value {
			t.Fatalf("options = %#v, want %#v", options, wantOptions)
		}
	}
	var allowList []map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[3], &allowList); err != nil {
		t.Fatal(err)
	}
	if len(allowList) != 1 || allowList[0]["type"][0]>>5 != 3 || allowList[0]["id"][0]>>5 != 2 {
		t.Fatalf("allowList = %#v", allowList)
	}
	if wantAuthorization {
		if fields[6][0]>>5 != 2 || fields[7][0]>>5 != 0 {
			t.Fatalf("authorization major types = %x/%x", fields[6], fields[7])
		}
	}
}

func assertAuthrGetAssertionReq2TokensWiped(t testing.TB, tokens [][]byte) {
	t.Helper()
	if len(tokens) != 2 {
		t.Fatalf("tokens = %d, want 2", len(tokens))
	}
	for index, token := range tokens {
		if len(token) != 32 || slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
			t.Fatalf("token %d was not wiped", index)
		}
	}
}

func assertAuthrGetAssertionReq2PINWiped(t testing.TB, pin []byte) {
	t.Helper()
	if len(pin) == 0 || slices.ContainsFunc(pin, func(value byte) bool { return value != 0 }) {
		t.Fatalf("PIN was not wiped: %x", pin)
	}
}

func assertAuthrGetAssertionReq2Status(
	t testing.TB,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()
	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrGetAssertionReq2MakeCredentialAuthData(t testing.TB, credentialID []byte) []byte {
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
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagAttestedCredentialDataIncluded)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, byte(len(credentialID)>>8), byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, authrGetAssertionReq2Marshal(t, key)...)

	return authData
}

func authrGetAssertionReq2AuthData(flags protocol.AuthDataFlag) []byte {
	authData := make([]byte, 37)
	authData[32] = byte(flags)

	return authData
}

func authrGetAssertionReq2Marshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
