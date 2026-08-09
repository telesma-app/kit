package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdh"
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

func TestAuthrMakeCredReq6Definitions(t *testing.T) {
	tests := authrMakeCredReq6Tests(Config{})
	want := []struct {
		id         conformance.TestID
		marker     string
		references []conformance.RequirementRef
	}{
		{
			id:     TestIDAuthrMakeCredReq6P1,
			marker: "P-1",
			references: []conformance.RequirementRef{
				authrMakeCredReq1CommandReference(),
				authrMakeCredReq6Reference("6.1", "make-credential-options", "makecred-input-parameters"),
				authrMakeCredReq6Reference("6.1.2", "unknown-options-treated-as-absent", "op-makecred-step-options"),
				makeCredentialResponseRequiredReference(),
				ctapMessageEncodingReference(),
			},
		},
		{
			id:     TestIDAuthrMakeCredReq6P2,
			marker: "P-2",
			references: []conformance.RequirementRef{
				authrMakeCredReq1CommandReference(),
				authrMakeCredReq6Reference("6.1", "make-credential-options", "makecred-input-parameters"),
				authrMakeCredReq6Reference("6.1.2", "uv-option-sets-auth-data-flag", "op-makecred-step-performBuiltInUv"),
				makeCredentialResponseRequiredReference(),
				ctapMessageEncodingReference(),
			},
		},
		{
			id:     TestIDAuthrMakeCredReq6P3,
			marker: "P-3",
			references: []conformance.RequirementRef{
				authrMakeCredReq1CommandReference(),
				authrMakeCredReq6Reference("6.1", "make-credential-options", "makecred-input-parameters"),
				authrMakeCredReq6Reference("6.1.2", "up-option-sets-auth-data-flag", "op-makecred-step-up"),
				makeCredentialResponseRequiredReference(),
				ctapMessageEncodingReference(),
			},
		},
		{
			id:     TestIDAuthrMakeCredReq6F1,
			marker: "F-1",
			references: []conformance.RequirementRef{
				authrMakeCredReq1CommandReference(),
				authrMakeCredReq6Reference("6.1", "make-credential-options", "makecred-input-parameters"),
				authrMakeCredReq6Reference("6.1.2", "up-false-returns-invalid-option", "op-makecred-step-up"),
			},
		},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != authrMakeCredReq6SourcePath ||
			test.Source.Case != expected.marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		if !slices.Equal(test.References, expected.references) {
			t.Fatalf("references for %s = %#v, want %#v", test.ID, test.References, expected.references)
		}
	}
}

func TestAuthrMakeCredReq6P1PassesAndSendsUnknownOption(t *testing.T) {
	device := newAuthrMakeCredReq6Device(t)
	lifecycle := &authrMakeCredReq6Lifecycle{t: t}
	result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P1)

	assertAuthrMakeCredReq6Status(t, result, conformance.StatusPassed)
	assertAuthrMakeCredReq6StandardLifecycle(t, device, lifecycle, false)
	assertAuthrMakeCredReq6Options(t, device.makeCredentialRequest, map[string]bool{"makeTea": true}, true)
}

func TestAuthrMakeCredReq6P2ConfiguresAdvertisedUVAndWipesPIN(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		protocols    []protocol.PinUvAuthProtocol
		wantProtocol protocol.PinUvAuthProtocol
	}{
		{
			name:         "prefer protocol 2",
			protocols:    []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne, protocol.PinUvAuthProtocolTwo},
			wantProtocol: protocol.PinUvAuthProtocolTwo,
		},
		{
			name:         "protocol 1 fallback",
			protocols:    []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			wantProtocol: protocol.PinUvAuthProtocolOne,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
			device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
			device.protocols = testCase.protocols
			device.responseFlags = protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified
			lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device, configureUV: true}
			result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P2)

			assertAuthrMakeCredReq6Status(t, result, conformance.StatusPassed)
			assertAuthrMakeCredReq6P2Lifecycle(t, device, lifecycle, true)
			if !slices.Equal(device.clientPINProtocols, []protocol.PinUvAuthProtocol{
				testCase.wantProtocol,
				testCase.wantProtocol,
			}) {
				t.Fatalf("ClientPIN protocols = %v, want %d twice", device.clientPINProtocols, testCase.wantProtocol)
			}
			assertAuthrMakeCredReq6Options(
				t,
				device.makeCredentialRequest,
				map[string]bool{string(protocol.OptionUserVerification): true},
				false,
			)
		})
	}
}

func TestAuthrMakeCredReq6P2UsesAlreadyConfiguredUVWithoutCallbacks(t *testing.T) {
	device := newAuthrMakeCredReq6Device(t)
	device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: true}
	device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: true}
	device.responseFlags = protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified
	lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device}
	config := Config{PowerCycler: lifecycle.powerCycle}
	result := runAuthrMakeCredReq6Test(t, device, config, TestIDAuthrMakeCredReq6P2)

	assertAuthrMakeCredReq6Status(t, result, conformance.StatusPassed)
	assertAuthrMakeCredReq6P2Lifecycle(t, device, lifecycle, false)
	assertAuthrMakeCredReq6Options(
		t,
		device.makeCredentialRequest,
		map[string]bool{string(protocol.OptionUserVerification): true},
		false,
	)
}

func TestAuthrMakeCredReq6P3HonorsUPApplicabilityAndDefault(t *testing.T) {
	for _, testCase := range []struct {
		name               string
		options            map[protocol.Option]bool
		omitInitialOptions bool
	}{
		{name: "options absent", options: map[protocol.Option]bool{protocol.OptionClientPIN: false}, omitInitialOptions: true},
		{name: "up absent", options: map[protocol.Option]bool{protocol.OptionClientPIN: false}},
		{
			name: "up true",
			options: map[protocol.Option]bool{
				protocol.OptionClientPIN:    false,
				protocol.OptionUserPresence: true,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.initialOptions = testCase.options
			device.currentOptions = testCase.options
			if testCase.omitInitialOptions {
				device.initialGetInfoData = authrMakeCredReq6Marshal(t, map[uint64]any{
					1:  []string{string(protocol.FIDO_2_3)},
					3:  make([]byte, 16),
					10: []map[string]any{{"type": "public-key", "alg": -7}},
				})
			}
			lifecycle := &authrMakeCredReq6Lifecycle{t: t}
			result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P3)

			assertAuthrMakeCredReq6Status(t, result, conformance.StatusPassed)
			assertAuthrMakeCredReq6StandardLifecycle(t, device, lifecycle, true)
			assertAuthrMakeCredReq6Options(
				t,
				device.makeCredentialRequest,
				map[string]bool{string(protocol.OptionUserPresence): true},
				true,
			)
		})
	}
}

func TestAuthrMakeCredReq6F1RequiresExactInvalidOption(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		status     ctaptransport.StatusCode
		wantStatus conformance.Status
	}{
		{
			name:       "exact status",
			status:     ctaptransport.CTAP2_ERR_INVALID_OPTION,
			wantStatus: conformance.StatusPassed,
		},
		{name: "success", status: ctaptransport.CTAP2_OK, wantStatus: conformance.StatusFailed},
		{
			name:       "different error",
			status:     ctaptransport.CTAP2_ERR_INVALID_CBOR,
			wantStatus: conformance.StatusFailed,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.makeCredentialStatus = testCase.status
			lifecycle := &authrMakeCredReq6Lifecycle{t: t}
			result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6F1)

			assertAuthrMakeCredReq6Status(t, result, testCase.wantStatus)
			assertAuthrMakeCredReq6StandardLifecycle(t, device, lifecycle, false)
			assertAuthrMakeCredReq6Options(
				t,
				device.makeCredentialRequest,
				map[string]bool{string(protocol.OptionUserPresence): false},
				true,
			)
		})
	}
}

func TestAuthrMakeCredReq6ApplicabilitySkipsBeforeMutation(t *testing.T) {
	t.Run("P2 uv absent", func(t *testing.T) {
		device := newAuthrMakeCredReq6Device(t)
		device.initialOptions = map[protocol.Option]bool{protocol.OptionClientPIN: false}
		result := runAuthrMakeCredReq6Test(t, device, Config{}, TestIDAuthrMakeCredReq6P2)

		assertAuthrMakeCredReq6Status(t, result, conformance.StatusSkipped)
		assertAuthrMakeCredReq6NoMutation(t, device)
	})

	t.Run("P3 up false", func(t *testing.T) {
		device := newAuthrMakeCredReq6Device(t)
		device.initialOptions = map[protocol.Option]bool{protocol.OptionUserPresence: false}
		result := runAuthrMakeCredReq6Test(t, device, Config{}, TestIDAuthrMakeCredReq6P3)

		assertAuthrMakeCredReq6Status(t, result, conformance.StatusSkipped)
		assertAuthrMakeCredReq6NoMutation(t, device)
	})
}

func TestAuthrMakeCredReq6RawApplicabilityRejectsWrongOptionTypes(t *testing.T) {
	for _, id := range []conformance.TestID{TestIDAuthrMakeCredReq6P2, TestIDAuthrMakeCredReq6P3} {
		t.Run(string(id), func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.initialGetInfoData = authrMakeCredReq6Marshal(t, map[uint64]any{
				1:  []string{string(protocol.FIDO_2_3)},
				3:  make([]byte, 16),
				4:  map[string]any{"uv": nil, "up": uint64(1)},
				10: []map[string]any{{"type": "public-key", "alg": -7}},
			})
			result := runAuthrMakeCredReq6Test(t, device, Config{}, id)

			assertAuthrMakeCredReq6Status(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq6NoMutation(t, device)
		})
	}
}

func TestAuthrMakeCredReq6RawOptionsNullFailsBeforeMutation(t *testing.T) {
	for _, id := range []conformance.TestID{TestIDAuthrMakeCredReq6P2, TestIDAuthrMakeCredReq6P3} {
		t.Run(string(id), func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.initialGetInfoData = authrMakeCredReq6Marshal(t, map[uint64]any{
				1:  []string{string(protocol.FIDO_2_3)},
				3:  make([]byte, 16),
				4:  nil,
				10: []map[string]any{{"type": "public-key", "alg": -7}},
			})
			result := runAuthrMakeCredReq6Test(t, device, Config{}, id)

			assertAuthrMakeCredReq6Status(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq6NoMutation(t, device)
		})
	}
}

func TestAuthrMakeCredReq6P2RevalidatesUVAfterReset(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		currentData []byte
	}{
		{
			name: "uv disappears",
			currentData: authrMakeCredReq6Marshal(t, map[uint64]any{
				1:  []string{string(protocol.FIDO_2_3)},
				3:  make([]byte, 16),
				4:  map[string]bool{string(protocol.OptionClientPIN): false},
				10: []map[string]any{{"type": "public-key", "alg": -7}},
			}),
		},
		{
			name: "uv becomes null",
			currentData: authrMakeCredReq6Marshal(t, map[uint64]any{
				1:  []string{string(protocol.FIDO_2_3)},
				3:  make([]byte, 16),
				4:  map[string]any{string(protocol.OptionUserVerification): nil},
				10: []map[string]any{{"type": "public-key", "alg": -7}},
			}),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: true}
			device.currentGetInfoData = testCase.currentData
			lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device}
			result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P2)

			assertAuthrMakeCredReq6Status(t, result, conformance.StatusFailed)
			if lifecycle.powerCycles != 3 || device.resets != 2 || len(device.makeCredentialRequest) != 0 {
				t.Fatalf("power cycles/resets/request = %d/%d/%x", lifecycle.powerCycles, device.resets, device.makeCredentialRequest)
			}
		})
	}
}

func TestAuthrMakeCredReq6P3RejectsOptionsNullAfterReset(t *testing.T) {
	device := newAuthrMakeCredReq6Device(t)
	device.initialOptions = map[protocol.Option]bool{protocol.OptionUserPresence: true}
	device.currentGetInfoData = authrMakeCredReq6Marshal(t, map[uint64]any{
		1:  []string{string(protocol.FIDO_2_3)},
		3:  make([]byte, 16),
		4:  nil,
		10: []map[string]any{{"type": "public-key", "alg": -7}},
	})
	lifecycle := &authrMakeCredReq6Lifecycle{t: t}
	result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P3)

	assertAuthrMakeCredReq6Status(t, result, conformance.StatusFailed)
	if lifecycle.powerCycles != 3 || device.resets != 2 || len(device.makeCredentialRequest) != 0 {
		t.Fatalf("power cycles/resets/request = %d/%d/%x", lifecycle.powerCycles, device.resets, device.makeCredentialRequest)
	}
}

func TestAuthrMakeCredReq6P2ConfigurationErrorsCleanUpAndWipePIN(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*authrMakeCredReq6Device, *authrMakeCredReq6Lifecycle, *Config)
	}{
		{
			name: "missing temporary PIN provider",
			configure: func(_ *authrMakeCredReq6Device, _ *authrMakeCredReq6Lifecycle, config *Config) {
				config.TemporaryPINProvider = nil
			},
		},
		{
			name: "missing UV configurator",
			configure: func(_ *authrMakeCredReq6Device, _ *authrMakeCredReq6Lifecycle, config *Config) {
				config.UVConfigurator = nil
			},
		},
		{
			name: "missing PIN UV protocol",
			configure: func(device *authrMakeCredReq6Device, _ *authrMakeCredReq6Lifecycle, _ *Config) {
				device.protocols = nil
			},
		},
		{
			name: "provider returns PIN and error",
			configure: func(_ *authrMakeCredReq6Device, lifecycle *authrMakeCredReq6Lifecycle, config *Config) {
				config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
					lifecycle.pin = []byte("1234")

					return lifecycle.pin, errors.New("PIN unavailable")
				}
			},
		},
		{
			name: "UV configurator fails",
			configure: func(_ *authrMakeCredReq6Device, _ *authrMakeCredReq6Lifecycle, config *Config) {
				config.UVConfigurator = func(context.Context, []byte) error {
					return errors.New("UV enrollment failed")
				}
			},
		},
		{
			name: "UV configurator leaves option false",
			configure: func(_ *authrMakeCredReq6Device, _ *authrMakeCredReq6Lifecycle, config *Config) {
				config.UVConfigurator = func(context.Context, []byte) error { return nil }
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
			device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
			lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device, configureUV: true}
			config := lifecycle.config()
			testCase.configure(device, lifecycle, &config)
			result := runAuthrMakeCredReq6Test(t, device, config, TestIDAuthrMakeCredReq6P2)

			assertAuthrMakeCredReq6Status(t, result, conformance.StatusError)
			if lifecycle.powerCycles != 3 || device.resets != 2 {
				t.Fatalf("power cycles/resets = %d/%d, want 3/2", lifecycle.powerCycles, device.resets)
			}
			assertAuthrMakeCredReq6Wiped(t, lifecycle.pin, "temporary PIN")
			if len(device.makeCredentialRequest) != 0 {
				t.Fatal("MakeCredential was sent after a configuration error")
			}
		})
	}
}

func TestAuthrMakeCredReq6P2RequiresPowerCyclerBeforeMutation(t *testing.T) {
	device := newAuthrMakeCredReq6Device(t)
	device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
	lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device, configureUV: true}
	config := lifecycle.config()
	config.PowerCycler = nil
	result := runAuthrMakeCredReq6Test(t, device, config, TestIDAuthrMakeCredReq6P2)

	assertAuthrMakeCredReq6Status(t, result, conformance.StatusError)
	assertAuthrMakeCredReq6NoMutation(t, device)
}

func TestAuthrMakeCredReq6P2SetPINFailuresAreClassifiedAndWiped(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		status ctaptransport.StatusCode
		err    error
		want   conformance.Status
	}{
		{
			name:   "CTAP status",
			status: ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
			want:   conformance.StatusFailed,
		},
		{name: "transport error", err: errors.New("device disconnected"), want: conformance.StatusError},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
			device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
			device.setPINStatus = testCase.status
			device.setPINError = testCase.err
			lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device, configureUV: true}
			result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P2)

			assertAuthrMakeCredReq6Status(t, result, testCase.want)
			if lifecycle.powerCycles != 3 || device.resets != 2 || device.setPINCalls != 1 {
				t.Fatalf("power cycles/resets/SetPIN = %d/%d/%d", lifecycle.powerCycles, device.resets, device.setPINCalls)
			}
			assertAuthrMakeCredReq6Wiped(t, lifecycle.pin, "temporary PIN")
			if len(device.makeCredentialRequest) != 0 {
				t.Fatal("MakeCredential was sent after SetPIN failure")
			}
		})
	}
}

func TestAuthrMakeCredReq6P2GetKeyAgreementFailuresAreClassifiedAndWiped(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		status ctaptransport.StatusCode
		err    error
		want   conformance.Status
	}{
		{
			name:   "CTAP status",
			status: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
			want:   conformance.StatusFailed,
		},
		{name: "transport error", err: errors.New("device disconnected"), want: conformance.StatusError},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
			device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
			device.getKeyAgreementStatus = testCase.status
			device.getKeyAgreementError = testCase.err
			lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device, configureUV: true}
			result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P2)

			assertAuthrMakeCredReq6Status(t, result, testCase.want)
			if lifecycle.powerCycles != 3 || device.resets != 2 || device.setPINCalls != 0 {
				t.Fatalf("power cycles/resets/SetPIN = %d/%d/%d", lifecycle.powerCycles, device.resets, device.setPINCalls)
			}
			assertAuthrMakeCredReq6Wiped(t, lifecycle.pin, "temporary PIN")
			if len(device.makeCredentialRequest) != 0 {
				t.Fatal("MakeCredential was sent after getKeyAgreement failure")
			}
		})
	}
}

func TestAuthrMakeCredReq6P2InvalidTemporaryPINIsWiped(t *testing.T) {
	device := newAuthrMakeCredReq6Device(t)
	device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
	device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
	lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device, configureUV: true}
	config := lifecycle.config()
	config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
		lifecycle.pin = []byte("123")

		return lifecycle.pin, nil
	}
	result := runAuthrMakeCredReq6Test(t, device, config, TestIDAuthrMakeCredReq6P2)

	assertAuthrMakeCredReq6Status(t, result, conformance.StatusError)
	if lifecycle.powerCycles != 3 || device.resets != 2 || len(device.clientPINProtocols) != 0 {
		t.Fatalf("power cycles/resets/ClientPIN = %d/%d/%v", lifecycle.powerCycles, device.resets, device.clientPINProtocols)
	}
	assertAuthrMakeCredReq6Wiped(t, lifecycle.pin, "temporary PIN")
}

func TestAuthrMakeCredReq6PositiveCasesValidateResponseFlagsAndSchema(t *testing.T) {
	tests := []struct {
		name      string
		id        conformance.TestID
		configure func(*authrMakeCredReq6Device)
	}{
		{
			name: "P2 UV flag absent",
			id:   TestIDAuthrMakeCredReq6P2,
			configure: func(device *authrMakeCredReq6Device) {
				device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: true}
				device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: true}
				device.responseFlags = protocol.AuthDataFlagUserPresent
			},
		},
		{
			name: "P3 UP flag absent",
			id:   TestIDAuthrMakeCredReq6P3,
			configure: func(device *authrMakeCredReq6Device) {
				device.responseFlags = 0
			},
		},
		{
			name: "P1 missing authData",
			id:   TestIDAuthrMakeCredReq6P1,
			configure: func(device *authrMakeCredReq6Device) {
				device.makeCredentialData = authrMakeCredReq6Marshal(t, map[uint64]any{
					1: "none",
					3: map[string]any{},
				})
			},
		},
		{
			name: "P2 missing authData",
			id:   TestIDAuthrMakeCredReq6P2,
			configure: func(device *authrMakeCredReq6Device) {
				device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: true}
				device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: true}
				device.makeCredentialData = authrMakeCredReq6Marshal(t, map[uint64]any{
					1: "none",
					3: map[string]any{},
				})
			},
		},
		{
			name: "P1 wrong authData type",
			id:   TestIDAuthrMakeCredReq6P1,
			configure: func(device *authrMakeCredReq6Device) {
				device.makeCredentialData = authrMakeCredReq6Marshal(t, map[uint64]any{
					1: "none",
					2: false,
					3: map[string]any{},
				})
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			testCase.configure(device)
			lifecycle := &authrMakeCredReq6Lifecycle{t: t, device: device}
			result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), testCase.id)

			assertAuthrMakeCredReq6Status(t, result, conformance.StatusFailed)
			if lifecycle.powerCycles != 3 || device.resets != 2 {
				t.Fatalf("power cycles/resets = %d/%d, want 3/2", lifecycle.powerCycles, device.resets)
			}
			assertAuthrMakeCredReq6Wiped(t, lifecycle.token, "PIN/UV token")
		})
	}
}

func TestAuthrMakeCredReq6CTAPAndTransportErrorsAreClassified(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		configure func(*authrMakeCredReq6Device)
		want      conformance.Status
	}{
		{
			name: "unexpected CTAP status fails",
			configure: func(device *authrMakeCredReq6Device) {
				device.makeCredentialStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			},
			want: conformance.StatusFailed,
		},
		{
			name: "transport error is execution error",
			configure: func(device *authrMakeCredReq6Device) {
				device.makeCredentialError = errors.New("device disconnected")
			},
			want: conformance.StatusError,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq6Device(t)
			testCase.configure(device)
			lifecycle := &authrMakeCredReq6Lifecycle{t: t}
			result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P1)

			assertAuthrMakeCredReq6Status(t, result, testCase.want)
			assertAuthrMakeCredReq6StandardLifecycle(t, device, lifecycle, false)
		})
	}
}

func TestAuthrMakeCredReq6CleanupFailureIsVisibleAndSecretsAreWiped(t *testing.T) {
	device := newAuthrMakeCredReq6Device(t)
	lifecycle := &authrMakeCredReq6Lifecycle{
		t:              t,
		cleanupFailure: errors.New("cleanup power cycle failed"),
	}
	result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P1)

	assertAuthrMakeCredReq6Status(t, result, conformance.StatusError)
	if lifecycle.powerCycles != 3 || device.resets != 1 || !slices.Equal(device.commands, []protocol.Command{
		protocol.AuthenticatorReset,
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorMakeCredential,
	}) {
		t.Fatalf("commands/power cycles/resets = %v/%d/%d", device.commands, lifecycle.powerCycles, device.resets)
	}
	assertAuthrMakeCredReq6Wiped(t, lifecycle.token, "PIN/UV token")
	last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusError ||
		last.Message != lifecycle.cleanupFailure.Error() {
		t.Fatalf("cleanup step = %#v", last)
	}
}

func TestAuthrMakeCredReq6P2CleanupFailureAfterUVSetupIsVisibleAndWipesPIN(t *testing.T) {
	device := newAuthrMakeCredReq6Device(t)
	device.initialOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
	device.currentOptions = map[protocol.Option]bool{protocol.OptionUserVerification: false}
	device.responseFlags = protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified
	lifecycle := &authrMakeCredReq6Lifecycle{
		t:              t,
		device:         device,
		configureUV:    true,
		cleanupFailure: errors.New("cleanup power cycle failed"),
	}
	result := runAuthrMakeCredReq6Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq6P2)

	assertAuthrMakeCredReq6Status(t, result, conformance.StatusError)
	if lifecycle.powerCycles != 3 || device.resets != 1 || device.setPINCalls != 1 ||
		len(device.makeCredentialRequest) == 0 {
		t.Fatalf(
			"power cycles/resets/SetPIN/request = %d/%d/%d/%x",
			lifecycle.powerCycles,
			device.resets,
			device.setPINCalls,
			device.makeCredentialRequest,
		)
	}
	assertAuthrMakeCredReq6Wiped(t, lifecycle.pin, "temporary PIN")
	last := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]
	if last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusError ||
		last.Message != lifecycle.cleanupFailure.Error() {
		t.Fatalf("cleanup step = %#v", last)
	}
}

type authrMakeCredReq6Lifecycle struct {
	t              testing.TB
	device         *authrMakeCredReq6Device
	powerCycles    int
	configureUV    bool
	uvCalls        int
	token          []byte
	pin            []byte
	cleanupFailure error
}

func (l *authrMakeCredReq6Lifecycle) config() Config {
	return Config{
		PowerCycler: l.powerCycle,
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			if request.Permission != protocol.PermissionMakeCredential || request.RPID != authrMakeCredReq6RPID {
				l.t.Fatalf("token request = %#v", request)
			}
			l.token = bytes.Repeat([]byte{0x76}, 32)

			return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: l.token}, nil
		},
		TemporaryPINProvider: func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
			if request.MinCodePoints > 4 || request.MaxCodePoints < 4 {
				l.t.Fatalf("temporary PIN request = %#v", request)
			}
			l.pin = []byte("1234")

			return l.pin, nil
		},
		UVConfigurator: func(_ context.Context, pin []byte) error {
			l.uvCalls++
			if !bytes.Equal(pin, []byte("1234")) {
				l.t.Fatalf("borrowed PIN = %q", pin)
			}
			if l.configureUV {
				l.device.currentOptions[protocol.OptionUserVerification] = true
			}

			return nil
		},
	}
}

func (l *authrMakeCredReq6Lifecycle) powerCycle(context.Context) error {
	l.powerCycles++
	if l.powerCycles == 3 && l.cleanupFailure != nil {
		return l.cleanupFailure
	}

	return nil
}

type authrMakeCredReq6Device struct {
	t                     testing.TB
	commands              []protocol.Command
	resets                int
	initialOptions        map[protocol.Option]bool
	currentOptions        map[protocol.Option]bool
	initialGetInfoData    []byte
	currentGetInfoData    []byte
	protocols             []protocol.PinUvAuthProtocol
	publicKey             cose.Key
	clientPINProtocols    []protocol.PinUvAuthProtocol
	getKeyAgreementStatus ctaptransport.StatusCode
	getKeyAgreementError  error
	setPINCalls           int
	setPINStatus          ctaptransport.StatusCode
	setPINError           error
	makeCredentialStatus  ctaptransport.StatusCode
	makeCredentialError   error
	makeCredentialData    []byte
	makeCredentialRequest []byte
	responseFlags         protocol.AuthDataFlag
}

func newAuthrMakeCredReq6Device(t testing.TB) *authrMakeCredReq6Device {
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
	options := map[protocol.Option]bool{protocol.OptionClientPIN: false}

	return &authrMakeCredReq6Device{
		t:              t,
		initialOptions: options,
		currentOptions: options,
		protocols:      []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		publicKey:      publicKey,
		responseFlags:  protocol.AuthDataFlagUserPresent,
	}
}

func (d *authrMakeCredReq6Device) CBOR(
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
		if d.resets == 0 && d.initialGetInfoData != nil {
			return ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       slices.Clone(d.initialGetInfoData),
			}, nil
		}
		if d.resets > 0 && d.currentGetInfoData != nil {
			return ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       slices.Clone(d.currentGetInfoData),
			}, nil
		}
		options := d.currentOptions
		if d.resets == 0 {
			options = d.initialOptions
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: authrMakeCredReq6Marshal(d.t, protocol.AuthenticatorGetInfoResponse{
				Versions:           []protocol.Version{protocol.FIDO_2_3},
				Extensions:         []extension.ExtensionIdentifier{},
				AAGUID:             uuid.Nil,
				Options:            options,
				PinUvAuthProtocols: d.protocols,
				Algorithms: []credential.PublicKeyCredentialParameters{{
					Type:      credential.PublicKeyCredentialTypePublicKey,
					Algorithm: cose.AlgorithmES256,
				}},
			}),
		}, nil
	case protocol.AuthenticatorClientPIN:
		var body protocol.AuthenticatorClientPINRequest
		if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
			d.t.Fatalf("decode ClientPIN request: %v", err)
		}
		d.clientPINProtocols = append(d.clientPINProtocols, body.PinUvAuthProtocol)
		switch body.SubCommand {
		case protocol.ClientPINSubCommandGetKeyAgreement:
			if d.getKeyAgreementError != nil {
				return ctaptransport.CBORResponse{}, d.getKeyAgreementError
			}
			if d.getKeyAgreementStatus != ctaptransport.CTAP2_OK {
				return ctaptransport.CBORResponse{}, &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorClientPIN,
					StatusCode: d.getKeyAgreementStatus,
				}
			}

			return ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       authrMakeCredReq6Marshal(d.t, map[uint64]any{1: d.publicKey}),
			}, nil
		case protocol.ClientPINSubCommandSetPIN:
			d.setPINCalls++
			if d.setPINError != nil {
				return ctaptransport.CBORResponse{}, d.setPINError
			}
			if d.setPINStatus != ctaptransport.CTAP2_OK {
				return ctaptransport.CBORResponse{}, &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorClientPIN,
					StatusCode: d.setPINStatus,
				}
			}

			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
		default:
			d.t.Fatalf("unexpected ClientPIN subcommand %s", body.SubCommand)
		}
	case protocol.AuthenticatorMakeCredential:
		d.makeCredentialRequest = slices.Clone(request)
		if d.makeCredentialError != nil {
			return ctaptransport.CBORResponse{}, d.makeCredentialError
		}
		response := ctaptransport.CBORResponse{StatusCode: d.makeCredentialStatus}
		if response.StatusCode == ctaptransport.CTAP2_OK {
			response.Data = slices.Clone(d.makeCredentialData)
			if response.Data == nil {
				response.Data = authrMakeCredReq6Marshal(d.t, protocol.AuthenticatorMakeCredentialResponse{
					Format:               attestation.AttestationStatementFormatIdentifierNone,
					AuthDataRaw:          authrMakeCredReq6AuthData(d.t, d.responseFlags),
					AttestationStatement: map[string]any{},
				})
			}
		}

		return response, nil
	default:
		d.t.Fatalf("unexpected command 0x%02x", byte(command))
	}

	return ctaptransport.CBORResponse{}, nil
}

func authrMakeCredReq6AuthData(t testing.TB, flags protocol.AuthDataFlag) []byte {
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
	credentialID := bytes.Repeat([]byte{0x66}, 16)
	authData = append(authData, 0, byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, authrMakeCredReq6Marshal(t, key)...)

	return authData
}

func runAuthrMakeCredReq6Test(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrMakeCredReq6Tests(config) {
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
		ID:    "authr-make-cred-req-6-test",
		Name:  "Authr MakeCred Req 6 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredReq6Options(
	t *testing.T,
	request []byte,
	want map[string]bool,
	wantAuthorization bool,
) {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
		t.Fatalf("MakeCredential request = %x", request)
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		t.Fatal(err)
	}
	var options map[string]bool
	if err := getInfoDecMode.Unmarshal(fields[7], &options); err != nil {
		t.Fatal(err)
	}
	if len(options) != len(want) {
		t.Fatalf("options = %v, want %v", options, want)
	}
	for key, value := range want {
		if got, present := options[key]; !present || got != value {
			t.Fatalf("option %q = %v/%t, want %v", key, got, present, value)
		}
	}
	for _, key := range []uint64{8, 9} {
		_, present := fields[key]
		if present != wantAuthorization {
			t.Fatalf("field %d present = %t, want %t", key, present, wantAuthorization)
		}
	}
}

func assertAuthrMakeCredReq6StandardLifecycle(
	t *testing.T,
	device *authrMakeCredReq6Device,
	lifecycle *authrMakeCredReq6Lifecycle,
	preflight bool,
) {
	t.Helper()

	wantCommands := []protocol.Command{
		protocol.AuthenticatorReset,
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorMakeCredential,
		protocol.AuthenticatorReset,
	}
	if preflight {
		wantCommands = []protocol.Command{
			protocol.AuthenticatorGetInfo,
			protocol.AuthenticatorReset,
			protocol.AuthenticatorGetInfo,
			protocol.AuthenticatorGetInfo,
			protocol.AuthenticatorMakeCredential,
			protocol.AuthenticatorReset,
		}
	}
	if !slices.Equal(device.commands, wantCommands) {
		t.Fatalf("commands = %v, want %v", device.commands, wantCommands)
	}
	if lifecycle.powerCycles != 3 || device.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/2", lifecycle.powerCycles, device.resets)
	}
	assertAuthrMakeCredReq6Wiped(t, lifecycle.token, "PIN/UV token")
}

func assertAuthrMakeCredReq6P2Lifecycle(
	t *testing.T,
	device *authrMakeCredReq6Device,
	lifecycle *authrMakeCredReq6Lifecycle,
	configured bool,
) {
	t.Helper()

	wantCommands := []protocol.Command{
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorReset,
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorMakeCredential,
		protocol.AuthenticatorReset,
	}
	if configured {
		wantCommands = []protocol.Command{
			protocol.AuthenticatorGetInfo,
			protocol.AuthenticatorReset,
			protocol.AuthenticatorGetInfo,
			protocol.AuthenticatorClientPIN,
			protocol.AuthenticatorClientPIN,
			protocol.AuthenticatorGetInfo,
			protocol.AuthenticatorMakeCredential,
			protocol.AuthenticatorReset,
		}
	}
	if !slices.Equal(device.commands, wantCommands) {
		t.Fatalf("commands = %v, want %v", device.commands, wantCommands)
	}
	if lifecycle.powerCycles != 3 || device.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/2", lifecycle.powerCycles, device.resets)
	}
	if lifecycle.uvCalls != btoi(configured) || device.setPINCalls != btoi(configured) {
		t.Fatalf("UV/SetPIN calls = %d/%d, configured = %t", lifecycle.uvCalls, device.setPINCalls, configured)
	}
	assertAuthrMakeCredReq6Wiped(t, lifecycle.pin, "temporary PIN")
}

func assertAuthrMakeCredReq6NoMutation(t *testing.T, device *authrMakeCredReq6Device) {
	t.Helper()

	if !slices.Equal(device.commands, []protocol.Command{protocol.AuthenticatorGetInfo}) ||
		device.resets != 0 || len(device.makeCredentialRequest) != 0 || device.setPINCalls != 0 {
		t.Fatalf("device state = %#v, want one GetInfo and no mutation", device)
	}
}

func assertAuthrMakeCredReq6Status(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertAuthrMakeCredReq6Wiped(t *testing.T, secret []byte, name string) {
	t.Helper()

	if len(secret) != 0 && slices.ContainsFunc(secret, func(value byte) bool { return value != 0 }) {
		t.Fatalf("%s was not wiped", name)
	}
}

func authrMakeCredReq6Marshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func btoi(value bool) int {
	if value {
		return 1
	}

	return 0
}
