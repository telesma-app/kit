package ctap23

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestMinPINLengthDefinitions(t *testing.T) {
	tests := minPINLengthTests(Config{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDMinPINLengthP1, "P-1"},
		{TestIDMinPINLengthF1, "F-1"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != minPINLengthSourcePath ||
			test.Source.Case != expected.marker || !test.Destructive {
			t.Errorf("test[%d] = %#v", index, test)
		}
		if len(test.References) != 2 {
			t.Fatalf("test[%d] references = %#v", index, test.References)
		}
		assertMinPINLengthReference(
			t,
			test.References[0],
			"ctap-2.3-ps-20260226:6.11.4:minimum-pin-length-rp-ids",
			"6.11.4",
			"minimum-pin-length-rp-ids",
			"#setMinPINLength",
		)
		assertMinPINLengthReference(
			t,
			test.References[1],
			"ctap-2.3-ps-20260226:12.5:rp-authorized-minimum-pin-length-output",
			"12.5",
			"rp-authorized-minimum-pin-length-output",
			"#sctn-minpinlength-extension",
		)
	}
}

func TestMinPINLengthCasesUseIndependentNoResetLifecycleAndExactWire(t *testing.T) {
	for _, testCase := range []struct {
		index       int
		allowedRPID string
		targetRPID  string
	}{
		{0, minPINLengthP1RPID, minPINLengthP1RPID},
		{1, minPINLengthF1AllowedRPID, minPINLengthF1TargetRPID},
	} {
		t.Run(minPINLengthTests(Config{})[testCase.index].Source.Case, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			pin := []byte("1234")
			config := extensionPINPolicyConfig(device, pin)
			result := runExtensionPINPolicyTest(t, device, minPINLengthTests(config)[testCase.index])
			if result.Status != conformance.StatusPassed {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
			if len(result.Steps) != 4 {
				t.Fatalf("steps = %#v", result.Steps)
			}
			for _, step := range result.Steps {
				if step.Status != conformance.StatusPassed {
					t.Fatalf("step = %#v", step)
				}
			}

			assertExtensionPINPolicyConfigRequest(t, device, testCase.allowedRPID)
			if !slices.Equal(device.tokenRequests, []PinUvAuthTokenRequest{{
				Permission: protocol.PermissionMakeCredential,
				RPID:       testCase.targetRPID,
			}}) {
				t.Fatalf("MakeCredential token requests = %#v", device.tokenRequests)
			}
			if !slices.Equal(device.makeCredentials, []extensionPINPolicyMakeCredentialRecord{{
				rpID:      testCase.targetRPID,
				extension: extension.ExtensionIdentifierMinPinLength,
			}}) {
				t.Fatalf("MakeCredential requests = %#v", device.makeCredentials)
			}
			assertExtensionPINPolicyLifecycleAndSecrets(t, device, pin)
		})
	}
}

func TestMinPINLengthRawOutputValidation(t *testing.T) {
	falseValue := false
	trueValue := true
	for _, testCase := range []struct {
		name          string
		index         int
		outputPresent *bool
		outputValue   any
		outputRaw     []byte
	}{
		{name: "allowed output absent", index: 0, outputPresent: &falseValue},
		{name: "allowed output wrong uint", index: 0, outputValue: uint(5)},
		{name: "allowed output wrong type", index: 0, outputValue: "4"},
		{
			name:      "allowed output noncanonical",
			index:     0,
			outputRaw: nonCanonicalExtensionPINPolicyOutput("minPinLength", 0x04),
		},
		{name: "unrelated RP output present", index: 1, outputPresent: &trueValue},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			device.outputPresent = testCase.outputPresent
			device.outputValue = testCase.outputValue
			device.outputRaw = testCase.outputRaw
			config := extensionPINPolicyConfig(device, []byte("1234"))
			result := runExtensionPINPolicyTest(t, device, minPINLengthTests(config)[testCase.index])
			if result.Status != conformance.StatusFailed {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
		})
	}
}

func TestMinPINLengthBuiltInPasscodeUsesDefaultFloorWithoutGetInfoValue(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		output     uint
		wantStatus conformance.Status
	}{
		{name: "above default floor", output: 6, wantStatus: conformance.StatusPassed},
		{name: "below default floor", output: 3, wantStatus: conformance.StatusFailed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			device.clientPINPresent = false
			device.uvPresent = true
			device.outputValue = testCase.output
			config := extensionPINPolicyConfig(device, []byte("1234"))

			result := runExtensionPINPolicyTest(t, device, minPINLengthTests(config)[0])
			if result.Status != testCase.wantStatus {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
		})
	}
}

func TestMinPINLengthAcceptsPositiveMaxRPIDCountIndependentOfMessageBytes(t *testing.T) {
	device := newExtensionPINPolicyDevice(t)
	device.maxRPIDs = 2048
	config := extensionPINPolicyConfig(device, []byte("1234"))

	result := runExtensionPINPolicyTest(t, device, minPINLengthTests(config)[0])
	if result.Status != conformance.StatusPassed {
		t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
	}
}

func TestMinPINLengthUnrelatedRPAllowsOtherExtensionOutput(t *testing.T) {
	device := newExtensionPINPolicyDevice(t)
	device.outputRaw = marshalGetAssertionFixture(t, map[string]any{"credProtect": uint(1)})
	config := extensionPINPolicyConfig(device, []byte("1234"))

	result := runExtensionPINPolicyTest(t, device, minPINLengthTests(config)[1])
	if result.Status != conformance.StatusPassed {
		t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
	}
}

func TestMinPINLengthApplicabilityStopsBeforeMutation(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*extensionPINPolicyDevice, *Config)
		want   conformance.Status
	}{
		{
			name: "extension absent non-featureful",
			mutate: func(device *extensionPINPolicyDevice, _ *Config) {
				device.extensions = []extension.ExtensionIdentifier{
					extension.ExtensionIdentifierPinComplexityPolicy,
				}
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "extension absent featureful",
			mutate: func(device *extensionPINPolicyDevice, config *Config) {
				device.extensions = nil
				config.Featureful = true
			},
			want: conformance.StatusFailed,
		},
		{
			name: "authnrCfg false",
			mutate: func(device *extensionPINPolicyDevice, _ *Config) {
				device.optionOverrides[string(protocol.OptionAuthenticatorConfig)] = false
			},
			want: conformance.StatusFailed,
		},
		{
			name: "setMinPINLength false",
			mutate: func(device *extensionPINPolicyDevice, _ *Config) {
				device.optionOverrides[string(protocol.OptionSetMinPINLength)] = false
			},
			want: conformance.StatusFailed,
		},
		{
			name: "setMinPINLength missing from inventory",
			mutate: func(device *extensionPINPolicyDevice, _ *Config) {
				device.commands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandToggleAlwaysUv}
			},
			want: conformance.StatusFailed,
		},
		{
			name: "protocol 2 absent",
			mutate: func(device *extensionPINPolicyDevice, _ *Config) {
				device.pinProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne}
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "maximum RP list absent",
			mutate: func(device *extensionPINPolicyDevice, _ *Config) {
				device.absentGetInfoFields[16] = true
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "maximum RP list zero",
			mutate: func(device *extensionPINPolicyDevice, _ *Config) {
				device.maxRPIDs = 0
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "token provider absent",
			mutate: func(_ *extensionPINPolicyDevice, config *Config) {
				config.TokenProvider = nil
			},
			want: conformance.StatusError,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			config := extensionPINPolicyConfig(device, []byte("1234"))
			testCase.mutate(device, &config)
			result := runExtensionPINPolicyTest(t, device, minPINLengthTests(config)[0])
			if result.Status != testCase.want {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
			if device.powerCycles != 0 || device.resets != 0 ||
				device.authenticatorConfigDevice.tokenRequests != 0 || len(device.tokenRequests) != 0 {
				t.Fatalf("mutation occurred during preflight: %#v", device)
			}
		})
	}
}

func TestMinPINLengthErrorClassificationAndTokenWipes(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		mutate     func(*extensionPINPolicyDevice)
		want       conformance.Status
		tokenGiven bool
	}{
		{
			name: "configuration CTAP status",
			mutate: func(device *extensionPINPolicyDevice) {
				device.configStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			},
			want: conformance.StatusFailed,
		},
		{
			name: "MakeCredential CTAP status",
			mutate: func(device *extensionPINPolicyDevice) {
				device.makeCredentialStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			},
			want:       conformance.StatusFailed,
			tokenGiven: true,
		},
		{
			name: "MakeCredential transport error",
			mutate: func(device *extensionPINPolicyDevice) {
				device.transportErrorCommand = protocol.AuthenticatorMakeCredential
			},
			want:       conformance.StatusError,
			tokenGiven: true,
		},
		{
			name: "token provider error",
			mutate: func(device *extensionPINPolicyDevice) {
				device.tokenError = errors.New("token canceled")
			},
			want: conformance.StatusError,
		},
		{
			name: "token provider returns protocol 1",
			mutate: func(device *extensionPINPolicyDevice) {
				device.tokenProtocol = protocol.PinUvAuthProtocolOne
			},
			want:       conformance.StatusError,
			tokenGiven: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			pin := []byte("1234")
			testCase.mutate(device)
			config := extensionPINPolicyConfig(device, pin)
			result := runExtensionPINPolicyTest(t, device, minPINLengthTests(config)[0])
			if result.Status != testCase.want {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
			assertAuthenticatorConfigZeroed(t, pin)
			if testCase.tokenGiven {
				assertAuthenticatorConfigZeroed(t, device.transferredToken)
			} else if !bytes.Equal(device.transferredToken, bytes.Repeat([]byte{0x5d}, 32)) {
				t.Fatal("untransferred token changed")
			}
		})
	}
}

func assertMinPINLengthReference(
	t *testing.T,
	reference conformance.RequirementRef,
	wantID string,
	wantSection string,
	wantClause string,
	wantURLSuffix string,
) {
	t.Helper()
	if string(reference.ID) != wantID || reference.Specification != conformance.SpecificationCTAP23 ||
		reference.Section != wantSection || reference.Clause != wantClause ||
		!strings.HasSuffix(reference.URL, wantURLSuffix) || reference.Level != conformance.RequirementMust {
		t.Fatalf("reference = %#v", reference)
	}
}
