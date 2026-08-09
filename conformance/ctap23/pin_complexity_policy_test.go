package ctap23

import (
	"slices"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestPINComplexityPolicyDefinitions(t *testing.T) {
	tests := pinComplexityPolicyTests(Config{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDPINComplexityPolicyP1, "P-1"},
		{TestIDPINComplexityPolicyP2, "P-2"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != pinComplexityPolicySourcePath ||
			test.Source.Case != expected.marker || !test.Destructive {
			t.Errorf("test[%d] = %#v", index, test)
		}
		if len(test.References) != 3 {
			t.Fatalf("test[%d] references = %#v", index, test.References)
		}
		assertMinPINLengthReference(
			t,
			test.References[0],
			"ctap-2.3-ps-20260226:7.5.1:pin-complexity-policy-feature-detection",
			"7.5.1",
			"pin-complexity-policy-feature-detection",
			"#sctn-pin-complexity-policy",
		)
		assertMinPINLengthReference(
			t,
			test.References[1],
			"ctap-2.3-ps-20260226:6.11.4:minimum-pin-length-rp-ids",
			"6.11.4",
			"minimum-pin-length-rp-ids",
			"#setMinPINLength",
		)
		assertMinPINLengthReference(
			t,
			test.References[2],
			"ctap-2.3-ps-20260226:12.6:rp-authorized-pin-complexity-policy-output",
			"12.6",
			"rp-authorized-pin-complexity-policy-output",
			"#sctn-pin-complexity-policy-extension",
		)
	}
}

func TestPINComplexityPolicyCasesUseIndependentNoResetLifecycleAndExactWire(t *testing.T) {
	for _, testCase := range []struct {
		index       int
		allowedRPID string
		targetRPID  string
	}{
		{0, pinComplexityPolicyP1RPID, pinComplexityPolicyP1RPID},
		{1, pinComplexityPolicyP2AllowedRPID, pinComplexityPolicyP2TargetRPID},
	} {
		t.Run(pinComplexityPolicyTests(Config{})[testCase.index].Source.Case, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			pin := []byte("1234")
			config := extensionPINPolicyConfig(device, pin)
			result := runExtensionPINPolicyTest(
				t,
				device,
				pinComplexityPolicyTests(config)[testCase.index],
			)
			if result.Status != conformance.StatusPassed {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
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
				extension: extension.ExtensionIdentifierPinComplexityPolicy,
			}}) {
				t.Fatalf("MakeCredential requests = %#v", device.makeCredentials)
			}
			assertExtensionPINPolicyLifecycleAndSecrets(t, device, pin)
		})
	}
}

func TestPINComplexityPolicyAllowedOutputMatchesFreshFalseAndTrue(t *testing.T) {
	for _, policy := range []bool{false, true} {
		t.Run(map[bool]string{false: "false", true: "true"}[policy], func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			device.complexityAfterReset = &policy
			config := extensionPINPolicyConfig(device, []byte("1234"))
			result := runExtensionPINPolicyTest(t, device, pinComplexityPolicyTests(config)[0])
			if result.Status != conformance.StatusPassed {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
		})
	}
}

func TestPINComplexityPolicyRawOutputValidation(t *testing.T) {
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
		{name: "allowed output wrong bool", index: 0, outputValue: true},
		{name: "allowed output wrong type", index: 0, outputValue: "false"},
		{
			name:      "allowed output noncanonical",
			index:     0,
			outputRaw: nonCanonicalExtensionPINPolicyOutput("pinComplexityPolicy", 0xf4),
		},
		{name: "unrelated RP output present", index: 1, outputPresent: &trueValue},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			device.outputPresent = testCase.outputPresent
			device.outputValue = testCase.outputValue
			device.outputRaw = testCase.outputRaw
			config := extensionPINPolicyConfig(device, []byte("1234"))
			result := runExtensionPINPolicyTest(
				t,
				device,
				pinComplexityPolicyTests(config)[testCase.index],
			)
			if result.Status != conformance.StatusFailed {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
		})
	}
}

func TestPINComplexityPolicyUnrelatedRPAllowsOtherExtensionOutput(t *testing.T) {
	device := newExtensionPINPolicyDevice(t)
	device.outputRaw = marshalGetAssertionFixture(t, map[string]any{"credProtect": uint(1)})
	config := extensionPINPolicyConfig(device, []byte("1234"))

	result := runExtensionPINPolicyTest(t, device, pinComplexityPolicyTests(config)[1])
	if result.Status != conformance.StatusPassed {
		t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
	}
}

func TestPINComplexityPolicyApplicabilityStopsBeforeMutation(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*extensionPINPolicyDevice)
		want   conformance.Status
	}{
		{
			name: "extension absent",
			mutate: func(device *extensionPINPolicyDevice) {
				device.extensions = []extension.ExtensionIdentifier{extension.ExtensionIdentifierMinPinLength}
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "GetInfo key 27 absent",
			mutate: func(device *extensionPINPolicyDevice) {
				device.absentGetInfoFields[27] = true
			},
			want: conformance.StatusFailed,
		},
		{
			name: "GetInfo key 27 wrong type",
			mutate: func(device *extensionPINPolicyDevice) {
				device.fieldOverrides[27] = "false"
			},
			want: conformance.StatusFailed,
		},
		{
			name: "clientPin absent",
			mutate: func(device *extensionPINPolicyDevice) {
				device.absentOptions[string(protocol.OptionClientPIN)] = true
			},
			want: conformance.StatusFailed,
		},
		{
			name: "authnrCfg false",
			mutate: func(device *extensionPINPolicyDevice) {
				device.optionOverrides[string(protocol.OptionAuthenticatorConfig)] = false
			},
			want: conformance.StatusFailed,
		},
		{
			name: "setMinPINLength false",
			mutate: func(device *extensionPINPolicyDevice) {
				device.optionOverrides[string(protocol.OptionSetMinPINLength)] = false
			},
			want: conformance.StatusFailed,
		},
		{
			name: "setMinPINLength absent from inventory",
			mutate: func(device *extensionPINPolicyDevice) {
				device.commands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandToggleAlwaysUv}
			},
			want: conformance.StatusFailed,
		},
		{
			name: "protocol 2 absent",
			mutate: func(device *extensionPINPolicyDevice) {
				device.pinProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne}
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "maximum RP list absent",
			mutate: func(device *extensionPINPolicyDevice) {
				device.absentGetInfoFields[16] = true
			},
			want: conformance.StatusSkipped,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			testCase.mutate(device)
			config := extensionPINPolicyConfig(device, []byte("1234"))
			result := runExtensionPINPolicyTest(t, device, pinComplexityPolicyTests(config)[0])
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

func TestPINComplexityPolicyStatusAndTransportClassification(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*extensionPINPolicyDevice)
		want   conformance.Status
	}{
		{
			name: "CTAP status",
			mutate: func(device *extensionPINPolicyDevice) {
				device.makeCredentialStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			},
			want: conformance.StatusFailed,
		},
		{
			name: "transport error",
			mutate: func(device *extensionPINPolicyDevice) {
				device.transportErrorCommand = protocol.AuthenticatorMakeCredential
			},
			want: conformance.StatusError,
		},
		{
			name: "cleanup error",
			mutate: func(device *extensionPINPolicyDevice) {
				device.resetErrorAt = 2
			},
			want: conformance.StatusError,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newExtensionPINPolicyDevice(t)
			testCase.mutate(device)
			config := extensionPINPolicyConfig(device, []byte("1234"))
			result := runExtensionPINPolicyTest(t, device, pinComplexityPolicyTests(config)[0])
			if result.Status != testCase.want {
				t.Fatalf("status = %s, steps = %#v", result.Status, result.Steps)
			}
			assertAuthenticatorConfigZeroed(t, device.transferredToken)
		})
	}
}
