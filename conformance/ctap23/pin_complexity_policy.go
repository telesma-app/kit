package ctap23

import (
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const (
	pinComplexityPolicySourcePath = "tests/CTAP2/Protocol/Extensions/pinComplexityPolicy.js"

	pinComplexityPolicyP1RPID        = "pin-complexity-policy-p1.ctap23-conformance.example"
	pinComplexityPolicyP2AllowedRPID = "pin-complexity-policy-p2-allowed.ctap23-conformance.example"
	pinComplexityPolicyP2TargetRPID  = "pin-complexity-policy-p2-target.ctap23-conformance.example"

	TestIDPINComplexityPolicyP1 conformance.TestID = "fido.ctap2.3.pin-complexity-policy.p-1"
	TestIDPINComplexityPolicyP2 conformance.TestID = "fido.ctap2.3.pin-complexity-policy.p-2"
)

func pinComplexityPolicyTests(config Config) []conformance.Test {
	featureReference := pinComplexityPolicyFeatureReference()
	configReference := minPINLengthConfigReference()
	outputReference := pinComplexityPolicyOutputReference()
	inputs := protocol.CreateExtensionInputs{
		CreatePinComplexityPolicyInput: protocol.CreatePinComplexityPolicyInput{
			PinComplexityPolicy: true,
		},
	}
	applicable := func(
		fields map[uint64]cbor.RawMessage,
		info protocol.AuthenticatorGetInfoResponse,
		commands []protocol.ConfigSubCommand,
	) error {
		return pinComplexityPolicyApplicable(fields, info, commands, config)
	}

	return []conformance.Test{
		extensionPINPolicyTest(config, extensionPINPolicyCase{
			id:              TestIDPINComplexityPolicyP1,
			marker:          "P-1",
			sessionMarker:   "pin-complexity-policy.P-1",
			sourcePath:      pinComplexityPolicySourcePath,
			name:            "Return the current PIN complexity policy to an allowed RP",
			description:     "Configures one allowed RP ID, omits MakeCredential options, and requires the canonical raw pinComplexityPolicy output to equal fresh GetInfo key 27, including false",
			allowedRPID:     pinComplexityPolicyP1RPID,
			targetRPID:      pinComplexityPolicyP1RPID,
			references:      []conformance.RequirementRef{featureReference, configReference, outputReference},
			configReference: configReference,
			extensions:      inputs,
			applicable:      applicable,
			validateOutput:  requirePINComplexityPolicyOutput,
		}),
		extensionPINPolicyTest(config, extensionPINPolicyCase{
			id:              TestIDPINComplexityPolicyP2,
			marker:          "P-2",
			sessionMarker:   "pin-complexity-policy.P-2",
			sourcePath:      pinComplexityPolicySourcePath,
			name:            "Do not disclose the PIN complexity policy to an unrelated RP",
			description:     "Independently configures a nonempty allowed list, targets another RP without MakeCredential options, and requires the pinComplexityPolicy output to be absent",
			allowedRPID:     pinComplexityPolicyP2AllowedRPID,
			targetRPID:      pinComplexityPolicyP2TargetRPID,
			references:      []conformance.RequirementRef{featureReference, configReference, outputReference},
			configReference: configReference,
			extensions:      inputs,
			applicable:      applicable,
			validateOutput:  rejectPINComplexityPolicyOutput,
		}),
	}
}

func pinComplexityPolicyApplicable(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
	config Config,
) error {
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy) {
		return conformance.Skip("authenticator does not advertise the pinComplexityPolicy extension")
	}

	rawPolicy, present := fields[27]
	if !present {
		return conformance.Fail("pinComplexityPolicy extension requires GetInfo key 27 to be present")
	}
	var policy bool
	if err := getInfoDecMode.Unmarshal(rawPolicy, &policy); err != nil {
		return conformance.Failf("invalid GetInfo pinComplexityPolicy key 27: %v", err)
	}
	if info.PinComplexityPolicy == nil || *info.PinComplexityPolicy != policy {
		return conformance.Fail("typed GetInfo pinComplexityPolicy does not match raw key 27")
	}

	if _, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN); err != nil {
		return err
	} else if !clientPINPresent {
		return conformance.Fail("pinComplexityPolicy requires the clientPin option to be present")
	}

	return extensionPINPolicySetMinRPIDsApplicable(fields, info, commands, config)
}

func requirePINComplexityPolicyOutput(
	fields map[uint64]cbor.RawMessage,
	_ protocol.AuthenticatorGetInfoResponse,
	authData []byte,
) error {
	rawPolicy, present := fields[27]
	if !present {
		return conformance.Fail("fresh GetInfo response does not contain pinComplexityPolicy key 27")
	}
	var expected bool
	if err := getInfoDecMode.Unmarshal(rawPolicy, &expected); err != nil {
		return conformance.Failf("invalid fresh GetInfo pinComplexityPolicy key 27: %v", err)
	}

	view, err := observeMakeCredentialAuthDataExtensions(authData)
	if err != nil {
		return err
	}
	defer view.clearValues()
	if !view.Included {
		return conformance.Fail("authenticatorMakeCredential authData does not include extension output")
	}

	raw, present := view.Values[string(extension.ExtensionIdentifierPinComplexityPolicy)]
	if !present {
		return conformance.Fail("authenticatorMakeCredential extension output does not contain pinComplexityPolicy")
	}
	var value bool
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return conformance.Failf("invalid pinComplexityPolicy extension output: %v", err)
	}
	if value != expected {
		return conformance.Failf(
			"pinComplexityPolicy extension output is %t, want fresh GetInfo key 27 value %t",
			value,
			expected,
		)
	}

	return nil
}

func rejectPINComplexityPolicyOutput(
	_ map[uint64]cbor.RawMessage,
	_ protocol.AuthenticatorGetInfoResponse,
	authData []byte,
) error {
	view, err := observeMakeCredentialAuthDataExtensions(authData)
	if err != nil {
		return err
	}
	defer view.clearValues()
	if !view.Included {
		return nil
	}
	if _, present := view.Values[string(extension.ExtensionIdentifierPinComplexityPolicy)]; present {
		return conformance.Fail(
			"authenticator disclosed pinComplexityPolicy to an RP ID outside minPinLengthRPIDs",
		)
	}

	return nil
}

func pinComplexityPolicyFeatureReference() conformance.RequirementRef {
	return extensionPINPolicyReference(
		"7.5.1",
		"pin-complexity-policy-feature-detection",
		"sctn-pin-complexity-policy",
		conformance.RequirementMust,
	)
}

func pinComplexityPolicyOutputReference() conformance.RequirementRef {
	return extensionPINPolicyReference(
		"12.6",
		"rp-authorized-pin-complexity-policy-output",
		"sctn-pin-complexity-policy-extension",
		conformance.RequirementMust,
	)
}
