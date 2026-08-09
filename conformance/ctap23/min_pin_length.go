package ctap23

import (
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const (
	minPINLengthSourcePath = "tests/CTAP2/Protocol/Extensions/minPINLength.js"

	minPINLengthP1RPID        = "min-pin-length-p1.ctap23-conformance.example"
	minPINLengthF1AllowedRPID = "min-pin-length-f1-allowed.ctap23-conformance.example"
	minPINLengthF1TargetRPID  = "min-pin-length-f1-target.ctap23-conformance.example"

	TestIDMinPINLengthP1 conformance.TestID = "fido.ctap2.3.min-pin-length.p-1"
	TestIDMinPINLengthF1 conformance.TestID = "fido.ctap2.3.min-pin-length.f-1"
)

func minPINLengthTests(config Config) []conformance.Test {
	configReference := minPINLengthConfigReference()
	outputReference := minPINLengthOutputReference()
	inputs := protocol.CreateExtensionInputs{
		CreateMinPinLengthInput: protocol.CreateMinPinLengthInput{MinPinLength: true},
	}
	applicable := func(
		fields map[uint64]cbor.RawMessage,
		info protocol.AuthenticatorGetInfoResponse,
		commands []protocol.ConfigSubCommand,
	) error {
		return minPINLengthApplicable(fields, info, commands, config)
	}

	return []conformance.Test{
		extensionPINPolicyTest(config, extensionPINPolicyCase{
			id:              TestIDMinPINLengthP1,
			marker:          "P-1",
			sessionMarker:   "min-pin-length.P-1",
			sourcePath:      minPINLengthSourcePath,
			name:            "Return the current minimum PIN length to an allowed RP",
			description:     "Configures one allowed RP ID, omits MakeCredential options, and requires the canonical raw minPinLength output to equal a fresh GetInfo value",
			allowedRPID:     minPINLengthP1RPID,
			targetRPID:      minPINLengthP1RPID,
			references:      []conformance.RequirementRef{configReference, outputReference},
			configReference: configReference,
			extensions:      inputs,
			applicable:      applicable,
			validateOutput:  requireMinPINLengthOutput,
		}),
		extensionPINPolicyTest(config, extensionPINPolicyCase{
			id:              TestIDMinPINLengthF1,
			marker:          "F-1",
			sessionMarker:   "min-pin-length.F-1",
			sourcePath:      minPINLengthSourcePath,
			name:            "Do not disclose the minimum PIN length to an unrelated RP",
			description:     "Independently configures a nonempty allowed list, targets another RP without MakeCredential options, and requires the minPinLength output to be absent",
			allowedRPID:     minPINLengthF1AllowedRPID,
			targetRPID:      minPINLengthF1TargetRPID,
			references:      []conformance.RequirementRef{configReference, outputReference},
			configReference: configReference,
			extensions:      inputs,
			applicable:      applicable,
			validateOutput:  rejectMinPINLengthOutput,
		}),
	}
}

func minPINLengthApplicable(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
	config Config,
) error {
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierMinPinLength) {
		if config.Featureful {
			return conformance.Fail("featureful profile requires the minPinLength extension")
		}

		return conformance.Skip("authenticator does not advertise the minPinLength extension")
	}
	if err := extensionPINPolicySetMinRPIDsApplicable(fields, info, commands, config); err != nil {
		return err
	}

	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	if !clientPINPresent && (info.UvModality == nil ||
		*info.UvModality&protocol.UserVerifyPasscodeInternal == 0) {
		return conformance.Fail("minPinLength requires ClientPIN or built-in passcode user verification")
	}

	return nil
}

func requireMinPINLengthOutput(
	fields map[uint64]cbor.RawMessage,
	_ protocol.AuthenticatorGetInfoResponse,
	authData []byte,
) error {
	view, err := observeMakeCredentialAuthDataExtensions(authData)
	if err != nil {
		return err
	}
	defer view.clearValues()
	if !view.Included {
		return conformance.Fail("authenticatorMakeCredential authData does not include extension output")
	}

	raw, present := view.Values[string(extension.ExtensionIdentifierMinPinLength)]
	if !present {
		return conformance.Fail("authenticatorMakeCredential extension output does not contain minPinLength")
	}
	var value uint
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return conformance.Failf("invalid minPinLength extension output: %v", err)
	}
	expectedRaw, present := fields[13]
	if !present {
		if value < protocol.DefaultMinPINCodePoints {
			return conformance.Failf(
				"minPinLength extension output is %d, want at least %d",
				value,
				protocol.DefaultMinPINCodePoints,
			)
		}

		return nil
	}
	if !hasCBORMajorType(expectedRaw, 0) {
		return conformance.Fail("GetInfo minPINLength is not a CBOR unsigned integer")
	}
	var expected uint
	if err := getInfoDecMode.Unmarshal(expectedRaw, &expected); err != nil {
		return conformance.Failf("invalid GetInfo minPINLength: %v", err)
	}
	if value != expected {
		return conformance.Failf("minPinLength extension output is %d, want fresh GetInfo value %d", value, expected)
	}

	return nil
}

func rejectMinPINLengthOutput(
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
	if _, present := view.Values[string(extension.ExtensionIdentifierMinPinLength)]; present {
		return conformance.Fail("authenticator disclosed minPinLength to an RP ID outside minPinLengthRPIDs")
	}

	return nil
}

func minPINLengthConfigReference() conformance.RequirementRef {
	return extensionPINPolicyReference(
		"6.11.4",
		"minimum-pin-length-rp-ids",
		"setMinPINLength",
		conformance.RequirementMust,
	)
}

func minPINLengthOutputReference() conformance.RequirementRef {
	return extensionPINPolicyReference(
		"12.5",
		"rp-authorized-minimum-pin-length-output",
		"sctn-minpinlength-extension",
		conformance.RequirementMust,
	)
}
