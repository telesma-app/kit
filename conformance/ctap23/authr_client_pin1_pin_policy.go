package ctap23

import (
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN1PinPolicySourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin1/Authr-ClientPin1-PinPolicy.js"

	TestIDAuthrClientPIN1PinPolicyP1 conformance.TestID = "fido.ctap2.3.authr-client-pin1-pin-policy.p-1"
	TestIDAuthrClientPIN1PinPolicyF1 conformance.TestID = "fido.ctap2.3.authr-client-pin1-pin-policy.f-1"
	TestIDAuthrClientPIN1PinPolicyF2 conformance.TestID = "fido.ctap2.3.authr-client-pin1-pin-policy.f-2"
	TestIDAuthrClientPIN1PinPolicyF3 conformance.TestID = "fido.ctap2.3.authr-client-pin1-pin-policy.f-3"
	TestIDAuthrClientPIN1PinPolicyF4 conformance.TestID = "fido.ctap2.3.authr-client-pin1-pin-policy.f-4"
)

type clientPIN1PinPolicyCase struct {
	id                  conformance.TestID
	marker              string
	name                string
	references          []conformance.RequirementRef
	requiresMaxPINField bool
	requiresPINProvider bool
	run                 func(*conformance.TestContext, Config, clientPIN1PinPolicySession)
}

type clientPIN1PinPolicySession struct {
	fields map[uint64]cbor.RawMessage
	info   protocol.AuthenticatorGetInfoResponse
}

func authrClientPIN1PinPolicyTests(config Config) []conformance.Test {
	pinRequirements := clientPIN1PinRequirementsReference()
	policyViolation := clientPIN1PinPolicyViolationReference()
	maxPINLength := clientPIN1MaxPINLengthReference()
	cases := []clientPIN1PinPolicyCase{
		{
			id:                  TestIDAuthrClientPIN1PinPolicyP1,
			marker:              "P-1",
			name:                "Set a protocol 1 PIN within the advertised policy",
			references:          []conformance.RequirementRef{pinRequirements},
			requiresPINProvider: true,
			run:                 runClientPIN1PinPolicyP1,
		},
		{
			id:         TestIDAuthrClientPIN1PinPolicyF1,
			marker:     "F-1",
			name:       "Reject a three-byte protocol 1 PIN",
			references: []conformance.RequirementRef{pinRequirements, policyViolation},
			run: func(test *conformance.TestContext, _ Config, _ clientPIN1PinPolicySession) {
				runClientPIN1PinPolicyRejected(test, "client-pin1-pin-policy.f-1.set", 3)
			},
		},
		{
			id:         TestIDAuthrClientPIN1PinPolicyF2,
			marker:     "F-2",
			name:       "Reject a protocol 1 PIN larger than 63 bytes",
			references: []conformance.RequirementRef{pinRequirements, policyViolation},
			run: func(test *conformance.TestContext, _ Config, _ clientPIN1PinPolicySession) {
				runClientPIN1PinPolicyRejected(test, "client-pin1-pin-policy.f-2.set", 64)
			},
		},
		{
			id:         TestIDAuthrClientPIN1PinPolicyF3,
			marker:     "F-3",
			name:       "Reject an exactly 64-byte protocol 1 PIN",
			references: []conformance.RequirementRef{pinRequirements, policyViolation},
			run: func(test *conformance.TestContext, _ Config, _ clientPIN1PinPolicySession) {
				runClientPIN1PinPolicyRejected(test, "client-pin1-pin-policy.f-3.set", 64)
			},
		},
		{
			id:                  TestIDAuthrClientPIN1PinPolicyF4,
			marker:              "F-4",
			name:                "Reject a protocol 1 PIN above maxPINLength",
			references:          []conformance.RequirementRef{pinRequirements, maxPINLength, policyViolation},
			requiresMaxPINField: true,
			run:                 runClientPIN1PinPolicyF4,
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		definition := definition
		tests = append(tests, clientPIN1PinPolicyTest(config, definition))
	}

	return tests
}

func clientPIN1PinPolicyTest(config Config, definition clientPIN1PinPolicyCase) conformance.Test {
	commonReferences := []conformance.RequirementRef{
		getInfoReference(),
		clientPIN1KeyAgreementProfileReference(),
		clientPIN1KeyAgreementProtocolOneReference(),
		resetReference(),
		clientPINPowerCycleReference(),
		clientPINSetReference(),
		ctapMessageEncodingReference(),
	}
	references := append(commonReferences, definition.references...)

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Validates one protocol 1 PIN length policy in an independent reset lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN1PinPolicySourcePath,
			Case: definition.marker,
		},
		References: references,
		Run: func(test *conformance.TestContext) {
			if !test.Step(clientPIN1GetRetriesSupportStep(test, config)) {
				return
			}
			if definition.requiresMaxPINField && !test.Step(clientPIN1PinPolicyMaxPreflightStep(test)) {
				return
			}
			if definition.requiresPINProvider && !test.Step(clientPIN1PinPolicyPositivePreflightStep(test, config)) {
				return
			}

			var session clientPIN1PinPolicySession
			if !test.Step(conformance.Step{
				ID:   "client-pin1-pin-policy.prepare",
				Name: "Power-cycle, reset, and refresh PIN policy",
				References: []conformance.RequirementRef{
					getInfoReference(),
					resetReference(),
					clientPINPowerCycleReference(),
				},
				Run: func(ctx context.Context) error {
					var err error
					session, err = prepareClientPIN1PinPolicySession(
						ctx,
						test,
						config,
						definition.requiresMaxPINField,
					)

					return err
				},
			}) {
				return
			}

			definition.run(test, config, session)
		},
	}
}

func clientPIN1PinPolicyPositivePreflightStep(
	test *conformance.TestContext,
	config Config,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin1-pin-policy.positive-preflight",
		Name:       "Confirm an in-policy PIN can be requested before mutation",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN1PinRequirementsReference()},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			if err := validateClientPIN1PinPolicyLengths(fields, info); err != nil {
				return err
			}
			minimum := info.EffectiveMinPINLength()
			maximum := info.EffectiveMaxPINLength()
			if minimum == maximum {
				return conformance.Skip("effective minPINLength equals effective maxPINLength")
			}
			if minimum > maximum {
				return conformance.Failf(
					"effective minPINLength %d exceeds effective maxPINLength %d",
					minimum,
					maximum,
				)
			}
			if config.TemporaryPINProvider == nil {
				return fmt.Errorf("ctap23: temporary PIN provider is required for ClientPIN policy P-1")
			}

			return nil
		},
	}
}

func clientPIN1PinPolicyMaxPreflightStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin1-pin-policy.max-pin-length",
		Name:       "Confirm maxPINLength applicability before mutation",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN1MaxPINLengthReference()},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			if _, present := fields[29]; !present {
				return conformance.Skip("authenticator does not advertise maxPINLength")
			}

			return validateClientPIN1PinPolicyLengths(fields, info)
		},
	}
}

func prepareClientPIN1PinPolicySession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	requireMaxPINField bool,
) (clientPIN1PinPolicySession, error) {
	if config.PowerCycler == nil {
		return clientPIN1PinPolicySession{}, fmt.Errorf(
			"ctap23: authenticator power cycler is required for ClientPIN policy tests",
		)
	}

	test.Cleanup(clientPIN1PinPolicyCleanupStep(test, config))
	if err := config.PowerCycler(ctx); err != nil {
		return clientPIN1PinPolicySession{}, err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return clientPIN1PinPolicySession{}, err
	}
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return clientPIN1PinPolicySession{}, err
	}
	if err := validateClientPIN1PinPolicyLengths(fields, info); err != nil {
		return clientPIN1PinPolicySession{}, err
	}
	if requireMaxPINField {
		if _, present := fields[29]; !present {
			return clientPIN1PinPolicySession{}, conformance.Fail(
				"maxPINLength disappeared after the isolated reset",
			)
		}
	}

	return clientPIN1PinPolicySession{fields: fields, info: info}, nil
}

func clientPIN1PinPolicyCleanupStep(test *conformance.TestContext, config Config) conformance.Step {
	return conformance.Step{
		ID:         "client-pin1-pin-policy.cleanup",
		Name:       "Power-cycle and reset after the PIN policy test",
		References: []conformance.RequirementRef{clientPINPowerCycleReference(), resetReference()},
		Run: func(ctx context.Context) error {
			if err := config.PowerCycler(ctx); err != nil {
				return err
			}

			return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
		},
	}
}

func validateClientPIN1PinPolicyLengths(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
) error {
	if _, present := fields[13]; present && info.MinPINLength < protocol.DefaultMinPINCodePoints {
		return conformance.Failf(
			"minPINLength is %d, want at least %d",
			info.MinPINLength,
			protocol.DefaultMinPINCodePoints,
		)
	}
	if _, present := fields[29]; present && (info.MaxPINLength < 8 || info.MaxPINLength > 63) {
		return conformance.Failf("maxPINLength is %d, want 8..63", info.MaxPINLength)
	}

	return nil
}

func runClientPIN1PinPolicyP1(
	test *conformance.TestContext,
	config Config,
	session clientPIN1PinPolicySession,
) {
	test.Step(conformance.Step{
		ID:   "client-pin1-pin-policy.p-1.set",
		Name: "Set a PIN between minPINLength and maxPINLength",
		References: []conformance.RequirementRef{
			clientPIN1PinRequirementsReference(),
			clientPINSetReference(),
		},
		Run: func(ctx context.Context) error {
			minimum := session.info.EffectiveMinPINLength()
			maximum := session.info.EffectiveMaxPINLength()
			if minimum == maximum {
				return conformance.Skip("effective minPINLength equals effective maxPINLength")
			}
			if minimum > maximum {
				return conformance.Failf(
					"effective minPINLength %d exceeds effective maxPINLength %d",
					minimum,
					maximum,
				)
			}
			request := TemporaryPINRequest{
				MinCodePoints: minimum + 1,
				MaxCodePoints: maximum,
			}
			pin, err := config.TemporaryPINProvider(ctx, request)
			defer clear(pin)
			if err != nil {
				return err
			}
			if err := validateTemporaryPIN(pin, request); err != nil {
				return err
			}
			keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolOne)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
			}
			err = test.Client().SetPIN(
				ctx,
				protocol.PinUvAuthProtocolOne,
				keyAgreement,
				string(pin),
			)

			return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
		},
	})
}

func runClientPIN1PinPolicyRejected(
	test *conformance.TestContext,
	stepID conformance.StepID,
	length int,
) {
	test.Step(conformance.Step{
		ID:         stepID,
		Name:       "Require PIN_POLICY_VIOLATION for the invalid PIN",
		References: []conformance.RequirementRef{clientPIN1PinRequirementsReference(), clientPIN1PinPolicyViolationReference()},
		Run: func(ctx context.Context) error {
			var paddedPIN [64]byte
			defer clear(paddedPIN[:])
			for index := 0; index < length; index++ {
				paddedPIN[index] = 'A'
			}
			err := setPINForPolicyTest(
				ctx,
				test.Client(),
				test.CBOR(),
				protocol.PinUvAuthProtocolOne,
				&paddedPIN,
			)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION)
		},
	})
}

func runClientPIN1PinPolicyF4(
	test *conformance.TestContext,
	_ Config,
	session clientPIN1PinPolicySession,
) {
	runClientPIN1PinPolicyRejected(
		test,
		"client-pin1-pin-policy.f-4.set",
		int(session.info.MaxPINLength)+1,
	)
}

func clientPIN1PinRequirementsReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.1:pin-requirements",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.1",
		Clause:        "pin-requirements",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinUvAuthProtocol",
		Level:         conformance.RequirementMust,
	}
}

func clientPIN1MaxPINLengthReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.4:max-pin-length",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.4",
		Clause:        "max-pin-length",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPIN1PinPolicyViolationReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.5:pin-policy-violation",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.5",
		Clause:        "pin-policy-violation",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#settingNewPin",
		Level:         conformance.RequirementMust,
	}
}
