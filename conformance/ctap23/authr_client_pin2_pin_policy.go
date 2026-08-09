package ctap23

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"golang.org/x/text/unicode/norm"
)

const (
	authrClientPIN2PinPolicySourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin2/Authr-ClientPin2-PinPolicy.js"

	TestIDAuthrClientPIN2PinPolicyP1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-pin-policy.p-1"
	TestIDAuthrClientPIN2PinPolicyF1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-pin-policy.f-1"
	TestIDAuthrClientPIN2PinPolicyF2 conformance.TestID = "fido.ctap2.3.authr-client-pin2-pin-policy.f-2"
	TestIDAuthrClientPIN2PinPolicyF3 conformance.TestID = "fido.ctap2.3.authr-client-pin2-pin-policy.f-3"
	TestIDAuthrClientPIN2PinPolicyF4 conformance.TestID = "fido.ctap2.3.authr-client-pin2-pin-policy.f-4"
	TestIDAuthrClientPIN2PinPolicyF5 conformance.TestID = "fido.ctap2.3.authr-client-pin2-pin-policy.f-5"
)

var clientPIN2PinPolicyRocket = [...]byte{0xf0, 0x9f, 0x9a, 0x80}

type clientPIN2PinPolicyCase struct {
	id                  conformance.TestID
	marker              string
	name                string
	references          []conformance.RequirementRef
	requiresMaxPINField bool
	requiresPINProvider bool
	requiresRocketRange bool
	run                 func(*conformance.TestContext, Config, clientPIN2PinPolicySession)
}

type clientPIN2PinPolicySession struct {
	fields map[uint64]cbor.RawMessage
	info   protocol.AuthenticatorGetInfoResponse
}

func authrClientPIN2PinPolicyTests(config Config) []conformance.Test {
	pinRequirements := clientPIN1PinRequirementsReference()
	policyViolation := clientPIN1PinPolicyViolationReference()
	maxPINLength := clientPIN1MaxPINLengthReference()
	cases := []clientPIN2PinPolicyCase{
		{
			id:                  TestIDAuthrClientPIN2PinPolicyP1,
			marker:              "P-1",
			name:                "Set a protocol 2 PIN within the advertised policy",
			references:          []conformance.RequirementRef{pinRequirements},
			requiresPINProvider: true,
			run:                 runClientPIN2PinPolicyP1,
		},
		{
			id:         TestIDAuthrClientPIN2PinPolicyF1,
			marker:     "F-1",
			name:       "Reject a three-byte protocol 2 PIN",
			references: []conformance.RequirementRef{pinRequirements, policyViolation},
			run: func(test *conformance.TestContext, _ Config, _ clientPIN2PinPolicySession) {
				runClientPIN2PinPolicyRejected(test, "client-pin2-pin-policy.f-1.set", 3)
			},
		},
		{
			id:         TestIDAuthrClientPIN2PinPolicyF2,
			marker:     "F-2",
			name:       "Reject a protocol 2 PIN larger than 63 bytes",
			references: []conformance.RequirementRef{pinRequirements, policyViolation},
			run: func(test *conformance.TestContext, _ Config, _ clientPIN2PinPolicySession) {
				runClientPIN2PinPolicyRejected(test, "client-pin2-pin-policy.f-2.set", 64)
			},
		},
		{
			id:         TestIDAuthrClientPIN2PinPolicyF3,
			marker:     "F-3",
			name:       "Reject an exactly 64-byte protocol 2 PIN",
			references: []conformance.RequirementRef{pinRequirements, policyViolation},
			run: func(test *conformance.TestContext, _ Config, _ clientPIN2PinPolicySession) {
				runClientPIN2PinPolicyRejected(test, "client-pin2-pin-policy.f-3.set", 64)
			},
		},
		{
			id:                  TestIDAuthrClientPIN2PinPolicyF4,
			marker:              "F-4",
			name:                "Reject a protocol 2 PIN above maxPINLength",
			references:          []conformance.RequirementRef{pinRequirements, maxPINLength, policyViolation},
			requiresMaxPINField: true,
			run:                 runClientPIN2PinPolicyF4,
		},
		{
			id:                  TestIDAuthrClientPIN2PinPolicyF5,
			marker:              "F-5",
			name:                "Reject a protocol 2 PIN below minPINLength by Unicode code points",
			references:          []conformance.RequirementRef{pinRequirements, policyViolation},
			requiresRocketRange: true,
			run:                 runClientPIN2PinPolicyF5,
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		definition := definition
		tests = append(tests, clientPIN2PinPolicyTest(config, definition))
	}

	return tests
}

func clientPIN2PinPolicyTest(config Config, definition clientPIN2PinPolicyCase) conformance.Test {
	commonReferences := []conformance.RequirementRef{
		getInfoReference(),
		clientPIN2KeyAgreementProtocolTwoReference(),
		clientPIN2KeyAgreementFeaturefulReference(),
		resetReference(),
		clientPINPowerCycleReference(),
		clientPINSetReference(),
		ctapMessageEncodingReference(),
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Validates one protocol 2 PIN length policy in an independent reset lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN2PinPolicySourcePath,
			Case: definition.marker,
		},
		References: appendClientPINReferences(commonReferences, definition.references...),
		Run: func(test *conformance.TestContext) {
			if !test.Step(clientPIN2PinPolicySupportStep(test, config)) {
				return
			}
			if definition.requiresMaxPINField && !test.Step(clientPIN2PinPolicyMaxPreflightStep(test)) {
				return
			}
			if definition.requiresRocketRange && !test.Step(clientPIN2PinPolicyRocketPreflightStep(test)) {
				return
			}
			if definition.requiresPINProvider && !test.Step(clientPIN2PinPolicyPositivePreflightStep(test, config)) {
				return
			}

			var session clientPIN2PinPolicySession
			if !test.Step(conformance.Step{
				ID:   "client-pin2-pin-policy.prepare",
				Name: "Power-cycle, reset, and refresh PIN policy",
				References: []conformance.RequirementRef{
					getInfoReference(),
					resetReference(),
					clientPINPowerCycleReference(),
				},
				Run: func(ctx context.Context) error {
					var err error
					session, err = prepareClientPIN2PinPolicySession(
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

func clientPIN2PinPolicySupportStep(
	test *conformance.TestContext,
	config Config,
) conformance.Step {
	return conformance.Step{
		ID:   "client-pin2-pin-policy.support",
		Name: "Confirm ClientPIN and protocol 2 support",
		References: []conformance.RequirementRef{
			getInfoReference(),
			clientPIN2KeyAgreementProtocolTwoReference(),
			clientPIN2KeyAgreementFeaturefulReference(),
		},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			if _, present := info.Options[protocol.OptionClientPIN]; !present {
				return conformance.Skip("authenticator does not advertise the clientPin option")
			}

			return validateClientPINProtocolSupport(
				fields,
				info,
				config,
				protocol.PinUvAuthProtocolTwo,
			)
		},
	}
}

func clientPIN2PinPolicyPositivePreflightStep(
	test *conformance.TestContext,
	config Config,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-pin-policy.positive-preflight",
		Name:       "Confirm an in-policy PIN can be requested before mutation",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN1PinRequirementsReference()},
		Run: func(ctx context.Context) error {
			_, info, err := clientPIN2PinPolicyInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			minimum := info.EffectiveMinPINLength()
			maximum := info.EffectiveMaxPINLength()
			if minimum == maximum {
				return conformance.Skip("effective minPINLength equals effective maxPINLength")
			}
			if config.TemporaryPINProvider == nil {
				return fmt.Errorf("ctap23: temporary PIN provider is required for ClientPIN policy P-1")
			}

			return nil
		},
	}
}

func clientPIN2PinPolicyMaxPreflightStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-pin-policy.max-pin-length",
		Name:       "Confirm maxPINLength applicability before mutation",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN1MaxPINLengthReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := clientPIN2PinPolicyInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			if _, present := fields[29]; !present {
				return conformance.Skip("authenticator does not advertise maxPINLength")
			}

			return nil
		},
	}
}

func clientPIN2PinPolicyRocketPreflightStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-pin-policy.unicode-range",
		Name:       "Confirm the below-minimum Unicode vector fits the PIN encoding limit",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN1PinRequirementsReference()},
		Run: func(ctx context.Context) error {
			_, info, err := clientPIN2PinPolicyInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			length := clientPIN2PinPolicyRocketBytes(info.EffectiveMinPINLength())
			if length > len([64]byte{}) {
				return conformance.Skipf(
					"the minPINLength-1 rocket vector is %d UTF-8 bytes and cannot be represented by the shared 64-byte raw PIN helper",
					length,
				)
			}

			return nil
		},
	}
}

func clientPIN2PinPolicyInfo(
	ctx context.Context,
	device ctaptransport.CBOR,
) (map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, error) {
	fields, info, err := readGetInfo(ctx, device)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if err := validateClientPIN1PinPolicyLengths(fields, info); err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, err
	}
	if info.EffectiveMinPINLength() > info.EffectiveMaxPINLength() {
		return nil, protocol.AuthenticatorGetInfoResponse{}, conformance.Failf(
			"effective minPINLength %d exceeds effective maxPINLength %d",
			info.EffectiveMinPINLength(),
			info.EffectiveMaxPINLength(),
		)
	}

	return fields, info, nil
}

func prepareClientPIN2PinPolicySession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	requireMaxPINField bool,
) (clientPIN2PinPolicySession, error) {
	if config.PowerCycler == nil {
		return clientPIN2PinPolicySession{}, fmt.Errorf(
			"ctap23: authenticator power cycler is required for ClientPIN policy tests",
		)
	}

	test.Cleanup(clientPIN2PinPolicyCleanupStep(test, config))
	if err := config.PowerCycler(ctx); err != nil {
		return clientPIN2PinPolicySession{}, err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return clientPIN2PinPolicySession{}, err
	}
	fields, info, err := clientPIN2PinPolicyInfo(ctx, test.CBOR())
	if err != nil {
		return clientPIN2PinPolicySession{}, err
	}
	if requireMaxPINField {
		if _, present := fields[29]; !present {
			return clientPIN2PinPolicySession{}, conformance.Fail(
				"maxPINLength disappeared after the isolated reset",
			)
		}
	}

	return clientPIN2PinPolicySession{fields: fields, info: info}, nil
}

func clientPIN2PinPolicyCleanupStep(test *conformance.TestContext, config Config) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-pin-policy.cleanup",
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

func runClientPIN2PinPolicyP1(
	test *conformance.TestContext,
	config Config,
	session clientPIN2PinPolicySession,
) {
	test.Step(conformance.Step{
		ID:   "client-pin2-pin-policy.p-1.set",
		Name: "Set a PIN between minPINLength and maxPINLength",
		References: []conformance.RequirementRef{
			clientPIN1PinRequirementsReference(),
			clientPINSetReference(),
			clientPIN2KeyAgreementProtocolTwoReference(),
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
			keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
			}
			err = test.Client().SetPIN(
				ctx,
				protocol.PinUvAuthProtocolTwo,
				keyAgreement,
				string(pin),
			)

			return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
		},
	})
}

func runClientPIN2PinPolicyRejected(
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
				protocol.PinUvAuthProtocolTwo,
				&paddedPIN,
			)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION)
		},
	})
}

func runClientPIN2PinPolicyF4(
	test *conformance.TestContext,
	_ Config,
	session clientPIN2PinPolicySession,
) {
	runClientPIN2PinPolicyRejected(
		test,
		"client-pin2-pin-policy.f-4.set",
		int(session.info.MaxPINLength)+1,
	)
}

func runClientPIN2PinPolicyF5(
	test *conformance.TestContext,
	_ Config,
	session clientPIN2PinPolicySession,
) {
	test.Step(conformance.Step{
		ID:         "client-pin2-pin-policy.f-5.set",
		Name:       "Require PIN_POLICY_VIOLATION for the below-minimum Unicode PIN",
		References: []conformance.RequirementRef{clientPIN1PinRequirementsReference(), clientPIN1PinPolicyViolationReference()},
		Run: func(ctx context.Context) error {
			minimum := session.info.EffectiveMinPINLength()
			length := clientPIN2PinPolicyRocketBytes(minimum)
			if length > len([64]byte{}) {
				return conformance.Skipf(
					"the minPINLength-1 rocket vector is %d UTF-8 bytes and cannot be represented by the shared 64-byte raw PIN helper",
					length,
				)
			}

			var paddedPIN [64]byte
			defer clear(paddedPIN[:])
			for offset := 0; offset < length; offset += len(clientPIN2PinPolicyRocket) {
				copy(paddedPIN[offset:], clientPIN2PinPolicyRocket[:])
			}
			pin := paddedPIN[:length]
			if !utf8.Valid(pin) || !norm.NFC.IsNormal(pin) ||
				utf8.RuneCount(pin) != int(minimum-1) || len(pin) == utf8.RuneCount(pin) {
				return fmt.Errorf("ctap23: invalid deterministic Unicode PIN policy vector")
			}
			err := setPINForPolicyTest(
				ctx,
				test.Client(),
				test.CBOR(),
				protocol.PinUvAuthProtocolTwo,
				&paddedPIN,
			)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION)
		},
	})
}

func clientPIN2PinPolicyRocketBytes(minimum uint) int {
	return int(minimum-1) * len(clientPIN2PinPolicyRocket)
}
