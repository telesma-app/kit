package ctap23

import (
	"context"
	"fmt"
	"slices"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN1GetRetriesSourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin1/Authr-ClientPin1-GetRetries.js"

	TestIDAuthrClientPIN1GetRetriesP1 conformance.TestID = "fido.ctap2.3.authr-client-pin1-get-retries.p-1"
	TestIDAuthrClientPIN1GetRetriesP2 conformance.TestID = "fido.ctap2.3.authr-client-pin1-get-retries.p-2"
	TestIDAuthrClientPIN1GetRetriesP3 conformance.TestID = "fido.ctap2.3.authr-client-pin1-get-retries.p-3"
	TestIDAuthrClientPIN1GetRetriesP4 conformance.TestID = "fido.ctap2.3.authr-client-pin1-get-retries.p-4"
)

type clientPIN1RetrySession struct {
	pin        []byte
	algorithms []credential.PublicKeyCredentialParameters
}

func authrClientPIN1GetRetriesTests(config Config) []conformance.Test {
	getInfoRequirement := getInfoReference()
	profileRequirement := clientPIN1KeyAgreementProfileReference()
	protocolOneRequirement := clientPIN1KeyAgreementProtocolOneReference()
	resetRequirement := resetReference()
	setPINRequirement := clientPINSetReference()
	powerCycleRequirement := clientPINPowerCycleReference()
	retriesRequirement := clientPINRetriesReference()
	maximumRetriesRequirement := clientPINMaximumRetriesReference()
	getRetriesRequirement := clientPINGetRetriesReference()
	getTokenRequirement := clientPINLegacyTokenReference()
	makeCredentialRequirement := clientPINMakeCredentialReference()
	encodingRequirement := ctapMessageEncodingReference()

	commonReferences := []conformance.RequirementRef{
		getInfoRequirement,
		profileRequirement,
		protocolOneRequirement,
		resetRequirement,
		setPINRequirement,
		powerCycleRequirement,
		retriesRequirement,
		maximumRetriesRequirement,
		getRetriesRequirement,
		encodingRequirement,
	}

	return []conformance.Test{
		clientPIN1GetRetriesTest(
			config,
			TestIDAuthrClientPIN1GetRetriesP1,
			"P-1",
			"PIN retry counter response",
			commonReferences,
			func(test *conformance.TestContext, _ clientPIN1RetrySession) {
				test.Step(conformance.Step{
					ID:   "client-pin1.get-retries",
					Name: "Read the protocol 1 PIN retry counter",
					References: []conformance.RequirementRef{
						retriesRequirement,
						maximumRetriesRequirement,
						getRetriesRequirement,
						encodingRequirement,
					},
					Run: func(ctx context.Context) error {
						_, err := readClientPINRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolOne)

						return err
					},
				})
			},
		),
		clientPIN1GetRetriesTest(
			config,
			TestIDAuthrClientPIN1GetRetriesP2,
			"P-2",
			"PIN retry decrement and reset",
			slices.Concat(commonReferences, []conformance.RequirementRef{getTokenRequirement, makeCredentialRequirement}),
			func(test *conformance.TestContext, session clientPIN1RetrySession) {
				originalRetries, ok := clientPIN1ReadInitialRetries(
					test,
					retriesRequirement,
					maximumRetriesRequirement,
					getRetriesRequirement,
					encodingRequirement,
				)
				if !ok {
					return
				}

				wrongPIN := differentTemporaryPIN(session.pin)
				defer clear(wrongPIN)
				if !test.Step(conformance.Step{
					ID:         "client-pin1.invalid-pin-attempts",
					Name:       "Submit two incorrect protocol 1 PINs",
					References: []conformance.RequirementRef{retriesRequirement, getTokenRequirement},
					Run: func(ctx context.Context) error {
						for range 2 {
							if err := expectClientPIN1TokenStatus(
								ctx,
								test.Client(),
								wrongPIN,
								ctaptransport.CTAP2_ERR_PIN_INVALID,
							); err != nil {
								return err
							}
						}

						return nil
					},
				}) {
					return
				}

				if !test.Step(conformance.Step{
					ID:   "client-pin1.decremented-retries",
					Name: "Check that two incorrect PINs consumed two retries",
					References: []conformance.RequirementRef{
						retriesRequirement,
						maximumRetriesRequirement,
						getRetriesRequirement,
						encodingRequirement,
					},
					Run: func(ctx context.Context) error {
						retries, err := readClientPINRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolOne)
						if err != nil {
							return err
						}
						if originalRetries < 2 {
							return conformance.Failf("initial pinRetries is %d, cannot decrease by two", originalRetries)
						}
						if retries != originalRetries-2 {
							return conformance.Failf("pinRetries is %d after two incorrect PINs, want %d", retries, originalRetries-2)
						}

						return nil
					},
				}) {
					return
				}

				if !test.Step(conformance.Step{
					ID:         "client-pin1.valid-pin-credential",
					Name:       "Use a valid legacy PIN token for MakeCredential",
					References: []conformance.RequirementRef{retriesRequirement, getTokenRequirement, makeCredentialRequirement},
					Run: func(ctx context.Context) error {
						token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolOne, string(session.pin))
						defer clear(token)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
						}

						_, err = makeCredentialWithPINToken(
							ctx,
							test.Client(),
							protocol.PinUvAuthProtocolOne,
							token,
							session.algorithms,
						)

						return err
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:   "client-pin1.restored-retries",
					Name: "Check that a correct PIN restored the retry counter",
					References: []conformance.RequirementRef{
						retriesRequirement,
						maximumRetriesRequirement,
						getRetriesRequirement,
						encodingRequirement,
					},
					Run: func(ctx context.Context) error {
						retries, err := readClientPINRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolOne)
						if err != nil {
							return err
						}
						if retries != originalRetries {
							return conformance.Failf("pinRetries is %d after a correct PIN, want %d", retries, originalRetries)
						}

						return nil
					},
				})
			},
		),
		clientPIN1GetRetriesTest(
			config,
			TestIDAuthrClientPIN1GetRetriesP3,
			"P-3",
			"Consecutive incorrect PIN limit",
			slices.Concat(commonReferences, []conformance.RequirementRef{getTokenRequirement}),
			func(test *conformance.TestContext, session clientPIN1RetrySession) {
				originalRetries, ok := clientPIN1ReadInitialRetries(
					test,
					retriesRequirement,
					maximumRetriesRequirement,
					getRetriesRequirement,
					encodingRequirement,
				)
				if !ok {
					return
				}

				wrongPIN := differentTemporaryPIN(session.pin)
				defer clear(wrongPIN)
				test.Step(conformance.Step{
					ID:         "client-pin1.consecutive-invalid-pins",
					Name:       "Check the third consecutive incorrect PIN status",
					References: []conformance.RequirementRef{retriesRequirement, getTokenRequirement},
					Run: func(ctx context.Context) error {
						for range 2 {
							if err := expectClientPIN1TokenStatus(
								ctx,
								test.Client(),
								wrongPIN,
								ctaptransport.CTAP2_ERR_PIN_INVALID,
							); err != nil {
								return err
							}
						}

						expected := ctaptransport.CTAP2_ERR_PIN_BLOCKED
						if originalRetries > 3 {
							expected = ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED
						}

						return expectClientPIN1TokenStatus(ctx, test.Client(), wrongPIN, expected)
					},
				})
			},
		),
		{
			ID:          TestIDAuthrClientPIN1GetRetriesP4,
			Name:        "PIN retry exhaustion",
			Description: "Reports the pinned source case that is disabled before issuing any authenticator command",
			Source: conformance.SourceLocation{
				Path: authrClientPIN1GetRetriesSourcePath,
				Case: "P-4",
			},
			References: []conformance.RequirementRef{retriesRequirement, getTokenRequirement},
			Run: func(test *conformance.TestContext) {
				test.Step(conformance.Step{
					ID:         "client-pin1.p4-disabled",
					Name:       "Honor the pinned P-4 skip",
					References: []conformance.RequirementRef{retriesRequirement, getTokenRequirement},
					Run: func(context.Context) error {
						return conformance.Skip("the pinned P-4 case is disabled before exercising the authenticator")
					},
				})
			},
		},
	}
}

func clientPIN1GetRetriesTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	references []conformance.RequirementRef,
	run func(*conformance.TestContext, clientPIN1RetrySession),
) conformance.Test {
	return conformance.Test{
		ID:          id,
		Name:        name,
		Description: "Exercises the protocol 1 PIN retry state using an independently provisioned temporary PIN",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN1GetRetriesSourcePath,
			Case: marker,
		},
		References: references,
		Run: func(test *conformance.TestContext) {
			var session clientPIN1RetrySession
			defer func() {
				clear(session.pin)
			}()

			if !test.Step(clientPIN1GetRetriesSupportStep(test, config)) {
				return
			}
			if !test.Step(conformance.Step{
				ID:   "client-pin1.prepare",
				Name: "Reset the authenticator and configure a temporary PIN",
				References: []conformance.RequirementRef{
					resetReference(),
					clientPINSetReference(),
					clientPINPowerCycleReference(),
				},
				Run: func(ctx context.Context) error {
					var err error
					session, err = prepareClientPIN1RetrySession(ctx, test, config)

					return err
				},
			}) {
				return
			}

			run(test, session)
		},
	}
}

func clientPIN1GetRetriesSupportStep(test *conformance.TestContext, config Config) conformance.Step {
	getInfoRequirement := getInfoReference()
	profileRequirement := clientPIN1KeyAgreementProfileReference()
	protocolOneRequirement := clientPIN1KeyAgreementProtocolOneReference()

	return conformance.Step{
		ID:         "client-pin1.support",
		Name:       "Confirm ClientPIN and protocol 1 support",
		References: []conformance.RequirementRef{getInfoRequirement, protocolOneRequirement, profileRequirement},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			if _, present := info.Options[protocol.OptionClientPIN]; !present {
				return conformance.Skip("authenticator does not advertise the clientPin option")
			}

			return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolOne)
		},
	}
}

func prepareClientPIN1RetrySession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) (clientPIN1RetrySession, error) {
	if config.PowerCycler == nil {
		return clientPIN1RetrySession{}, fmt.Errorf("ctap23: authenticator power cycler is required for ClientPIN retry tests")
	}
	if config.TemporaryPINProvider == nil {
		return clientPIN1RetrySession{}, fmt.Errorf("ctap23: temporary PIN provider is required for ClientPIN retry tests")
	}

	if err := config.PowerCycler(ctx); err != nil {
		return clientPIN1RetrySession{}, err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return clientPIN1RetrySession{}, err
	}

	_, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return clientPIN1RetrySession{}, err
	}
	request := temporaryPINRequest(info)
	pin, err := config.TemporaryPINProvider(ctx, request)
	if err != nil {
		clear(pin)

		return clientPIN1RetrySession{}, err
	}
	if err := validateTemporaryPIN(pin, request); err != nil {
		clear(pin)

		return clientPIN1RetrySession{}, err
	}

	keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolOne)
	if err != nil {
		clear(pin)

		return clientPIN1RetrySession{}, unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	test.Cleanup(clientPIN1RetryCleanupStep(test, config))
	if err := test.Client().SetPIN(ctx, protocol.PinUvAuthProtocolOne, keyAgreement, string(pin)); err != nil {
		return clientPIN1RetrySession{pin: pin}, unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	return clientPIN1RetrySession{
		pin:        pin,
		algorithms: info.Algorithms,
	}, nil
}

func clientPIN1RetryCleanupStep(test *conformance.TestContext, config Config) conformance.Step {
	return conformance.Step{
		ID:         "client-pin1.cleanup",
		Name:       "Reset the authenticator after the PIN retry test",
		References: []conformance.RequirementRef{resetReference(), clientPINPowerCycleReference()},
		Run: func(ctx context.Context) error {
			if err := config.PowerCycler(ctx); err != nil {
				return err
			}

			return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
		},
	}
}

func clientPIN1ReadInitialRetries(
	test *conformance.TestContext,
	retriesRequirement conformance.RequirementRef,
	maximumRetriesRequirement conformance.RequirementRef,
	getRetriesRequirement conformance.RequirementRef,
	encodingRequirement conformance.RequirementRef,
) (uint, bool) {
	var retries uint
	passed := test.Step(conformance.Step{
		ID:   "client-pin1.initial-retries",
		Name: "Read the initial PIN retry counter",
		References: []conformance.RequirementRef{
			retriesRequirement,
			maximumRetriesRequirement,
			getRetriesRequirement,
			encodingRequirement,
		},
		Run: func(ctx context.Context) error {
			var err error
			retries, err = readClientPINRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolOne)

			return err
		},
	})

	return retries, passed
}

func expectClientPIN1TokenStatus(
	ctx context.Context,
	client *client.Client,
	wrongPIN []byte,
	expected ctaptransport.StatusCode,
) error {
	token, err := getLegacyPINToken(ctx, client, protocol.PinUvAuthProtocolOne, string(wrongPIN))
	clear(token)

	return expectCTAPStatus(err, expected)
}
