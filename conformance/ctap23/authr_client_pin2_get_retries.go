package ctap23

import (
	"context"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN2GetRetriesSourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin2/Authr-ClientPin2-GetRetries.js"

	TestIDAuthrClientPIN2GetRetriesP1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-retries.p-1"
	TestIDAuthrClientPIN2GetRetriesP2 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-retries.p-2"
	TestIDAuthrClientPIN2GetRetriesP3 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-retries.p-3"
	TestIDAuthrClientPIN2GetRetriesP4 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-retries.p-4"
	TestIDAuthrClientPIN2GetRetriesP5 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-retries.p-5"
)

type clientPIN2GetRetriesSession struct {
	info protocol.AuthenticatorGetInfoResponse
	pin  []byte
}

func authrClientPIN2GetRetriesTests(config Config) []conformance.Test {
	getInfoRequirement := getInfoReference()
	protocolRequirement := clientPIN2KeyAgreementProtocolTwoReference()
	resetRequirement := resetReference()
	featurefulRequirement := clientPIN2KeyAgreementFeaturefulReference()
	setPINRequirement := clientPINSetReference()
	powerCycleRequirement := clientPINPowerCycleReference()
	retriesRequirement := clientPINRetriesReference()
	maximumPINRetriesRequirement := clientPINMaximumRetriesReference()
	uvRetriesRangeRequirement := clientUVRetriesRangeReference()
	getPINRetriesRequirement := clientPINGetRetriesReference()
	getUVRetriesRequirement := clientUVGetRetriesReference()
	legacyTokenRequirement := clientPINLegacyTokenReference()
	makeCredentialRequirement := clientPINMakeCredentialReference()
	encodingRequirement := ctapMessageEncodingReference()

	commonReferences := []conformance.RequirementRef{
		getInfoRequirement,
		protocolRequirement,
		resetRequirement,
		featurefulRequirement,
		setPINRequirement,
		powerCycleRequirement,
		encodingRequirement,
	}

	return []conformance.Test{
		{
			ID:          TestIDAuthrClientPIN2GetRetriesP1,
			Name:        "PIN retries response",
			Description: "Requests protocol 2 PIN retries and validates the required unsigned counter and maximum",
			Destructive: true,
			Source: conformance.SourceLocation{
				Path: authrClientPIN2GetRetriesSourcePath,
				Case: "P-1",
			},
			References: appendClientPINReferences(commonReferences, retriesRequirement, maximumPINRetriesRequirement, getPINRetriesRequirement),
			Run: clientPIN2GetRetriesCase(config, false, false, func(test *conformance.TestContext, _ clientPIN2GetRetriesSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2.get-pin-retries",
					Name:       "Read and validate PIN retries",
					References: []conformance.RequirementRef{maximumPINRetriesRequirement, getPINRetriesRequirement, encodingRequirement},
					Run: func(ctx context.Context) error {
						_, err := readClientPINRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolTwo)

						return err
					},
				})
			}),
		},
		{
			ID:          TestIDAuthrClientPIN2GetRetriesP2,
			Name:        "Built-in UV retries response",
			Description: "Configures advertised built-in user verification and validates its protocol 2 retries counter",
			Destructive: true,
			Source: conformance.SourceLocation{
				Path: authrClientPIN2GetRetriesSourcePath,
				Case: "P-2",
			},
			References: appendClientPINReferences(commonReferences, retriesRequirement, uvRetriesRangeRequirement, getUVRetriesRequirement),
			Run: clientPIN2GetRetriesCase(config, true, false, func(test *conformance.TestContext, session clientPIN2GetRetriesSession) {
				if !test.Step(conformance.Step{
					ID:         "client-pin2.configure-uv",
					Name:       "Configure built-in user verification when needed",
					References: []conformance.RequirementRef{getInfoRequirement, getUVRetriesRequirement},
					Run: func(ctx context.Context) error {
						configured, present := session.info.Options[protocol.OptionUserVerification]
						if !present {
							return conformance.Fail("built-in user verification capability disappeared after reset")
						}
						if configured {
							// The pinned helper always enters its configuration flow. A current
							// GetInfo value of true already proves that UV is configured, so an
							// additional enrollment prompt would change state without adding evidence.
							return nil
						}
						if config.UVConfigurator == nil {
							return errors.New("ctap23: UV configurator is required for P-2 when built-in UV is not configured")
						}

						return config.UVConfigurator(ctx, session.pin)
					},
				}) {
					return
				}

				if !test.Step(conformance.Step{
					ID:         "client-pin2.refresh-get-info",
					Name:       "Refresh authenticator information after UV configuration",
					References: []conformance.RequirementRef{getInfoRequirement},
					Run: func(ctx context.Context) error {
						_, _, err := readGetInfo(ctx, test.CBOR())

						return err
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "client-pin2.get-uv-retries",
					Name:       "Read and validate built-in UV retries",
					References: []conformance.RequirementRef{uvRetriesRangeRequirement, getUVRetriesRequirement, encodingRequirement},
					Run: func(ctx context.Context) error {
						_, err := readClientUVRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolTwo)

						return err
					},
				})
			}),
		},
		{
			ID:          TestIDAuthrClientPIN2GetRetriesP3,
			Name:        "PIN retry decrement and restoration",
			Description: "Verifies two invalid PIN entries decrement the counter and a valid PIN-authorized MakeCredential restores it",
			Destructive: true,
			Source: conformance.SourceLocation{
				Path: authrClientPIN2GetRetriesSourcePath,
				Case: "P-3",
			},
			References: appendClientPINReferences(commonReferences, retriesRequirement, getPINRetriesRequirement, legacyTokenRequirement, makeCredentialRequirement),
			Run: clientPIN2GetRetriesCase(config, false, false, func(test *conformance.TestContext, session clientPIN2GetRetriesSession) {
				original, ok := clientPIN2ReadOriginalRetries(test, retriesRequirement, getPINRetriesRequirement)
				if !ok {
					return
				}

				invalidPIN := differentTemporaryPIN(session.pin)
				defer clear(invalidPIN)
				for attempt := 1; attempt <= 2; attempt++ {
					if !test.Step(conformance.Step{
						ID:         conformance.StepID(fmt.Sprintf("client-pin2.invalid-pin-%d", attempt)),
						Name:       fmt.Sprintf("Reject invalid PIN attempt %d", attempt),
						References: []conformance.RequirementRef{retriesRequirement, legacyTokenRequirement},
						Run: func(ctx context.Context) error {
							token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(invalidPIN))
							clear(token)

							return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_INVALID)
						},
					}) {
						return
					}
				}

				if !test.Step(conformance.Step{
					ID:         "client-pin2.verify-decrement",
					Name:       "Verify two PIN retries were consumed",
					References: []conformance.RequirementRef{retriesRequirement, getPINRetriesRequirement},
					Run: func(ctx context.Context) error {
						if original < 2 {
							return conformance.Failf("initial pinRetries is %d, cannot decrease by two", original)
						}
						retries, err := readClientPINRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolTwo)
						if err != nil {
							return err
						}
						if retries != original-2 {
							return conformance.Failf("pinRetries is %d after two invalid PINs, want %d", retries, original-2)
						}

						return nil
					},
				}) {
					return
				}

				if !test.Step(conformance.Step{
					ID:         "client-pin2.valid-pin-make-credential",
					Name:       "Use a valid PIN token for MakeCredential",
					References: []conformance.RequirementRef{retriesRequirement, legacyTokenRequirement, makeCredentialRequirement},
					Run: func(ctx context.Context) error {
						token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(session.pin))
						if err != nil {
							return unexpectedCTAPStatus("valid getPinToken", err)
						}
						defer clear(token)

						_, err = makeCredentialWithPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, token, session.info.Algorithms)

						return unexpectedCTAPStatus("PIN-authorized MakeCredential", err)
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "client-pin2.verify-restoration",
					Name:       "Verify the PIN retries counter was restored",
					References: []conformance.RequirementRef{retriesRequirement, getPINRetriesRequirement},
					Run: func(ctx context.Context) error {
						retries, err := readClientPINRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolTwo)
						if err != nil {
							return err
						}
						if retries != original {
							return conformance.Failf("pinRetries is %d after a correct PIN, want restored value %d", retries, original)
						}

						return nil
					},
				})
			}),
		},
		{
			ID:          TestIDAuthrClientPIN2GetRetriesP4,
			Name:        "Temporary PIN authentication block",
			Description: "Verifies the third consecutive invalid PIN is temporarily or permanently blocked according to the remaining counter",
			Destructive: true,
			Source: conformance.SourceLocation{
				Path: authrClientPIN2GetRetriesSourcePath,
				Case: "P-4",
			},
			References: appendClientPINReferences(commonReferences, retriesRequirement, getPINRetriesRequirement, legacyTokenRequirement),
			Run: clientPIN2GetRetriesCase(config, false, false, func(test *conformance.TestContext, session clientPIN2GetRetriesSession) {
				original, ok := clientPIN2ReadOriginalRetries(test, retriesRequirement, getPINRetriesRequirement)
				if !ok {
					return
				}

				invalidPIN := differentTemporaryPIN(session.pin)
				defer clear(invalidPIN)
				for attempt := 1; attempt <= 3; attempt++ {
					expected := ctaptransport.CTAP2_ERR_PIN_INVALID
					if attempt == 3 {
						expected = ctaptransport.CTAP2_ERR_PIN_BLOCKED
						if original > 3 {
							expected = ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED
						}
					}

					if !test.Step(conformance.Step{
						ID:         conformance.StepID(fmt.Sprintf("client-pin2.blocking-invalid-pin-%d", attempt)),
						Name:       fmt.Sprintf("Check invalid PIN attempt %d status", attempt),
						References: []conformance.RequirementRef{retriesRequirement, legacyTokenRequirement},
						Run: func(ctx context.Context) error {
							token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(invalidPIN))
							clear(token)

							return expectCTAPStatus(err, expected)
						},
					}) {
						return
					}
				}
			}),
		},
		{
			ID:          TestIDAuthrClientPIN2GetRetriesP5,
			Name:        "Permanent PIN block",
			Description: "Consumes every remaining PIN retry across required power cycles and verifies that the correct PIN is permanently blocked",
			Destructive: true,
			Source: conformance.SourceLocation{
				Path: authrClientPIN2GetRetriesSourcePath,
				Case: "P-5",
			},
			References: appendClientPINReferences(commonReferences, retriesRequirement, getPINRetriesRequirement, legacyTokenRequirement),
			Run: clientPIN2GetRetriesCase(config, false, true, func(test *conformance.TestContext, session clientPIN2GetRetriesSession) {
				original, ok := clientPIN2ReadOriginalRetries(test, retriesRequirement, getPINRetriesRequirement)
				if !ok {
					return
				}
				if !test.Step(conformance.Step{
					ID:         "client-pin2.permanent-block-applicability",
					Name:       "Require more than three initial PIN retries",
					References: []conformance.RequirementRef{retriesRequirement},
					Run: func(context.Context) error {
						if original <= 3 {
							return conformance.Skip("P-5 requires an initial pinRetries value greater than three")
						}

						return nil
					},
				}) {
					return
				}

				if !test.Step(clientPIN2PowerCycleStep(config, "client-pin2.permanent-block-initial-cycle", powerCycleRequirement)) {
					return
				}

				remaining, ok := clientPIN2ReadCurrentRetries(test, "client-pin2.permanent-block-current-retries", retriesRequirement, getPINRetriesRequirement)
				if !ok {
					return
				}

				invalidPIN := differentTemporaryPIN(session.pin)
				defer clear(invalidPIN)
				for attempt := 1; remaining > 0; attempt++ {
					before := remaining
					var status ctaptransport.StatusCode
					if !test.Step(conformance.Step{
						ID:         conformance.StepID(fmt.Sprintf("client-pin2.exhaust-invalid-pin-%d", attempt)),
						Name:       fmt.Sprintf("Consume PIN retry %d", attempt),
						References: []conformance.RequirementRef{retriesRequirement, legacyTokenRequirement},
						Run: func(ctx context.Context) error {
							token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(invalidPIN))
							clear(token)

							var ok bool
							status, ok = returnedCTAPStatus(err)
							if !ok {
								if err == nil {
									return conformance.Fail("invalid PIN unexpectedly produced a token")
								}

								return err
							}
							switch status {
							case ctaptransport.CTAP2_ERR_PIN_INVALID, ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED:
								return nil
							case ctaptransport.CTAP2_ERR_PIN_BLOCKED:
								if before == 1 {
									return nil
								}
							}

							return conformance.Failf("invalid PIN returned %s with %d retries remaining", status, before)
						},
					}) {
						return
					}

					needsCycle := status == ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED || config.Transport == AuthenticatorTransportNFC
					if status == ctaptransport.CTAP2_ERR_PIN_BLOCKED {
						zero, ok := clientPIN2ReadCurrentRetries(test, conformance.StepID(fmt.Sprintf("client-pin2.exhaust-retries-%d", attempt)), retriesRequirement, getPINRetriesRequirement)
						if !ok {
							return
						}
						if !test.Step(conformance.Step{
							ID:         "client-pin2.exhausted-retries",
							Name:       "Verify the PIN retries counter reached zero",
							References: []conformance.RequirementRef{retriesRequirement},
							Run: func(context.Context) error {
								if zero != 0 {
									return conformance.Failf("pinRetries is %d after PIN_BLOCKED, want 0", zero)
								}

								return nil
							},
						}) {
							return
						}
						remaining = zero
						break
					}
					if needsCycle && !test.Step(clientPIN2PowerCycleStep(config, conformance.StepID(fmt.Sprintf("client-pin2.exhaust-cycle-%d", attempt)), powerCycleRequirement)) {
						return
					}

					// The pinned case tracks a speculative local decrement. Reading the
					// authenticator's counter makes the same transition observable and
					// prevents a non-decrementing implementation from looping forever.
					after, ok := clientPIN2ReadCurrentRetries(test, conformance.StepID(fmt.Sprintf("client-pin2.exhaust-retries-%d", attempt)), retriesRequirement, getPINRetriesRequirement)
					if !ok {
						return
					}
					if !test.Step(conformance.Step{
						ID:         conformance.StepID(fmt.Sprintf("client-pin2.exhaust-decrement-%d", attempt)),
						Name:       fmt.Sprintf("Verify PIN retry %d was consumed", attempt),
						References: []conformance.RequirementRef{retriesRequirement},
						Run: func(context.Context) error {
							if after+1 != before {
								return conformance.Failf("pinRetries changed from %d to %d, want a decrement of one", before, after)
							}

							return nil
						},
					}) {
						return
					}
					remaining = after
				}

				test.Step(conformance.Step{
					ID:         "client-pin2.correct-pin-blocked",
					Name:       "Verify the correct PIN remains blocked",
					References: []conformance.RequirementRef{retriesRequirement, legacyTokenRequirement},
					Run: func(ctx context.Context) error {
						token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(session.pin))
						clear(token)

						return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_BLOCKED)
					},
				})
			}),
		},
	}
}

func clientPIN2GetRetriesCase(
	config Config,
	requireUV bool,
	requireKnownTransport bool,
	body func(*conformance.TestContext, clientPIN2GetRetriesSession),
) func(*conformance.TestContext) {
	getInfoRequirement := getInfoReference()
	protocolRequirement := clientPIN2KeyAgreementProtocolTwoReference()
	resetRequirement := resetReference()
	featurefulRequirement := clientPIN2KeyAgreementFeaturefulReference()
	setPINRequirement := clientPINSetReference()
	powerCycleRequirement := clientPINPowerCycleReference()

	return func(test *conformance.TestContext) {
		// The pinned file has one shared before hook. Repeating that lifecycle
		// makes every exact marker independently runnable and prevents P-4/P-5
		// lockout state from leaking into another reported Go Test.
		var initialFields map[uint64]cbor.RawMessage
		var initialInfo protocol.AuthenticatorGetInfoResponse
		if !test.Step(conformance.Step{
			ID:         "client-pin2.applicability",
			Name:       "Confirm ClientPIN and case applicability",
			References: []conformance.RequirementRef{getInfoRequirement},
			Run: func(ctx context.Context) error {
				fields, info, err := readGetInfo(ctx, test.CBOR())
				if err != nil {
					return err
				}
				initialFields = fields
				initialInfo = info
				if _, present := info.Options[protocol.OptionClientPIN]; !present {
					return conformance.Skip("authenticator does not advertise ClientPIN capability")
				}
				if requireUV {
					if _, present := info.Options[protocol.OptionUserVerification]; !present {
						return conformance.Skip("authenticator does not advertise built-in user verification")
					}
				}

				return nil
			},
		}) {
			return
		}

		if !test.Step(conformance.Step{
			ID:         "client-pin2.protocol-support",
			Name:       "Confirm PIN/UV protocol 2 support",
			References: []conformance.RequirementRef{getInfoRequirement, protocolRequirement, featurefulRequirement},
			Run: func(context.Context) error {
				return validateClientPINProtocolSupport(initialFields, initialInfo, config, protocol.PinUvAuthProtocolTwo)
			},
		}) {
			return
		}

		if requireKnownTransport && !test.Step(conformance.Step{
			ID:         "client-pin2.transport",
			Name:       "Confirm a supported transport for retry exhaustion",
			References: []conformance.RequirementRef{powerCycleRequirement},
			Run: func(context.Context) error {
				switch config.Transport {
				case AuthenticatorTransportHID, AuthenticatorTransportNFC, AuthenticatorTransportBLE:
					return nil
				default:
					return fmt.Errorf("ctap23: P-5 requires a known HID, NFC, or BLE authenticator transport, got %q", config.Transport)
				}
			},
		}) {
			return
		}

		if config.PowerCycler == nil {
			test.Step(conformance.Step{
				ID:   "client-pin2.power-cycle",
				Name: "Power-cycle the authenticator before reset",
				Run: func(context.Context) error {
					return errors.New("ctap23: authenticator power cycler is required for destructive ClientPIN retry tests")
				},
			})

			return
		}
		if config.TemporaryPINProvider == nil {
			test.Step(conformance.Step{
				ID:   "client-pin2.temporary-pin",
				Name: "Obtain a temporary PIN",
				Run: func(context.Context) error {
					return errors.New("ctap23: temporary PIN provider is required for destructive ClientPIN retry tests")
				},
			})

			return
		}

		if !test.Step(clientPIN2PowerCycleStep(config, "client-pin2.power-cycle", powerCycleRequirement)) {
			return
		}

		if !test.Step(conformance.Step{
			ID:         "client-pin2.reset",
			Name:       "Reset the authenticator",
			References: []conformance.RequirementRef{resetRequirement},
			Run: func(ctx context.Context) error {
				return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
			},
		}) {
			return
		}

		var info protocol.AuthenticatorGetInfoResponse
		if !test.Step(conformance.Step{
			ID:         "client-pin2.refresh-after-reset",
			Name:       "Refresh authenticator information after reset",
			References: []conformance.RequirementRef{getInfoRequirement},
			Run: func(ctx context.Context) error {
				_, refreshed, err := readGetInfo(ctx, test.CBOR())
				if err != nil {
					return err
				}
				info = refreshed

				return nil
			},
		}) {
			return
		}

		var pin []byte
		if !test.Step(conformance.Step{
			ID:   "client-pin2.temporary-pin",
			Name: "Obtain a temporary PIN",
			Run: func(ctx context.Context) error {
				var err error
				request := temporaryPINRequest(info)
				pin, err = config.TemporaryPINProvider(ctx, request)
				if err == nil {
					err = validateTemporaryPIN(pin, request)
				}

				return err
			},
		}) {
			clear(pin)

			return
		}
		defer clear(pin)
		test.Cleanup(conformance.Step{
			ID:         "client-pin2.cleanup",
			Name:       "Power-cycle and reset the authenticator after the case",
			References: []conformance.RequirementRef{powerCycleRequirement, resetRequirement},
			Run: func(ctx context.Context) error {
				if err := config.PowerCycler(ctx); err != nil {
					return err
				}

				return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
			},
		})

		if !test.Step(conformance.Step{
			ID:         "client-pin2.set-pin",
			Name:       "Set the temporary PIN using protocol 2",
			References: []conformance.RequirementRef{setPINRequirement, protocolRequirement},
			Run: func(ctx context.Context) error {
				keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
				if err != nil {
					return unexpectedCTAPStatus("getKeyAgreement before setPIN", err)
				}
				err = test.Client().SetPIN(ctx, protocol.PinUvAuthProtocolTwo, keyAgreement, string(pin))

				return unexpectedCTAPStatus("setPIN", err)
			},
		}) {
			return
		}

		body(test, clientPIN2GetRetriesSession{info: info, pin: pin})
	}
}

func clientPIN2ReadOriginalRetries(
	test *conformance.TestContext,
	retriesRequirement conformance.RequirementRef,
	getRetriesRequirement conformance.RequirementRef,
) (uint, bool) {
	return clientPIN2ReadCurrentRetries(test, "client-pin2.original-retries", retriesRequirement, getRetriesRequirement)
}

func clientPIN2ReadCurrentRetries(
	test *conformance.TestContext,
	stepID conformance.StepID,
	retriesRequirement conformance.RequirementRef,
	getRetriesRequirement conformance.RequirementRef,
) (uint, bool) {
	var retries uint
	ok := test.Step(conformance.Step{
		ID:         stepID,
		Name:       "Read the current PIN retries counter",
		References: []conformance.RequirementRef{retriesRequirement, getRetriesRequirement},
		Run: func(ctx context.Context) error {
			var err error
			retries, err = readClientPINRetries(ctx, test.CBOR(), protocol.PinUvAuthProtocolTwo)

			return err
		},
	})

	return retries, ok
}

func clientPIN2PowerCycleStep(config Config, id conformance.StepID, reference conformance.RequirementRef) conformance.Step {
	return conformance.Step{
		ID:         id,
		Name:       "Power-cycle the authenticator and restore the transport session",
		References: []conformance.RequirementRef{reference},
		Run: func(ctx context.Context) error {
			return config.PowerCycler(ctx)
		},
	}
}

func returnedCTAPStatus(err error) (ctaptransport.StatusCode, bool) {
	var ctapError *ctaptransport.CTAPError
	if !errors.As(err, &ctapError) {
		return 0, false
	}

	return ctapError.StatusCode, true
}

func appendClientPINReferences(base []conformance.RequirementRef, extra ...conformance.RequirementRef) []conformance.RequirementRef {
	references := make([]conformance.RequirementRef, 0, len(base)+len(extra))
	references = append(references, base...)
	references = append(references, extra...)

	return references
}

func clientUVRetriesRangeReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.2.3:uv-retries-range",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.2.3",
		Clause:        "uv-retries-range",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#uvRetries",
		Level:         conformance.RequirementMust,
	}
}

func clientUVGetRetriesReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.3:get-uv-retries-response",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.3",
		Clause:        "get-uv-retries-response",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getUVRetries",
		Level:         conformance.RequirementConstraint,
	}
}
