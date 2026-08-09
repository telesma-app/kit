package ctap23

import (
	"context"
	"errors"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN2NewPINSourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin2/Authr-ClientPin2-NewPin.js"

	TestIDAuthrClientPIN2NewPINP1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-new-pin.p-1"
	TestIDAuthrClientPIN2NewPINP2 conformance.TestID = "fido.ctap2.3.authr-client-pin2-new-pin.p-2"
	TestIDAuthrClientPIN2NewPINP3 conformance.TestID = "fido.ctap2.3.authr-client-pin2-new-pin.p-3"
	TestIDAuthrClientPIN2NewPINP4 conformance.TestID = "fido.ctap2.3.authr-client-pin2-new-pin.p-4"
)

type clientPIN2NewPINCase struct {
	id               conformance.TestID
	marker           string
	name             string
	references       []conformance.RequirementRef
	requireSetMin    bool
	requirePerCredRO bool
	run              func(*conformance.TestContext, clientPIN2NewPINSession)
}

type clientPIN2NewPINSession struct {
	pin []byte
}

func authrClientPIN2NewPINTests(config Config) []conformance.Test {
	changePINReference := clientPIN1NewPINChangeReference()
	setMinPINLengthReference := clientPIN1NewPINSetMinPINLengthReference()
	forcePINChangeReference := clientPIN1NewPINForceChangeReference()
	permissionsReference := clientPIN2NewPINPermissionsReference()
	credentialManagementReference := clientPIN2NewPINCredentialManagementReference()
	tokenInvalidationReference := clientPIN2NewPINTokenInvalidationReference()

	cases := []clientPIN2NewPINCase{
		{
			id:     TestIDAuthrClientPIN2NewPINP1,
			marker: "P-1",
			name:   "Set a new protocol 2 PIN",
		},
		{
			id:         TestIDAuthrClientPIN2NewPINP2,
			marker:     "P-2",
			name:       "Change the protocol 2 PIN",
			references: []conformance.RequirementRef{changePINReference},
			run: func(test *conformance.TestContext, session clientPIN2NewPINSession) {
				newPIN := differentTemporaryPIN(session.pin)
				defer clear(newPIN)

				test.Step(clientPIN2NewPINChangeStep(
					test,
					"client-pin2-new-pin.p-2.change",
					"Change the current PIN with protocol 2",
					session.pin,
					newPIN,
					changePINReference,
				))
			},
		},
		{
			id:            TestIDAuthrClientPIN2NewPINP3,
			marker:        "P-3",
			name:          "Changing a protocol 2 PIN clears forcePINChange",
			references:    []conformance.RequirementRef{changePINReference, setMinPINLengthReference, forcePINChangeReference, permissionsReference},
			requireSetMin: true,
			run: func(test *conformance.TestContext, session clientPIN2NewPINSession) {
				if !test.Step(clientPIN2NewPINForceChangeStep(
					test,
					session.pin,
					setMinPINLengthReference,
					forcePINChangeReference,
					permissionsReference,
				)) {
					return
				}
				if !test.Step(clientPIN2NewPINRequireForceChangeStep(
					test,
					forcePINChangeReference,
				)) {
					return
				}

				newPIN := differentTemporaryPIN(session.pin)
				defer clear(newPIN)
				if !test.Step(clientPIN2NewPINChangeStep(
					test,
					"client-pin2-new-pin.p-3.change",
					"Change the PIN while forcePINChange is true",
					session.pin,
					newPIN,
					changePINReference,
				)) {
					return
				}

				test.Step(conformance.Step{
					ID:         "client-pin2-new-pin.p-3.force-cleared",
					Name:       "Confirm that changing the PIN cleared forcePINChange",
					References: []conformance.RequirementRef{forcePINChangeReference, getInfoReference()},
					Run: func(ctx context.Context) error {
						_, info, err := readGetInfo(ctx, test.CBOR())
						if err != nil {
							return err
						}
						if info.ForcePINChange {
							return conformance.Fail("forcePINChange is true after a successful protocol 2 PIN change")
						}

						return nil
					},
				})
			},
		},
		{
			id:               TestIDAuthrClientPIN2NewPINP4,
			marker:           "P-4",
			name:             "Changing a PIN invalidates persistent credential-management tokens",
			references:       []conformance.RequirementRef{changePINReference, permissionsReference, credentialManagementReference, tokenInvalidationReference},
			requirePerCredRO: true,
			run: func(test *conformance.TestContext, session clientPIN2NewPINSession) {
				var oldToken []byte
				defer clear(oldToken)
				if !test.Step(conformance.Step{
					ID:         "client-pin2-new-pin.p-4.token",
					Name:       "Obtain a protocol 2 persistent credential-management token",
					References: []conformance.RequirementRef{permissionsReference, credentialManagementReference},
					Run: func(ctx context.Context) error {
						keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
						}

						oldToken, err = test.Client().GetPinUvAuthTokenUsingPinWithPermissions(
							ctx,
							protocol.PinUvAuthProtocolTwo,
							keyAgreement,
							string(session.pin),
							protocol.PermissionPersistentCredentialManagementReadOnly,
							"",
						)

						return unexpectedCTAPStatus(
							"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
							err,
						)
					},
				}) {
					return
				}

				newPIN := differentTemporaryPIN(session.pin)
				defer clear(newPIN)
				if !test.Step(clientPIN2NewPINChangeStep(
					test,
					"client-pin2-new-pin.p-4.change",
					"Change the PIN and invalidate the old token",
					session.pin,
					newPIN,
					changePINReference,
				)) {
					return
				}

				test.Step(conformance.Step{
					ID:         "client-pin2-new-pin.p-4.old-token",
					Name:       "Reject the old token on a fresh enumerateRPsBegin request",
					References: []conformance.RequirementRef{credentialManagementReference, tokenInvalidationReference},
					Run: func(ctx context.Context) error {
						for _, err := range test.Client().EnumerateRPs(
							ctx,
							false,
							protocol.PinUvAuthProtocolTwo,
							oldToken,
						) {
							if err == nil {
								return conformance.Fail("old pinUvAuthToken authorized enumerateRPsBegin after changePIN")
							}

							return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID)
						}

						return conformance.Fail("enumerateRPsBegin returned neither a response nor an error")
					},
				})
			},
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		tests = append(tests, clientPIN2NewPINTest(config, definition))
	}

	return tests
}

func clientPIN2NewPINTest(config Config, definition clientPIN2NewPINCase) conformance.Test {
	commonReferences := []conformance.RequirementRef{
		getInfoReference(),
		clientPIN2KeyAgreementProtocolTwoReference(),
		clientPIN2KeyAgreementFeaturefulReference(),
		resetReference(),
		clientPINSetReference(),
		clientPINPowerCycleReference(),
		ctapMessageEncodingReference(),
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Exercises one protocol 2 PIN establishment, change, forced-change, or token-invalidation behavior in an independent reset lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN2NewPINSourcePath,
			Case: definition.marker,
		},
		References: appendClientPINReferences(commonReferences, definition.references...),
		Run: func(test *conformance.TestContext) {
			if !test.Step(conformance.Step{
				ID:         "client-pin2-new-pin.applicability",
				Name:       "Confirm ClientPIN and protocol 2 applicability",
				References: []conformance.RequirementRef{getInfoReference(), clientPIN2KeyAgreementProtocolTwoReference()},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}
					if _, present := info.Options[protocol.OptionClientPIN]; !present {
						return conformance.Skip("authenticator does not advertise ClientPIN capability")
					}
					return validateClientPINProtocolSupport(
						fields,
						info,
						config,
						protocol.PinUvAuthProtocolTwo,
					)
				},
			}) {
				return
			}

			if definition.requireSetMin && !test.Step(clientPIN1NewPINSetMinSupportStep(test)) {
				return
			}
			if definition.requirePerCredRO && !test.Step(clientPIN2NewPINPerCredROSupportStep(test)) {
				return
			}

			if config.PowerCycler == nil {
				test.Step(conformance.Step{
					ID:   "client-pin2-new-pin.power-cycle",
					Name: "Require a power-cycle environment",
					Run: func(context.Context) error {
						return errors.New("ctap23: authenticator power cycler is required for destructive ClientPIN new-PIN tests")
					},
				})

				return
			}
			if config.TemporaryPINProvider == nil {
				test.Step(conformance.Step{
					ID:   "client-pin2-new-pin.temporary-pin",
					Name: "Require a temporary PIN provider",
					Run: func(context.Context) error {
						return errors.New("ctap23: temporary PIN provider is required for destructive ClientPIN new-PIN tests")
					},
				})

				return
			}

			if !test.Step(clientPIN2PowerCycleStep(
				config,
				"client-pin2-new-pin.power-cycle",
				clientPINPowerCycleReference(),
			)) {
				return
			}
			test.Cleanup(conformance.Step{
				ID:         "client-pin2-new-pin.cleanup",
				Name:       "Power-cycle and reset the authenticator after the case",
				References: []conformance.RequirementRef{clientPINPowerCycleReference(), resetReference()},
				Run: func(ctx context.Context) error {
					if err := config.PowerCycler(ctx); err != nil {
						return err
					}

					return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
				},
			})
			if !test.Step(conformance.Step{
				ID:         "client-pin2-new-pin.reset",
				Name:       "Reset the authenticator before the case",
				References: []conformance.RequirementRef{resetReference()},
				Run: func(ctx context.Context) error {
					return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
				},
			}) {
				return
			}

			var refreshedInfo protocol.AuthenticatorGetInfoResponse
			if !test.Step(conformance.Step{
				ID:         "client-pin2-new-pin.refresh-after-reset",
				Name:       "Refresh authenticator information after reset",
				References: []conformance.RequirementRef{getInfoReference()},
				Run: func(ctx context.Context) error {
					_, info, err := readGetInfo(ctx, test.CBOR())
					refreshedInfo = info

					return err
				},
			}) {
				return
			}

			request := temporaryPINRequest(refreshedInfo)
			var pin []byte
			if !test.Step(conformance.Step{
				ID:   "client-pin2-new-pin.temporary-pin",
				Name: "Obtain an independent temporary PIN",
				Run: func(ctx context.Context) error {
					var err error
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

			if !test.Step(conformance.Step{
				ID:         "client-pin2-new-pin.set-pin",
				Name:       "Set the temporary PIN with protocol 2",
				References: []conformance.RequirementRef{clientPINSetReference(), clientPIN2KeyAgreementProtocolTwoReference()},
				Run: func(ctx context.Context) error {
					keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
					if err != nil {
						return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
					}
					err = test.Client().SetPIN(ctx, protocol.PinUvAuthProtocolTwo, keyAgreement, string(pin))

					return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
				},
			}) {
				return
			}

			if definition.run != nil {
				definition.run(test, clientPIN2NewPINSession{pin: pin})
			}
		},
	}
}

func clientPIN2NewPINPerCredROSupportStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-new-pin.per-cred-ro",
		Name:       "Confirm persistent credential-management read-only support",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN2NewPINCredentialManagementReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			enabled, present, err := rawGetInfoOption(
				fields,
				protocol.OptionPersistentCredentialManagementReadOnly,
			)
			if err != nil {
				return err
			}
			if !present || !enabled {
				return conformance.Skip("authenticator does not enable perCredMgmtRO")
			}

			return nil
		},
	}
}

func clientPIN2NewPINChangeStep(
	test *conformance.TestContext,
	id conformance.StepID,
	name string,
	currentPIN []byte,
	newPIN []byte,
	reference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         id,
		Name:       name,
		References: []conformance.RequirementRef{reference, clientPIN2KeyAgreementProtocolTwoReference()},
		Run: func(ctx context.Context) error {
			keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
			}
			err = test.Client().ChangePIN(
				ctx,
				protocol.PinUvAuthProtocolTwo,
				keyAgreement,
				string(currentPIN),
				string(newPIN),
			)

			return unexpectedCTAPStatus("authenticatorClientPIN changePIN", err)
		},
	}
}

func clientPIN2NewPINForceChangeStep(
	test *conformance.TestContext,
	pin []byte,
	setMinPINLengthReference conformance.RequirementRef,
	forcePINChangeReference conformance.RequirementRef,
	permissionsReference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-new-pin.p-3.force-change",
		Name:       "Set forcePINChange with a protocol 2 acfg token",
		References: []conformance.RequirementRef{setMinPINLengthReference, forcePINChangeReference, permissionsReference},
		Run: func(ctx context.Context) error {
			keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
			}

			token, err := test.Client().GetPinUvAuthTokenUsingPinWithPermissions(
				ctx,
				protocol.PinUvAuthProtocolTwo,
				keyAgreement,
				string(pin),
				protocol.PermissionAuthenticatorConfiguration,
				"",
			)
			defer clear(token)
			if err != nil {
				return unexpectedCTAPStatus(
					"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
					err,
				)
			}

			err = test.Client().SetMinPINLength(
				ctx,
				protocol.PinUvAuthProtocolTwo,
				token,
				protocol.SetMinPINLengthConfigSubCommandParams{ForceChangePIN: true},
			)

			return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
		},
	}
}

func clientPIN2NewPINRequireForceChangeStep(
	test *conformance.TestContext,
	forcePINChangeReference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-new-pin.p-3.force-confirmed",
		Name:       "Confirm forcePINChange before changing the PIN",
		References: []conformance.RequirementRef{forcePINChangeReference, getInfoReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}

			rawForcePINChange, present := fields[12]
			if !present {
				return conformance.Fail("forcePINChange is missing after successful setMinPINLength")
			}
			var forcePINChange bool
			if err := getInfoDecMode.Unmarshal(rawForcePINChange, &forcePINChange); err != nil {
				return conformance.Failf("forcePINChange is not a boolean: %v", err)
			}
			if !forcePINChange {
				return conformance.Fail("forcePINChange is false after successful setMinPINLength")
			}

			return nil
		},
	}
}

func clientPIN2NewPINPermissionsReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.5.5.7",
		"pin-uv-auth-token-permissions",
		"gettingPinUvAuthToken",
		conformance.RequirementConstraint,
	)
}

func clientPIN2NewPINTokenInvalidationReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.5.5.6",
		"pin-change-invalidates-pin-uv-auth-tokens",
		"changingExistingPin",
		conformance.RequirementMust,
	)
}

func clientPIN2NewPINCredentialManagementReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.8.3",
		"enumerate-rps-begin-authorization",
		"authenticatorCredentialManagement",
		conformance.RequirementConstraint,
	)
}
