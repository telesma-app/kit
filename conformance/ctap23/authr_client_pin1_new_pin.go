package ctap23

import (
	"context"
	"slices"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN1NewPINSourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin1/Authr-ClientPin1-NewPin.js"

	TestIDAuthrClientPIN1NewPINP1 conformance.TestID = "fido.ctap2.3.authr-client-pin1-new-pin.p-1"
	TestIDAuthrClientPIN1NewPINP2 conformance.TestID = "fido.ctap2.3.authr-client-pin1-new-pin.p-2"
	TestIDAuthrClientPIN1NewPINP3 conformance.TestID = "fido.ctap2.3.authr-client-pin1-new-pin.p-3"
	TestIDAuthrClientPIN1NewPINP4 conformance.TestID = "fido.ctap2.3.authr-client-pin1-new-pin.p-4"
	TestIDAuthrClientPIN1NewPINP5 conformance.TestID = "fido.ctap2.3.authr-client-pin1-new-pin.p-5"
	TestIDAuthrClientPIN1NewPINP6 conformance.TestID = "fido.ctap2.3.authr-client-pin1-new-pin.p-6"
	TestIDAuthrClientPIN1NewPINF1 conformance.TestID = "fido.ctap2.3.authr-client-pin1-new-pin.f-1"
)

var clientPIN1NewPINGetAssertionClientDataHash = [...]byte{
	0x9d, 0xd7, 0xe7, 0xe3, 0x6c, 0x10, 0x4d, 0x2d,
	0x21, 0x11, 0xe5, 0xa4, 0x6e, 0x3a, 0x89, 0xb1,
	0x83, 0xec, 0x8c, 0x6f, 0x6f, 0xf3, 0x8f, 0x91,
	0x69, 0xd7, 0x0d, 0x3a, 0x61, 0xd0, 0x6f, 0x77,
}

type clientPIN1NewPINCase struct {
	id                 conformance.TestID
	marker             string
	name               string
	references         []conformance.RequirementRef
	requiresLegacyMCGA bool
	requiresSetMin     bool
	run                func(*conformance.TestContext, clientPIN1RetrySession)
}

func authrClientPIN1NewPINTests(config Config) []conformance.Test {
	changePINReference := clientPIN1NewPINChangeReference()
	legacyTokenReference := clientPINLegacyTokenReference()
	makeCredentialReference := clientPINMakeCredentialReference()
	getAssertionReference := clientPIN1NewPINGetAssertionReference()
	forcePINChangeReference := clientPIN1NewPINForceChangeReference()
	setMinPINLengthReference := clientPIN1NewPINSetMinPINLengthReference()

	cases := []clientPIN1NewPINCase{
		{
			id:     TestIDAuthrClientPIN1NewPINP1,
			marker: "P-1",
			name:   "Set a new protocol 1 PIN",
		},
		{
			id:         TestIDAuthrClientPIN1NewPINP2,
			marker:     "P-2",
			name:       "Change the protocol 1 PIN",
			references: []conformance.RequirementRef{changePINReference},
			run: func(test *conformance.TestContext, session clientPIN1RetrySession) {
				newPIN := differentTemporaryPIN(session.pin)
				defer clear(newPIN)

				test.Step(conformance.Step{
					ID:         "client-pin1-new-pin.p-2.change",
					Name:       "Change the current PIN with protocol 1",
					References: []conformance.RequirementRef{changePINReference},
					Run: func(ctx context.Context) error {
						return clientPIN1NewPINChange(ctx, test.Client(), session.pin, newPIN)
					},
				})
			},
		},
		{
			id:         TestIDAuthrClientPIN1NewPINP3,
			marker:     "P-3",
			name:       "Obtain a valid protocol 1 PIN token",
			references: []conformance.RequirementRef{legacyTokenReference},
			run: func(test *conformance.TestContext, session clientPIN1RetrySession) {
				test.Step(conformance.Step{
					ID:         "client-pin1-new-pin.p-3.token",
					Name:       "Obtain and decrypt a legacy protocol 1 PIN token",
					References: []conformance.RequirementRef{legacyTokenReference},
					Run: func(ctx context.Context) error {
						return clientPIN1NewPINWithLegacyToken(
							ctx,
							test.Client(),
							session.pin,
							func(token []byte) error {
								if len(token) != 16 && len(token) != 32 {
									return conformance.Failf(
										"decrypted protocol 1 pinUvAuthToken is %d bytes, want 16 or 32",
										len(token),
									)
								}

								return nil
							},
						)
					},
				})
			},
		},
		{
			id:                 TestIDAuthrClientPIN1NewPINP4,
			marker:             "P-4",
			name:               "MakeCredential with a protocol 1 PIN token",
			references:         []conformance.RequirementRef{legacyTokenReference, makeCredentialReference},
			requiresLegacyMCGA: true,
			run: func(test *conformance.TestContext, session clientPIN1RetrySession) {
				test.Step(conformance.Step{
					ID:   "client-pin1-new-pin.p-4.make-credential",
					Name: "Create a credential with a legacy protocol 1 PIN token",
					References: []conformance.RequirementRef{
						legacyTokenReference,
						makeCredentialReference,
					},
					Run: func(ctx context.Context) error {
						return clientPIN1NewPINWithLegacyToken(
							ctx,
							test.Client(),
							session.pin,
							func(token []byte) error {
								response, err := makeCredentialWithPINToken(
									ctx,
									test.Client(),
									protocol.PinUvAuthProtocolOne,
									token,
									session.algorithms,
								)
								if err != nil {
									return err
								}
								if response.AuthData == nil || !response.AuthData.Flags.UserVerified() {
									return conformance.Fail(
										"authenticatorMakeCredential authData UV flag is false",
									)
								}

								return nil
							},
						)
					},
				})
			},
		},
		{
			id:                 TestIDAuthrClientPIN1NewPINP5,
			marker:             "P-5",
			name:               "GetAssertion with a fresh protocol 1 PIN token",
			requiresLegacyMCGA: true,
			references: []conformance.RequirementRef{
				legacyTokenReference,
				makeCredentialReference,
				getAssertionReference,
			},
			run: func(test *conformance.TestContext, session clientPIN1RetrySession) {
				var credentialID []byte
				if !test.Step(conformance.Step{
					ID:   "client-pin1-new-pin.p-5.make-credential",
					Name: "Create a credential with the first protocol 1 PIN token",
					References: []conformance.RequirementRef{
						legacyTokenReference,
						makeCredentialReference,
					},
					Run: func(ctx context.Context) error {
						return clientPIN1NewPINWithLegacyToken(
							ctx,
							test.Client(),
							session.pin,
							func(token []byte) error {
								response, err := makeCredentialWithPINToken(
									ctx,
									test.Client(),
									protocol.PinUvAuthProtocolOne,
									token,
									session.algorithms,
								)
								if err != nil {
									return err
								}
								if response.AuthData == nil || !response.AuthData.Flags.UserVerified() ||
									response.AuthData.AttestedCredentialData == nil ||
									len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
									return conformance.Fail(
										"authenticatorMakeCredential response has no UV-verified credential ID",
									)
								}
								credentialID = response.AuthData.AttestedCredentialData.CredentialID

								return nil
							},
						)
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:   "client-pin1-new-pin.p-5.get-assertion",
					Name: "Get the credential with a fresh protocol 1 PIN token",
					References: []conformance.RequirementRef{
						legacyTokenReference,
						getAssertionReference,
					},
					Run: func(ctx context.Context) error {
						return clientPIN1NewPINWithLegacyToken(
							ctx,
							test.Client(),
							session.pin,
							func(token []byte) error {
								return clientPIN1NewPINGetAssertion(
									ctx,
									test.Client(),
									token,
									credentialID,
								)
							},
						)
					},
				})
			},
		},
		{
			id:             TestIDAuthrClientPIN1NewPINP6,
			marker:         "P-6",
			name:           "Changing a PIN clears forcePINChange",
			references:     []conformance.RequirementRef{changePINReference, setMinPINLengthReference, forcePINChangeReference},
			requiresSetMin: true,
			run: func(test *conformance.TestContext, session clientPIN1RetrySession) {
				if !test.Step(clientPIN1NewPINForceChangeStep(test, session, setMinPINLengthReference)) {
					return
				}

				newPIN := differentTemporaryPIN(session.pin)
				defer clear(newPIN)
				if !test.Step(conformance.Step{
					ID:         "client-pin1-new-pin.p-6.change",
					Name:       "Change the PIN while forcePINChange is true",
					References: []conformance.RequirementRef{changePINReference, forcePINChangeReference},
					Run: func(ctx context.Context) error {
						return clientPIN1NewPINChange(ctx, test.Client(), session.pin, newPIN)
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "client-pin1-new-pin.p-6.force-cleared",
					Name:       "Confirm that changing the PIN cleared forcePINChange",
					References: []conformance.RequirementRef{forcePINChangeReference, getInfoReference()},
					Run: func(ctx context.Context) error {
						_, info, err := readGetInfo(ctx, test.CBOR())
						if err != nil {
							return err
						}
						if info.ForcePINChange {
							return conformance.Fail("forcePINChange is true after a successful PIN change")
						}

						return nil
					},
				})
			},
		},
		{
			id:             TestIDAuthrClientPIN1NewPINF1,
			marker:         "F-1",
			name:           "Legacy PIN token is rejected while forcePINChange is true",
			references:     []conformance.RequirementRef{legacyTokenReference, setMinPINLengthReference, forcePINChangeReference},
			requiresSetMin: true,
			run: func(test *conformance.TestContext, session clientPIN1RetrySession) {
				if !test.Step(clientPIN1NewPINForceChangeStep(test, session, setMinPINLengthReference)) {
					return
				}

				test.Step(conformance.Step{
					ID:         "client-pin1-new-pin.f-1.get-pin-token",
					Name:       "Require PIN_INVALID from getPinToken while PIN change is forced",
					References: []conformance.RequirementRef{legacyTokenReference, forcePINChangeReference},
					Run: func(ctx context.Context) error {
						token, err := getLegacyPINToken(
							ctx,
							test.Client(),
							protocol.PinUvAuthProtocolOne,
							string(session.pin),
						)
						clear(token)

						return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_INVALID)
					},
				})
			},
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		tests = append(tests, clientPIN1NewPINTest(config, definition))
	}

	return tests
}

func clientPIN1NewPINTest(config Config, definition clientPIN1NewPINCase) conformance.Test {
	commonReferences := []conformance.RequirementRef{
		getInfoReference(),
		clientPIN1KeyAgreementProfileReference(),
		clientPIN1KeyAgreementProtocolOneReference(),
		resetReference(),
		clientPINSetReference(),
		clientPINPowerCycleReference(),
		ctapMessageEncodingReference(),
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Exercises one protocol 1 PIN establishment, token, credential, or forced-change behavior in an independent reset lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN1NewPINSourcePath,
			Case: definition.marker,
		},
		References: append(commonReferences, definition.references...),
		Run: func(test *conformance.TestContext) {
			if !test.Step(clientPIN1GetRetriesSupportStep(test, config)) {
				return
			}
			if definition.requiresLegacyMCGA && !test.Step(clientPIN1NewPINLegacyMCGASupportStep(test)) {
				return
			}
			if definition.requiresSetMin && !test.Step(clientPIN1NewPINSetMinSupportStep(test)) {
				return
			}

			var session clientPIN1RetrySession
			defer func() {
				clear(session.pin)
			}()
			if !test.Step(conformance.Step{
				ID:   "client-pin1-new-pin.prepare",
				Name: "Reset the authenticator and set an independent protocol 1 PIN",
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

			if definition.run != nil {
				definition.run(test, session)
			}
		},
	}
}

func clientPIN1NewPINLegacyMCGASupportStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin1-new-pin.legacy-mc-ga-support",
		Name:       "Confirm legacy PIN tokens may authorize MakeCredential and GetAssertion",
		References: []conformance.RequirementRef{getInfoReference(), clientPINLegacyTokenReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			restricted, present, err := rawGetInfoOption(
				fields,
				protocol.OptionNoMcGaPermissionsWithClientPin,
			)
			if err != nil {
				return err
			}
			if present && restricted {
				return conformance.Skip(
					"authenticator disables MakeCredential and GetAssertion authorization with legacy PIN tokens",
				)
			}

			return nil
		},
	}
}

func clientPIN1NewPINSetMinSupportStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin1-new-pin.configuration-profile",
		Name:       "Confirm the force-PIN-change configuration profile",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN1NewPINSetMinPINLengthReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			setMinPINLength, present, err := rawGetInfoOption(
				fields,
				protocol.OptionSetMinPINLength,
			)
			if err != nil {
				return err
			}
			if !present || !setMinPINLength {
				return conformance.Skip("authenticator does not enable the setMinPINLength option")
			}
			for _, required := range []protocol.Option{
				protocol.OptionAuthenticatorConfig,
				protocol.OptionPinUvAuthToken,
			} {
				enabled, present, err := rawGetInfoOption(fields, required)
				if err != nil {
					return err
				}
				if !present || !enabled {
					return conformance.Failf(
						"GetInfo %s must be present and true when setMinPINLength is enabled",
						required,
					)
				}
			}

			rawCommands, present := fields[31]
			if !present {
				return conformance.Fail(
					"GetInfo authenticatorConfigCommands is missing while setMinPINLength is enabled",
				)
			}
			if !hasCBORMajorType(rawCommands, 4) {
				return conformance.Fail(
					"GetInfo authenticatorConfigCommands is not a CBOR array",
				)
			}
			var commands []protocol.ConfigSubCommand
			if err := getInfoDecMode.Unmarshal(rawCommands, &commands); err != nil {
				return conformance.Failf("invalid GetInfo authenticatorConfigCommands: %v", err)
			}
			if !slices.Contains(commands, protocol.ConfigSubCommandSetMinPINLength) {
				return conformance.Fail(
					"GetInfo authenticatorConfigCommands does not contain setMinPINLength",
				)
			}

			return nil
		},
	}
}

func clientPIN1NewPINChange(
	ctx context.Context,
	client *client.Client,
	currentPIN []byte,
	newPIN []byte,
) error {
	keyAgreement, err := client.GetKeyAgreement(ctx, protocol.PinUvAuthProtocolOne)
	if err != nil {
		return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}

	err = client.ChangePIN(
		ctx,
		protocol.PinUvAuthProtocolOne,
		keyAgreement,
		string(currentPIN),
		string(newPIN),
	)

	return unexpectedCTAPStatus("authenticatorClientPIN changePIN", err)
}

func clientPIN1NewPINWithLegacyToken(
	ctx context.Context,
	client *client.Client,
	pin []byte,
	run func([]byte) error,
) error {
	token, err := getLegacyPINToken(ctx, client, protocol.PinUvAuthProtocolOne, string(pin))
	defer clear(token)
	if err != nil {
		return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
	}

	return run(token)
}

func clientPIN1NewPINGetAssertion(
	ctx context.Context,
	client *client.Client,
	token []byte,
	credentialID []byte,
) error {
	for response, err := range client.GetAssertion(
		ctx,
		protocol.PinUvAuthProtocolOne,
		token,
		clientPINRetryRPID,
		clientPIN1NewPINGetAssertionClientDataHash[:],
		[]credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   credentialID,
		}},
		nil,
		nil,
	) {
		if err != nil {
			return unexpectedCTAPStatus("authenticatorGetAssertion", err)
		}
		if response.AuthData == nil || !response.AuthData.Flags.UserVerified() {
			return conformance.Fail("authenticatorGetAssertion authData UV flag is false")
		}

		return nil
	}

	return conformance.Fail("authenticatorGetAssertion returned no assertion")
}

func clientPIN1NewPINForceChangeStep(
	test *conformance.TestContext,
	session clientPIN1RetrySession,
	reference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin1-new-pin.force-change",
		Name:       "Set forcePINChange with a protocol 1 acfg token",
		References: []conformance.RequirementRef{reference, clientPIN1NewPINForceChangeReference()},
		Run: func(ctx context.Context) error {
			keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolOne)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
			}

			token, err := test.Client().GetPinUvAuthTokenUsingPinWithPermissions(
				ctx,
				protocol.PinUvAuthProtocolOne,
				keyAgreement,
				string(session.pin),
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
				protocol.PinUvAuthProtocolOne,
				token,
				protocol.SetMinPINLengthConfigSubCommandParams{ForceChangePIN: true},
			)

			return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
		},
	}
}

func clientPIN1NewPINChangeReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.5.5.6",
		"change-pin",
		"changingExistingPin",
		conformance.RequirementConstraint,
	)
}

func clientPIN1NewPINGetAssertionReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.2",
		"pin-uv-authenticated-get-assertion",
		"authenticatorGetAssertion",
		conformance.RequirementConstraint,
	)
}

func clientPIN1NewPINSetMinPINLengthReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.11.4",
		"set-min-pin-length-force-change",
		"settingMinPinLength",
		conformance.RequirementConstraint,
	)
}

func clientPIN1NewPINForceChangeReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.4",
		"force-pin-change",
		"authenticatorGetInfo",
		conformance.RequirementConstraint,
	)
}

func clientPIN1NewPINReference(
	section string,
	clause string,
	anchor string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:" + section + ":" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       section,
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#" + anchor,
		Level: level,
	}
}
