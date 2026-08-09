package ctap23

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN2GetPINTokenSourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin2/Authr-ClientPin2-GetPinToken.js"

	TestIDAuthrClientPIN2GetPINTokenP1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-token.p-1"
	TestIDAuthrClientPIN2GetPINTokenP2 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-token.p-2"
	TestIDAuthrClientPIN2GetPINTokenP3 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-token.p-3"
	TestIDAuthrClientPIN2GetPINTokenF1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-token.f-1"
	TestIDAuthrClientPIN2GetPINTokenF2 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-token.f-2"
	TestIDAuthrClientPIN2GetPINTokenF3 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-token.f-3"
	TestIDAuthrClientPIN2GetPINTokenF4 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-token.f-4"
	TestIDAuthrClientPIN2GetPINTokenF5 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-token.f-5"
)

var clientPIN2GetPINTokenAssertionHash = [...]byte{
	0x73, 0x1f, 0xa8, 0xa6, 0x33, 0xd4, 0xb0, 0xe2,
	0x22, 0x96, 0x87, 0x5a, 0xee, 0x4d, 0x67, 0x5b,
	0xbd, 0xa1, 0x24, 0x71, 0x15, 0x82, 0x45, 0xcf,
	0xef, 0x16, 0xe5, 0xc5, 0xe2, 0x89, 0x3a, 0xb4,
}

type clientPIN2GetPINTokenCase struct {
	id         conformance.TestID
	marker     string
	name       string
	references []conformance.RequirementRef
	preflight  func(*conformance.TestContext) conformance.Step
	run        func(*conformance.TestContext, clientPIN2GetPINTokenSession)
}

type clientPIN2GetPINTokenSession struct {
	info protocol.AuthenticatorGetInfoResponse
	pin  []byte
}

func authrClientPIN2GetPINTokenTests(config Config) []conformance.Test {
	legacyTokenReference := clientPINLegacyTokenReference()
	makeCredentialReference := clientPINMakeCredentialReference()
	getAssertionReference := clientPIN1NewPINGetAssertionReference()
	credentialManagementReference := clientPIN2GetPINTokenReference(
		"6.8.2",
		"get-creds-metadata-authorization",
		"getCredsMetadata",
	)
	bioEnrollmentReference := clientPIN2GetPINTokenReference(
		"6.7.4",
		"enroll-begin-authorization",
		"enrollingFingerprint",
	)
	largeBlobsReference := clientPIN2GetPINTokenReference(
		"6.10.2",
		"large-blob-write-authorization",
		"largeBlobsRW",
	)
	authenticatorConfigReference := clientPIN2GetPINTokenReference(
		"6.11",
		"authenticator-config-authorization",
		"authenticatorConfig",
	)
	setMinPINLengthReference := clientPIN2GetPINTokenSetMinPINLengthReference()
	minPINLengthExtensionReference := clientPIN2GetPINTokenMinPINLengthExtensionReference()
	permissionsReference := clientPIN2NewPINPermissionsReference()
	configurationPreflight := func(test *conformance.TestContext) conformance.Step {
		return clientPIN2GetPINTokenConfigurationSupportStep(
			test,
			setMinPINLengthReference,
			minPINLengthExtensionReference,
		)
	}

	cases := []clientPIN2GetPINTokenCase{
		{
			id:         TestIDAuthrClientPIN2GetPINTokenP1,
			marker:     "P-1",
			name:       "Obtain a legacy token with PIN/UV protocol 2",
			references: []conformance.RequirementRef{legacyTokenReference},
			run: func(test *conformance.TestContext, session clientPIN2GetPINTokenSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-get-pin-token.p-1.token",
					Name:       "Obtain and decrypt a legacy protocol 2 PIN token",
					References: []conformance.RequirementRef{legacyTokenReference},
					Run: func(ctx context.Context) error {
						token, err := getLegacyPINToken(
							ctx,
							test.Client(),
							protocol.PinUvAuthProtocolTwo,
							string(session.pin),
						)
						defer clear(token)

						return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
					},
				})
			},
		},
		{
			id:         TestIDAuthrClientPIN2GetPINTokenP2,
			marker:     "P-2",
			name:       "Authorize MakeCredential with a legacy protocol 2 token",
			references: []conformance.RequirementRef{legacyTokenReference, makeCredentialReference},
			preflight:  clientPIN1NewPINLegacyMCGASupportStep,
			run: func(test *conformance.TestContext, session clientPIN2GetPINTokenSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-get-pin-token.p-2.make-credential",
					Name:       "Make a credential with a fresh legacy protocol 2 token",
					References: []conformance.RequirementRef{legacyTokenReference, makeCredentialReference},
					Run: func(ctx context.Context) error {
						token, err := getLegacyPINToken(
							ctx,
							test.Client(),
							protocol.PinUvAuthProtocolTwo,
							string(session.pin),
						)
						defer clear(token)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
						}

						response, err := makeCredentialWithPINToken(
							ctx,
							test.Client(),
							protocol.PinUvAuthProtocolTwo,
							token,
							session.info.Algorithms,
						)
						if err != nil {
							return err
						}
						if response.AuthData == nil ||
							response.AuthData.Flags&protocol.AuthDataFlagUserVerified == 0 {
							return conformance.Fail("MakeCredential response does not set the UV flag")
						}

						return nil
					},
				})
			},
		},
		{
			id:         TestIDAuthrClientPIN2GetPINTokenP3,
			marker:     "P-3",
			name:       "Authorize GetAssertion with a fresh legacy protocol 2 token",
			references: []conformance.RequirementRef{legacyTokenReference, makeCredentialReference, getAssertionReference},
			preflight:  clientPIN1NewPINLegacyMCGASupportStep,
			run: func(test *conformance.TestContext, session clientPIN2GetPINTokenSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-get-pin-token.p-3.make-and-get",
					Name:       "Create and assert one credential with independent legacy tokens",
					References: []conformance.RequirementRef{legacyTokenReference, makeCredentialReference, getAssertionReference},
					Run: func(ctx context.Context) error {
						makeToken, err := getLegacyPINToken(
							ctx,
							test.Client(),
							protocol.PinUvAuthProtocolTwo,
							string(session.pin),
						)
						defer clear(makeToken)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
						}

						created, err := makeCredentialWithPINToken(
							ctx,
							test.Client(),
							protocol.PinUvAuthProtocolTwo,
							makeToken,
							session.info.Algorithms,
						)
						clear(makeToken)
						if err != nil {
							return err
						}
						if created.AuthData == nil || created.AuthData.AttestedCredentialData == nil ||
							len(created.AuthData.AttestedCredentialData.CredentialID) == 0 {
							return conformance.Fail("MakeCredential response does not contain an attested credential ID")
						}

						assertionToken, err := getLegacyPINToken(
							ctx,
							test.Client(),
							protocol.PinUvAuthProtocolTwo,
							string(session.pin),
						)
						defer clear(assertionToken)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
						}

						allowList := []credential.PublicKeyCredentialDescriptor{{
							Type: credential.PublicKeyCredentialTypePublicKey,
							ID:   created.AuthData.AttestedCredentialData.CredentialID,
						}}
						for response, err := range test.Client().GetAssertion(
							ctx,
							protocol.PinUvAuthProtocolTwo,
							assertionToken,
							clientPINRetryRPID,
							clientPIN2GetPINTokenAssertionHash[:],
							allowList,
							nil,
							nil,
						) {
							if err != nil {
								return unexpectedCTAPStatus("authenticatorGetAssertion", err)
							}
							if response.AuthData == nil ||
								response.AuthData.Flags&protocol.AuthDataFlagUserVerified == 0 {
								return conformance.Fail("GetAssertion response does not set the UV flag")
							}

							return nil
						}

						return conformance.Fail("GetAssertion returned neither a response nor an error")
					},
				})
			},
		},
		{
			id:         TestIDAuthrClientPIN2GetPINTokenF1,
			marker:     "F-1",
			name:       "Reject a legacy token for credential management",
			references: []conformance.RequirementRef{legacyTokenReference, credentialManagementReference},
			preflight:  clientPIN2GetPINTokenCredentialManagementSupportStep,
			run: func(test *conformance.TestContext, session clientPIN2GetPINTokenSession) {
				test.Step(clientPIN2GetPINTokenForbiddenCredentialManagementStep(
					test,
					session.pin,
					credentialManagementReference,
				))
			},
		},
		{
			id:         TestIDAuthrClientPIN2GetPINTokenF2,
			marker:     "F-2",
			name:       "Reject a legacy token for biometric enrollment",
			references: []conformance.RequirementRef{legacyTokenReference, bioEnrollmentReference},
			preflight:  clientPIN2GetPINTokenBioEnrollmentSupportStep,
			run: func(test *conformance.TestContext, session clientPIN2GetPINTokenSession) {
				test.Step(clientPIN2GetPINTokenForbiddenBioEnrollmentStep(
					test,
					session.pin,
					bioEnrollmentReference,
				))
			},
		},
		{
			id:         TestIDAuthrClientPIN2GetPINTokenF3,
			marker:     "F-3",
			name:       "Reject a legacy token for a large-blob write",
			references: []conformance.RequirementRef{legacyTokenReference, largeBlobsReference},
			preflight:  clientPIN2GetPINTokenLargeBlobsSupportStep,
			run: func(test *conformance.TestContext, session clientPIN2GetPINTokenSession) {
				test.Step(clientPIN2GetPINTokenForbiddenLargeBlobStep(
					test,
					session.pin,
					largeBlobsReference,
				))
			},
		},
		{
			id:     TestIDAuthrClientPIN2GetPINTokenF4,
			marker: "F-4",
			name:   "Reject a legacy token for authenticator configuration",
			references: []conformance.RequirementRef{
				legacyTokenReference,
				authenticatorConfigReference,
				setMinPINLengthReference,
				minPINLengthExtensionReference,
			},
			preflight: configurationPreflight,
			run: func(test *conformance.TestContext, session clientPIN2GetPINTokenSession) {
				test.Step(clientPIN2GetPINTokenForbiddenConfigStep(
					test,
					session.pin,
					authenticatorConfigReference,
					setMinPINLengthReference,
				))
			},
		},
		{
			id:     TestIDAuthrClientPIN2GetPINTokenF5,
			marker: "F-5",
			name:   "Reject getPinToken while forcePINChange is set",
			references: []conformance.RequirementRef{
				legacyTokenReference,
				setMinPINLengthReference,
				minPINLengthExtensionReference,
				permissionsReference,
			},
			preflight: configurationPreflight,
			run: func(test *conformance.TestContext, session clientPIN2GetPINTokenSession) {
				test.Step(clientPIN2GetPINTokenForceChangeStep(
					test,
					session.pin,
					setMinPINLengthReference,
					permissionsReference,
				))
			},
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		tests = append(tests, clientPIN2GetPINTokenTest(config, definition))
	}

	return tests
}

func clientPIN2GetPINTokenConfigurationSupportStep(
	test *conformance.TestContext,
	setMinPINLengthReference conformance.RequirementRef,
	minPINLengthExtensionReference conformance.RequirementRef,
) conformance.Step {
	configurationProfile := clientPIN1NewPINSetMinSupportStep(test)

	return conformance.Step{
		ID:   "client-pin2-get-pin-token.configuration-profile",
		Name: "Confirm the force-PIN-change configuration profile",
		References: []conformance.RequirementRef{
			getInfoReference(),
			setMinPINLengthReference,
			minPINLengthExtensionReference,
		},
		Run: func(ctx context.Context) error {
			if err := configurationProfile.Run(ctx); err != nil {
				return err
			}

			_, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			if !slices.Contains(info.Extensions, extension.ExtensionIdentifierMinPinLength) {
				return conformance.Fail(
					"GetInfo extensions does not contain minPinLength while setMinPINLength is enabled",
				)
			}

			return nil
		},
	}
}

func clientPIN2GetPINTokenTest(config Config, definition clientPIN2GetPINTokenCase) conformance.Test {
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
		Description: "Exercises one legacy protocol 2 PIN-token behavior in an independent reset lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN2GetPINTokenSourcePath,
			Case: definition.marker,
		},
		References: appendClientPINReferences(commonReferences, definition.references...),
		Run: func(test *conformance.TestContext) {
			if !test.Step(conformance.Step{
				ID:         "client-pin2-get-pin-token.applicability",
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
			if definition.preflight != nil && !test.Step(definition.preflight(test)) {
				return
			}

			if config.PowerCycler == nil {
				test.Step(conformance.Step{
					ID:   "client-pin2-get-pin-token.power-cycle",
					Name: "Require a power-cycle environment",
					Run: func(context.Context) error {
						return errors.New("ctap23: authenticator power cycler is required for destructive getPinToken tests")
					},
				})

				return
			}
			if config.TemporaryPINProvider == nil {
				test.Step(conformance.Step{
					ID:   "client-pin2-get-pin-token.temporary-pin",
					Name: "Require a temporary PIN provider",
					Run: func(context.Context) error {
						return errors.New("ctap23: temporary PIN provider is required for destructive getPinToken tests")
					},
				})

				return
			}

			if !test.Step(clientPIN2PowerCycleStep(
				config,
				"client-pin2-get-pin-token.power-cycle",
				clientPINPowerCycleReference(),
			)) {
				return
			}
			test.Cleanup(conformance.Step{
				ID:         "client-pin2-get-pin-token.cleanup",
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
				ID:         "client-pin2-get-pin-token.reset",
				Name:       "Reset the authenticator before the case",
				References: []conformance.RequirementRef{resetReference()},
				Run: func(ctx context.Context) error {
					return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
				},
			}) {
				return
			}

			var session clientPIN2GetPINTokenSession
			if !test.Step(conformance.Step{
				ID:         "client-pin2-get-pin-token.refresh-after-reset",
				Name:       "Refresh authenticator information after reset",
				References: []conformance.RequirementRef{getInfoReference()},
				Run: func(ctx context.Context) error {
					_, info, err := readGetInfo(ctx, test.CBOR())
					session.info = info

					return err
				},
			}) {
				return
			}

			request := temporaryPINRequest(session.info)
			if !test.Step(conformance.Step{
				ID:   "client-pin2-get-pin-token.temporary-pin",
				Name: "Obtain an independent temporary PIN",
				Run: func(ctx context.Context) error {
					var err error
					session.pin, err = config.TemporaryPINProvider(ctx, request)
					if err == nil {
						err = validateTemporaryPIN(session.pin, request)
					}

					return err
				},
			}) {
				clear(session.pin)

				return
			}
			defer clear(session.pin)

			if !test.Step(conformance.Step{
				ID:         "client-pin2-get-pin-token.set-pin",
				Name:       "Set the independent PIN with protocol 2",
				References: []conformance.RequirementRef{clientPINSetReference(), clientPIN2KeyAgreementProtocolTwoReference()},
				Run: func(ctx context.Context) error {
					keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
					if err != nil {
						return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
					}
					err = test.Client().SetPIN(
						ctx,
						protocol.PinUvAuthProtocolTwo,
						keyAgreement,
						string(session.pin),
					)

					return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
				},
			}) {
				return
			}

			definition.run(test, session)
		},
	}
}

func clientPIN2GetPINTokenCredentialManagementSupportStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-get-pin-token.credential-management-support",
		Name:       "Confirm credential management and resident keys are enabled",
		References: []conformance.RequirementRef{getInfoReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			for _, option := range []protocol.Option{
				protocol.OptionCredentialManagement,
				protocol.OptionResidentKeys,
			} {
				enabled, present, err := rawGetInfoOption(fields, option)
				if err != nil {
					return err
				}
				if !present || !enabled {
					return conformance.Skip("authenticator does not enable credential management with resident keys")
				}
			}

			return nil
		},
	}
}

func clientPIN2GetPINTokenBioEnrollmentSupportStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-get-pin-token.bio-enrollment-support",
		Name:       "Confirm the bioEnroll option is present",
		References: []conformance.RequirementRef{getInfoReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			_, present, err := rawGetInfoOption(fields, protocol.OptionBioEnroll)
			if err != nil {
				return err
			}
			if !present {
				return conformance.Skip("authenticator does not advertise bioEnroll")
			}

			return nil
		},
	}
}

func clientPIN2GetPINTokenLargeBlobsSupportStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-get-pin-token.large-blobs-support",
		Name:       "Confirm large-blob writes are enabled",
		References: []conformance.RequirementRef{getInfoReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			enabled, present, err := rawGetInfoOption(fields, protocol.OptionLargeBlobs)
			if err != nil {
				return err
			}
			if !present || !enabled {
				return conformance.Skip("authenticator does not enable largeBlobs")
			}

			return nil
		},
	}
}

func clientPIN2GetPINTokenForbiddenCredentialManagementStep(
	test *conformance.TestContext,
	pin []byte,
	reference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-get-pin-token.f-1.credential-management",
		Name:       "Reject getCredsMetadata authorization by a legacy token",
		References: []conformance.RequirementRef{clientPINLegacyTokenReference(), reference},
		Run: func(ctx context.Context) error {
			token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(pin))
			defer clear(token)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
			}

			authParam := ctapcrypto.Authenticate(
				protocol.PinUvAuthProtocolTwo,
				token,
				[]byte{byte(protocol.CredentialManagementSubCommandGetCredsMetadata)},
			)
			defer clear(authParam)
			_, err = exchangeCTAP2(
				ctx,
				test.CBOR(),
				protocol.AuthenticatorCredentialManagement,
				protocol.AuthenticatorCredentialManagementRequest{
					SubCommand:        protocol.CredentialManagementSubCommandGetCredsMetadata,
					PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
					PinUvAuthParam:    authParam,
				},
			)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID)
		},
	}
}

func clientPIN2GetPINTokenForbiddenBioEnrollmentStep(
	test *conformance.TestContext,
	pin []byte,
	reference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-get-pin-token.f-2.bio-enrollment",
		Name:       "Reject enrollBegin authorization by a legacy token",
		References: []conformance.RequirementRef{clientPINLegacyTokenReference(), reference},
		Run: func(ctx context.Context) error {
			token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(pin))
			defer clear(token)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
			}

			params := protocol.BioEnrollmentSubCommandParams{TimeoutMilliseconds: 10000}
			encodedParams, err := ctap2EncMode.Marshal(params)
			if err != nil {
				panic(err)
			}
			message := slices.Concat(
				[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnrollBegin)},
				encodedParams,
			)
			authParam := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, message)
			defer clear(authParam)
			_, err = exchangeCTAP2(
				ctx,
				test.CBOR(),
				protocol.AuthenticatorBioEnrollment,
				protocol.AuthenticatorBioEnrollmentRequest{
					Modality:          protocol.BioModalityFingerprint,
					SubCommand:        protocol.BioEnrollmentSubCommandEnrollBegin,
					SubCommandParams:  params,
					PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
					PinUvAuthParam:    authParam,
				},
			)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID)
		},
	}
}

func clientPIN2GetPINTokenForbiddenLargeBlobStep(
	test *conformance.TestContext,
	pin []byte,
	reference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-get-pin-token.f-3.large-blob",
		Name:       "Reject a large-blob write authorized by a legacy token",
		References: []conformance.RequirementRef{clientPINLegacyTokenReference(), reference},
		Run: func(ctx context.Context) error {
			token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(pin))
			defer clear(token)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
			}

			fragment := []byte{
				0x14, 0x5b, 0x6e, 0x9f, 0xa2, 0xb8, 0xc1, 0xd7,
				0xe0, 0xf4, 0x0a, 0x19, 0x25, 0x38, 0x43, 0x5d,
				0x67, 0x71, 0x8c, 0x92, 0xa9, 0xbc, 0xca, 0xd3,
				0xeb, 0xf6, 0x03, 0x17, 0x2c, 0x36, 0x4f, 0x58,
			}
			dataHash := sha256.Sum256(fragment)
			message := make([]byte, 0, 70)
			message = append(message, bytesOf(0xff, 32)...)
			message = append(message, 0x0c, 0x00)
			message = binary.LittleEndian.AppendUint32(message, 0)
			message = append(message, dataHash[:]...)
			authParam := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, message)
			defer clear(authParam)
			_, err = exchangeCTAP2(
				ctx,
				test.CBOR(),
				protocol.AuthenticatorLargeBlobs,
				protocol.AuthenticatorLargeBlobsRequest{
					Set:               fragment,
					Offset:            0,
					Length:            uint(len(fragment)),
					PinUvAuthParam:    authParam,
					PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
				},
			)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID)
		},
	}
}

func clientPIN2GetPINTokenForbiddenConfigStep(
	test *conformance.TestContext,
	pin []byte,
	authenticatorConfigReference conformance.RequirementRef,
	setMinPINLengthReference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "client-pin2-get-pin-token.f-4.authenticator-config",
		Name: "Reject a deliberately mis-authorized setMinPINLength request",
		References: []conformance.RequirementRef{
			clientPINLegacyTokenReference(),
			authenticatorConfigReference,
			setMinPINLengthReference,
		},
		Run: func(ctx context.Context) error {
			token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(pin))
			defer clear(token)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getPinToken", err)
			}

			message := slices.Concat(
				bytesOf(0xff, 32),
				[]byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)},
			)
			authParam := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, message)
			defer clear(authParam)
			_, err = exchangeCTAP2(
				ctx,
				test.CBOR(),
				protocol.AuthenticatorConfig,
				protocol.AuthenticatorConfigRequest{
					SubCommand:        protocol.ConfigSubCommandSetMinPINLength,
					SubCommandParams:  map[uint64]any{3: true},
					PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
					PinUvAuthParam:    authParam,
				},
			)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID)
		},
	}
}

func clientPIN2GetPINTokenForceChangeStep(
	test *conformance.TestContext,
	pin []byte,
	setMinPINLengthReference conformance.RequirementRef,
	permissionsReference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-get-pin-token.f-5.force-change",
		Name:       "Set forcePINChange and require getPinToken to reject the PIN",
		References: []conformance.RequirementRef{clientPINLegacyTokenReference(), setMinPINLengthReference, permissionsReference},
		Run: func(ctx context.Context) error {
			keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
			if err != nil {
				return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
			}
			configToken, err := test.Client().GetPinUvAuthTokenUsingPinWithPermissions(
				ctx,
				protocol.PinUvAuthProtocolTwo,
				keyAgreement,
				string(pin),
				protocol.PermissionAuthenticatorConfiguration,
				"",
			)
			defer clear(configToken)
			if err != nil {
				return unexpectedCTAPStatus(
					"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
					err,
				)
			}

			if err := test.Client().SetMinPINLength(
				ctx,
				protocol.PinUvAuthProtocolTwo,
				configToken,
				protocol.SetMinPINLengthConfigSubCommandParams{ForceChangePIN: true},
			); err != nil {
				return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
			}
			clear(configToken)

			token, err := getLegacyPINToken(ctx, test.Client(), protocol.PinUvAuthProtocolTwo, string(pin))
			defer clear(token)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_INVALID)
		},
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}

	return result
}

func clientPIN2GetPINTokenReference(section string, clause string, anchor string) conformance.RequirementRef {
	return clientPIN1NewPINReference(section, clause, anchor, conformance.RequirementConstraint)
}

func clientPIN2GetPINTokenSetMinPINLengthReference() conformance.RequirementRef {
	return clientPIN2GetPINTokenReference(
		"6.11.4",
		"set-min-pin-length-force-change",
		"setMinPINLength",
	)
}

func clientPIN2GetPINTokenMinPINLengthExtensionReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"7.4.3",
		"min-pin-length-extension-advertisement",
		"sctn-feature-descriptions-minPinLength-authnr-actions",
		conformance.RequirementMust,
	)
}
