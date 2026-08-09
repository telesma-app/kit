package ctap23

import (
	"context"
	"errors"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN2PermissionsSourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin2/Authr-ClientPin2-GetPinUvAuthTokenUsingPinWithPermissions.js"
	clientPIN2PermissionsRPID            = "pin-permissions.ctap23-conformance.example"

	TestIDAuthrClientPIN2PermissionsP1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-pin-with-permissions.p-1"
	TestIDAuthrClientPIN2PermissionsP2 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-pin-with-permissions.p-2"
	TestIDAuthrClientPIN2PermissionsP3 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-pin-with-permissions.p-3"
	TestIDAuthrClientPIN2PermissionsP4 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-pin-with-permissions.p-4"
	TestIDAuthrClientPIN2PermissionsF1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-pin-with-permissions.f-1"
)

type clientPIN2PermissionsCase struct {
	id                 conformance.TestID
	marker             string
	name               string
	references         []conformance.RequirementRef
	requireMCGA        bool
	requirePerCredRO   bool
	requireExistingPIN bool
	requireSetMin      bool
	run                func(*conformance.TestContext, clientPIN2PermissionsSession)
}

type clientPIN2PermissionsSession struct {
	fields map[uint64]cbor.RawMessage
	info   protocol.AuthenticatorGetInfoResponse
	pin    []byte
}

func authrClientPIN2GetPinUvAuthTokenUsingPinWithPermissionsTests(config Config) []conformance.Test {
	permissionsReference := clientPIN2NewPINPermissionsReference()
	makeCredentialReference := authrMakeCredReq1CommandReference()
	getAssertionReference := authrGetAssertionReq1CommandReference()
	credentialManagementReference := clientPIN2NewPINCredentialManagementReference()
	setMinPINLengthReference := clientPIN1NewPINSetMinPINLengthReference()
	forcePINChangeReference := clientPIN1NewPINForceChangeReference()

	cases := []clientPIN2PermissionsCase{
		{
			id:         TestIDAuthrClientPIN2PermissionsP1,
			marker:     "P-1",
			name:       "Issue a protocol 2 PIN token with all advertised PIN permissions",
			references: []conformance.RequirementRef{permissionsReference},
			run: func(test *conformance.TestContext, session clientPIN2PermissionsSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-permissions.p-1.issue",
					Name:       "Request the combined advertised PIN permission scope",
					References: []conformance.RequirementRef{permissionsReference},
					Run: func(ctx context.Context) error {
						permissions, rpID, err := clientPIN2AdvertisedPINPermissions(session.fields)
						if err != nil {
							return err
						}
						if permissions == protocol.PermissionNone {
							return conformance.Skip("authenticator advertises no PIN-token permission exercised by this case")
						}

						token, err := clientPIN2IssuePermissionToken(ctx, test.Client(), session.pin, permissions, rpID)
						defer clear(token)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions", err)
						}

						return clientPIN2ValidatePermissionToken(token)
					},
				})
			},
		},
		{
			id:          TestIDAuthrClientPIN2PermissionsP2,
			marker:      "P-2",
			name:        "Use a makeCredential-only protocol 2 PIN token",
			references:  []conformance.RequirementRef{permissionsReference, makeCredentialReference},
			requireMCGA: true,
			run: func(test *conformance.TestContext, session clientPIN2PermissionsSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-permissions.p-2.make-credential",
					Name:       "Create a discoverable credential with a makeCredential-only token",
					References: []conformance.RequirementRef{permissionsReference, makeCredentialReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssuePermissionToken(
							ctx,
							test.Client(),
							session.pin,
							protocol.PermissionMakeCredential,
							clientPIN2PermissionsRPID,
						)
						defer clear(token)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							return err
						}

						response, err := clientPIN2MakeDiscoverableCredential(ctx, test.Client(), token, session.info)
						if err != nil {
							return err
						}
						if response.AuthData == nil || !response.AuthData.Flags.UserVerified() ||
							response.AuthData.AttestedCredentialData == nil ||
							len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
							return conformance.Fail("authenticatorMakeCredential response has no UV-verified credential ID")
						}

						return nil
					},
				})
			},
		},
		{
			id:          TestIDAuthrClientPIN2PermissionsP3,
			marker:      "P-3",
			name:        "Use independent makeCredential and getAssertion protocol 2 PIN tokens",
			references:  []conformance.RequirementRef{permissionsReference, makeCredentialReference, getAssertionReference},
			requireMCGA: true,
			run: func(test *conformance.TestContext, session clientPIN2PermissionsSession) {
				var credentialID []byte
				if !test.Step(conformance.Step{
					ID:         "client-pin2-permissions.p-3.make-credential",
					Name:       "Create this case's discoverable credential with a makeCredential-only token",
					References: []conformance.RequirementRef{permissionsReference, makeCredentialReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssuePermissionToken(
							ctx,
							test.Client(),
							session.pin,
							protocol.PermissionMakeCredential,
							clientPIN2PermissionsRPID,
						)
						if err != nil {
							clear(token)

							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							clear(token)

							return err
						}

						response, commandErr := clientPIN2MakeDiscoverableCredential(ctx, test.Client(), token, session.info)
						clear(token)
						if commandErr != nil {
							return commandErr
						}
						if response.AuthData == nil || !response.AuthData.Flags.UserVerified() ||
							response.AuthData.AttestedCredentialData == nil ||
							len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
							return conformance.Fail("authenticatorMakeCredential response has no UV-verified credential ID")
						}
						credentialID = slices.Clone(response.AuthData.AttestedCredentialData.CredentialID)

						return nil
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "client-pin2-permissions.p-3.get-assertion",
					Name:       "Get the new credential with a fresh getAssertion-only token",
					References: []conformance.RequirementRef{permissionsReference, getAssertionReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssuePermissionToken(
							ctx,
							test.Client(),
							session.pin,
							protocol.PermissionGetAssertion,
							clientPIN2PermissionsRPID,
						)
						defer clear(token)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							return err
						}

						return clientPIN2GetAssertion(ctx, test.Client(), token, credentialID)
					},
				})
			},
		},
		{
			id:               TestIDAuthrClientPIN2PermissionsP4,
			marker:           "P-4",
			name:             "Use a persistent credential-management read-only protocol 2 PIN token",
			references:       []conformance.RequirementRef{permissionsReference, credentialManagementReference},
			requirePerCredRO: true,
			run: func(test *conformance.TestContext, session clientPIN2PermissionsSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-permissions.p-4.credentials-metadata",
					Name:       "Read credential metadata with a pcmr-only token",
					References: []conformance.RequirementRef{permissionsReference, credentialManagementReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssuePermissionToken(
							ctx,
							test.Client(),
							session.pin,
							protocol.PermissionPersistentCredentialManagementReadOnly,
							"",
						)
						defer clear(token)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							return err
						}

						_, err = test.Client().GetCredsMetadata(
							ctx,
							false,
							protocol.PinUvAuthProtocolTwo,
							token,
						)

						return unexpectedCTAPStatus("authenticatorCredentialManagement getCredsMetadata", err)
					},
				})
			},
		},
		{
			id:                 TestIDAuthrClientPIN2PermissionsF1,
			marker:             "F-1",
			name:               "Reject protocol 2 permission-token issuance while forcePINChange is true",
			references:         []conformance.RequirementRef{permissionsReference, setMinPINLengthReference, forcePINChangeReference},
			requireExistingPIN: true,
			requireSetMin:      true,
			run: func(test *conformance.TestContext, session clientPIN2PermissionsSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-permissions.f-1.force-change",
					Name:       "Set forcePINChange and require PIN_POLICY_VIOLATION from fresh token issuance",
					References: []conformance.RequirementRef{permissionsReference, setMinPINLengthReference, forcePINChangeReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssuePermissionToken(
							ctx,
							test.Client(),
							session.pin,
							protocol.PermissionAuthenticatorConfiguration,
							"",
						)
						if err != nil {
							clear(token)

							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							clear(token)

							return err
						}

						err = test.Client().SetMinPINLength(
							ctx,
							protocol.PinUvAuthProtocolTwo,
							token,
							protocol.SetMinPINLengthConfigSubCommandParams{ForceChangePIN: true},
						)
						clear(token)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
						}

						invalidToken, err := clientPIN2IssuePermissionToken(
							ctx,
							test.Client(),
							session.pin,
							protocol.PermissionAuthenticatorConfiguration,
							"",
						)
						defer clear(invalidToken)

						return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION)
					},
				})
			},
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		tests = append(tests, clientPIN2PermissionsTest(config, definition))
	}

	return tests
}

func clientPIN2PermissionsTest(config Config, definition clientPIN2PermissionsCase) conformance.Test {
	commonReferences := []conformance.RequirementRef{
		getInfoReference(),
		clientPIN2KeyAgreementProtocolTwoReference(),
		clientPIN2KeyAgreementFeaturefulReference(),
		clientPIN2NewPINPermissionsReference(),
		resetReference(),
		clientPINSetReference(),
		clientPINPowerCycleReference(),
		ctapMessageEncodingReference(),
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Exercises one protocol 2 PIN permission-token behavior in an independent reset and PIN lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN2PermissionsSourcePath,
			Case: definition.marker,
		},
		References: appendClientPINReferences(commonReferences, definition.references...),
		Run: func(test *conformance.TestContext) {
			if !test.Step(clientPIN2PermissionsApplicabilityStep(test, config)) {
				return
			}
			if definition.requireMCGA && !test.Step(clientPIN2PermissionsMCGAStep(test)) {
				return
			}
			if definition.requirePerCredRO && !test.Step(clientPIN2PermissionsPerCredROStep(test)) {
				return
			}
			if definition.requireExistingPIN && !test.Step(clientPIN2PermissionsExistingPINStep(test)) {
				return
			}
			if definition.requireSetMin && !test.Step(clientPIN1NewPINSetMinSupportStep(test)) {
				return
			}
			if !test.Step(clientPIN2PermissionsEnvironmentStep(config)) {
				return
			}

			var session clientPIN2PermissionsSession
			prepared := test.Step(conformance.Step{
				ID:         "client-pin2-permissions.prepare",
				Name:       "Reset the authenticator and set an independent protocol 2 PIN",
				References: []conformance.RequirementRef{resetReference(), clientPINSetReference(), clientPINPowerCycleReference()},
				Run: func(ctx context.Context) error {
					var err error
					session, err = prepareClientPIN2PermissionsSession(ctx, test, config)

					return err
				},
			})
			defer clear(session.pin)
			if !prepared {
				return
			}

			definition.run(test, session)
		},
	}
}

func clientPIN2PermissionsApplicabilityStep(test *conformance.TestContext, config Config) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-permissions.applicability",
		Name:       "Confirm ClientPIN, protocol 2, and permission-token applicability",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN2KeyAgreementProtocolTwoReference(), clientPIN2NewPINPermissionsReference()},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}

			return validateClientPIN2PermissionsProfile(fields, info, config)
		},
	}
}

func validateClientPIN2PermissionsProfile(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
) error {
	if _, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN); err != nil {
		return err
	} else if !present {
		return conformance.Skip("authenticator does not advertise ClientPIN capability")
	}
	if err := validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolTwo); err != nil {
		return err
	}

	enabled, present, err := rawGetInfoOption(fields, protocol.OptionPinUvAuthToken)
	if err != nil {
		return err
	}
	if present && enabled {
		return nil
	}
	if config.Featureful {
		return conformance.Fail("featureful profile requires pinUvAuthToken to be present and true")
	}

	return conformance.Skip("authenticator does not advertise pinUvAuthToken=true")
}

func clientPIN2PermissionsMCGAStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-permissions.mc-ga",
		Name:       "Confirm PIN authorization of makeCredential and getAssertion",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN2NewPINPermissionsReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			restricted, present, err := rawGetInfoOption(fields, protocol.OptionNoMcGaPermissionsWithClientPin)
			if err != nil {
				return err
			}
			if present && restricted {
				return conformance.Skip("authenticator disables makeCredential and getAssertion permissions with ClientPIN")
			}

			return nil
		},
	}
}

func clientPIN2PermissionsPerCredROStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-permissions.per-cred-ro",
		Name:       "Confirm persistent credential-management read-only support",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN2NewPINCredentialManagementReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			enabled, present, err := rawGetInfoOption(fields, protocol.OptionPersistentCredentialManagementReadOnly)
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

func clientPIN2PermissionsExistingPINStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-permissions.existing-pin",
		Name:       "Confirm a PIN is set before the force-PIN-change case",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN1NewPINForceChangeReference()},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			enabled, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
			if err != nil {
				return err
			}
			if !present || !enabled {
				return conformance.Skip("authenticator has no PIN set before the force-PIN-change case")
			}

			return nil
		},
	}
}

func clientPIN2PermissionsEnvironmentStep(config Config) conformance.Step {
	return conformance.Step{
		ID:   "client-pin2-permissions.environment",
		Name: "Require the destructive ClientPIN environment",
		Run: func(context.Context) error {
			if config.PowerCycler == nil {
				return errors.New("ctap23: authenticator power cycler is required for ClientPIN permission-token tests")
			}
			if config.TemporaryPINProvider == nil {
				return errors.New("ctap23: temporary PIN provider is required for ClientPIN permission-token tests")
			}

			return nil
		},
	}
}

func prepareClientPIN2PermissionsSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) (clientPIN2PermissionsSession, error) {
	var session clientPIN2PermissionsSession
	if err := config.PowerCycler(ctx); err != nil {
		return session, err
	}
	test.Cleanup(conformance.Step{
		ID:         "client-pin2-permissions.cleanup",
		Name:       "Power-cycle and reset the authenticator after the case",
		References: []conformance.RequirementRef{clientPINPowerCycleReference(), resetReference()},
		Run: func(ctx context.Context) error {
			if err := config.PowerCycler(ctx); err != nil {
				return err
			}

			return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
		},
	})
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return session, err
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return session, err
	}
	if err := validateClientPIN2PermissionsProfile(fields, info, config); err != nil {
		return session, err
	}

	request := temporaryPINRequest(info)
	session.pin, err = config.TemporaryPINProvider(ctx, request)
	if err != nil {
		return session, err
	}
	if err := validateTemporaryPIN(session.pin, request); err != nil {
		return session, err
	}

	keyAgreement, err := test.Client().GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
	if err != nil {
		return session, unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	if err := test.Client().SetPIN(ctx, protocol.PinUvAuthProtocolTwo, keyAgreement, string(session.pin)); err != nil {
		return session, unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	session.fields, session.info, err = readGetInfo(ctx, test.CBOR())
	if err != nil {
		return session, err
	}
	if err := validateClientPIN2PermissionsProfile(session.fields, session.info, config); err != nil {
		return session, err
	}
	clientPIN, present, err := rawGetInfoOption(session.fields, protocol.OptionClientPIN)
	if err != nil {
		return session, err
	}
	if !present || !clientPIN {
		return session, conformance.Fail("clientPin is not true after successful setPIN")
	}

	return session, nil
}

func clientPIN2AdvertisedPINPermissions(fields map[uint64]cbor.RawMessage) (protocol.Permission, string, error) {
	var permissions protocol.Permission
	restricted, present, err := rawGetInfoOption(fields, protocol.OptionNoMcGaPermissionsWithClientPin)
	if err != nil {
		return protocol.PermissionNone, "", err
	}
	if !present || !restricted {
		permissions |= protocol.PermissionMakeCredential | protocol.PermissionGetAssertion
	}

	for _, candidate := range []struct {
		option     protocol.Option
		permission protocol.Permission
		presence   bool
	}{
		{option: protocol.OptionCredentialManagement, permission: protocol.PermissionCredentialManagement},
		{option: protocol.OptionBioEnroll, permission: protocol.PermissionBioEnrollment, presence: true},
		{option: protocol.OptionLargeBlobs, permission: protocol.PermissionLargeBlobWrite},
		{option: protocol.OptionAuthenticatorConfig, permission: protocol.PermissionAuthenticatorConfiguration},
	} {
		enabled, present, err := rawGetInfoOption(fields, candidate.option)
		if err != nil {
			return protocol.PermissionNone, "", err
		}
		if enabled || candidate.presence && present {
			permissions |= candidate.permission
		}
	}

	rpID := ""
	if permissions&(protocol.PermissionMakeCredential|protocol.PermissionGetAssertion) != 0 {
		rpID = clientPIN2PermissionsRPID
	}

	return permissions, rpID, nil
}

func clientPIN2IssuePermissionToken(
	ctx context.Context,
	client *client.Client,
	pin []byte,
	permissions protocol.Permission,
	rpID string,
) ([]byte, error) {
	keyAgreement, err := client.GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
	if err != nil {
		return nil, err
	}

	return client.GetPinUvAuthTokenUsingPinWithPermissions(
		ctx,
		protocol.PinUvAuthProtocolTwo,
		keyAgreement,
		string(pin),
		permissions,
		rpID,
	)
}

func clientPIN2ValidatePermissionToken(token []byte) error {
	if len(token) != 32 {
		return conformance.Failf("decrypted pinUvAuthToken is %d bytes, want 32", len(token))
	}

	return nil
}

func clientPIN2MakeDiscoverableCredential(
	ctx context.Context,
	client *client.Client,
	token []byte,
	info protocol.AuthenticatorGetInfoResponse,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	response, err := client.MakeCredential(
		ctx,
		protocol.PinUvAuthProtocolTwo,
		token,
		makeCredentialFixtureClientDataHash[:],
		credential.PublicKeyCredentialRpEntity{
			ID:   clientPIN2PermissionsRPID,
			Name: makeCredentialFixtureRPName,
		},
		credential.PublicKeyCredentialUserEntity{
			ID:          makeCredentialFixtureUserID[:],
			Name:        makeCredentialFixtureUserName,
			DisplayName: makeCredentialFixtureUserDisplayName,
		},
		algorithms,
		nil,
		nil,
		map[protocol.Option]bool{protocol.OptionResidentKeys: true},
		0,
		nil,
	)

	return response, unexpectedCTAPStatus("authenticatorMakeCredential", err)
}

func clientPIN2GetAssertion(
	ctx context.Context,
	client *client.Client,
	token []byte,
	credentialID []byte,
) error {
	for response, err := range client.GetAssertion(
		ctx,
		protocol.PinUvAuthProtocolTwo,
		token,
		clientPIN2PermissionsRPID,
		getAssertionFixtureClientDataHash[:],
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
