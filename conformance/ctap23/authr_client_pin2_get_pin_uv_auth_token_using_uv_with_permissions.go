package ctap23

import (
	"context"
	"errors"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN2UVPermissionsSourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin2/Authr-ClientPin2-GetPinUvAuthTokenUsingUvWithPermissions.js"
	clientPIN2UVPermissionsRPID            = "uv-permissions.ctap23-conformance.example"

	TestIDAuthrClientPIN2UVPermissionsP1 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-uv-with-permissions.p-1"
	TestIDAuthrClientPIN2UVPermissionsP2 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-uv-with-permissions.p-2"
	TestIDAuthrClientPIN2UVPermissionsP3 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-uv-with-permissions.p-3"
	TestIDAuthrClientPIN2UVPermissionsP4 conformance.TestID = "fido.ctap2.3.authr-client-pin2-get-pin-uv-auth-token-using-uv-with-permissions.p-4"
)

type clientPIN2UVPermissionsCase struct {
	id               conformance.TestID
	marker           string
	name             string
	references       []conformance.RequirementRef
	requirePerCredRO bool
	run              func(*conformance.TestContext, clientPIN2UVPermissionsSession)
}

type clientPIN2UVPermissionsSession struct {
	fields map[uint64]cbor.RawMessage
	info   protocol.AuthenticatorGetInfoResponse
}

func authrClientPIN2GetPinUvAuthTokenUsingUvWithPermissionsTests(config Config) []conformance.Test {
	permissionsReference := clientPIN2UVPermissionsReference()
	makeCredentialReference := authrMakeCredReq1CommandReference()
	getAssertionReference := authrGetAssertionReq1CommandReference()
	credentialManagementReference := clientPIN2NewPINCredentialManagementReference()
	cases := []clientPIN2UVPermissionsCase{
		{
			id:         TestIDAuthrClientPIN2UVPermissionsP1,
			marker:     "P-1",
			name:       "Issue a protocol 2 built-in-UV token with all advertised UV permissions",
			references: []conformance.RequirementRef{permissionsReference},
			run: func(test *conformance.TestContext, session clientPIN2UVPermissionsSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-uv-permissions.p-1.issue",
					Name:       "Request the combined advertised built-in-UV permission scope",
					References: []conformance.RequirementRef{permissionsReference},
					Run: func(ctx context.Context) error {
						permissions, err := clientPIN2AdvertisedUVPermissions(session.fields)
						if err != nil {
							return err
						}

						token, err := clientPIN2IssueUVPermissionToken(
							ctx,
							test.Client(),
							permissions,
							clientPIN2UVPermissionsRPID,
						)
						defer clear(token)
						if err != nil {
							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions", err)
						}

						return clientPIN2ValidatePermissionToken(token)
					},
				})
			},
		},
		{
			id:         TestIDAuthrClientPIN2UVPermissionsP2,
			marker:     "P-2",
			name:       "Use a makeCredential-only protocol 2 built-in-UV token",
			references: []conformance.RequirementRef{permissionsReference, makeCredentialReference},
			run: func(test *conformance.TestContext, session clientPIN2UVPermissionsSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-uv-permissions.p-2.make-credential",
					Name:       "Immediately create a same-RP credential with a makeCredential-only token",
					References: []conformance.RequirementRef{permissionsReference, makeCredentialReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssueUVPermissionToken(
							ctx,
							test.Client(),
							protocol.PermissionMakeCredential,
							clientPIN2UVPermissionsRPID,
						)
						if err != nil {
							clear(token)

							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							clear(token)

							return err
						}

						response, commandErr := clientPIN2UVMakeCredential(ctx, test.CBOR(), token, session.info)
						clear(token)
						if commandErr != nil {
							return commandErr
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
			id:         TestIDAuthrClientPIN2UVPermissionsP3,
			marker:     "P-3",
			name:       "Use fresh makeCredential and getAssertion protocol 2 built-in-UV tokens",
			references: []conformance.RequirementRef{permissionsReference, makeCredentialReference, getAssertionReference},
			run: func(test *conformance.TestContext, session clientPIN2UVPermissionsSession) {
				var credentialID []byte
				if !test.Step(conformance.Step{
					ID:         "client-pin2-uv-permissions.p-3.make-credential",
					Name:       "Create this case's credential with a makeCredential-only token",
					References: []conformance.RequirementRef{permissionsReference, makeCredentialReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssueUVPermissionToken(
							ctx,
							test.Client(),
							protocol.PermissionMakeCredential,
							clientPIN2UVPermissionsRPID,
						)
						if err != nil {
							clear(token)

							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							clear(token)

							return err
						}

						response, commandErr := clientPIN2UVMakeCredential(ctx, test.CBOR(), token, session.info)
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
					ID:         "client-pin2-uv-permissions.p-3.get-assertion",
					Name:       "Get the new credential with a fresh getAssertion-only token",
					References: []conformance.RequirementRef{permissionsReference, getAssertionReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssueUVPermissionToken(
							ctx,
							test.Client(),
							protocol.PermissionGetAssertion,
							clientPIN2UVPermissionsRPID,
						)
						if err != nil {
							clear(token)

							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							clear(token)

							return err
						}

						commandErr := clientPIN2UVGetAssertion(ctx, test.CBOR(), token, credentialID)
						clear(token)

						return commandErr
					},
				})
			},
		},
		{
			id:               TestIDAuthrClientPIN2UVPermissionsP4,
			marker:           "P-4",
			name:             "Use a persistent credential-management read-only built-in-UV token",
			references:       []conformance.RequirementRef{permissionsReference, credentialManagementReference},
			requirePerCredRO: true,
			run: func(test *conformance.TestContext, _ clientPIN2UVPermissionsSession) {
				test.Step(conformance.Step{
					ID:         "client-pin2-uv-permissions.p-4.credentials-metadata",
					Name:       "Read credential metadata with a pcmr-only token",
					References: []conformance.RequirementRef{permissionsReference, credentialManagementReference},
					Run: func(ctx context.Context) error {
						token, err := clientPIN2IssueUVPermissionToken(
							ctx,
							test.Client(),
							protocol.PermissionPersistentCredentialManagementReadOnly,
							clientPIN2UVPermissionsRPID,
						)
						if err != nil {
							clear(token)

							return unexpectedCTAPStatus("authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions", err)
						}
						if err := clientPIN2ValidatePermissionToken(token); err != nil {
							clear(token)

							return err
						}

						commandErr := clientPIN2UVGetCredsMetadata(ctx, test.CBOR(), token)
						clear(token)

						return commandErr
					},
				})
			},
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		tests = append(tests, clientPIN2UVPermissionsTest(config, definition))
	}

	return tests
}

func clientPIN2UVPermissionsTest(config Config, definition clientPIN2UVPermissionsCase) conformance.Test {
	commonReferences := []conformance.RequirementRef{
		getInfoReference(),
		clientPIN2KeyAgreementProtocolTwoReference(),
		clientPIN2KeyAgreementFeaturefulReference(),
		clientPIN2UVPermissionsReference(),
		resetReference(),
		clientPINPowerCycleReference(),
		ctapMessageEncodingReference(),
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Exercises one protocol 2 built-in-UV permission-token behavior in an independent reset lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN2UVPermissionsSourcePath,
			Case: definition.marker,
		},
		References: appendClientPINReferences(commonReferences, definition.references...),
		Run: func(test *conformance.TestContext) {
			if !test.Step(clientPIN2UVPermissionsApplicabilityStep(test, config)) {
				return
			}
			if definition.requirePerCredRO && !test.Step(clientPIN2UVPermissionsPerCredROStep(test)) {
				return
			}
			if !test.Step(clientPIN2UVPermissionsEnvironmentStep(config)) {
				return
			}

			var session clientPIN2UVPermissionsSession
			if !test.Step(conformance.Step{
				ID:         "client-pin2-uv-permissions.prepare",
				Name:       "Reset the authenticator and configure built-in UV when needed",
				References: []conformance.RequirementRef{resetReference(), clientPINPowerCycleReference(), getInfoReference()},
				Run: func(ctx context.Context) error {
					var err error
					session, err = prepareClientPIN2UVPermissionsSession(ctx, test, config)

					return err
				},
			}) {
				return
			}

			definition.run(test, session)
		},
	}
}

func clientPIN2UVPermissionsApplicabilityStep(test *conformance.TestContext, config Config) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-uv-permissions.applicability",
		Name:       "Confirm built-in UV presence and protocol 2 support",
		References: []conformance.RequirementRef{getInfoReference(), clientPIN2KeyAgreementProtocolTwoReference(), clientPIN2UVPermissionsReference()},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			if _, present, err := rawGetInfoOption(fields, protocol.OptionUserVerification); err != nil {
				return err
			} else if !present {
				return conformance.Skip("authenticator does not advertise the uv option")
			}

			return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolTwo)
		},
	}
}

func clientPIN2UVPermissionsPerCredROStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:         "client-pin2-uv-permissions.per-cred-ro",
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

func clientPIN2UVPermissionsEnvironmentStep(config Config) conformance.Step {
	return conformance.Step{
		ID:   "client-pin2-uv-permissions.environment",
		Name: "Require the destructive built-in-UV environment",
		Run: func(context.Context) error {
			if config.PowerCycler == nil {
				return errors.New("ctap23: authenticator power cycler is required for built-in-UV permission-token tests")
			}

			return nil
		},
	}
}

func prepareClientPIN2UVPermissionsSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) (clientPIN2UVPermissionsSession, error) {
	var session clientPIN2UVPermissionsSession
	test.Cleanup(conformance.Step{
		ID:         "client-pin2-uv-permissions.cleanup",
		Name:       "Power-cycle and reset the authenticator after the case",
		References: []conformance.RequirementRef{clientPINPowerCycleReference(), resetReference()},
		Run: func(ctx context.Context) error {
			if err := config.PowerCycler(ctx); err != nil {
				return err
			}

			return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
		},
	})
	if err := config.PowerCycler(ctx); err != nil {
		return session, err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return session, err
	}

	fields, info, uvConfigured, err := clientPIN2UVPermissionsRefreshedInfo(ctx, test.CBOR())
	if err != nil {
		return session, err
	}
	if !uvConfigured {
		if err := configureClientPIN2UVPermissions(ctx, test, config, info); err != nil {
			return session, err
		}

		fields, info, uvConfigured, err = clientPIN2UVPermissionsRefreshedInfo(ctx, test.CBOR())
		if err != nil {
			return session, err
		}
		if !uvConfigured {
			return session, errors.New("ctap23: UV configurator completed but GetInfo uv is not true")
		}
	}

	return clientPIN2UVPermissionsSession{fields: fields, info: info}, nil
}

func clientPIN2UVPermissionsRefreshedInfo(
	ctx context.Context,
	device ctaptransport.CBOR,
) (map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, bool, error) {
	fields, info, err := readGetInfo(ctx, device)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, false, err
	}
	uvConfigured, present, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return nil, protocol.AuthenticatorGetInfoResponse{}, false, err
	}
	if !present {
		return nil, protocol.AuthenticatorGetInfoResponse{}, false, conformance.Fail(
			"GetInfo uv option disappeared after reset",
		)
	}
	if _, extensionsPresent := fields[2]; !extensionsPresent ||
		!slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		return nil, protocol.AuthenticatorGetInfoResponse{}, false, conformance.Fail(
			"PIN/UV protocol 2 support disappeared after reset",
		)
	}

	return fields, info, uvConfigured, nil
}

func configureClientPIN2UVPermissions(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	info protocol.AuthenticatorGetInfoResponse,
) error {
	if config.TemporaryPINProvider == nil {
		return errors.New("ctap23: temporary PIN provider is required to configure built-in UV")
	}
	if config.UVConfigurator == nil {
		return errors.New("ctap23: UV configurator is required when built-in UV is not configured")
	}

	request := temporaryPINRequest(info)
	pin, err := config.TemporaryPINProvider(ctx, request)
	defer clear(pin)
	if err != nil {
		return err
	}
	if err := validateTemporaryPIN(pin, request); err != nil {
		return err
	}

	var paddedPIN [64]byte
	defer clear(paddedPIN[:])
	copy(paddedPIN[:], pin)
	if err := setPINForPolicyTest(
		ctx,
		test.Client(),
		test.CBOR(),
		protocol.PinUvAuthProtocolTwo,
		&paddedPIN,
	); err != nil {
		return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	return config.UVConfigurator(ctx, pin)
}

func clientPIN2AdvertisedUVPermissions(fields map[uint64]cbor.RawMessage) (protocol.Permission, error) {
	permissions := protocol.PermissionMakeCredential | protocol.PermissionGetAssertion

	credentialManagement, _, err := rawGetInfoOption(fields, protocol.OptionCredentialManagement)
	if err != nil {
		return protocol.PermissionNone, err
	}
	if credentialManagement {
		permissions |= protocol.PermissionCredentialManagement
	}

	uvBioEnroll, _, err := rawGetInfoOption(fields, protocol.OptionUvBioEnroll)
	if err != nil {
		return protocol.PermissionNone, err
	}
	if uvBioEnroll {
		if _, present, err := rawGetInfoOption(fields, protocol.OptionBioEnroll); err != nil {
			return protocol.PermissionNone, err
		} else if !present {
			return protocol.PermissionNone, conformance.Fail("uvBioEnroll=true requires the bioEnroll option to be present")
		}
		permissions |= protocol.PermissionBioEnrollment
	}

	largeBlobs, _, err := rawGetInfoOption(fields, protocol.OptionLargeBlobs)
	if err != nil {
		return protocol.PermissionNone, err
	}
	if largeBlobs {
		permissions |= protocol.PermissionLargeBlobWrite
	}

	uvAcfg, _, err := rawGetInfoOption(fields, protocol.OptionUvAcfg)
	if err != nil {
		return protocol.PermissionNone, err
	}
	if uvAcfg {
		authenticatorConfig, present, err := rawGetInfoOption(fields, protocol.OptionAuthenticatorConfig)
		if err != nil {
			return protocol.PermissionNone, err
		}
		if !present || !authenticatorConfig {
			return protocol.PermissionNone, conformance.Fail("uvAcfg=true requires authnrCfg=true")
		}
		permissions |= protocol.PermissionAuthenticatorConfiguration
	}

	return permissions, nil
}

func clientPIN2IssueUVPermissionToken(
	ctx context.Context,
	ctapClient *client.Client,
	permissions protocol.Permission,
	rpID string,
) ([]byte, error) {
	keyAgreement, err := ctapClient.GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
	if err != nil {
		return nil, err
	}

	return ctapClient.GetPinUvAuthTokenUsingUvWithPermissions(
		ctx,
		protocol.PinUvAuthProtocolTwo,
		keyAgreement,
		permissions,
		rpID,
	)
}

func clientPIN2UVMakeCredential(
	ctx context.Context,
	device ctaptransport.CBOR,
	token []byte,
	info protocol.AuthenticatorGetInfoResponse,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}
	authParam := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		makeCredentialFixtureClientDataHash[:],
	)
	defer clear(authParam)
	response, err := exchangeCTAP2(ctx, device, protocol.AuthenticatorMakeCredential, protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash: makeCredentialFixtureClientDataHash[:],
		RP: credential.PublicKeyCredentialRpEntity{
			ID:   clientPIN2UVPermissionsRPID,
			Name: makeCredentialFixtureRPName,
		},
		User: credential.PublicKeyCredentialUserEntity{
			ID:          makeCredentialFixtureUserID[:],
			Name:        makeCredentialFixtureUserName,
			DisplayName: makeCredentialFixtureUserDisplayName,
		},
		PubKeyCredParams:  algorithms,
		Options:           map[protocol.Option]bool{protocol.OptionResidentKeys: true},
		PinUvAuthParam:    authParam,
		PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
	})
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, unexpectedCTAPStatus("authenticatorMakeCredential", err)
	}

	var decoded protocol.AuthenticatorMakeCredentialResponse
	if err := getInfoDecMode.Unmarshal(response.Data, &decoded); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, conformance.Failf(
			"invalid authenticatorMakeCredential response CBOR: %v",
			err,
		)
	}
	authData, err := protocol.ParseMakeCredentialAuthData(decoded.AuthDataRaw)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, conformance.Failf(
			"invalid authenticatorMakeCredential authData: %v",
			err,
		)
	}
	decoded.AuthData = &authData

	return decoded, nil
}

func clientPIN2UVGetAssertion(
	ctx context.Context,
	device ctaptransport.CBOR,
	token []byte,
	credentialID []byte,
) error {
	authParam := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		getAssertionFixtureClientDataHash[:],
	)
	defer clear(authParam)
	response, err := exchangeCTAP2(ctx, device, protocol.AuthenticatorGetAssertion, protocol.AuthenticatorGetAssertionRequest{
		RPID:           clientPIN2UVPermissionsRPID,
		ClientDataHash: getAssertionFixtureClientDataHash[:],
		AllowList: []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   credentialID,
		}},
		PinUvAuthParam:    authParam,
		PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
	})
	if err != nil {
		return unexpectedCTAPStatus("authenticatorGetAssertion", err)
	}

	var decoded protocol.AuthenticatorGetAssertionResponse
	if err := getInfoDecMode.Unmarshal(response.Data, &decoded); err != nil {
		return conformance.Failf("invalid authenticatorGetAssertion response CBOR: %v", err)
	}
	authData, err := protocol.ParseGetAssertionAuthData(decoded.AuthDataRaw)
	if err != nil {
		return conformance.Failf("invalid authenticatorGetAssertion authData: %v", err)
	}
	if !authData.Flags.UserVerified() {
		return conformance.Fail("authenticatorGetAssertion authData UV flag is false")
	}

	return nil
}

func clientPIN2UVGetCredsMetadata(
	ctx context.Context,
	device ctaptransport.CBOR,
	token []byte,
) error {
	authParam := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		[]byte{byte(protocol.CredentialManagementSubCommandGetCredsMetadata)},
	)
	defer clear(authParam)
	response, err := exchangeCTAP2(
		ctx,
		device,
		protocol.AuthenticatorCredentialManagement,
		protocol.AuthenticatorCredentialManagementRequest{
			SubCommand:        protocol.CredentialManagementSubCommandGetCredsMetadata,
			PinUvAuthProtocol: protocol.PinUvAuthProtocolTwo,
			PinUvAuthParam:    authParam,
		},
	)
	if err != nil {
		return unexpectedCTAPStatus("authenticatorCredentialManagement getCredsMetadata", err)
	}

	var decoded protocol.AuthenticatorCredentialManagementResponse
	if err := getInfoDecMode.Unmarshal(response.Data, &decoded); err != nil {
		return conformance.Failf("invalid authenticatorCredentialManagement getCredsMetadata response CBOR: %v", err)
	}

	return nil
}

func clientPIN2UVPermissionsReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.7.3:get-pin-uv-auth-token-using-uv-with-permissions",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.7.3",
		Clause:        "get-pin-uv-auth-token-using-uv-with-permissions",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getPinUvAuthTokenUsingUvWithPermissions",
		Level:         conformance.RequirementMust,
	}
}
