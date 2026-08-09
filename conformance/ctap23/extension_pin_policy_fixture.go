package ctap23

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

type extensionPINPolicyCase struct {
	id              conformance.TestID
	marker          string
	sessionMarker   string
	sourcePath      string
	name            string
	description     string
	allowedRPID     string
	targetRPID      string
	references      []conformance.RequirementRef
	configReference conformance.RequirementRef
	extensions      protocol.CreateExtensionInputs
	applicable      func(map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, []protocol.ConfigSubCommand) error
	validateOutput  func(map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, []byte) error
}

type extensionPINPolicyMakeCredentialFixture struct {
	makeCredentialFixture
	fields map[uint64]cbor.RawMessage
}

func extensionPINPolicyTest(config Config, definition extensionPINPolicyCase) conformance.Test {
	configCase := authenticatorConfigCase{
		marker:     definition.sessionMarker,
		reference:  definition.configReference,
		applicable: definition.applicable,
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: definition.description,
		Source: conformance.SourceLocation{
			Path: definition.sourcePath,
			Case: definition.marker,
		},
		References:  definition.references,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			if !test.Step(extensionPINPolicyApplicabilityStep(test, config, configCase)) {
				return
			}

			var session authenticatorConfigSession
			prepared := test.Step(conformance.Step{
				ID:         conformance.StepID("extension-pin-policy." + definition.sessionMarker + ".prepare"),
				Name:       "Reset the authenticator and obtain protocol 2 configuration authorization",
				References: []conformance.RequirementRef{resetReference(), authenticatorConfigCommandReference()},
				Run: func(ctx context.Context) error {
					var err error
					session, err = prepareAuthenticatorConfigSession(ctx, test, config, configCase)

					return err
				},
			})
			defer clear(session.token.Value)
			if !prepared {
				return
			}

			test.Step(conformance.Step{
				ID:         conformance.StepID("extension-pin-policy." + definition.sessionMarker + ".execute"),
				Name:       "Configure the allowed RP ID and make one credential without another reset",
				References: definition.references,
				Run: func(ctx context.Context) error {
					configErr := extensionPINPolicyConfigureAllowedRP(
						ctx,
						test,
						session,
						definition.allowedRPID,
					)
					clear(session.token.Value)
					session.token.Value = nil
					if configErr != nil {
						return configErr
					}

					fixture, err := prepareExtensionPINPolicyMakeCredential(
						ctx,
						test,
						config,
						definition.targetRPID,
						definition.extensions,
						definition.applicable,
					)
					if err != nil {
						return err
					}
					defer fixture.clear()

					response, err := fixture.makeCredential(ctx, test.CBOR(), fixture.Request)
					if err != nil {
						return err
					}
					defer clearMakeCredentialResponse(&response)

					return definition.validateOutput(fixture.fields, fixture.Info, response.AuthDataRaw)
				},
			})
		},
	}
}

func extensionPINPolicyApplicabilityStep(
	test *conformance.TestContext,
	config Config,
	definition authenticatorConfigCase,
) conformance.Step {
	return conformance.Step{
		ID:         conformance.StepID("extension-pin-policy." + definition.marker + ".applicability"),
		Name:       "Confirm extension, configuration, protocol 2, and environment applicability",
		References: []conformance.RequirementRef{getInfoReference(), definition.reference},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			commands, err := rawAuthenticatorConfigCommands(fields)
			if err != nil {
				return err
			}
			if err := definition.applicable(fields, info, commands); err != nil {
				return err
			}

			return extensionPINPolicyEnvironmentApplicable(fields, config)
		},
	}
}

func extensionPINPolicySetMinRPIDsApplicable(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
	config Config,
) error {
	authenticatorConfig, present, err := rawGetInfoOption(fields, protocol.OptionAuthenticatorConfig)
	if err != nil {
		return err
	}
	if !present || !authenticatorConfig {
		return conformance.Fail("an advertised PIN policy extension requires authnrCfg=true")
	}

	setMinPINLength, present, err := rawGetInfoOption(fields, protocol.OptionSetMinPINLength)
	if err != nil {
		return err
	}
	if !present || !setMinPINLength {
		return conformance.Fail("an advertised PIN policy extension requires setMinPINLength=true")
	}
	if !slices.Contains(commands, protocol.ConfigSubCommandSetMinPINLength) {
		return conformance.Fail("authenticatorConfigCommands does not contain setMinPINLength")
	}
	if err := authenticatorConfigProtocolTwoApplicable(info, config); err != nil {
		return err
	}
	if _, present := fields[16]; !present || info.MaxRPIDsForSetMinPINLength == nil ||
		*info.MaxRPIDsForSetMinPINLength == 0 {
		return conformance.Skip("authenticator does not advertise a positive maxRPIDsForSetMinPINLength")
	}

	return nil
}

func extensionPINPolicyEnvironmentApplicable(
	fields map[uint64]cbor.RawMessage,
	config Config,
) error {
	if config.PowerCycler == nil {
		return errors.New("ctap23: authenticator power cycler is required for extension PIN policy tests")
	}
	if config.TemporaryPINProvider == nil {
		return errors.New("ctap23: temporary PIN provider is required for extension PIN policy tests")
	}
	if config.TokenProvider == nil {
		return errors.New("ctap23: PIN/UV token provider is required for extension PIN policy tests")
	}

	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	if !clientPINPresent && config.UVConfigurator == nil {
		return errors.New("ctap23: UV configurator is required for extension PIN policy tests without ClientPIN")
	}

	return nil
}

func extensionPINPolicyConfigureAllowedRP(
	ctx context.Context,
	test *conformance.TestContext,
	session authenticatorConfigSession,
	rpID string,
) error {
	err := test.Client().SetMinPINLength(
		ctx,
		session.token.Protocol,
		session.token.Value,
		protocol.SetMinPINLengthConfigSubCommandParams{MinPINLengthRPIDs: []string{rpID}},
	)

	return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
}

func prepareExtensionPINPolicyMakeCredential(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	rpID string,
	extensions protocol.CreateExtensionInputs,
	applicable func(map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, []protocol.ConfigSubCommand) error,
) (extensionPINPolicyMakeCredentialFixture, error) {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return extensionPINPolicyMakeCredentialFixture{}, err
	}
	commands, err := rawAuthenticatorConfigCommands(fields)
	if err != nil {
		return extensionPINPolicyMakeCredentialFixture{}, err
	}
	if err := applicable(fields, info, commands); err != nil {
		return extensionPINPolicyMakeCredentialFixture{}, err
	}

	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		return extensionPINPolicyMakeCredentialFixture{}, err
	}
	authorization, err := config.TokenProvider(ctx, test.Client(), PinUvAuthTokenRequest{
		Permission: protocol.PermissionMakeCredential,
		RPID:       rpID,
	})
	if err != nil {
		clear(authorization.Value)

		return extensionPINPolicyMakeCredentialFixture{}, err
	}
	if authorization.Protocol != protocol.PinUvAuthProtocolTwo {
		clear(authorization.Value)

		return extensionPINPolicyMakeCredentialFixture{}, fmt.Errorf(
			"ctap23: PIN/UV token provider returned protocol %d; extension PIN policy tests require protocol 2",
			authorization.Protocol,
		)
	}
	if err := validatePinUvAuthorization(info, authorization); err != nil {
		clear(authorization.Value)

		return extensionPINPolicyMakeCredentialFixture{}, err
	}

	fixture := extensionPINPolicyMakeCredentialFixture{
		makeCredentialFixture: makeCredentialFixture{
			Info: info,
			Request: protocol.AuthenticatorMakeCredentialRequest{
				ClientDataHash: slices.Clone(makeCredentialFixtureClientDataHash[:]),
				RP: credential.PublicKeyCredentialRpEntity{
					ID:   rpID,
					Name: makeCredentialFixtureRPName,
				},
				User: credential.PublicKeyCredentialUserEntity{
					ID:          slices.Clone(makeCredentialFixtureUserID[:]),
					Name:        makeCredentialFixtureUserName,
					DisplayName: makeCredentialFixtureUserDisplayName,
				},
				PubKeyCredParams:  algorithms,
				Extensions:        extensions,
				PinUvAuthProtocol: authorization.Protocol,
			},
			Authorization: authorization,
		},
		fields: fields,
	}
	fixture.Request.PinUvAuthParam = ctapcrypto.Authenticate(
		authorization.Protocol,
		authorization.Value,
		fixture.Request.ClientDataHash,
	)

	return fixture, nil
}

func extensionPINPolicyReference(
	section string,
	clause string,
	anchor string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID("ctap-2.3-ps-20260226:" + section + ":" + clause),
		Specification: conformance.SpecificationCTAP23,
		Section:       section,
		Clause:        clause,
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#" + anchor,
		Level:         level,
	}
}
