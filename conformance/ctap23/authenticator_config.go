package ctap23

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const authenticatorConfigSourcePath = "tests/CTAP2/Protocol/AuthenticatorConfig/AuthenticatorConfig.js"

const (
	TestIDAuthenticatorConfigP1 conformance.TestID = "fido.ctap2.3.authenticator-config.p-1"
	TestIDAuthenticatorConfigP2 conformance.TestID = "fido.ctap2.3.authenticator-config.p-2"
	TestIDAuthenticatorConfigP3 conformance.TestID = "fido.ctap2.3.authenticator-config.p-3"
	TestIDAuthenticatorConfigP4 conformance.TestID = "fido.ctap2.3.authenticator-config.p-4"
	TestIDAuthenticatorConfigP5 conformance.TestID = "fido.ctap2.3.authenticator-config.p-5"
	TestIDAuthenticatorConfigP6 conformance.TestID = "fido.ctap2.3.authenticator-config.p-6"
	TestIDAuthenticatorConfigP7 conformance.TestID = "fido.ctap2.3.authenticator-config.p-7"
)

type authenticatorConfigCase struct {
	id         conformance.TestID
	marker     string
	name       string
	reference  conformance.RequirementRef
	applicable func(map[uint64]cbor.RawMessage, protocol.AuthenticatorGetInfoResponse, []protocol.ConfigSubCommand) error
	run        func(context.Context, *conformance.TestContext, authenticatorConfigSession) error
}

type authenticatorConfigSession struct {
	fields map[uint64]cbor.RawMessage
	info   protocol.AuthenticatorGetInfoResponse
	token  PinUvAuthToken
}

func authenticatorConfigTests(config Config) []conformance.Test {
	definitions := []authenticatorConfigCase{
		{
			id:         TestIDAuthenticatorConfigP1,
			marker:     "P-1",
			name:       "Enable enterprise attestation",
			reference:  authenticatorConfigEnableEnterpriseAttestationReference(),
			applicable: authenticatorConfigEnterpriseAttestationApplicable,
			run:        runAuthenticatorConfigEnableEnterpriseAttestation,
		},
		{
			id:         TestIDAuthenticatorConfigP2,
			marker:     "P-2",
			name:       "Toggle always-required user verification",
			reference:  authenticatorConfigToggleAlwaysUVReference(),
			applicable: authenticatorConfigToggleAlwaysUVApplicable,
			run:        runAuthenticatorConfigToggleAlwaysUV,
		},
		{
			id:         TestIDAuthenticatorConfigP3,
			marker:     "P-3",
			name:       "Increase the minimum PIN length",
			reference:  authenticatorConfigSetMinPINLengthReference("increase-minimum-pin-length"),
			applicable: authenticatorConfigSetMinPINLengthApplicable,
			run:        runAuthenticatorConfigIncreaseMinPINLength,
		},
		{
			id:         TestIDAuthenticatorConfigP4,
			marker:     "P-4",
			name:       "Configure the maximum supported minimum-PIN-length RP ID list",
			reference:  authenticatorConfigSetMinPINLengthReference("minimum-pin-length-rp-ids"),
			applicable: authenticatorConfigMinPINLengthRPIDsApplicable,
			run:        runAuthenticatorConfigMinPINLengthRPIDs,
		},
		{
			id:         TestIDAuthenticatorConfigP5,
			marker:     "P-5",
			name:       "Require a PIN change",
			reference:  authenticatorConfigSetMinPINLengthReference("force-pin-change"),
			applicable: authenticatorConfigForcePINChangeApplicable,
			run:        runAuthenticatorConfigForcePINChange,
		},
		{
			id:         TestIDAuthenticatorConfigP6,
			marker:     "P-6",
			name:       "Enable the PIN complexity policy",
			reference:  authenticatorConfigSetMinPINLengthReference("pin-complexity-policy"),
			applicable: authenticatorConfigPINComplexityPolicyApplicable,
			run:        runAuthenticatorConfigPINComplexityPolicy,
		},
		{
			id:         TestIDAuthenticatorConfigP7,
			marker:     "P-7",
			name:       "Enable long touch for reset",
			reference:  authenticatorConfigEnableLongTouchForResetReference(),
			applicable: authenticatorConfigLongTouchForResetApplicable,
			run:        runAuthenticatorConfigEnableLongTouchForReset,
		},
	}

	tests := make([]conformance.Test, len(definitions))
	for index, definition := range definitions {
		references := []conformance.RequirementRef{authenticatorConfigCommandReference(), definition.reference}
		tests[index] = conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: "Exercises one authorized authenticatorConfig state transition and verifies it through a fresh authenticatorGetInfo response",
			Source: conformance.SourceLocation{
				Path: authenticatorConfigSourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(authenticatorConfigApplicabilityStep(test, config, definition)) {
					return
				}
				if !test.Step(authenticatorConfigEnvironmentStep(config)) {
					return
				}

				var session authenticatorConfigSession
				prepared := test.Step(conformance.Step{
					ID:         conformance.StepID("authenticator-config." + definition.marker + ".prepare"),
					Name:       "Reset the authenticator and obtain protocol 2 configuration authorization",
					References: []conformance.RequirementRef{resetReference(), authenticatorConfigCommandReference()},
					Run: func(ctx context.Context) error {
						var err error
						session, err = prepareAuthenticatorConfigSession(ctx, test, config, definition)

						return err
					},
				})
				defer clear(session.token.Value)
				if !prepared {
					return
				}

				test.Step(conformance.Step{
					ID:         conformance.StepID("authenticator-config." + definition.marker + ".execute"),
					Name:       definition.name + " and verify refreshed configuration state",
					References: references,
					Run: func(ctx context.Context) error {
						return definition.run(ctx, test, session)
					},
				})
			},
		}
	}

	return tests
}

func authenticatorConfigApplicabilityStep(
	test *conformance.TestContext,
	config Config,
	definition authenticatorConfigCase,
) conformance.Step {
	return conformance.Step{
		ID:         conformance.StepID("authenticator-config." + definition.marker + ".applicability"),
		Name:       "Confirm authenticatorConfig and subcommand applicability",
		References: []conformance.RequirementRef{getInfoReference(), authenticatorConfigCommandReference(), definition.reference},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			commands, err := validateAuthenticatorConfigProfile(fields, config)
			if err != nil {
				return err
			}
			if err := authenticatorConfigProtocolTwoApplicable(info, config); err != nil {
				return err
			}

			return definition.applicable(fields, info, commands)
		},
	}
}

func authenticatorConfigEnvironmentStep(config Config) conformance.Step {
	return conformance.Step{
		ID:   "authenticator-config.environment",
		Name: "Require the destructive authenticator configuration environment",
		Run: func(context.Context) error {
			if config.PowerCycler == nil {
				return errors.New("ctap23: authenticator power cycler is required for authenticatorConfig tests")
			}

			return nil
		},
	}
}

func prepareAuthenticatorConfigSession(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	definition authenticatorConfigCase,
) (authenticatorConfigSession, error) {
	var session authenticatorConfigSession
	if err := config.PowerCycler(ctx); err != nil {
		return session, err
	}
	test.Cleanup(conformance.Step{
		ID:         conformance.StepID("authenticator-config." + definition.marker + ".cleanup"),
		Name:       "Power-cycle and reset the authenticator after configuration",
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
	if _, err := validateAuthenticatorConfigProfile(fields, config); err != nil {
		return session, err
	}
	if err := authenticatorConfigProtocolTwoApplicable(info, config); err != nil {
		return session, err
	}

	session.token, err = prepareAuthenticatorConfigAuthorization(ctx, test, config, fields, info)
	if err != nil {
		return session, err
	}
	if err := clientPIN2ValidatePermissionToken(session.token.Value); err != nil {
		return session, err
	}

	session.fields, session.info, err = readGetInfo(ctx, test.CBOR())
	if err != nil {
		return session, err
	}
	commands, err := validateAuthenticatorConfigProfile(session.fields, config)
	if err != nil {
		return session, err
	}
	if err := definition.applicable(session.fields, session.info, commands); err != nil {
		return session, err
	}

	return session, nil
}

func prepareAuthenticatorConfigAuthorization(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
) (PinUvAuthToken, error) {
	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if clientPINPresent {
		return prepareAuthenticatorConfigPINAuthorization(ctx, test.Client(), config, info)
	}

	_, uvPresent, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if !uvPresent {
		return PinUvAuthToken{}, errors.New(
			"ctap23: authenticatorConfig tests require ClientPIN or configurable built-in UV after reset",
		)
	}

	return prepareAuthenticatorConfigUVAuthorization(ctx, test, config, info)
}

func prepareAuthenticatorConfigPINAuthorization(
	ctx context.Context,
	ctapClient *client.Client,
	config Config,
	info protocol.AuthenticatorGetInfoResponse,
) (PinUvAuthToken, error) {
	if config.TemporaryPINProvider == nil {
		return PinUvAuthToken{}, errors.New(
			"ctap23: temporary PIN provider is required to configure ClientPIN for authenticatorConfig tests",
		)
	}

	minimum := info.EffectiveMinPINLength()
	request := TemporaryPINRequest{MinCodePoints: minimum, MaxCodePoints: minimum}
	pin, err := authenticatorConfigTemporaryPIN(ctx, config, request)
	defer clear(pin)
	if err != nil {
		return PinUvAuthToken{}, err
	}

	keyAgreement, err := ctapClient.GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
	if err != nil {
		return PinUvAuthToken{}, unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	if err := ctapClient.SetPIN(ctx, protocol.PinUvAuthProtocolTwo, keyAgreement, string(pin)); err != nil {
		return PinUvAuthToken{}, unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	token, err := clientPIN2IssuePermissionToken(
		ctx,
		ctapClient,
		pin,
		protocol.PermissionAuthenticatorConfiguration,
		"",
	)
	if err != nil {
		clear(token)

		return PinUvAuthToken{}, unexpectedCTAPStatus(
			"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
			err,
		)
	}

	return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, nil
}

func prepareAuthenticatorConfigUVAuthorization(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	info protocol.AuthenticatorGetInfoResponse,
) (PinUvAuthToken, error) {
	if config.TemporaryPINProvider == nil {
		return PinUvAuthToken{}, errors.New(
			"ctap23: temporary PIN provider is required to configure built-in UV for authenticatorConfig tests",
		)
	}
	if config.UVConfigurator == nil {
		return PinUvAuthToken{}, errors.New(
			"ctap23: UV configurator is required to configure built-in UV for authenticatorConfig tests",
		)
	}

	request := temporaryPINRequest(info)
	pin, err := authenticatorConfigTemporaryPIN(ctx, config, request)
	defer clear(pin)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if err := config.UVConfigurator(ctx, pin); err != nil {
		return PinUvAuthToken{}, err
	}

	fields, refreshed, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if _, err := validateAuthenticatorConfigProfile(fields, config); err != nil {
		return PinUvAuthToken{}, err
	}
	if err := authenticatorConfigProtocolTwoApplicable(refreshed, config); err != nil {
		return PinUvAuthToken{}, err
	}
	uvConfigured, present, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return PinUvAuthToken{}, err
	}
	if !present || !uvConfigured {
		return PinUvAuthToken{}, errors.New(
			"ctap23: UV configurator completed but GetInfo uv is not true",
		)
	}

	token, err := clientPIN2IssueUVPermissionToken(
		ctx,
		test.Client(),
		protocol.PermissionAuthenticatorConfiguration,
		"",
	)
	if err != nil {
		clear(token)

		return PinUvAuthToken{}, unexpectedCTAPStatus(
			"authenticatorClientPIN getPinUvAuthTokenUsingUvWithPermissions",
			err,
		)
	}

	return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: token}, nil
}

func authenticatorConfigTemporaryPIN(
	ctx context.Context,
	config Config,
	request TemporaryPINRequest,
) ([]byte, error) {
	pin, err := config.TemporaryPINProvider(ctx, request)
	if err != nil {
		clear(pin)

		return nil, err
	}
	if err := validateTemporaryPIN(pin, request); err != nil {
		clear(pin)

		return nil, err
	}

	return pin, nil
}

func authenticatorConfigProtocolTwoApplicable(
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
) error {
	if slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		return nil
	}
	if config.Featureful {
		return conformance.Fail("featureful profile requires PIN/UV protocol 2 for authenticatorConfig")
	}

	return conformance.Skip("authenticator does not advertise PIN/UV protocol 2 for authenticatorConfig")
}

func validateAuthenticatorConfigProfile(
	fields map[uint64]cbor.RawMessage,
	config Config,
) ([]protocol.ConfigSubCommand, error) {
	enabled, present, err := rawGetInfoOption(fields, protocol.OptionAuthenticatorConfig)
	if err != nil {
		return nil, err
	}
	if !present || !enabled {
		if config.Featureful {
			return nil, conformance.Fail("featureful profile requires authnrCfg to be present and true")
		}

		return nil, conformance.Skip("authenticator does not advertise authnrCfg=true")
	}

	commands, err := rawAuthenticatorConfigCommands(fields)
	if err != nil {
		return nil, err
	}
	if config.Featureful {
		for _, command := range []protocol.ConfigSubCommand{
			protocol.ConfigSubCommandToggleAlwaysUv,
			protocol.ConfigSubCommandSetMinPINLength,
		} {
			if !slices.Contains(commands, command) {
				return nil, conformance.Failf(
					"featureful profile authenticatorConfigCommands does not contain 0x%02x",
					command,
				)
			}
		}
	}

	return commands, nil
}

func rawAuthenticatorConfigCommands(fields map[uint64]cbor.RawMessage) ([]protocol.ConfigSubCommand, error) {
	raw, present := fields[31]
	if !present {
		return nil, nil
	}

	var values []cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &values); err != nil {
		return nil, conformance.Failf("invalid authenticatorConfigCommands: %v", err)
	}
	if values == nil {
		return nil, conformance.Fail("invalid authenticatorConfigCommands: want an array, got null")
	}

	commands := make([]protocol.ConfigSubCommand, len(values))
	for index, rawValue := range values {
		var value uint64
		if err := getInfoDecMode.Unmarshal(rawValue, &value); err != nil {
			return nil, conformance.Failf("invalid authenticatorConfigCommands[%d]: %v", index, err)
		}
		commands[index] = protocol.ConfigSubCommand(value)
	}

	return commands, nil
}

func authenticatorConfigEnterpriseAttestationApplicable(
	fields map[uint64]cbor.RawMessage,
	_ protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
) error {
	if _, present, err := rawGetInfoOption(fields, protocol.OptionEnterpriseAttestation); err != nil {
		return err
	} else if !present {
		return conformance.Skip("authenticator does not advertise the ep option")
	}
	if !slices.Contains(commands, protocol.ConfigSubCommandEnableEnterpriseAttestation) {
		return conformance.Fail("authenticatorConfigCommands does not contain enableEnterpriseAttestation")
	}

	return nil
}

func authenticatorConfigToggleAlwaysUVApplicable(
	fields map[uint64]cbor.RawMessage,
	_ protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
) error {
	if _, present, err := rawGetInfoOption(fields, protocol.OptionAlwaysUv); err != nil {
		return err
	} else if !present {
		return conformance.Skip("authenticator does not advertise the alwaysUv option")
	}
	if !slices.Contains(commands, protocol.ConfigSubCommandToggleAlwaysUv) {
		return conformance.Skip("authenticator does not advertise toggleAlwaysUv")
	}

	return nil
}

func authenticatorConfigSetMinPINLengthApplicable(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
) error {
	enabled, present, err := rawGetInfoOption(fields, protocol.OptionSetMinPINLength)
	if err != nil {
		return err
	}
	if !present || !enabled {
		return conformance.Skip("authenticator does not advertise setMinPINLength=true")
	}
	if !slices.Contains(commands, protocol.ConfigSubCommandSetMinPINLength) {
		return conformance.Fail("authenticatorConfigCommands does not contain setMinPINLength")
	}
	if _, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN); err != nil {
		return err
	} else if !clientPINPresent && (info.UvModality == nil || *info.UvModality&protocol.UserVerifyPasscodeInternal == 0) {
		return conformance.Fail("setMinPINLength requires ClientPIN or built-in passcode user verification")
	}

	return nil
}

func authenticatorConfigMinPINLengthRPIDsApplicable(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
) error {
	if err := authenticatorConfigSetMinPINLengthApplicable(fields, info, commands); err != nil {
		return err
	}
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierMinPinLength) {
		return conformance.Skip("authenticator does not advertise the minPinLength extension")
	}
	if _, present := fields[16]; !present || info.MaxRPIDsForSetMinPINLength == nil || *info.MaxRPIDsForSetMinPINLength == 0 {
		return conformance.Skip("authenticator does not advertise a positive maxRPIDsForSetMinPINLength")
	}
	if *info.MaxRPIDsForSetMinPINLength > info.EffectiveMaxMsgSize() {
		return conformance.Fail("maxRPIDsForSetMinPINLength cannot fit in the advertised maximum message size")
	}

	return nil
}

func authenticatorConfigForcePINChangeApplicable(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
) error {
	if err := authenticatorConfigSetMinPINLengthApplicable(fields, info, commands); err != nil {
		return err
	}
	clientPIN, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	if !present || !clientPIN {
		return conformance.Skip("authenticator does not have a configured ClientPIN")
	}

	return nil
}

func authenticatorConfigPINComplexityPolicyApplicable(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
) error {
	if err := authenticatorConfigSetMinPINLengthApplicable(fields, info, commands); err != nil {
		return err
	}
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy) {
		return conformance.Skip("authenticator does not advertise the pinComplexityPolicy extension")
	}

	return nil
}

func authenticatorConfigLongTouchForResetApplicable(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	commands []protocol.ConfigSubCommand,
) error {
	if _, present := fields[24]; !present || info.LongTouchForReset == nil {
		return conformance.Skip("authenticator does not advertise longTouchForReset")
	}
	if !slices.Contains(commands, protocol.ConfigSubCommandEnableLongTouchForReset) {
		return conformance.Skip("authenticator does not advertise enableLongTouchForReset")
	}

	return nil
}

func runAuthenticatorConfigEnableEnterpriseAttestation(
	ctx context.Context,
	test *conformance.TestContext,
	session authenticatorConfigSession,
) error {
	if err := test.Client().EnableEnterpriseAttestation(ctx, session.token.Protocol, session.token.Value); err != nil {
		return unexpectedCTAPStatus("authenticatorConfig enableEnterpriseAttestation", err)
	}

	fields, _, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	enabled, present, err := rawGetInfoOption(fields, protocol.OptionEnterpriseAttestation)
	if err != nil {
		return err
	}
	if !present || !enabled {
		return conformance.Fail("ep is not true after enableEnterpriseAttestation")
	}

	return nil
}

func runAuthenticatorConfigToggleAlwaysUV(
	ctx context.Context,
	test *conformance.TestContext,
	session authenticatorConfigSession,
) error {
	before, _, err := rawGetInfoOption(session.fields, protocol.OptionAlwaysUv)
	if err != nil {
		return err
	}

	commandErr := test.Client().ToggleAlwaysUV(ctx, session.token.Protocol, session.token.Value)
	fields, _, refreshErr := readGetInfo(ctx, test.CBOR())
	if refreshErr != nil {
		return refreshErr
	}
	after, present, err := rawGetInfoOption(fields, protocol.OptionAlwaysUv)
	if err != nil {
		return err
	}
	if !present {
		return conformance.Fail("alwaysUv is absent after toggleAlwaysUv")
	}
	if commandErr == nil {
		if after == before {
			return conformance.Fail("alwaysUv did not change after successful toggleAlwaysUv")
		}

		return nil
	}
	if authenticatorConfigHasCTAPStatus(commandErr, ctaptransport.CTAP2_ERR_OPERATION_DENIED) {
		if !before || !after {
			return conformance.Fail("toggleAlwaysUv was denied without preserving enabled alwaysUv")
		}

		return nil
	}

	return unexpectedCTAPStatus("authenticatorConfig toggleAlwaysUv", commandErr)
}

func runAuthenticatorConfigIncreaseMinPINLength(
	ctx context.Context,
	test *conformance.TestContext,
	session authenticatorConfigSession,
) error {
	newMinimum := session.info.EffectiveMinPINLength() + 1
	if newMinimum > session.info.EffectiveMaxPINLength() {
		return conformance.Skip("authenticator has no larger supported minimum PIN length")
	}
	if err := test.Client().SetMinPINLength(
		ctx,
		session.token.Protocol,
		session.token.Value,
		protocol.SetMinPINLengthConfigSubCommandParams{NewMinPINLength: &newMinimum},
	); err != nil {
		return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if _, present := fields[13]; !present || info.MinPINLength != newMinimum {
		return conformance.Failf("minPINLength is %d after setting %d", info.MinPINLength, newMinimum)
	}
	clientPIN, _, err := rawGetInfoOption(session.fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	if clientPIN && !info.ForcePINChange {
		return conformance.Fail("forcePINChange is false after increasing the minimum above the configured PIN length")
	}

	return nil
}

func runAuthenticatorConfigMinPINLengthRPIDs(
	ctx context.Context,
	test *conformance.TestContext,
	session authenticatorConfigSession,
) error {
	count := *session.info.MaxRPIDsForSetMinPINLength
	rpIDs := make([]string, count)
	for index := range rpIDs {
		rpIDs[index] = fmt.Sprintf("config-rp-%d.example", index)
	}
	if err := test.Client().SetMinPINLength(
		ctx,
		session.token.Protocol,
		session.token.Value,
		protocol.SetMinPINLengthConfigSubCommandParams{MinPINLengthRPIDs: rpIDs},
	); err != nil {
		return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if _, present := fields[16]; !present || info.MaxRPIDsForSetMinPINLength == nil ||
		*info.MaxRPIDsForSetMinPINLength != count {
		return conformance.Fail("maxRPIDsForSetMinPINLength changed after configuring its full RP ID list")
	}

	return nil
}

func runAuthenticatorConfigForcePINChange(
	ctx context.Context,
	test *conformance.TestContext,
	session authenticatorConfigSession,
) error {
	if err := test.Client().SetMinPINLength(
		ctx,
		session.token.Protocol,
		session.token.Value,
		protocol.SetMinPINLengthConfigSubCommandParams{ForceChangePIN: true},
	); err != nil {
		return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
	}

	_, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if !info.ForcePINChange {
		return conformance.Fail("forcePINChange is false after requesting a PIN change")
	}

	return nil
}

func runAuthenticatorConfigPINComplexityPolicy(
	ctx context.Context,
	test *conformance.TestContext,
	session authenticatorConfigSession,
) error {
	if err := test.Client().SetMinPINLength(
		ctx,
		session.token.Protocol,
		session.token.Value,
		protocol.SetMinPINLengthConfigSubCommandParams{PINComplexityPolicy: true},
	); err != nil {
		return unexpectedCTAPStatus("authenticatorConfig setMinPINLength", err)
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if _, present := fields[27]; !present || info.PinComplexityPolicy == nil || !*info.PinComplexityPolicy {
		return conformance.Fail("pinComplexityPolicy is not true after enabling it")
	}

	return nil
}

func runAuthenticatorConfigEnableLongTouchForReset(
	ctx context.Context,
	test *conformance.TestContext,
	session authenticatorConfigSession,
) error {
	if err := test.Client().EnableLongTouchForReset(ctx, session.token.Protocol, session.token.Value); err != nil {
		return unexpectedCTAPStatus("authenticatorConfig enableLongTouchForReset", err)
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if _, present := fields[24]; !present || info.LongTouchForReset == nil || !*info.LongTouchForReset {
		return conformance.Fail("longTouchForReset is not true after enabling it")
	}

	return nil
}

func authenticatorConfigHasCTAPStatus(err error, status ctaptransport.StatusCode) bool {
	var ctapErr *ctaptransport.CTAPError

	return errors.As(err, &ctapErr) && ctapErr.StatusCode == status
}

func authenticatorConfigCommandReference() conformance.RequirementRef {
	return authenticatorConfigReference(
		"6.11",
		"authenticator-config-command",
		"authenticatorConfig",
		conformance.RequirementMust,
	)
}

func authenticatorConfigEnableEnterpriseAttestationReference() conformance.RequirementRef {
	return authenticatorConfigReference(
		"6.11.1",
		"enable-enterprise-attestation",
		"enable-enterprise-attestation",
		conformance.RequirementMust,
	)
}

func authenticatorConfigToggleAlwaysUVReference() conformance.RequirementRef {
	return authenticatorConfigReference(
		"6.11.2",
		"toggle-always-require-user-verification",
		"toggle-alwaysUv",
		conformance.RequirementMust,
	)
}

func authenticatorConfigSetMinPINLengthReference(clause string) conformance.RequirementRef {
	return authenticatorConfigReference(
		"6.11.4",
		clause,
		"setMinPINLength",
		conformance.RequirementMust,
	)
}

func authenticatorConfigEnableLongTouchForResetReference() conformance.RequirementRef {
	return authenticatorConfigReference(
		"6.11.5",
		"enable-long-touch-for-reset",
		"enableLongTouchForReset",
		conformance.RequirementMust,
	)
}

func authenticatorConfigReference(
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
