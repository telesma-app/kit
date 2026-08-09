package ctap23

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrMakeCredReq6SourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-6.js"
	authrMakeCredReq6RPID       = "make-cred-req-6.ctap23-conformance.example"

	TestIDAuthrMakeCredReq6P1 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-6.p-1"
	TestIDAuthrMakeCredReq6P2 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-6.p-2"
	TestIDAuthrMakeCredReq6P3 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-6.p-3"
	TestIDAuthrMakeCredReq6F1 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-6.f-1"
)

type authrMakeCredReq6Definition struct {
	id          conformance.TestID
	marker      string
	name        string
	description string
	references  []conformance.RequirementRef
	run         func(*conformance.TestContext)
}

func authrMakeCredReq6Tests(config Config) []conformance.Test {
	commandReference := authrMakeCredReq1CommandReference()
	optionsReference := authrMakeCredReq6Reference(
		"6.1",
		"make-credential-options",
		"makecred-input-parameters",
	)
	unknownReference := authrMakeCredReq6Reference(
		"6.1.2",
		"unknown-options-treated-as-absent",
		"op-makecred-step-options",
	)
	uvReference := authrMakeCredReq6Reference(
		"6.1.2",
		"uv-option-sets-auth-data-flag",
		"op-makecred-step-performBuiltInUv",
	)
	upReference := authrMakeCredReq6Reference(
		"6.1.2",
		"up-option-sets-auth-data-flag",
		"op-makecred-step-up",
	)
	upFalseReference := authrMakeCredReq6Reference(
		"6.1.2",
		"up-false-returns-invalid-option",
		"op-makecred-step-up",
	)
	responseReference := makeCredentialResponseRequiredReference()
	encodingReference := ctapMessageEncodingReference()

	definitions := []authrMakeCredReq6Definition{
		{
			id:          TestIDAuthrMakeCredReq6P1,
			marker:      "P-1",
			name:        "MakeCredential ignores an unknown option",
			description: "Sends an unknown true-valued option and requires successful credential creation",
			references: []conformance.RequirementRef{
				commandReference,
				optionsReference,
				unknownReference,
				responseReference,
				encodingReference,
			},
			run: authrMakeCredReq6FixtureRun(config, "P-1", nil, func(
				ctx context.Context,
				test *conformance.TestContext,
				fixture makeCredentialFixture,
			) error {
				request := fixture.Request
				request.Options = map[protocol.Option]bool{
					protocol.Option("makeTea"): true,
				}
				_, err := fixture.makeCredential(ctx, test.CBOR(), request)

				return err
			}),
		},
		{
			id:          TestIDAuthrMakeCredReq6P2,
			marker:      "P-2",
			name:        "MakeCredential performs built-in user verification",
			description: "Configures advertised built-in UV when needed and requires the UV response flag",
			references: []conformance.RequirementRef{
				commandReference,
				optionsReference,
				uvReference,
				responseReference,
				encodingReference,
			},
			run: authrMakeCredReq6P2Run(config, uvReference),
		},
		{
			id:          TestIDAuthrMakeCredReq6P3,
			marker:      "P-3",
			name:        "MakeCredential performs user presence",
			description: "Exercises explicit up=true when GetInfo omits up or advertises it as true",
			references: []conformance.RequirementRef{
				commandReference,
				optionsReference,
				upReference,
				responseReference,
				encodingReference,
			},
			run: authrMakeCredReq6FixtureRun(
				config,
				"P-3",
				authrMakeCredReq6P3Applicability,
				func(
					ctx context.Context,
					test *conformance.TestContext,
					fixture makeCredentialFixture,
				) error {
					request := fixture.Request
					request.Options = map[protocol.Option]bool{
						protocol.OptionUserPresence: true,
					}
					response, err := fixture.makeCredential(ctx, test.CBOR(), request)
					if err != nil {
						return err
					}
					if !response.AuthData.Flags.UserPresent() {
						return conformance.Fail("authenticatorMakeCredential authData UP flag is false")
					}

					return nil
				},
			),
		},
		{
			id:          TestIDAuthrMakeCredReq6F1,
			marker:      "F-1",
			name:        "MakeCredential rejects up=false",
			description: "Requires the exact CTAP2_ERR_INVALID_OPTION response for options.up=false",
			references: []conformance.RequirementRef{
				commandReference,
				optionsReference,
				upFalseReference,
			},
			run: authrMakeCredReq6FixtureRun(config, "F-1", nil, func(
				ctx context.Context,
				test *conformance.TestContext,
				fixture makeCredentialFixture,
			) error {
				fields := fixture.rawFields()
				fields[7] = map[string]any{string(protocol.OptionUserPresence): false}
				_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)

				return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_INVALID_OPTION)
			}),
		},
	}

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: definition.description,
			Source: conformance.SourceLocation{
				Path: authrMakeCredReq6SourcePath,
				Case: definition.marker,
			},
			References:  definition.references,
			Destructive: true,
			Run:         definition.run,
		})
	}

	return tests
}

func authrMakeCredReq6FixtureRun(
	config Config,
	marker string,
	applicability func(map[uint64]cbor.RawMessage) error,
	exchange func(context.Context, *conformance.TestContext, makeCredentialFixture) error,
) func(*conformance.TestContext) {
	caseID := strings.ToLower(marker)

	return func(test *conformance.TestContext) {
		if applicability != nil && !test.Step(conformance.Step{
			ID:   conformance.StepID("make-cred-req-6." + caseID + ".applicability"),
			Name: "Check the advertised option applicability",
			Run: func(ctx context.Context) error {
				fields, _, err := readGetInfo(ctx, test.CBOR())
				if err != nil {
					return err
				}

				return applicability(fields)
			},
		}) {
			return
		}

		var fixture makeCredentialFixture
		if !test.Step(conformance.Step{
			ID:   conformance.StepID("make-cred-req-6." + caseID + ".prepare"),
			Name: "Prepare an isolated valid MakeCredential request",
			Run: func(ctx context.Context) error {
				var err error
				fixture, err = prepareMakeCredentialFixture(ctx, test, config, authrMakeCredReq6RPID)

				return err
			},
		}) {
			return
		}
		defer fixture.clear()
		if applicability != nil && !test.Step(conformance.Step{
			ID:   conformance.StepID("make-cred-req-6." + caseID + ".current-applicability"),
			Name: "Recheck the advertised option after reset",
			Run: func(ctx context.Context) error {
				fields, _, err := readGetInfo(ctx, test.CBOR())
				if err != nil {
					return err
				}

				return applicability(fields)
			},
		}) {
			return
		}

		test.Step(conformance.Step{
			ID:   conformance.StepID("make-cred-req-6." + caseID + ".exchange"),
			Name: "Send the MakeCredential options case",
			Run: func(ctx context.Context) error {
				return exchange(ctx, test, fixture)
			},
		})
	}
}

func authrMakeCredReq6P2Run(
	config Config,
	uvReference conformance.RequirementRef,
) func(*conformance.TestContext) {
	return func(test *conformance.TestContext) {
		if !test.Step(conformance.Step{
			ID:         "make-cred-req-6.p-2.applicability",
			Name:       "Check whether built-in user verification is advertised",
			References: []conformance.RequirementRef{uvReference},
			Run: func(ctx context.Context) error {
				fields, _, err := readGetInfo(ctx, test.CBOR())
				if err != nil {
					return err
				}
				_, present, err := rawGetInfoOption(
					fields,
					protocol.OptionUserVerification,
				)
				if err != nil {
					return err
				}
				if !present {
					return conformance.Skip("authenticator does not advertise the uv option")
				}

				return nil
			},
		}) {
			return
		}

		var fixture makeCredentialFixture
		var uvConfigured bool
		if !test.Step(conformance.Step{
			ID:         "make-cred-req-6.p-2.prepare",
			Name:       "Reset the authenticator and prepare an unauthenticated request",
			References: []conformance.RequirementRef{uvReference},
			Run: func(ctx context.Context) error {
				var err error
				fixture, uvConfigured, err = prepareAuthrMakeCredReq6UVFixture(ctx, test, config)

				return err
			},
		}) {
			return
		}
		defer fixture.clear()

		if !uvConfigured {
			if !test.Step(conformance.Step{
				ID:         "make-cred-req-6.p-2.configure-uv",
				Name:       "Configure built-in user verification",
				References: []conformance.RequirementRef{uvReference},
				Run: func(ctx context.Context) error {
					return configureAuthrMakeCredReq6UV(ctx, test, config, fixture.Info)
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "make-cred-req-6.p-2.refresh-uv",
				Name:       "Confirm built-in user verification is configured",
				References: []conformance.RequirementRef{uvReference},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}
					configured, present, err := rawGetInfoOption(
						fields,
						protocol.OptionUserVerification,
					)
					if err != nil {
						return err
					}
					if !present || !configured {
						return errors.New("ctap23: UV configurator completed but GetInfo uv is not true")
					}
					fixture.Info = info

					return nil
				},
			}) {
				return
			}
		}

		test.Step(conformance.Step{
			ID:         "make-cred-req-6.p-2.exchange",
			Name:       "Create a credential using built-in user verification",
			References: []conformance.RequirementRef{uvReference},
			Run: func(ctx context.Context) error {
				request := fixture.Request
				request.Options = map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				}
				request.PinUvAuthParam = nil
				request.PinUvAuthProtocol = 0
				response, err := fixture.makeCredential(ctx, test.CBOR(), request)
				if err != nil {
					return err
				}
				if !response.AuthData.Flags.UserVerified() {
					return conformance.Fail("authenticatorMakeCredential authData UV flag is false")
				}

				return nil
			},
		})
	}
}

func prepareAuthrMakeCredReq6UVFixture(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) (makeCredentialFixture, bool, error) {
	// P-2 deliberately prepares an unauthenticated request: the pinned
	// configureUvPin helper establishes built-in UV out of band, and the case
	// must send options.uv=true without pinUvAuthParam or pinUvAuthProtocol.
	if config.PowerCycler == nil {
		return makeCredentialFixture{}, false, errors.New(
			"ctap23: authenticator power cycler is required for MakeCredential request tests",
		)
	}

	test.Cleanup(makeCredentialFixtureCleanupStep(test, config))
	if err := config.PowerCycler(ctx); err != nil {
		return makeCredentialFixture{}, false, err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return makeCredentialFixture{}, false, err
	}
	if err := config.PowerCycler(ctx); err != nil {
		return makeCredentialFixture{}, false, err
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return makeCredentialFixture{}, false, err
	}
	uvConfigured, present, err := rawGetInfoOption(
		fields,
		protocol.OptionUserVerification,
	)
	if err != nil {
		return makeCredentialFixture{}, false, err
	}
	if !present {
		return makeCredentialFixture{}, false, conformance.Fail(
			"GetInfo uv option disappeared after reset",
		)
	}
	algorithms, err := makeCredentialFixtureAlgorithms(info.Algorithms)
	if err != nil {
		return makeCredentialFixture{}, false, err
	}

	return makeCredentialFixture{
		Info: info,
		Request: protocol.AuthenticatorMakeCredentialRequest{
			ClientDataHash: slices.Clone(makeCredentialFixtureClientDataHash[:]),
			RP: credential.PublicKeyCredentialRpEntity{
				ID:   authrMakeCredReq6RPID,
				Name: makeCredentialFixtureRPName,
			},
			User: credential.PublicKeyCredentialUserEntity{
				ID:          slices.Clone(makeCredentialFixtureUserID[:]),
				Name:        makeCredentialFixtureUserName,
				DisplayName: makeCredentialFixtureUserDisplayName,
			},
			PubKeyCredParams: algorithms,
		},
	}, uvConfigured, nil
}

func configureAuthrMakeCredReq6UV(
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

	pinProtocol, err := authrMakeCredReq6PINProtocol(info.PinUvAuthProtocols)
	if err != nil {
		return err
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

	keyAgreement, err := test.Client().GetKeyAgreement(ctx, pinProtocol)
	if err != nil {
		return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	if err := test.Client().SetPIN(ctx, pinProtocol, keyAgreement, string(pin)); err != nil {
		return unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	return config.UVConfigurator(ctx, pin)
}

func authrMakeCredReq6PINProtocol(
	protocols []protocol.PinUvAuthProtocol,
) (protocol.PinUvAuthProtocol, error) {
	for _, candidate := range []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolTwo,
		protocol.PinUvAuthProtocolOne,
	} {
		if slices.Contains(protocols, candidate) {
			return candidate, nil
		}
	}

	return 0, errors.New("ctap23: built-in UV configuration requires an advertised PIN/UV protocol")
}

func authrMakeCredReq6P3Applicability(fields map[uint64]cbor.RawMessage) error {
	up, present, err := rawGetInfoOption(fields, protocol.OptionUserPresence)
	if err != nil {
		return err
	}
	if present && !up {
		return conformance.Skip("GetInfo advertises up=false")
	}

	return nil
}

func authrMakeCredReq6Reference(
	section string,
	clause string,
	fragment string,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:" + section + ":" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       section,
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#" + fragment,
		Level: conformance.RequirementConstraint,
	}
}
