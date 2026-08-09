package ctap23

import (
	"context"
	"errors"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrGetAssertionReq2SourcePath = "tests/CTAP2/Protocol/Get/Authr-GetAssertion-Req-2.js"
	authrGetAssertionReq2RPID       = "get-assertion-req-2.ctap23-conformance.example"

	TestIDAuthrGetAssertionReq2P1 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-2.p-1"
	TestIDAuthrGetAssertionReq2P2 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-2.p-2"
	TestIDAuthrGetAssertionReq2P3 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-2.p-3"
)

type authrGetAssertionReq2Definition struct {
	id          conformance.TestID
	marker      string
	name        string
	description string
	references  []conformance.RequirementRef
	run         func(*conformance.TestContext)
}

func authrGetAssertionReq2Tests(config Config) []conformance.Test {
	commandReference := authrGetAssertionReq1CommandReference()
	optionsReference := authrGetAssertionReq2Reference(
		"6.2",
		"get-assertion-options",
		"getassert-input-parameters",
	)
	unknownReference := authrGetAssertionReq2Reference(
		"6.2.2",
		"unknown-options-treated-as-absent",
		"op-getassert-step-options",
	)
	upReference := authrGetAssertionReq2Reference(
		"6.2.2",
		"up-option-sets-auth-data-flag",
		"op-getassert-step-up",
	)
	uvReference := authrGetAssertionReq2Reference(
		"6.2.2",
		"uv-option-sets-auth-data-flag",
		"op-getassert-step-performBuiltInUv",
	)
	responseReference := authrGetAssertionReq2Reference(
		"6.2",
		"get-assertion-response-auth-data",
		"authenticatorGetAssertion",
	)
	encodingReference := ctapMessageEncodingReference()

	definitions := []authrGetAssertionReq2Definition{
		{
			id:          TestIDAuthrGetAssertionReq2P1,
			marker:      "P-1",
			name:        "GetAssertion ignores an unknown option",
			description: "Sends an unknown true-valued option and requires a successful assertion",
			references: []conformance.RequirementRef{
				commandReference,
				optionsReference,
				unknownReference,
				responseReference,
				encodingReference,
			},
			run: authrGetAssertionReq2P1Run(config),
		},
		{
			id:          TestIDAuthrGetAssertionReq2P2,
			marker:      "P-2",
			name:        "GetAssertion performs user presence",
			description: "Exercises explicit up=true when GetInfo omits up or advertises it as true",
			references: []conformance.RequirementRef{
				commandReference,
				optionsReference,
				upReference,
				responseReference,
				encodingReference,
			},
			run: authrGetAssertionReq2P2Run(config, upReference),
		},
		{
			id:          TestIDAuthrGetAssertionReq2P3,
			marker:      "P-3",
			name:        "GetAssertion performs built-in user verification",
			description: "Configures advertised built-in UV when needed and requires the UV response flag",
			references: []conformance.RequirementRef{
				commandReference,
				optionsReference,
				uvReference,
				responseReference,
				encodingReference,
			},
			run: authrGetAssertionReq2P3Run(config, uvReference),
		},
	}

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: definition.description,
			Source: conformance.SourceLocation{
				Path: authrGetAssertionReq2SourcePath,
				Case: definition.marker,
			},
			References:  definition.references,
			Destructive: true,
			Run:         definition.run,
		})
	}

	return tests
}

func authrGetAssertionReq2P1Run(config Config) func(*conformance.TestContext) {
	return func(test *conformance.TestContext) {
		fixture, ok := prepareAuthrGetAssertionReq2Fixture(test, config, "p-1")
		if !ok {
			return
		}
		defer fixture.clear()

		test.Step(conformance.Step{
			ID:   "get-assertion-req-2.p-1.exchange",
			Name: "Get an assertion with an unknown option",
			Run: func(ctx context.Context) error {
				request := fixture.Request
				request.Options = map[protocol.Option]bool{
					protocol.Option("makeTea"): true,
				}
				_, err := fixture.getAssertion(ctx, test.CBOR(), request)

				return err
			},
		})
	}
}

func authrGetAssertionReq2P2Run(
	config Config,
	reference conformance.RequirementRef,
) func(*conformance.TestContext) {
	return func(test *conformance.TestContext) {
		fixture, ok := prepareAuthrGetAssertionReq2Fixture(test, config, "p-2")
		if !ok {
			return
		}
		defer fixture.clear()

		if !test.Step(conformance.Step{
			ID:         "get-assertion-req-2.p-2.applicability",
			Name:       "Check whether user presence can be requested",
			References: []conformance.RequirementRef{reference},
			Run: func(ctx context.Context) error {
				fields, _, err := readGetInfo(ctx, test.CBOR())
				if err != nil {
					return err
				}
				up, present, err := rawGetInfoOption(fields, protocol.OptionUserPresence)
				if err != nil {
					return err
				}
				if present && !up {
					return conformance.Skip("GetInfo advertises up=false")
				}

				return nil
			},
		}) {
			return
		}

		test.Step(conformance.Step{
			ID:         "get-assertion-req-2.p-2.exchange",
			Name:       "Get an assertion using explicit user presence",
			References: []conformance.RequirementRef{reference},
			Run: func(ctx context.Context) error {
				request := fixture.Request
				request.Options = map[protocol.Option]bool{
					protocol.OptionUserPresence: true,
				}
				response, err := fixture.getAssertion(ctx, test.CBOR(), request)
				if err != nil {
					return err
				}
				if !response.Response.AuthData.Flags.UserPresent() {
					return conformance.Fail("authenticatorGetAssertion authData UP flag is false")
				}

				return nil
			},
		})
	}
}

func authrGetAssertionReq2P3Run(
	config Config,
	reference conformance.RequirementRef,
) func(*conformance.TestContext) {
	return func(test *conformance.TestContext) {
		fixture, ok := prepareAuthrGetAssertionReq2Fixture(test, config, "p-3")
		if !ok {
			return
		}
		defer fixture.clear()

		var (
			info         protocol.AuthenticatorGetInfoResponse
			uvConfigured bool
		)
		if !test.Step(conformance.Step{
			ID:         "get-assertion-req-2.p-3.applicability",
			Name:       "Check whether built-in user verification is advertised",
			References: []conformance.RequirementRef{reference},
			Run: func(ctx context.Context) error {
				fields, currentInfo, err := readGetInfo(ctx, test.CBOR())
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
				if !present {
					return conformance.Skip("authenticator does not advertise the uv option")
				}
				info = currentInfo
				uvConfigured = configured

				return nil
			},
		}) {
			return
		}

		if !uvConfigured {
			if !test.Step(conformance.Step{
				ID:         "get-assertion-req-2.p-3.configure-uv",
				Name:       "Configure built-in user verification",
				References: []conformance.RequirementRef{reference},
				Run: func(ctx context.Context) error {
					return configureAuthrGetAssertionReq2UV(ctx, config, info)
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "get-assertion-req-2.p-3.refresh-uv",
				Name:       "Confirm built-in user verification is configured",
				References: []conformance.RequirementRef{reference},
				Run: func(ctx context.Context) error {
					fields, _, err := readGetInfo(ctx, test.CBOR())
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
						return errors.New(
							"ctap23: UV configurator completed but GetInfo uv is not true",
						)
					}

					return nil
				},
			}) {
				return
			}
		}

		test.Step(conformance.Step{
			ID:         "get-assertion-req-2.p-3.exchange",
			Name:       "Get an assertion using built-in user verification",
			References: []conformance.RequirementRef{reference},
			Run: func(ctx context.Context) error {
				request := fixture.Request
				request.Options = map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				}
				request.PinUvAuthParam = nil
				request.PinUvAuthProtocol = 0
				response, err := fixture.getAssertion(ctx, test.CBOR(), request)
				if err != nil {
					return err
				}
				if !response.Response.AuthData.Flags.UserVerified() {
					return conformance.Fail("authenticatorGetAssertion authData UV flag is false")
				}

				return nil
			},
		})
	}
}

func prepareAuthrGetAssertionReq2Fixture(
	test *conformance.TestContext,
	config Config,
	caseID string,
) (getAssertionFixture, bool) {
	var fixture getAssertionFixture
	ok := test.Step(conformance.Step{
		ID:   conformance.StepID("get-assertion-req-2." + caseID + ".prepare"),
		Name: "Prepare an isolated valid GetAssertion request",
		Run: func(ctx context.Context) error {
			var err error
			fixture, err = prepareGetAssertionFixture(
				ctx,
				test,
				config,
				getAssertionFixtureSpec{RPID: authrGetAssertionReq2RPID},
			)

			return err
		},
	})

	return fixture, ok
}

func configureAuthrGetAssertionReq2UV(
	ctx context.Context,
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

	return config.UVConfigurator(ctx, pin)
}

func authrGetAssertionReq2Reference(
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
