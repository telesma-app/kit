package ctap23

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/telesma-app/kit/conformance"
)

const hmacSecretSourcePath = "tests/CTAP2/Protocol/Extensions/hmacSecret.js"

const (
	TestIDHMACSecretP1 conformance.TestID = "fido.ctap2.3.hmac-secret.p-1"
	TestIDHMACSecretP2 conformance.TestID = "fido.ctap2.3.hmac-secret.p-2"
	TestIDHMACSecretP3 conformance.TestID = "fido.ctap2.3.hmac-secret.p-3"
	TestIDHMACSecretF1 conformance.TestID = "fido.ctap2.3.hmac-secret.f-1"
	TestIDHMACSecretF2 conformance.TestID = "fido.ctap2.3.hmac-secret.f-2"
	TestIDHMACSecretF3 conformance.TestID = "fido.ctap2.3.hmac-secret.f-3"
)

func hmacSecretTests(config Config) []conformance.Test {
	featureReference := hmacSecretMandatoryReference()
	createReference := hmacSecretReference(
		"make-credential-hmac-secret",
		conformance.RequirementMust,
	)
	getReference := hmacSecretReference(
		"get-assertion-hmac-secret",
		conformance.RequirementMust,
	)
	inputReference := hmacSecretReference(
		"hmac-secret-input-validation",
		conformance.RequirementMust,
	)
	protocolReference := hmacSecretProtocolOneReference()
	makeCredentialReference := authrMakeCredReq1CommandReference()
	getAssertionReference := authrGetAssertionReq1CommandReference()
	encodingReference := ctapMessageEncodingReference()

	return []conformance.Test{
		hmacSecretTest(
			config,
			TestIDHMACSecretP1,
			"P-1",
			"MakeCredential enables hmac-secret",
			"Creates both non-discoverable and discoverable credentials with the boolean hmac-secret input and requires the canonical true output",
			[]conformance.RequirementRef{
				featureReference,
				createReference,
				protocolReference,
				makeCredentialReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretSession) error {
				return runHMACSecretCredentialKinds(func(discoverable bool) error {
					_, err := hmacSecretCreateCredential(
						ctx,
						test,
						session,
						hmacSecretLabel("p-1", discoverable),
						hmacSecretRPID("p-1", discoverable),
						discoverable,
					)

					return err
				})
			},
		),
		hmacSecretTest(
			config,
			TestIDHMACSecretP2,
			"P-2",
			"No-UV hmac-secret output is stable and salt-positioned",
			"For both credential kinds, uses one credential and fresh protocol 1 key agreements to require stable one-salt output and correctly positioned two-salt output",
			[]conformance.RequirementRef{
				createReference,
				getReference,
				protocolReference,
				makeCredentialReference,
				getAssertionReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretSession) error {
				if session.alwaysUV {
					return conformance.Skip("P-2 is not applicable when alwaysUv is enabled")
				}

				return runHMACSecretCredentialKinds(func(discoverable bool) error {
					material, err := prepareHMACSecretCredentialMaterial(
						ctx, test, session, "p-2", discoverable,
					)
					if err != nil {
						return err
					}
					defer material.clear()

					first, err := hmacSecretGetAssertion(
						ctx,
						test,
						session,
						material.Credential,
						material.FirstSalt,
						nil,
						hmacSecretProtocolOmitted,
						false,
					)
					if err != nil {
						return err
					}
					defer first.clear()

					repeated, err := hmacSecretGetAssertion(
						ctx,
						test,
						session,
						material.Credential,
						material.FirstSalt,
						nil,
						hmacSecretProtocolOmitted,
						false,
					)
					if err != nil {
						return err
					}
					defer repeated.clear()

					twoSalt, err := hmacSecretGetAssertion(
						ctx,
						test,
						session,
						material.Credential,
						material.SecondSalt,
						material.FirstSalt,
						hmacSecretProtocol,
						false,
					)
					if err != nil {
						return err
					}
					defer twoSalt.clear()

					if !bytes.Equal(first.First, repeated.First) {
						return conformance.Fail("the same credential and salt produced different no-UV hmac-secret outputs")
					}
					if !bytes.Equal(first.First, twoSalt.Second) {
						return conformance.Fail("the first salt output did not move intact to the second two-salt output position")
					}
					if bytes.Equal(twoSalt.First, twoSalt.Second) {
						return conformance.Fail("distinct salts produced equal hmac-secret outputs")
					}

					return nil
				})
			},
		),
		hmacSecretTest(
			config,
			TestIDHMACSecretP3,
			"P-3",
			"UV changes both hmac-secret outputs",
			"For both credential kinds, uses one credential and identical salts to require different no-UV and UV outputs in both positions",
			[]conformance.RequirementRef{
				createReference,
				getReference,
				protocolReference,
				makeCredentialReference,
				getAssertionReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretSession) error {
				if session.alwaysUV {
					return conformance.Skip("P-3 is not applicable when alwaysUv is enabled")
				}

				return runHMACSecretCredentialKinds(func(discoverable bool) error {
					material, err := prepareHMACSecretCredentialMaterial(
						ctx, test, session, "p-3", discoverable,
					)
					if err != nil {
						return err
					}
					defer material.clear()

					unverified, err := hmacSecretGetAssertion(
						ctx,
						test,
						session,
						material.Credential,
						material.FirstSalt,
						material.SecondSalt,
						hmacSecretProtocol,
						false,
					)
					if err != nil {
						return err
					}
					defer unverified.clear()

					verified, err := hmacSecretGetAssertion(
						ctx,
						test,
						session,
						material.Credential,
						material.FirstSalt,
						material.SecondSalt,
						hmacSecretProtocol,
						true,
					)
					if err != nil {
						return err
					}
					defer verified.clear()

					if bytes.Equal(unverified.First, verified.First) {
						return conformance.Fail("UV did not change the first hmac-secret output")
					}
					if bytes.Equal(unverified.Second, verified.Second) {
						return conformance.Fail("UV did not change the second hmac-secret output")
					}

					return nil
				})
			},
		),
		hmacSecretTest(
			config,
			TestIDHMACSecretF1,
			"F-1",
			"MakeCredential rejects a non-boolean hmac-secret input",
			"Sends a text-string hmac-secret input for both non-discoverable and discoverable credentials and accepts any CTAP error as required by the source case",
			[]conformance.RequirementRef{
				createReference,
				inputReference,
				protocolReference,
				makeCredentialReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretSession) error {
				return runHMACSecretCredentialKinds(func(discoverable bool) error {
					return hmacSecretMalformedMakeCredential(
						ctx,
						test,
						session,
						hmacSecretLabel("f-1", discoverable),
						hmacSecretRPID("f-1", discoverable),
						discoverable,
					)
				})
			},
		),
		hmacSecretTest(
			config,
			TestIDHMACSecretF2,
			"F-2",
			"GetAssertion rejects a short first salt",
			"Creates both credential kinds and requires CTAP1_ERR_INVALID_PARAMETER for a protocol 1 salt plaintext shorter than 32 bytes",
			[]conformance.RequirementRef{
				createReference,
				getReference,
				inputReference,
				protocolReference,
				makeCredentialReference,
				getAssertionReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretSession) error {
				return runHMACSecretCredentialKinds(func(discoverable bool) error {
					label := hmacSecretLabel("f-2", discoverable)
					credential, err := hmacSecretCreateCredential(
						ctx,
						test,
						session,
						label,
						hmacSecretRPID("f-2", discoverable),
						discoverable,
					)
					if err != nil {
						return err
					}

					salt := hmacSecretSalt(label + "-short-first")
					defer clear(salt)

					return hmacSecretMalformedGetAssertion(ctx, test, session, credential, salt[:16])
				})
			},
		),
		hmacSecretTest(
			config,
			TestIDHMACSecretF3,
			"F-3",
			"GetAssertion rejects a short second salt",
			"Creates both credential kinds and requires CTAP1_ERR_INVALID_PARAMETER for a 32-byte first salt followed by a short second salt",
			[]conformance.RequirementRef{
				createReference,
				getReference,
				inputReference,
				protocolReference,
				makeCredentialReference,
				getAssertionReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretSession) error {
				return runHMACSecretCredentialKinds(func(discoverable bool) error {
					label := hmacSecretLabel("f-3", discoverable)
					credential, err := hmacSecretCreateCredential(
						ctx,
						test,
						session,
						label,
						hmacSecretRPID("f-3", discoverable),
						discoverable,
					)
					if err != nil {
						return err
					}

					firstSalt := hmacSecretSalt(label + "-first")
					defer clear(firstSalt)
					secondSalt := hmacSecretSalt(label + "-short-second")
					defer clear(secondSalt)
					plaintext := make([]byte, 0, 48)
					plaintext = append(plaintext, firstSalt...)
					plaintext = append(plaintext, secondSalt[:16]...)
					defer clear(plaintext)

					return hmacSecretMalformedGetAssertion(ctx, test, session, credential, plaintext)
				})
			},
		),
	}
}

func hmacSecretTest(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	description string,
	references []conformance.RequirementRef,
	run func(context.Context, *conformance.TestContext, *hmacSecretSession) error,
) conformance.Test {
	featureReference := hmacSecretMandatoryReference()
	resetRequirement := resetReference()
	powerCycleRequirement := clientPINPowerCycleReference()
	testReferences := make([]conformance.RequirementRef, 0, len(references)+3)
	testReferences = append(testReferences, featureReference)
	testReferences = append(testReferences, references...)
	testReferences = append(testReferences, resetRequirement, powerCycleRequirement)

	return conformance.Test{
		ID:          id,
		Name:        name,
		Description: description,
		Source: conformance.SourceLocation{
			Path: hmacSecretSourcePath,
			Case: marker,
		},
		References:  testReferences,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			if !test.Step(conformance.Step{
				ID:         "hmac-secret.applicability",
				Name:       "Check hmac-secret and protocol 1 applicability",
				References: []conformance.RequirementRef{featureReference},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}

					return hmacSecretApplicability(fields, info, config)
				},
			}) {
				return
			}

			if config.PowerCycler == nil {
				test.Step(conformance.Step{
					ID:         "hmac-secret.environment",
					Name:       "Require authenticator lifecycle control",
					References: []conformance.RequirementRef{powerCycleRequirement},
					Run: func(context.Context) error {
						return errors.New("ctap23: authenticator power cycler is required for hmac-secret tests")
					},
				})

				return
			}

			test.Cleanup(hmacSecretCleanupStep(test, config, resetRequirement, powerCycleRequirement))
			if !test.Step(hmacSecretResetStep(test, config, resetRequirement, powerCycleRequirement)) {
				return
			}

			var session hmacSecretSession
			if !test.Step(conformance.Step{
				ID:   "hmac-secret.authorization",
				Name: "Prepare an exact PIN/UV protocol 1 authorization session",
				References: []conformance.RequirementRef{
					hmacSecretProtocolOneReference(),
				},
				Run: func(ctx context.Context) error {
					return prepareHMACSecretSession(ctx, test, config, &session)
				},
			}) {
				return
			}
			defer session.clear()

			test.Step(conformance.Step{
				ID:         conformance.StepID("hmac-secret." + strings.ToLower(marker) + ".command"),
				Name:       name,
				References: references,
				Run: func(ctx context.Context) error {
					return run(ctx, test, &session)
				},
			})
		},
	}
}

func runHMACSecretCredentialKinds(run func(bool) error) error {
	for _, discoverable := range []bool{false, true} {
		if err := run(discoverable); err != nil {
			return err
		}
	}

	return nil
}

func hmacSecretLabel(marker string, discoverable bool) string {
	kind := "non-discoverable"
	if discoverable {
		kind = "discoverable"
	}

	return marker + "-" + kind
}

func hmacSecretResetStep(
	test *conformance.TestContext,
	config Config,
	resetRequirement conformance.RequirementRef,
	powerCycleRequirement conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "hmac-secret.reset",
		Name: "Reset and rebind the authenticator before the case",
		References: []conformance.RequirementRef{
			resetRequirement,
			powerCycleRequirement,
		},
		Run: func(ctx context.Context) error {
			return hmacSecretResetAndRebind(ctx, test, config)
		},
	}
}

func hmacSecretCleanupStep(
	test *conformance.TestContext,
	config Config,
	resetRequirement conformance.RequirementRef,
	powerCycleRequirement conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "hmac-secret.cleanup",
		Name: "Reset and rebind the authenticator after the case",
		References: []conformance.RequirementRef{
			resetRequirement,
			powerCycleRequirement,
		},
		Run: func(ctx context.Context) error {
			return hmacSecretResetAndRebind(ctx, test, config)
		},
	}
}

func hmacSecretResetAndRebind(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) error {
	if err := config.PowerCycler(ctx); err != nil {
		return err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return err
	}

	return config.PowerCycler(ctx)
}

func hmacSecretReference(
	clause string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:12.7:" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       "12.7",
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-hmac-secret-extension",
		Level: level,
	}
}

func hmacSecretMandatoryReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:9:hmac-secret-mandatory",
		Specification: conformance.SpecificationCTAP23,
		Section:       "9",
		Clause:        "hmac-secret-mandatory",
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#mandatory-features",
		Level: conformance.RequirementMust,
	}
}

func hmacSecretProtocolOneReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.6:pin-uv-auth-protocol-one",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.6",
		Clause:        "pin-uv-auth-protocol-one",
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinUvAuthProtocolOne",
		Level: conformance.RequirementMust,
	}
}
