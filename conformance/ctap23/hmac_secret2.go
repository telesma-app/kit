package ctap23

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const hmacSecret2SourcePath = "tests/CTAP2/Protocol/Extensions/hmacSecret2.js"

const (
	TestIDHMACSecret2P1 conformance.TestID = "fido.ctap2.3.hmac-secret2.p-1"
	TestIDHMACSecret2P2 conformance.TestID = "fido.ctap2.3.hmac-secret2.p-2"
	TestIDHMACSecret2P3 conformance.TestID = "fido.ctap2.3.hmac-secret2.p-3"
	TestIDHMACSecret2F1 conformance.TestID = "fido.ctap2.3.hmac-secret2.f-1"
	TestIDHMACSecret2F2 conformance.TestID = "fido.ctap2.3.hmac-secret2.f-2"
	TestIDHMACSecret2F3 conformance.TestID = "fido.ctap2.3.hmac-secret2.f-3"
)

func hmacSecret2Tests(config Config) []conformance.Test {
	createReference := hmacSecretReference("make-credential-hmac-secret", conformance.RequirementMust)
	getReference := hmacSecretReference("get-assertion-hmac-secret", conformance.RequirementMust)
	inputReference := hmacSecretReference("hmac-secret-input-validation", conformance.RequirementMust)
	protocolReference := hmacSecretProtocolTwoReference()
	makeCredentialReference := authrMakeCredReq1CommandReference()
	getAssertionReference := authrGetAssertionReq1CommandReference()
	encodingReference := ctapMessageEncodingReference()

	return []conformance.Test{
		hmacSecret2Test(
			config,
			TestIDHMACSecret2P1,
			"P-1",
			"Protocol 2 MakeCredential enables hmac-secret",
			[]conformance.RequirementRef{
				createReference,
				protocolReference,
				makeCredentialReference,
				encodingReference,
			},
			func(ctx context.Context, test *conformance.TestContext, session *hmacSecretSession) error {
				return runHMACSecretCredentialKinds(func(discoverable bool) error {
					credential, err := hmacSecretCreateCredential(
						ctx,
						test,
						session,
						hmacSecretLabel("hmac-secret2-p-1", discoverable),
						hmacSecret2RPID("p-1", discoverable),
						discoverable,
					)
					defer clear(credential.ID)

					return err
				})
			},
		),
		hmacSecret2Test(
			config,
			TestIDHMACSecret2P2,
			"P-2",
			"Protocol 2 no-UV outputs are stable and salt-positioned",
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
					material, err := prepareHMACSecret2CredentialMaterial(
						ctx,
						test,
						session,
						"p-2",
						discoverable,
					)
					if err != nil {
						return err
					}
					defer clearHMACSecretCredentialMaterial(&material)

					first, err := hmacSecretGetAssertion(
						ctx, test, session, material.Credential,
						material.FirstSalt, nil, protocol.PinUvAuthProtocolTwo, false,
					)
					if err != nil {
						return err
					}
					defer first.clear()

					repeated, err := hmacSecretGetAssertion(
						ctx, test, session, material.Credential,
						material.FirstSalt, nil, protocol.PinUvAuthProtocolTwo, false,
					)
					if err != nil {
						return err
					}
					defer repeated.clear()

					twoSalt, err := hmacSecretGetAssertion(
						ctx, test, session, material.Credential,
						material.SecondSalt, material.FirstSalt,
						protocol.PinUvAuthProtocolTwo, false,
					)
					if err != nil {
						return err
					}
					defer twoSalt.clear()

					if !bytes.Equal(first.First, repeated.First) {
						return conformance.Fail("protocol 2 repeated one-salt output changed")
					}
					if !bytes.Equal(first.First, twoSalt.Second) {
						return conformance.Fail("protocol 2 salt output did not follow its two-salt position")
					}
					if bytes.Equal(twoSalt.First, twoSalt.Second) {
						return conformance.Fail("protocol 2 distinct salts produced equal outputs")
					}

					return nil
				})
			},
		),
		hmacSecret2Test(
			config,
			TestIDHMACSecret2P3,
			"P-3",
			"Protocol 2 UV changes both hmac-secret outputs",
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
					material, err := prepareHMACSecret2CredentialMaterial(
						ctx, test, session, "p-3", discoverable,
					)
					if err != nil {
						return err
					}
					defer clearHMACSecretCredentialMaterial(&material)

					unverified, err := hmacSecretGetAssertion(
						ctx, test, session, material.Credential,
						material.FirstSalt, material.SecondSalt,
						protocol.PinUvAuthProtocolTwo, false,
					)
					if err != nil {
						return err
					}
					defer unverified.clear()

					verified, err := hmacSecretGetAssertion(
						ctx, test, session, material.Credential,
						material.FirstSalt, material.SecondSalt,
						protocol.PinUvAuthProtocolTwo, true,
					)
					if err != nil {
						return err
					}
					defer verified.clear()

					if bytes.Equal(unverified.First, verified.First) {
						return conformance.Fail("protocol 2 UV did not change the first output")
					}
					if bytes.Equal(unverified.Second, verified.Second) {
						return conformance.Fail("protocol 2 UV did not change the second output")
					}

					return nil
				})
			},
		),
		hmacSecret2Test(
			config,
			TestIDHMACSecret2F1,
			"F-1",
			"Protocol 2 rejects a non-boolean hmac-secret input",
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
						hmacSecretLabel("hmac-secret2-f-1", discoverable),
						hmacSecret2RPID("f-1", discoverable),
						discoverable,
					)
				})
			},
		),
		hmacSecret2Test(
			config,
			TestIDHMACSecret2F2,
			"F-2",
			"Protocol 2 rejects a short first salt",
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
					credential, err := hmacSecret2Credential(
						ctx, test, session, "f-2", discoverable,
					)
					if err != nil {
						return err
					}
					defer clear(credential.ID)

					salt := hmacSecretSalt(hmacSecretLabel("hmac-secret2-f-2", discoverable))
					defer clear(salt)

					return hmacSecretMalformedGetAssertion(ctx, test, session, credential, salt[:16])
				})
			},
		),
		hmacSecret2Test(
			config,
			TestIDHMACSecret2F3,
			"F-3",
			"Protocol 2 rejects a short second salt",
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
					credential, err := hmacSecret2Credential(
						ctx, test, session, "f-3", discoverable,
					)
					if err != nil {
						return err
					}
					defer clear(credential.ID)

					first := hmacSecretSalt(hmacSecretLabel("hmac-secret2-f-3-first", discoverable))
					defer clear(first)
					second := hmacSecretSalt(hmacSecretLabel("hmac-secret2-f-3-second", discoverable))
					defer clear(second)
					plaintext := make([]byte, 0, 48)
					plaintext = append(plaintext, first...)
					plaintext = append(plaintext, second[:16]...)
					defer clear(plaintext)

					return hmacSecretMalformedGetAssertion(ctx, test, session, credential, plaintext)
				})
			},
		),
	}
}

func hmacSecret2Test(
	config Config,
	id conformance.TestID,
	marker string,
	name string,
	references []conformance.RequirementRef,
	run func(context.Context, *conformance.TestContext, *hmacSecretSession) error,
) conformance.Test {
	featureReference := hmacSecretMandatoryReference()
	protocolReference := hmacSecretProtocolTwoReference()
	resetRequirement := resetReference()
	powerCycleRequirement := clientPINPowerCycleReference()
	testReferences := make([]conformance.RequirementRef, 0, len(references)+3)
	testReferences = append(testReferences, featureReference)
	testReferences = append(testReferences, references...)
	testReferences = append(testReferences, resetRequirement, powerCycleRequirement)

	return conformance.Test{
		ID:          id,
		Name:        name,
		Description: name,
		Source: conformance.SourceLocation{
			Path: hmacSecret2SourcePath,
			Case: marker,
		},
		References:  testReferences,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			if !test.Step(conformance.Step{
				ID:   "hmac-secret2.applicability",
				Name: "Check hmac-secret and strict protocol 2 applicability",
				References: []conformance.RequirementRef{
					featureReference,
					protocolReference,
				},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}

					return hmacSecret2Applicability(fields, info, config)
				},
			}) {
				return
			}

			if config.PowerCycler == nil {
				test.Step(conformance.Step{
					ID:   "hmac-secret2.environment",
					Name: "Require authenticator lifecycle control",
					Run: func(context.Context) error {
						return errors.New("ctap23: authenticator power cycler is required for hmac-secret2 tests")
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
				ID:         "hmac-secret2.authorization",
				Name:       "Prepare an exact PIN/UV protocol 2 authorization session",
				References: []conformance.RequirementRef{protocolReference},
				Run: func(ctx context.Context) error {
					return prepareHMACSecretSessionForProtocol(
						ctx,
						test,
						config,
						&session,
						protocol.PinUvAuthProtocolTwo,
					)
				},
			}) {
				return
			}
			defer session.clear()

			test.Step(conformance.Step{
				ID:         conformance.StepID("hmac-secret2." + strings.ToLower(marker) + ".command"),
				Name:       name,
				References: references,
				Run: func(ctx context.Context) error {
					return run(ctx, test, &session)
				},
			})
		},
	}
}

func hmacSecret2Applicability(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
) error {
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		return conformance.Fail("FIDO_2_3 authenticator does not advertise the mandatory hmac-secret extension")
	}

	return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolTwo)
}

func prepareHMACSecret2CredentialMaterial(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretSession,
	marker string,
	discoverable bool,
) (hmacSecretCredentialMaterial, error) {
	credential, err := hmacSecret2Credential(ctx, test, session, marker, discoverable)
	if err != nil {
		return hmacSecretCredentialMaterial{}, err
	}
	label := hmacSecretLabel("hmac-secret2-"+marker, discoverable)

	return hmacSecretCredentialMaterial{
		Credential: credential,
		FirstSalt:  hmacSecretSalt(label + "-first"),
		SecondSalt: hmacSecretSalt(label + "-second"),
	}, nil
}

func hmacSecret2Credential(
	ctx context.Context,
	test *conformance.TestContext,
	session *hmacSecretSession,
	marker string,
	discoverable bool,
) (hmacSecretCredential, error) {
	return hmacSecretCreateCredential(
		ctx,
		test,
		session,
		hmacSecretLabel("hmac-secret2-"+marker, discoverable),
		hmacSecret2RPID(marker, discoverable),
		discoverable,
	)
}

func clearHMACSecretCredentialMaterial(material *hmacSecretCredentialMaterial) {
	clear(material.Credential.ID)
	material.Credential.ID = nil
	material.clear()
}

func hmacSecret2RPID(marker string, discoverable bool) string {
	return "hmac-secret2-" + hmacSecretLabel(marker, discoverable) + ".ctap23-conformance.example"
}

func hmacSecretProtocolTwoReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.7:pin-uv-auth-protocol-two",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.7",
		Clause:        "pin-uv-auth-protocol-two",
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinUvAuthProtocolTwo",
		Level: conformance.RequirementMust,
	}
}
