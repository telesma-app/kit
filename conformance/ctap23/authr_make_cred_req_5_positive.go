package ctap23

import (
	"bytes"
	"context"
	"strings"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrMakeCredReq5PositiveSourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-5.js"
	authrMakeCredReq5PositiveRPID       = "make-cred-req-5-positive.ctap23-conformance.example"

	TestIDAuthrMakeCredReq5PositiveP1 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.p-1"
	TestIDAuthrMakeCredReq5PositiveP2 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.p-2"
	TestIDAuthrMakeCredReq5PositiveP3 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.p-3"
)

type authrMakeCredReq5PositiveCase struct {
	id          conformance.TestID
	marker      string
	name        string
	description string
	reference   conformance.RequirementRef
	mutate      func(makeCredentialFixture, map[uint64]any)
}

func authrMakeCredReq5PositiveTests(config Config) []conformance.Test {
	commandReference := authrMakeCredReq1CommandReference()
	excludeListReference := authrMakeCredReq5PositiveReference(
		"exclude-list-unknown-credential-type",
	)
	attestationFormatsReference := authrMakeCredReq5PositiveReference(
		"attestation-formats-preference-array-of-strings",
	)

	cases := []authrMakeCredReq5PositiveCase{
		{
			id:          TestIDAuthrMakeCredReq5PositiveP1,
			marker:      "P-1",
			name:        "MakeCredential ignores an unknown exclude-list credential type",
			description: "Validates successful credential creation with a well-formed exclude list containing an unknown credential type",
			reference:   excludeListReference,
			mutate: func(_ makeCredentialFixture, fields map[uint64]any) {
				fields[5] = []any{
					map[string]any{
						"type": credential.PublicKeyCredentialTypePublicKey,
						"id":   bytes.Repeat([]byte{0x51}, 32),
					},
					map[string]any{
						"type": "mangoPapayaCoconutIamNotAPublicKey",
						"id":   bytes.Repeat([]byte{0x52}, 32),
					},
				}
			},
		},
		{
			id:     TestIDAuthrMakeCredReq5PositiveP2,
			marker: "P-2",
			name:   "MakeCredential accepts an attestation-format preference list",
			description: "Corrects the pinned source's omitted generator argument and sends " +
				"the intended attestationFormatsPreference field",
			reference: attestationFormatsReference,
			mutate: func(fixture makeCredentialFixture, fields map[uint64]any) {
				formats := fixture.Info.AttestationFormats
				if len(formats) == 0 {
					formats = []attestation.AttestationStatementFormatIdentifier{
						attestation.AttestationStatementFormatIdentifierPacked,
						attestation.AttestationStatementFormatIdentifierTPM,
					}
				}
				fields[11] = formats
			},
		},
		{
			id:     TestIDAuthrMakeCredReq5PositiveP3,
			marker: "P-3",
			name:   "MakeCredential accepts the none attestation-format preference",
			description: "Corrects the pinned source's omitted generator argument and sends " +
				"the intended none attestationFormatsPreference",
			reference: attestationFormatsReference,
			mutate: func(_ makeCredentialFixture, fields map[uint64]any) {
				fields[11] = []attestation.AttestationStatementFormatIdentifier{
					attestation.AttestationStatementFormatIdentifierNone,
				}
			},
		},
	}

	// Source adjudication: P-2 and P-3 assign attestationFormatsPreference,
	// but their generator calls omit the argument and the pinned generator has
	// no key 0x0B at all. Sending that exact wire would only repeat a baseline
	// MakeCredential. The port follows each case's prose and current CTAP 2.3 by
	// placing the intended preference array in request key 0x0B.
	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		definition := definition
		references := []conformance.RequirementRef{commandReference, definition.reference}
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: definition.description,
			Source: conformance.SourceLocation{
				Path: authrMakeCredReq5PositiveSourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var fixture makeCredentialFixture
				if !test.Step(conformance.Step{
					ID: conformance.StepID(
						"make-cred-req-5-positive." + strings.ToLower(definition.marker) + ".prepare",
					),
					Name:       "Prepare an isolated valid MakeCredential request",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						var err error
						fixture, err = prepareMakeCredentialFixture(
							ctx,
							test,
							config,
							authrMakeCredReq5PositiveRPID,
						)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				test.Step(conformance.Step{
					ID: conformance.StepID(
						"make-cred-req-5-positive." + strings.ToLower(definition.marker) + ".exchange",
					),
					Name:       "Create a credential with the requested optional input",
					References: references,
					Run: func(ctx context.Context) error {
						fields := fixture.rawFields()
						definition.mutate(fixture, fields)
						_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)

						return unexpectedCTAPStatus("authenticatorMakeCredential", err)
					},
				})
			},
		})
	}

	return tests
}

func authrMakeCredReq5PositiveReference(clause string) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:6.1:" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		Level: conformance.RequirementConstraint,
	}
}
