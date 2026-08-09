package ctap23

import (
	"context"
	"slices"
	"strings"

	"github.com/telesma-app/kit/conformance"
)

const (
	authrMakeCredReq2SourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-2.js"
	authrMakeCredReq2RPID       = "make-cred-req-2.ctap23-conformance.example"

	TestIDAuthrMakeCredReq2F1 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-2.f-1"
	TestIDAuthrMakeCredReq2F2 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-2.f-2"
	TestIDAuthrMakeCredReq2F3 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-2.f-3"
)

type authrMakeCredReq2Case struct {
	id        conformance.TestID
	marker    string
	name      string
	reference conformance.RequirementRef
	mutate    func(map[string]any)
}

func authrMakeCredReq2Tests(config Config) []conformance.Test {
	commandReference := authrMakeCredReq1CommandReference()
	cases := []authrMakeCredReq2Case{
		{
			id:        TestIDAuthrMakeCredReq2F1,
			marker:    "F-1",
			name:      "MakeCredential with a non-text RP ID",
			reference: authrMakeCredReq2RPReference("rp-id-required-text-string", conformance.RequirementConstraint),
			mutate:    func(rp map[string]any) { rp["id"] = []byte("not-text") },
		},
		{
			id:        TestIDAuthrMakeCredReq2F2,
			marker:    "F-2",
			name:      "MakeCredential with a non-text RP name",
			reference: authrMakeCredReq2RPReference("rp-name-optional-text-string", conformance.RequirementConstraint),
			mutate:    func(rp map[string]any) { rp["name"] = uint64(1) },
		},
	}

	tests := make([]conformance.Test, 0, 3)
	for _, definition := range cases {
		references := []conformance.RequirementRef{commandReference, definition.reference}
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: "Validates one relying-party entity member type in authenticatorMakeCredential",
			Source: conformance.SourceLocation{
				Path: authrMakeCredReq2SourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var fixture makeCredentialFixture
				if !test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-2." + strings.ToLower(definition.marker) + ".prepare"),
					Name:       "Prepare an isolated valid MakeCredential request",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						var err error
						fixture, err = prepareMakeCredentialFixture(ctx, test, config, authrMakeCredReq2RPID)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-2." + strings.ToLower(definition.marker) + ".exchange"),
					Name:       "Send the malformed relying-party entity",
					References: references,
					Run: func(ctx context.Context) error {
						fields := fixture.rawFields()
						rp := fields[2].(map[string]any)
						definition.mutate(rp)
						_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)

						return expectAnyCTAPError(err)
					},
				})
			},
		})
	}

	iconReference := authrMakeCredReq2RPReference(
		"rp-icon-presence-must-not-error",
		conformance.RequirementMustNot,
	)
	iconReferences := slices.Clone([]conformance.RequirementRef{commandReference, iconReference})
	tests = append(tests, conformance.Test{
		ID:          TestIDAuthrMakeCredReq2F3,
		Name:        "Legacy RP icon type assertion",
		Description: "Records the disabled upstream case without imposing a removed WebAuthn member constraint",
		Source: conformance.SourceLocation{
			Path: authrMakeCredReq2SourcePath,
			Case: "F-3",
		},
		References: iconReferences,
		Run: func(test *conformance.TestContext) {
			test.Step(conformance.Step{
				ID:         "make-cred-req-2.f-3.adjudication",
				Name:       "Record the removed RP icon assertion",
				References: iconReferences,
				Run: func(context.Context) error {
					// The pinned marker is lexical only: its entire case body is
					// commented out because WebAuthn removed rp.icon. Current CTAP
					// requires authenticators not to reject an RP entity merely
					// because the legacy icon member is present.
					return conformance.Skip("the pinned F-3 case is disabled and current CTAP defines no RP icon type assertion")
				},
			})
		},
	})

	return tests
}

func authrMakeCredReq2RPReference(
	clause string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:6.1:" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		Level: level,
	}
}
