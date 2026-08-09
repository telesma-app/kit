package ctap23

import (
	"context"
	"strings"

	"github.com/telesma-app/kit/conformance"
)

const (
	authrMakeCredReq3SourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-3.js"
	authrMakeCredReq3RPID       = "make-cred-req-3.ctap23-conformance.example"

	TestIDAuthrMakeCredReq3F1 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-3.f-1"
	TestIDAuthrMakeCredReq3F2 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-3.f-2"
	TestIDAuthrMakeCredReq3F3 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-3.f-3"
	TestIDAuthrMakeCredReq3F4 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-3.f-4"
)

type authrMakeCredReq3Case struct {
	id        conformance.TestID
	marker    string
	name      string
	reference conformance.RequirementRef
	mutate    func(map[string]any)
}

func authrMakeCredReq3Tests(config Config) []conformance.Test {
	commandReference := authrMakeCredReq1CommandReference()
	cases := []authrMakeCredReq3Case{
		{
			id:        TestIDAuthrMakeCredReq3F1,
			marker:    "F-1",
			name:      "MakeCredential with a non-byte-string user ID",
			reference: authrMakeCredReq3UserReference("user-id-required-byte-string", conformance.RequirementConstraint),
			mutate:    func(user map[string]any) { user["id"] = "not-a-byte-string" },
		},
		{
			id:        TestIDAuthrMakeCredReq3F2,
			marker:    "F-2",
			name:      "MakeCredential with a non-text user name",
			reference: authrMakeCredReq3UserReference("user-name-optional-text-string", conformance.RequirementConstraint),
			mutate:    func(user map[string]any) { user["name"] = false },
		},
		{
			id:        TestIDAuthrMakeCredReq3F3,
			marker:    "F-3",
			name:      "MakeCredential with a non-text user display name",
			reference: authrMakeCredReq3UserReference("user-display-name-optional-text-string", conformance.RequirementConstraint),
			mutate:    func(user map[string]any) { user["displayName"] = uint64(1) },
		},
	}

	tests := make([]conformance.Test, 0, 4)
	for _, definition := range cases {
		references := []conformance.RequirementRef{commandReference, definition.reference}
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: "Validates one user-entity member type in authenticatorMakeCredential",
			Source: conformance.SourceLocation{
				Path: authrMakeCredReq3SourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var fixture makeCredentialFixture
				if !test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-3." + strings.ToLower(definition.marker) + ".prepare"),
					Name:       "Prepare an isolated valid MakeCredential request",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						var err error
						fixture, err = prepareMakeCredentialFixture(ctx, test, config, authrMakeCredReq3RPID)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-3." + strings.ToLower(definition.marker) + ".exchange"),
					Name:       "Send the malformed user entity",
					References: references,
					Run: func(ctx context.Context) error {
						fields := fixture.rawFields()
						definition.mutate(fields[3].(map[string]any))
						_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)

						return expectAnyCTAPError(err)
					},
				})
			},
		})
	}

	iconReference := authrMakeCredReq3UserReference(
		"user-icon-presence-must-not-error",
		conformance.RequirementMustNot,
	)
	iconReferences := []conformance.RequirementRef{commandReference, iconReference}
	tests = append(tests, conformance.Test{
		ID:          TestIDAuthrMakeCredReq3F4,
		Name:        "Legacy user icon type assertion",
		Description: "Records the commented upstream marker without executing its removed WebAuthn assertion",
		Source: conformance.SourceLocation{
			Path: authrMakeCredReq3SourcePath,
			Case: "F-4",
		},
		References: iconReferences,
		Run: func(test *conformance.TestContext) {
			test.Step(conformance.Step{
				ID:         "make-cred-req-3.f-4.adjudication",
				Name:       "Record the disabled legacy icon assertion",
				References: iconReferences,
				Run: func(context.Context) error {
					return conformance.Skip("the pinned F-4 marker is commented out after WebAuthn removed user.icon")
				},
			})
		},
	})

	return tests
}

func authrMakeCredReq3UserReference(
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
