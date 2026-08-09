package ctap23

import (
	"context"
	"slices"
	"strings"

	"github.com/telesma-app/kit/conformance"
)

const (
	authrMakeCredReq1SourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-1.js"
	authrMakeCredReq1RPID       = "make-cred-req-1.ctap23-conformance.example"

	TestIDAuthrMakeCredReq1P1  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.p-1"
	TestIDAuthrMakeCredReq1F1  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-1"
	TestIDAuthrMakeCredReq1F2  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-2"
	TestIDAuthrMakeCredReq1F3  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-3"
	TestIDAuthrMakeCredReq1F4  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-4"
	TestIDAuthrMakeCredReq1F5  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-5"
	TestIDAuthrMakeCredReq1F6  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-6"
	TestIDAuthrMakeCredReq1F7  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-7"
	TestIDAuthrMakeCredReq1F8  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-8"
	TestIDAuthrMakeCredReq1F9  conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-9"
	TestIDAuthrMakeCredReq1F10 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-10"
	TestIDAuthrMakeCredReq1F11 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-1.f-11"
)

type authrMakeCredReq1Case struct {
	id         conformance.TestID
	marker     string
	name       string
	references []conformance.RequirementRef
	mutate     func(map[uint64]any)
}

func authrMakeCredReq1Tests(config Config) []conformance.Test {
	commandReference := authrMakeCredReq1CommandReference()
	messageEncodingReference := ctapMessageEncodingReference()
	responseRequiredReference := makeCredentialResponseRequiredReference()
	clientDataHashReference := authrMakeCredReq1ParameterReference(
		"client-data-hash-required-byte-string",
	)
	rpReference := authrMakeCredReq1ParameterReference("rp-required-map")
	userReference := authrMakeCredReq1ParameterReference("user-required-map")
	parametersReference := authrMakeCredReq1ParameterReference(
		"public-key-credential-parameters-required-array",
	)
	excludeListReference := authrMakeCredReq1ParameterReference(
		"exclude-list-optional-array",
	)
	extensionsReference := authrMakeCredReq1ParameterReference(
		"extensions-optional-map",
	)
	optionsReference := authrMakeCredReq1ParameterReference("options-optional-map")

	cases := []authrMakeCredReq1Case{
		{
			id:     TestIDAuthrMakeCredReq1P1,
			marker: "P-1",
			name:   "Valid MakeCredential request",
			references: []conformance.RequirementRef{
				messageEncodingReference,
				responseRequiredReference,
			},
		},
		{
			id:         TestIDAuthrMakeCredReq1F1,
			marker:     "F-1",
			name:       "MakeCredential without clientDataHash",
			references: []conformance.RequirementRef{clientDataHashReference},
			mutate:     func(fields map[uint64]any) { delete(fields, 1) },
		},
		{
			id:         TestIDAuthrMakeCredReq1F2,
			marker:     "F-2",
			name:       "MakeCredential with non-byte-string clientDataHash",
			references: []conformance.RequirementRef{clientDataHashReference},
			mutate:     func(fields map[uint64]any) { fields[1] = "not-a-byte-string" },
		},
		{
			id:         TestIDAuthrMakeCredReq1F3,
			marker:     "F-3",
			name:       "MakeCredential without relying party",
			references: []conformance.RequirementRef{rpReference},
			mutate:     func(fields map[uint64]any) { delete(fields, 2) },
		},
		{
			id:         TestIDAuthrMakeCredReq1F4,
			marker:     "F-4",
			name:       "MakeCredential with non-map relying party",
			references: []conformance.RequirementRef{rpReference},
			mutate:     func(fields map[uint64]any) { fields[2] = []any{} },
		},
		{
			id:         TestIDAuthrMakeCredReq1F5,
			marker:     "F-5",
			name:       "MakeCredential without user",
			references: []conformance.RequirementRef{userReference},
			mutate:     func(fields map[uint64]any) { delete(fields, 3) },
		},
		{
			id:         TestIDAuthrMakeCredReq1F6,
			marker:     "F-6",
			name:       "MakeCredential with non-map user",
			references: []conformance.RequirementRef{userReference},
			mutate:     func(fields map[uint64]any) { fields[3] = true },
		},
		{
			id:         TestIDAuthrMakeCredReq1F7,
			marker:     "F-7",
			name:       "MakeCredential without credential parameters",
			references: []conformance.RequirementRef{parametersReference},
			mutate:     func(fields map[uint64]any) { delete(fields, 4) },
		},
		{
			id:         TestIDAuthrMakeCredReq1F8,
			marker:     "F-8",
			name:       "MakeCredential with non-array credential parameters",
			references: []conformance.RequirementRef{parametersReference},
			mutate:     func(fields map[uint64]any) { fields[4] = map[string]any{} },
		},
		{
			id:         TestIDAuthrMakeCredReq1F9,
			marker:     "F-9",
			name:       "MakeCredential with non-array exclude list",
			references: []conformance.RequirementRef{excludeListReference},
			mutate:     func(fields map[uint64]any) { fields[5] = map[string]any{} },
		},
		{
			id:         TestIDAuthrMakeCredReq1F10,
			marker:     "F-10",
			name:       "MakeCredential with non-map extensions",
			references: []conformance.RequirementRef{extensionsReference},
			mutate:     func(fields map[uint64]any) { fields[6] = []any{} },
		},
		{
			id:         TestIDAuthrMakeCredReq1F11,
			marker:     "F-11",
			name:       "MakeCredential with non-map options",
			references: []conformance.RequirementRef{optionsReference},
			mutate:     func(fields map[uint64]any) { fields[7] = []any{} },
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		definition := definition
		references := slices.Concat(
			[]conformance.RequirementRef{commandReference},
			definition.references,
		)
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: "Validates one top-level authenticatorMakeCredential request-map constraint",
			Source: conformance.SourceLocation{
				Path: authrMakeCredReq1SourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var fixture makeCredentialFixture
				if !test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-1." + strings.ToLower(definition.marker) + ".prepare"),
					Name:       "Prepare an isolated valid MakeCredential request",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						var err error
						fixture, err = prepareMakeCredentialFixture(ctx, test, config, authrMakeCredReq1RPID)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				if definition.mutate == nil {
					test.Step(conformance.Step{
						ID:         "make-cred-req-1.p-1.exchange",
						Name:       "Create a credential with the valid request",
						References: references,
						Run: func(ctx context.Context) error {
							_, err := fixture.makeCredential(ctx, test.CBOR(), fixture.Request)

							return err
						},
					})

					return
				}

				test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-1." + strings.ToLower(definition.marker) + ".exchange"),
					Name:       "Send the isolated malformed request",
					References: references,
					Run: func(ctx context.Context) error {
						fields := fixture.rawFields()
						definition.mutate(fields)
						_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)

						return expectAnyCTAPError(err)
					},
				})
			},
		})
	}

	return tests
}

func authrMakeCredReq1CommandReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1:authenticator-make-credential-request",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        "authenticator-make-credential-request",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		Level:         conformance.RequirementConstraint,
	}
}

func authrMakeCredReq1ParameterReference(clause string) conformance.RequirementRef {
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
