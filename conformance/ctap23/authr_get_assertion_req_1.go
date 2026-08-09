package ctap23

import (
	"bytes"
	"context"
	"slices"
	"strings"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrGetAssertionReq1SourcePath = "tests/CTAP2/Protocol/Get/Authr-GetAssertion-Req-1.js"
	authrGetAssertionReq1RPID       = "get-assertion-req-1.ctap23-conformance.example"

	TestIDAuthrGetAssertionReq1P1 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-1.p-1"
	TestIDAuthrGetAssertionReq1F1 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-1.f-1"
	TestIDAuthrGetAssertionReq1F2 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-1.f-2"
	TestIDAuthrGetAssertionReq1F3 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-1.f-3"
	TestIDAuthrGetAssertionReq1F4 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-1.f-4"
	TestIDAuthrGetAssertionReq1F5 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-1.f-5"
	TestIDAuthrGetAssertionReq1F6 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-1.f-6"
)

type authrGetAssertionReq1Case struct {
	id             conformance.TestID
	marker         string
	name           string
	references     []conformance.RequirementRef
	expectedStatus ctaptransport.StatusCode
	mutate         func(map[uint64]any)
}

func authrGetAssertionReq1Tests(config Config) []conformance.Test {
	commandReference := authrGetAssertionReq1CommandReference()
	rpIDReference := authrGetAssertionReq1ParameterReference("rp-id-required-text-string")
	clientDataHashReference := authrGetAssertionReq1ParameterReference(
		"client-data-hash-required-byte-string",
	)
	allowListReference := authrGetAssertionReq1ParameterReference("allow-list-optional-array")
	missingReference := authrGetAssertionReq1MissingParameterReference()
	wrongTypeReference := authrGetAssertionReq1WrongTypeReference()

	cases := []authrGetAssertionReq1Case{
		{
			id:     TestIDAuthrGetAssertionReq1P1,
			marker: "P-1",
			name:   "Valid GetAssertion request",
			references: []conformance.RequirementRef{
				ctapMessageEncodingReference(),
				authrGetAssertionReq1ResponseCredentialReference(),
			},
		},
		{
			id:             TestIDAuthrGetAssertionReq1F1,
			marker:         "F-1",
			name:           "GetAssertion without RP ID",
			references:     []conformance.RequirementRef{rpIDReference, missingReference},
			expectedStatus: ctaptransport.CTAP2_ERR_MISSING_PARAMETER,
			mutate:         func(fields map[uint64]any) { delete(fields, 1) },
		},
		{
			id:             TestIDAuthrGetAssertionReq1F2,
			marker:         "F-2",
			name:           "GetAssertion with non-text-string RP ID",
			references:     []conformance.RequirementRef{rpIDReference, wrongTypeReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate:         func(fields map[uint64]any) { fields[1] = []any{} },
		},
		{
			id:             TestIDAuthrGetAssertionReq1F3,
			marker:         "F-3",
			name:           "GetAssertion without clientDataHash",
			references:     []conformance.RequirementRef{clientDataHashReference, missingReference},
			expectedStatus: ctaptransport.CTAP2_ERR_MISSING_PARAMETER,
			mutate:         func(fields map[uint64]any) { delete(fields, 2) },
		},
		{
			id:             TestIDAuthrGetAssertionReq1F4,
			marker:         "F-4",
			name:           "GetAssertion with non-byte-string clientDataHash",
			references:     []conformance.RequirementRef{clientDataHashReference, wrongTypeReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate:         func(fields map[uint64]any) { fields[2] = "not-a-byte-string" },
		},
		{
			id:             TestIDAuthrGetAssertionReq1F5,
			marker:         "F-5",
			name:           "GetAssertion with non-array allowList",
			references:     []conformance.RequirementRef{allowListReference, wrongTypeReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate:         func(fields map[uint64]any) { fields[3] = map[string]any{} },
		},
		{
			id:             TestIDAuthrGetAssertionReq1F6,
			marker:         "F-6",
			name:           "GetAssertion with a non-map allowList member",
			references:     []conformance.RequirementRef{allowListReference, wrongTypeReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate: func(fields map[uint64]any) {
				fields[3] = append(fields[3].([]any), true)
			},
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
			Description: "Validates one top-level authenticatorGetAssertion request-map constraint",
			Source: conformance.SourceLocation{
				Path: authrGetAssertionReq1SourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var fixture getAssertionFixture
				if !test.Step(conformance.Step{
					ID: conformance.StepID(
						"get-assertion-req-1." + strings.ToLower(definition.marker) + ".prepare",
					),
					Name:       "Prepare an isolated valid GetAssertion request",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						var err error
						fixture, err = prepareGetAssertionFixture(
							ctx,
							test,
							config,
							getAssertionFixtureSpec{RPID: authrGetAssertionReq1RPID},
						)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				if definition.mutate == nil {
					test.Step(conformance.Step{
						ID:         "get-assertion-req-1.p-1.exchange",
						Name:       "Get the created credential with the valid request",
						References: references,
						Run: func(ctx context.Context) error {
							response, err := fixture.getAssertion(ctx, test.CBOR(), fixture.Request)
							if err != nil {
								return err
							}
							if !bytes.Equal(response.Response.Credential.ID, fixture.Request.AllowList[0].ID) {
								return conformance.Fail(
									"authenticatorGetAssertion returned a different credential ID",
								)
							}

							return nil
						},
					})

					return
				}

				test.Step(conformance.Step{
					ID: conformance.StepID(
						"get-assertion-req-1." + strings.ToLower(definition.marker) + ".exchange",
					),
					Name:       "Send the isolated malformed request",
					References: references,
					Run: func(ctx context.Context) error {
						fields := fixture.rawFields()
						definition.mutate(fields)
						_, err := exchangeRawGetAssertion(ctx, test.CBOR(), fields)

						return expectCTAPStatus(err, definition.expectedStatus)
					},
				})
			},
		})
	}

	return tests
}

func authrGetAssertionReq1CommandReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.2:authenticator-get-assertion-request",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.2",
		Clause:        "authenticator-get-assertion-request",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion",
		Level:         conformance.RequirementConstraint,
	}
}

func authrGetAssertionReq1ParameterReference(clause string) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID: conformance.RequirementID(
			"ctap-2.3-ps-20260226:6.2:" + clause,
		),
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.2",
		Clause:        clause,
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion",
		Level:         conformance.RequirementConstraint,
	}
}

func authrGetAssertionReq1ResponseCredentialReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.2.2:get-assertion-response-credential",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.2.2",
		Clause:        "get-assertion-response-credential",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion",
		Level:         conformance.RequirementConstraint,
	}
}

func authrGetAssertionReq1MissingParameterReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:8:missing-required-member",
		Specification: conformance.SpecificationCTAP23,
		Section:       "8",
		Clause:        "missing-required-member",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding",
		Level:         conformance.RequirementShould,
	}
}

func authrGetAssertionReq1WrongTypeReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:8:wrong-known-member-type",
		Specification: conformance.SpecificationCTAP23,
		Section:       "8",
		Clause:        "wrong-known-member-type",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding",
		Level:         conformance.RequirementShould,
	}
}
