package ctap23

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
	mdsmodel "github.com/telesma-app/mds/model"
)

const (
	authrGetAssertionReq3SourcePath = "tests/CTAP2/Protocol/Get/Authr-GetAssertion-Req-3.js"
	authrGetAssertionReq3RPID       = "get-assertion-req-3.ctap23-conformance.example"

	TestIDAuthrGetAssertionReq3P1 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-3.p-1"
	TestIDAuthrGetAssertionReq3F1 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-3.f-1"
	TestIDAuthrGetAssertionReq3F2 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-3.f-2"
	TestIDAuthrGetAssertionReq3F3 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-3.f-3"
	TestIDAuthrGetAssertionReq3F4 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-3.f-4"
	TestIDAuthrGetAssertionReq3F5 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-3.f-5"
	TestIDAuthrGetAssertionReq3F6 conformance.TestID = "fido.ctap2.3.authr-get-assertion-req-3.f-6"
)

type authrGetAssertionReq3Case struct {
	id                       conformance.TestID
	marker                   string
	name                     string
	references               []conformance.RequirementRef
	expectedStatus           ctaptransport.StatusCode
	secondFactorPrecondition bool
	mutate                   func(map[uint64]any)
}

func authrGetAssertionReq3Tests(config Config) []conformance.Test {
	commandReference := authrGetAssertionReq1CommandReference()
	allowListReference := authrGetAssertionReq1ParameterReference("allow-list-optional-array")
	malformedStructureReference := authrGetAssertionReq3MalformedStructureReference()
	descriptorReference := authrGetAssertionReq3CredentialDescriptorReference()

	cases := []authrGetAssertionReq3Case{
		{
			id:     TestIDAuthrGetAssertionReq3P1,
			marker: "P-1",
			name:   "GetAssertion ignores an unknown credential type after a matching descriptor",
			references: []conformance.RequirementRef{
				allowListReference,
				authrGetAssertionReq3UnknownCredentialTypeReference(),
				authrGetAssertionReq1ResponseCredentialReference(),
			},
			expectedStatus: ctaptransport.CTAP2_OK,
			mutate: func(fields map[uint64]any) {
				fields[3] = append(fields[3].([]any), map[string]any{
					"type": "ctap23-unknown-credential-type",
					"id":   bytes.Repeat([]byte{0xa3}, 32),
				})
			},
		},
		{
			id:             TestIDAuthrGetAssertionReq3F1,
			marker:         "F-1",
			name:           "GetAssertion allowList with a non-map descriptor",
			references:     []conformance.RequirementRef{allowListReference, descriptorReference, malformedStructureReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate: func(fields map[uint64]any) {
				fields[3] = append(fields[3].([]any), true)
			},
		},
		{
			id:             TestIDAuthrGetAssertionReq3F2,
			marker:         "F-2",
			name:           "GetAssertion allowList descriptor without type",
			references:     []conformance.RequirementRef{allowListReference, descriptorReference, malformedStructureReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate: func(fields map[uint64]any) {
				fields[3] = append(fields[3].([]any), map[string]any{
					"id": bytes.Repeat([]byte{0xa3}, 32),
				})
			},
		},
		{
			id:             TestIDAuthrGetAssertionReq3F3,
			marker:         "F-3",
			name:           "GetAssertion allowList descriptor with non-text type",
			references:     []conformance.RequirementRef{allowListReference, descriptorReference, malformedStructureReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate: func(fields map[uint64]any) {
				fields[3] = append(fields[3].([]any), map[string]any{
					"type": uint64(7),
					"id":   bytes.Repeat([]byte{0xa3}, 32),
				})
			},
		},
		{
			id:             TestIDAuthrGetAssertionReq3F4,
			marker:         "F-4",
			name:           "GetAssertion allowList descriptor without ID",
			references:     []conformance.RequirementRef{allowListReference, descriptorReference, malformedStructureReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate: func(fields map[uint64]any) {
				fields[3] = append(fields[3].([]any), map[string]any{
					"type": "public-key",
				})
			},
		},
		{
			id:             TestIDAuthrGetAssertionReq3F5,
			marker:         "F-5",
			name:           "GetAssertion allowList descriptor with non-byte-string ID",
			references:     []conformance.RequirementRef{allowListReference, descriptorReference, malformedStructureReference},
			expectedStatus: ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			mutate: func(fields map[uint64]any) {
				fields[3] = append(fields[3].([]any), map[string]any{
					"type": "public-key",
					"id":   "not-a-byte-string",
				})
			},
		},
		{
			id:                       TestIDAuthrGetAssertionReq3F6,
			marker:                   "F-6",
			name:                     "Presence-only authenticator GetAssertion without allowList",
			references:               authrGetAssertionReq3F6References(allowListReference),
			expectedStatus:           ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
			secondFactorPrecondition: true,
			mutate:                   func(fields map[uint64]any) { delete(fields, 3) },
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
			Description: "Validates one authenticatorGetAssertion allowList descriptor constraint",
			Source: conformance.SourceLocation{
				Path: authrGetAssertionReq3SourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if definition.secondFactorPrecondition && !test.Step(conformance.Step{
					ID:         "get-assertion-req-3.f-6.metadata",
					Name:       "Determine whether metadata declares a presence-only authenticator",
					References: definition.references,
					Run: func(context.Context) error {
						applies, err := authrGetAssertionReq3SecondFactorOnly(config.Metadata)
						if err != nil {
							return err
						}
						if !applies {
							return conformance.Skip(
								"metadata does not describe a presence-only second-factor authenticator",
							)
						}

						return nil
					},
				}) {
					return
				}

				var fixture getAssertionFixture
				if !test.Step(conformance.Step{
					ID: conformance.StepID(
						"get-assertion-req-3." + strings.ToLower(definition.marker) + ".prepare",
					),
					Name:       "Prepare an isolated valid GetAssertion request",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						var err error
						fixture, err = prepareGetAssertionFixture(
							ctx,
							test,
							config,
							getAssertionFixtureSpec{RPID: authrGetAssertionReq3RPID},
						)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				test.Step(conformance.Step{
					ID: conformance.StepID(
						"get-assertion-req-3." + strings.ToLower(definition.marker) + ".exchange",
					),
					Name:       "Send the isolated allowList request",
					References: references,
					Run: func(ctx context.Context) error {
						fields := fixture.rawFields()
						definition.mutate(fields)

						if definition.expectedStatus != ctaptransport.CTAP2_OK {
							_, err := exchangeRawGetAssertion(ctx, test.CBOR(), fields)

							return expectCTAPStatus(err, definition.expectedStatus)
						}

						return authrGetAssertionReq3ExpectCredential(
							ctx,
							test.CBOR(),
							fields,
							fixture.Request.AllowList[0].ID,
						)
					},
				})
			},
		})
	}

	return tests
}

func authrGetAssertionReq3ExpectCredential(
	ctx context.Context,
	device ctaptransport.CBOR,
	fields map[uint64]any,
	wantCredentialID []byte,
) error {
	wireResponse, err := exchangeRawGetAssertion(ctx, device, fields)
	if err != nil {
		return unexpectedCTAPStatus("authenticatorGetAssertion", err)
	}
	if err := validateGetAssertionResponseRequiredFields(wireResponse.Data); err != nil {
		return err
	}
	if err := validateCanonicalCTAP2Response("authenticatorGetAssertion", wireResponse.Data); err != nil {
		return err
	}

	var response protocol.AuthenticatorGetAssertionResponse
	if err := getInfoDecMode.Unmarshal(wireResponse.Data, &response); err != nil {
		return conformance.Failf("invalid authenticatorGetAssertion response CBOR: %v", err)
	}
	if !bytes.Equal(response.Credential.ID, wantCredentialID) {
		return conformance.Fail("authenticatorGetAssertion returned a different credential ID")
	}

	return nil
}

func authrGetAssertionReq3SecondFactorOnly(metadata Metadata) (bool, error) {
	statement, err := parseMetadataStatement(metadata.StatementJSON)
	if err != nil {
		return false, err
	}

	var alternatives []json.RawMessage
	present, err := statement.field("userVerificationDetails", &alternatives)
	if err != nil {
		return false, err
	}
	if !present {
		return false, fmt.Errorf(
			"ctap23: metadata field userVerificationDetails is required for Authr-GetAssertion-Req-3 F-6",
		)
	}
	if len(alternatives) == 0 {
		return false, fmt.Errorf("ctap23: metadata field userVerificationDetails must not be empty")
	}

	var onlyMethod registry.UserVerificationMethod
	var onlyDescriptorCount int
	for alternativeIndex, rawAlternative := range alternatives {
		var descriptors []json.RawMessage
		if err := json.Unmarshal(rawAlternative, &descriptors); err != nil {
			return false, fmt.Errorf(
				"ctap23: metadata userVerificationDetails alternative %d must be an array: %w",
				alternativeIndex,
				err,
			)
		}
		if len(descriptors) == 0 {
			return false, fmt.Errorf(
				"ctap23: metadata userVerificationDetails alternative %d must not be empty",
				alternativeIndex,
			)
		}
		if alternativeIndex == 0 {
			onlyDescriptorCount = len(descriptors)
		}

		for descriptorIndex, rawDescriptor := range descriptors {
			descriptor, err := mdsmodel.ParseMetadataStatementDocument(rawDescriptor)
			if err != nil {
				return false, fmt.Errorf(
					"ctap23: metadata userVerificationDetails descriptor %d/%d must be an object: %w",
					alternativeIndex,
					descriptorIndex,
					err,
				)
			}

			var methodName string
			present, err := descriptor.DecodeField("userVerificationMethod", &methodName)
			if err != nil {
				return false, fmt.Errorf(
					"ctap23: metadata userVerificationDetails descriptor %d/%d: %w",
					alternativeIndex,
					descriptorIndex,
					err,
				)
			}
			if !present || methodName == "" {
				return false, fmt.Errorf(
					"ctap23: metadata userVerificationDetails descriptor %d/%d requires userVerificationMethod",
					alternativeIndex,
					descriptorIndex,
				)
			}

			method, ok := registry.ParseUserVerificationMethod(methodName)
			if !ok || !method.ValidMetadata() {
				return false, fmt.Errorf(
					"ctap23: metadata userVerificationDetails descriptor %d/%d has invalid userVerificationMethod %q",
					alternativeIndex,
					descriptorIndex,
					methodName,
				)
			}
			if alternativeIndex == 0 && descriptorIndex == 0 {
				onlyMethod = method
			}
		}
	}

	return len(alternatives) == 1 &&
		onlyDescriptorCount == 1 &&
		onlyMethod == registry.UserVerificationPresenceInternal, nil
}

func authrGetAssertionReq3F6References(
	allowListReference conformance.RequirementRef,
) []conformance.RequirementRef {
	return slices.Concat(
		[]conformance.RequirementRef{
			allowListReference,
			authrGetAssertionReq3NoCredentialsReference(),
		},
		metadataP15ThroughP24References(
			"3.6",
			"verification-method-and-combinations",
			"sctn-type-vmac",
			conformance.RequirementConstraint,
		),
		metadataReferences(
			"4",
			"userVerificationDetails",
			conformance.RequirementConstraint,
		),
		[]conformance.RequirementRef{
			fidoRegistryReference("3.1", "user-verification-methods"),
		},
	)
}

func authrGetAssertionReq3CredentialDescriptorReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "webauthn-3:5.8.3:public-key-credential-descriptor",
		Specification: "webauthn-level-3",
		Section:       "5.8.3",
		Clause:        "public-key-credential-descriptor",
		URL:           "https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor",
		Level:         conformance.RequirementConstraint,
	}
}

func authrGetAssertionReq3UnknownCredentialTypeReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "webauthn-3:5.8.3:ignore-unknown-credential-type",
		Specification: "webauthn-level-3",
		Section:       "5.8.3",
		Clause:        "ignore-unknown-credential-type",
		URL:           "https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptor-type",
		Level:         conformance.RequirementMust,
	}
}

func authrGetAssertionReq3MalformedStructureReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:8:invalid-external-structure",
		Specification: conformance.SpecificationCTAP23,
		Section:       "8",
		Clause:        "invalid-external-structure",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding",
		Level:         conformance.RequirementShould,
	}
}

func authrGetAssertionReq3NoCredentialsReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.2.2:empty-applicable-credentials-list",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.2.2",
		Clause:        "empty-applicable-credentials-list",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion",
		Level:         conformance.RequirementMust,
	}
}
