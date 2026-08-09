package ctap23

import (
	"context"
	"slices"
	"strings"

	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrMakeCredReq5NegativeSourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-5.js"
	authrMakeCredReq5NegativeRPID       = "make-cred-req-5-negative.ctap23-conformance.example"

	TestIDAuthrMakeCredReq5NegativeF1 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.f-1"
	TestIDAuthrMakeCredReq5NegativeF2 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.f-2"
	TestIDAuthrMakeCredReq5NegativeF3 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.f-3"
	TestIDAuthrMakeCredReq5NegativeF5 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.f-5"
	TestIDAuthrMakeCredReq5NegativeF6 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.f-6"
	TestIDAuthrMakeCredReq5NegativeF7 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.f-7"
)

var (
	authrMakeCredReq5NegativeDescriptorID = [...]byte{
		0xe1, 0x20, 0xf6, 0x5c, 0xca, 0x8d, 0x46, 0x37,
		0xa4, 0x89, 0xb0, 0xf4, 0x22, 0x50, 0x2b, 0xd0,
	}
	authrMakeCredReq5NegativeSecondClientDataHash = [...]byte{
		0x76, 0x7d, 0xda, 0xd8, 0x4a, 0xe8, 0x54, 0xb1,
		0x02, 0x1a, 0x34, 0xcc, 0x2d, 0x67, 0xc8, 0x8a,
		0x87, 0x21, 0x59, 0x55, 0x31, 0xd7, 0xc4, 0x8c,
		0x72, 0xf2, 0xc3, 0x63, 0xd4, 0x71, 0x6e, 0x9f,
	}
)

type authrMakeCredReq5NegativeCase struct {
	id     conformance.TestID
	marker string
	name   string
	mutate func(map[uint64]any)
}

func authrMakeCredReq5NegativeTests(config Config) []conformance.Test {
	commandReference := authrMakeCredReq1CommandReference()
	descriptorReference := authrMakeCredReq5DescriptorReference()
	wrongTypeReference := authrMakeCredReq5AttestationTypeWrongTypeReference()
	cases := []authrMakeCredReq5NegativeCase{
		{
			id:     TestIDAuthrMakeCredReq5NegativeF1,
			marker: "F-1",
			name:   "Exclude list rejects a non-map element",
			mutate: func(fields map[uint64]any) {
				fields[5] = []any{authrMakeCredReq5ValidDescriptor(), false}
			},
		},
		{
			id:     TestIDAuthrMakeCredReq5NegativeF2,
			marker: "F-2",
			name:   "Exclude list rejects a descriptor without type",
			mutate: func(fields map[uint64]any) {
				fields[5] = []any{
					authrMakeCredReq5ValidDescriptor(),
					map[string]any{"id": slices.Clone(authrMakeCredReq5NegativeDescriptorID[:])},
				}
			},
		},
		{
			id:     TestIDAuthrMakeCredReq5NegativeF3,
			marker: "F-3",
			name:   "Exclude list rejects a non-text descriptor type",
			mutate: func(fields map[uint64]any) {
				fields[5] = []any{
					authrMakeCredReq5ValidDescriptor(),
					map[string]any{
						"type": false,
						"id":   slices.Clone(authrMakeCredReq5NegativeDescriptorID[:]),
					},
				}
			},
		},
		{
			id:     TestIDAuthrMakeCredReq5NegativeF5,
			marker: "F-5",
			name:   "Exclude list rejects a descriptor without ID",
			mutate: func(fields map[uint64]any) {
				fields[5] = []any{
					authrMakeCredReq5ValidDescriptor(),
					map[string]any{"type": string(credential.PublicKeyCredentialTypePublicKey)},
				}
			},
		},
		{
			id:     TestIDAuthrMakeCredReq5NegativeF6,
			marker: "F-6",
			name:   "Exclude list rejects a non-byte-string descriptor ID",
			mutate: func(fields map[uint64]any) {
				fields[5] = []any{
					authrMakeCredReq5ValidDescriptor(),
					map[string]any{
						"type": string(credential.PublicKeyCredentialTypePublicKey),
						"id":   "not-a-byte-string",
					},
				}
			},
		},
	}

	tests := make([]conformance.Test, 0, 6)
	for _, definition := range cases {
		definition := definition
		references := []conformance.RequirementRef{
			commandReference,
			descriptorReference,
			wrongTypeReference,
		}
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: "Validates one excludeList descriptor structure constraint and its required error status",
			Source: conformance.SourceLocation{
				Path: authrMakeCredReq5NegativeSourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var fixture makeCredentialFixture
				if !test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-5." + strings.ToLower(definition.marker) + ".prepare"),
					Name:       "Prepare an isolated valid MakeCredential request",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						var err error
						fixture, err = prepareMakeCredentialFixture(ctx, test, config, authrMakeCredReq5NegativeRPID)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-5." + strings.ToLower(definition.marker) + ".exchange"),
					Name:       "Send the malformed exclude list",
					References: references,
					Run: func(ctx context.Context) error {
						fields := fixture.rawFields()
						definition.mutate(fields)
						_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)

						return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
					},
				})
			},
		})
	}

	excludedReference := authrMakeCredReq5CredentialExcludedReference()
	responseReference := makeCredentialResponseRequiredReference()
	encodingReference := ctapMessageEncodingReference()
	f7References := []conformance.RequirementRef{
		commandReference,
		descriptorReference,
		excludedReference,
		responseReference,
		encodingReference,
	}
	tests = append(tests, conformance.Test{
		ID:          TestIDAuthrMakeCredReq5NegativeF7,
		Name:        "MakeCredential rejects a previously created credential",
		Description: "Creates a credential and verifies its ID is rejected through excludeList",
		Source: conformance.SourceLocation{
			Path: authrMakeCredReq5NegativeSourcePath,
			Case: "F-7",
		},
		References:  f7References,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			var fixture makeCredentialFixture
			if !test.Step(conformance.Step{
				ID:         "make-cred-req-5.f-7.prepare",
				Name:       "Prepare an isolated valid MakeCredential request",
				References: []conformance.RequirementRef{commandReference},
				Run: func(ctx context.Context) error {
					var err error
					fixture, err = prepareMakeCredentialFixture(ctx, test, config, authrMakeCredReq5NegativeRPID)

					return err
				},
			}) {
				return
			}
			defer fixture.clear()

			var credentialID []byte
			if !test.Step(conformance.Step{
				ID:         "make-cred-req-5.f-7.create",
				Name:       "Create the credential to exclude",
				References: []conformance.RequirementRef{commandReference, responseReference, encodingReference},
				Run: func(ctx context.Context) error {
					response, err := fixture.makeCredential(ctx, test.CBOR(), fixture.Request)
					if err != nil {
						return err
					}
					if response.AuthData == nil || response.AuthData.AttestedCredentialData == nil ||
						len(response.AuthData.AttestedCredentialData.CredentialID) == 0 {
						return conformance.Fail("authenticatorMakeCredential response has no credential ID")
					}
					credentialID = slices.Clone(response.AuthData.AttestedCredentialData.CredentialID)

					return nil
				},
			}) {
				return
			}
			fixture.clear()

			test.Step(conformance.Step{
				ID:         "make-cred-req-5.f-7.exclude",
				Name:       "Attempt to create with the credential ID in excludeList",
				References: []conformance.RequirementRef{descriptorReference, excludedReference},
				Run: func(ctx context.Context) error {
					request := fixture.Request
					request.ClientDataHash = slices.Clone(authrMakeCredReq5NegativeSecondClientDataHash[:])
					request.ExcludeList = []credential.PublicKeyCredentialDescriptor{{
						Type: credential.PublicKeyCredentialTypePublicKey,
						ID:   credentialID,
					}}

					var authorization PinUvAuthToken
					if fixtureNeedsAuthorization(fixture.Info) {
						var err error
						authorization, err = config.TokenProvider(ctx, test.Client(), PinUvAuthTokenRequest{
							Permission: protocol.PermissionMakeCredential,
							RPID:       authrMakeCredReq5NegativeRPID,
						})
						if err != nil {
							clear(authorization.Value)

							return err
						}
						defer clear(authorization.Value)
						if err := validatePinUvAuthorization(fixture.Info, authorization); err != nil {
							return err
						}
						request.PinUvAuthProtocol = authorization.Protocol
						request.PinUvAuthParam = ctapcrypto.Authenticate(
							authorization.Protocol,
							authorization.Value,
							request.ClientDataHash,
						)
					}

					fields := makeCredentialFixture{Request: request}.rawFields()
					_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)

					return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED)
				},
			})
		},
	})

	return tests
}

func authrMakeCredReq5ValidDescriptor() map[string]any {
	return map[string]any{
		"type": string(credential.PublicKeyCredentialTypePublicKey),
		"id":   slices.Clone(authrMakeCredReq5NegativeDescriptorID[:]),
	}
}

func authrMakeCredReq5DescriptorReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1:exclude-list-credential-descriptors",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        "exclude-list-credential-descriptors",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#makecred-excludelist",
		Level:         conformance.RequirementConstraint,
	}
}

func authrMakeCredReq5CredentialExcludedReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1.2:matching-exclude-list-credential",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1.2",
		Clause:        "matching-exclude-list-credential",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		Level:         conformance.RequirementConstraint,
	}
}
