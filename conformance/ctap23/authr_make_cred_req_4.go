package ctap23

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrMakeCredReq4SourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-4.js"
	authrMakeCredReq4RPID       = "make-cred-req-4.ctap23-conformance.example"

	TestIDAuthrMakeCredReq4P1 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-4.p-1"
	TestIDAuthrMakeCredReq4F1 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-4.f-1"
	TestIDAuthrMakeCredReq4F2 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-4.f-2"
	TestIDAuthrMakeCredReq4F3 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-4.f-3"
	TestIDAuthrMakeCredReq4F4 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-4.f-4"
	TestIDAuthrMakeCredReq4F5 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-4.f-5"
	TestIDAuthrMakeCredReq4F6 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-4.f-6"
	TestIDAuthrMakeCredReq4F7 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-4.f-7"
)

type authrMakeCredReq4Case struct {
	id             conformance.TestID
	marker         string
	name           string
	mutate         func(map[uint64]any)
	expectedStatus ctaptransport.StatusCode
}

func authrMakeCredReq4Tests(config Config) []conformance.Test {
	parametersReference := authrMakeCredReq4ParametersReference()
	algorithmReference := authrMakeCredReq4AlgorithmReference()
	messageEncodingReference := ctapMessageEncodingReference()
	responseRequiredReference := makeCredentialResponseRequiredReference()
	cases := []authrMakeCredReq4Case{
		{
			id:     TestIDAuthrMakeCredReq4P1,
			marker: "P-1",
			name:   "MakeCredential chooses the first supported algorithm",
		},
		{
			id:     TestIDAuthrMakeCredReq4F1,
			marker: "F-1",
			name:   "Credential parameters reject a non-map element",
			mutate: func(fields map[uint64]any) {
				parameters := fields[4].([]any)
				fields[4] = append(parameters, true)
			},
		},
		{
			id:     TestIDAuthrMakeCredReq4F2,
			marker: "F-2",
			name:   "Credential parameters reject an element without type",
			mutate: func(fields map[uint64]any) {
				delete(authrMakeCredReq4FirstParameter(fields), "type")
			},
		},
		{
			id:     TestIDAuthrMakeCredReq4F3,
			marker: "F-3",
			name:   "Credential parameters reject a non-text type",
			mutate: func(fields map[uint64]any) {
				authrMakeCredReq4SecondParameter(fields)["type"] = false
			},
		},
		{
			id:     TestIDAuthrMakeCredReq4F4,
			marker: "F-4",
			name:   "Credential parameters reject an element without alg",
			mutate: func(fields map[uint64]any) {
				delete(authrMakeCredReq4SecondParameter(fields), "alg")
			},
		},
		{
			id:     TestIDAuthrMakeCredReq4F5,
			marker: "F-5",
			name:   "Credential parameters reject a non-integer alg",
			mutate: func(fields map[uint64]any) {
				authrMakeCredReq4SecondParameter(fields)["alg"] = "not-an-integer"
			},
		},
		{
			id:             TestIDAuthrMakeCredReq4F6,
			marker:         "F-6",
			name:           "MakeCredential rejects an unsupported algorithm",
			expectedStatus: ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM,
			mutate: func(fields map[uint64]any) {
				fields[4] = []any{map[string]any{
					"type": string(credential.PublicKeyCredentialTypePublicKey),
					"alg":  uint64(0x45),
				}}
			},
		},
		{
			id:             TestIDAuthrMakeCredReq4F7,
			marker:         "F-7",
			name:           "MakeCredential rejects an unsupported credential type",
			expectedStatus: ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM,
			mutate: func(fields map[uint64]any) {
				parameter := maps.Clone(authrMakeCredReq4FirstParameter(fields))
				parameter["type"] = "not-public-key"
				fields[4] = []any{parameter}
			},
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		references := []conformance.RequirementRef{parametersReference, algorithmReference}
		if definition.id == TestIDAuthrMakeCredReq4P1 {
			references = append(
				references,
				messageEncodingReference,
				responseRequiredReference,
			)
		}
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: "Validates one pubKeyCredParams sequence constraint",
			Source: conformance.SourceLocation{
				Path: authrMakeCredReq4SourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var fixture makeCredentialFixture
				if !test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-4." + strings.ToLower(definition.marker) + ".prepare"),
					Name:       "Prepare an isolated valid MakeCredential request",
					References: []conformance.RequirementRef{parametersReference},
					Run: func(ctx context.Context) error {
						var err error
						fixture, err = prepareMakeCredentialFixture(ctx, test, config, authrMakeCredReq4RPID)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				if definition.id == TestIDAuthrMakeCredReq4P1 {
					test.Step(conformance.Step{
						ID:         "make-cred-req-4.p-1.exchange",
						Name:       "Create a credential with an unsupported algorithm before the supported list",
						References: references,
						Run: func(ctx context.Context) error {
							want := fixture.Request.PubKeyCredParams[0].Algorithm
							unsupported := authrMakeCredReq4UnsupportedAlgorithm(fixture.Request.PubKeyCredParams)
							request := fixture.Request
							request.PubKeyCredParams = slices.Concat(
								[]credential.PublicKeyCredentialParameters{{
									Type:      credential.PublicKeyCredentialTypePublicKey,
									Algorithm: unsupported,
								}},
								fixture.Request.PubKeyCredParams,
							)
							response, err := fixture.makeCredential(ctx, test.CBOR(), request)
							if err != nil {
								return err
							}

							return validateAuthrMakeCredReq4Algorithm(response, want)
						},
					})

					return
				}

				test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-req-4." + strings.ToLower(definition.marker) + ".exchange"),
					Name:       "Send the isolated credential-parameter mutation",
					References: references,
					Run: func(ctx context.Context) error {
						fields := fixture.rawFields()
						definition.mutate(fields)
						_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)
						if definition.expectedStatus != 0 {
							return expectCTAPStatus(err, definition.expectedStatus)
						}

						return expectAnyCTAPError(err)
					},
				})
			},
		})
	}

	return tests
}

func authrMakeCredReq4FirstParameter(fields map[uint64]any) map[string]any {
	return fields[4].([]any)[0].(map[string]any)
}

func authrMakeCredReq4SecondParameter(fields map[uint64]any) map[string]any {
	parameters := fields[4].([]any)
	second := maps.Clone(parameters[0].(map[string]any))
	if len(parameters) == 1 {
		parameters = append(parameters, second)
	} else {
		parameters[1] = second
	}
	fields[4] = parameters

	return second
}

func authrMakeCredReq4UnsupportedAlgorithm(
	parameters []credential.PublicKeyCredentialParameters,
) cose.Algorithm {
	algorithm := cose.Algorithm(-99)
	for slices.ContainsFunc(parameters, func(parameter credential.PublicKeyCredentialParameters) bool {
		return parameter.Type == credential.PublicKeyCredentialTypePublicKey &&
			parameter.Algorithm == algorithm
	}) {
		algorithm--
	}

	return algorithm
}

func validateAuthrMakeCredReq4Algorithm(
	response protocol.AuthenticatorMakeCredentialResponse,
	want cose.Algorithm,
) error {
	if response.AuthData == nil || response.AuthData.AttestedCredentialData == nil {
		return conformance.Fail("authenticatorMakeCredential response has no attested credential data")
	}
	got, err := response.AuthData.AttestedCredentialData.CredentialPublicKey.Algorithm()
	if err != nil {
		return conformance.Failf("credential public key has no valid algorithm: %v", err)
	}
	if got != want {
		return conformance.Failf("credential public key algorithm is %d, want first supported algorithm %d", got, want)
	}

	return nil
}

func authrMakeCredReq4ParametersReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1:pub-key-credential-parameters-sequence",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        "pub-key-credential-parameters-sequence",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#makecred-input-parameters",
		Level:         conformance.RequirementConstraint,
	}
}

func authrMakeCredReq4AlgorithmReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1.2:validate-pub-key-credential-parameters",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1.2",
		Clause:        "validate-pub-key-credential-parameters",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#op-makecred-step-alg",
		Level:         conformance.RequirementConstraint,
	}
}
