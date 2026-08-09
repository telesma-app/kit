package ctap23

import (
	"context"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrMakeCredReq5AttestationTypeSourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-5.js"
	authrMakeCredReq5AttestationTypeRPID       = "make-cred-req-5-attestation-type.ctap23-conformance.example"

	TestIDAuthrMakeCredReq5AttestationTypeP4 conformance.TestID = "fido.ctap2.3.authr-make-cred-req-5.p-4"
)

func authrMakeCredReq5AttestationTypeTests(config Config) []conformance.Test {
	commandReference := authrMakeCredReq1CommandReference()
	preferenceReference := authrMakeCredReq5AttestationTypePreferenceReference()
	wrongTypeReference := authrMakeCredReq5AttestationTypeWrongTypeReference()
	references := []conformance.RequirementRef{
		commandReference,
		preferenceReference,
		wrongTypeReference,
	}

	return []conformance.Test{{
		ID:   TestIDAuthrMakeCredReq5AttestationTypeP4,
		Name: "MakeCredential rejects a non-array attestation-format preference",
		Description: "Corrects the pinned case's omitted request member and success expectation by " +
			"sending the intended malformed attestationFormatsPreference",
		Source: conformance.SourceLocation{
			Path: authrMakeCredReq5AttestationTypeSourcePath,
			Case: "P-4",
		},
		References:  references,
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			var fixture makeCredentialFixture
			if !test.Step(conformance.Step{
				ID:         "make-cred-req-5.p-4.prepare",
				Name:       "Prepare an isolated valid MakeCredential request",
				References: []conformance.RequirementRef{commandReference},
				Run: func(ctx context.Context) error {
					var err error
					fixture, err = prepareMakeCredentialFixture(
						ctx,
						test,
						config,
						authrMakeCredReq5AttestationTypeRPID,
					)

					return err
				},
			}) {
				return
			}
			defer fixture.clear()

			test.Step(conformance.Step{
				ID:         "make-cred-req-5.p-4.exchange",
				Name:       "Send a non-array attestation-format preference",
				References: references,
				Run: func(ctx context.Context) error {
					fields := fixture.rawFields()
					// The pinned case mutates a local preference value but omits
					// member 0x0B from its encoded request. Put the intended
					// malformed value on the wire and apply current CTAP behavior.
					fields[11] = true
					_, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)

					return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
				},
			})
		},
	}}
}

func authrMakeCredReq5AttestationTypePreferenceReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1:attestation-formats-preference-array-of-strings",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        "attestation-formats-preference-array-of-strings",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		Level:         conformance.RequirementConstraint,
	}
}

func authrMakeCredReq5AttestationTypeWrongTypeReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:8:wrong-known-member-type",
		Specification: conformance.SpecificationCTAP23,
		Section:       "8",
		Clause:        "wrong-known-member-type",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding",
		Level:         conformance.RequirementShould,
	}
}
