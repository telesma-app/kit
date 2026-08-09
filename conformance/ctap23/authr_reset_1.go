package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrReset1SourcePath = "tests/CTAP2/Protocol/Reset/Authr-Reset-1.js"
	authrReset1RPID       = "reset-1.ctap23-conformance.example"

	TestIDAuthrReset1P1 conformance.TestID = "fido.ctap2.3.authr-reset-1.p-1"
)

var authrReset1PostResetClientDataHash = sha256.Sum256(
	[]byte("ctap23 Authr-Reset-1 post-reset GetAssertion"),
)

func authrReset1Tests(config Config) []conformance.Test {
	makeCredentialReference := authrMakeCredReq1CommandReference()
	getAssertionReference := authrGetAssertionReq1CommandReference()
	getAssertionResponseReference := authrGetAssertionReq1ResponseCredentialReference()
	noCredentialsReference := authrGetAssertionReq3NoCredentialsReference()
	resetRequirement := resetReference()
	resetWindowRequirement := authrReset1ResetWindowReference()
	credentialInvalidationRequirement := authrReset1CredentialInvalidationReference()

	return []conformance.Test{{
		ID:          TestIDAuthrReset1P1,
		Name:        "Reset deletes an existing credential",
		Description: "Creates and exercises a credential, resets the authenticator, and requires the credential to be gone",
		Source: conformance.SourceLocation{
			Path: authrReset1SourcePath,
			Case: "P-1",
		},
		References: []conformance.RequirementRef{
			makeCredentialReference,
			getAssertionReference,
			getAssertionResponseReference,
			resetRequirement,
			resetWindowRequirement,
			credentialInvalidationRequirement,
			noCredentialsReference,
		},
		Destructive: true,
		Run: func(test *conformance.TestContext) {
			var fixture getAssertionFixture
			if !test.Step(conformance.Step{
				ID:         "authr-reset-1.prepare",
				Name:       "Create an isolated credential",
				References: []conformance.RequirementRef{makeCredentialReference},
				Run: func(ctx context.Context) error {
					var err error
					fixture, err = prepareGetAssertionFixture(
						ctx,
						test,
						config,
						getAssertionFixtureSpec{RPID: authrReset1RPID},
					)

					return err
				},
			}) {
				return
			}
			defer fixture.clear()

			if !test.Step(conformance.Step{
				ID:   "authr-reset-1.get-before-reset",
				Name: "Use the credential before reset",
				References: []conformance.RequirementRef{
					getAssertionReference,
					getAssertionResponseReference,
				},
				Run: func(ctx context.Context) error {
					response, err := fixture.getAssertion(ctx, test.CBOR(), fixture.Request)
					if err != nil {
						return err
					}
					if !bytes.Equal(response.Response.Credential.ID, fixture.Request.AllowList[0].ID) {
						return conformance.Fail(
							"authenticatorGetAssertion returned a different credential before reset",
						)
					}

					return nil
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "authr-reset-1.power-cycle",
				Name:       "Open the authenticator reset window",
				References: []conformance.RequirementRef{resetWindowRequirement},
				Run: func(ctx context.Context) error {
					return config.PowerCycler(ctx)
				},
			}) {
				return
			}
			if !test.Step(conformance.Step{
				ID:   "authr-reset-1.reset",
				Name: "Reset the authenticator",
				References: []conformance.RequirementRef{
					resetRequirement,
					credentialInvalidationRequirement,
				},
				Run: func(ctx context.Context) error {
					return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "authr-reset-1.refresh-authorization",
				Name:       "Authorize a post-reset GetAssertion request",
				References: []conformance.RequirementRef{getAssertionReference},
				Run: func(ctx context.Context) error {
					fixture.Request.ClientDataHash = slices.Clone(
						authrReset1PostResetClientDataHash[:],
					)

					return fixture.refreshAuthorization(ctx, test, config, &fixture.Request)
				},
			}) {
				return
			}

			test.Step(conformance.Step{
				ID:   "authr-reset-1.get-after-reset",
				Name: "Require the reset credential to be unavailable",
				References: []conformance.RequirementRef{
					getAssertionReference,
					noCredentialsReference,
				},
				Run: func(ctx context.Context) error {
					_, err := exchangeGetAssertion(ctx, test.CBOR(), fixture.Request)

					return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_NO_CREDENTIALS)
				},
			})
		},
	}}
}

func authrReset1ResetWindowReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.6:reset-within-power-up-window",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.6",
		Clause:        "reset-within-power-up-window",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset",
		Level:         conformance.RequirementMust,
	}
}

func authrReset1CredentialInvalidationReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.6:reset-invalidates-generated-credentials",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.6",
		Clause:        "reset-invalidates-generated-credentials",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset",
		Level:         conformance.RequirementConstraint,
	}
}
