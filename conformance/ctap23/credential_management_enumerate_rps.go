package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const (
	credentialManagementEnumerateRPsSourcePath = "tests/CTAP2/Protocol/CredentialManagement/CredentialManagement-EnumerateRPs.js"
	credentialManagementEnumerateRPsRP1        = "one.enumerate-rps.ctap23-conformance.example"
	credentialManagementEnumerateRPsRP2        = "two.enumerate-rps.ctap23-conformance.example"

	TestIDCredentialManagementEnumerateRPsP1 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-rps.p-1"
	TestIDCredentialManagementEnumerateRPsP2 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-rps.p-2"
	TestIDCredentialManagementEnumerateRPsP3 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-rps.p-3"
	TestIDCredentialManagementEnumerateRPsP4 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-rps.p-4"
	TestIDCredentialManagementEnumerateRPsP5 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-rps.p-5"
	TestIDCredentialManagementEnumerateRPsP6 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-rps.p-6"
)

type credentialManagementEnumerateRPsCase struct {
	id                 conformance.TestID
	marker             string
	name               string
	persistentReadOnly bool
	run                func(*conformance.TestContext, *credentialManagementFixture)
}

func credentialManagementEnumerateRPsTests(config Config) []conformance.Test {
	cases := []credentialManagementEnumerateRPsCase{
		{
			id:     TestIDCredentialManagementEnumerateRPsP1,
			marker: "P-1",
			name:   "Report discoverable credential counts as credentials are created",
			run:    credentialManagementEnumerateRPsP1,
		},
		{
			id:     TestIDCredentialManagementEnumerateRPsP2,
			marker: "P-2",
			name:   "Begin RP enumeration with a credential-management token",
			run:    credentialManagementEnumerateRPsP2,
		},
		{
			id:     TestIDCredentialManagementEnumerateRPsP3,
			marker: "P-3",
			name:   "Continue RP enumeration without authorization fields",
			run:    credentialManagementEnumerateRPsP3,
		},
		{
			id:                 TestIDCredentialManagementEnumerateRPsP4,
			marker:             "P-4",
			name:               "Read credential metadata with a persistent read-only token",
			persistentReadOnly: true,
			run:                credentialManagementEnumerateRPsP4,
		},
		{
			id:                 TestIDCredentialManagementEnumerateRPsP5,
			marker:             "P-5",
			name:               "Begin RP enumeration with a persistent read-only token",
			persistentReadOnly: true,
			run:                credentialManagementEnumerateRPsP5,
		},
		{
			id:                 TestIDCredentialManagementEnumerateRPsP6,
			marker:             "P-6",
			name:               "Continue RP enumeration initialized by a persistent read-only token",
			persistentReadOnly: true,
			run:                credentialManagementEnumerateRPsP6,
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		tests = append(tests, credentialManagementEnumerateRPsTest(config, definition))
	}

	return tests
}

func credentialManagementEnumerateRPsTest(
	config Config,
	definition credentialManagementEnumerateRPsCase,
) conformance.Test {
	references := []conformance.RequirementRef{
		getInfoReference(),
		credentialManagementEnumerateRPsFeatureReference(),
		credentialManagementEnumerateRPsCommandReference(),
		clientPIN2KeyAgreementProtocolTwoReference(),
		clientPIN2NewPINPermissionsReference(),
		clientPINSetReference(),
		clientPINPowerCycleReference(),
		resetReference(),
		ctapMessageEncodingReference(),
	}
	if definition.marker == "P-1" || definition.marker == "P-4" {
		references = append(references, credentialManagementEnumerateRPsMetadataReference())
	}
	if definition.marker == "P-4" {
		references = append(references, clientPIN2PermissionsPCMRReference())
	}
	if definition.marker == "P-3" || definition.marker == "P-6" {
		references = append(references, credentialManagementEnumerateRPsStateReference())
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Exercises one credential-management RP enumeration behavior in an independent reset, PIN, and discoverable-credential lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: credentialManagementEnumerateRPsSourcePath,
			Case: definition.marker,
		},
		References: references,
		Run: func(test *conformance.TestContext) {
			var fixture *credentialManagementFixture
			if !test.Step(conformance.Step{
				ID:   "credential-management-enumerate-rps.prepare",
				Name: "Prepare an independent credential-management fixture",
				References: []conformance.RequirementRef{
					credentialManagementEnumerateRPsFeatureReference(),
					clientPIN2KeyAgreementProtocolTwoReference(),
					clientPIN2NewPINPermissionsReference(),
					clientPINSetReference(),
					clientPINPowerCycleReference(),
					resetReference(),
				},
				Run: func(ctx context.Context) error {
					var err error
					fixture, err = prepareCredentialManagementFixture(
						ctx,
						test,
						config,
						credentialManagementFixtureRequirements{
							PersistentReadOnly: definition.persistentReadOnly,
						},
					)

					return err
				},
			}) {
				return
			}

			definition.run(test, fixture)
		},
	}
}

func credentialManagementEnumerateRPsP1(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementEnumerateRPsCreateStep(
		fixture,
		"credential-management-enumerate-rps.p-1.create-first",
		"Create the first discoverable credential",
		credentialManagementEnumerateRPsRP1,
	)) {
		return
	}
	if !test.Step(conformance.Step{
		ID:   "credential-management-enumerate-rps.p-1.metadata-one",
		Name: "Read credential metadata after the first credential",
		References: []conformance.RequirementRef{
			credentialManagementEnumerateRPsMetadataReference(),
		},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateRPsAuthorized(
				ctx,
				test,
				fixture,
				protocol.PermissionCredentialManagement,
				protocol.CredentialManagementSubCommandGetCredsMetadata,
			)
			if err != nil {
				return err
			}

			return validateCredentialManagementMetadata(response, 1, true)
		},
	}) {
		return
	}
	if !test.Step(credentialManagementEnumerateRPsCreateStep(
		fixture,
		"credential-management-enumerate-rps.p-1.create-second",
		"Create a second credential for a distinct RP",
		credentialManagementEnumerateRPsRP2,
	)) {
		return
	}

	test.Step(conformance.Step{
		ID:   "credential-management-enumerate-rps.p-1.metadata-two",
		Name: "Read credential metadata after the second credential",
		References: []conformance.RequirementRef{
			credentialManagementEnumerateRPsMetadataReference(),
		},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateRPsAuthorized(
				ctx,
				test,
				fixture,
				protocol.PermissionCredentialManagement,
				protocol.CredentialManagementSubCommandGetCredsMetadata,
			)
			if err != nil {
				return err
			}

			return validateCredentialManagementMetadata(response, 2, false)
		},
	})
}

func credentialManagementEnumerateRPsP2(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementEnumerateRPsProvisionStep(fixture, "p-2")) {
		return
	}

	test.Step(conformance.Step{
		ID:         "credential-management-enumerate-rps.p-2.begin",
		Name:       "Begin RP enumeration with a fresh credential-management token",
		References: []conformance.RequirementRef{credentialManagementEnumerateRPsCommandReference()},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateRPsAuthorized(
				ctx,
				test,
				fixture,
				protocol.PermissionCredentialManagement,
				protocol.CredentialManagementSubCommandEnumerateRPsBegin,
			)
			if err != nil {
				return err
			}

			_, err = validateCredentialManagementEnumeratedRP(response, fixture, true)

			return err
		},
	})
}

func credentialManagementEnumerateRPsP3(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	credentialManagementEnumerateRPsContinuation(
		test,
		fixture,
		"p-3",
		protocol.PermissionCredentialManagement,
	)
}

func credentialManagementEnumerateRPsP4(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementEnumerateRPsProvisionStep(fixture, "p-4")) {
		return
	}

	test.Step(conformance.Step{
		ID:   "credential-management-enumerate-rps.p-4.metadata",
		Name: "Read credential metadata with a fresh pcmr-only token",
		References: []conformance.RequirementRef{
			clientPIN2PermissionsPCMRReference(),
			credentialManagementEnumerateRPsMetadataReference(),
		},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateRPsAuthorized(
				ctx,
				test,
				fixture,
				protocol.PermissionPersistentCredentialManagementReadOnly,
				protocol.CredentialManagementSubCommandGetCredsMetadata,
			)
			if err != nil {
				return err
			}

			return validateCredentialManagementMetadata(response, 2, false)
		},
	})
}

func credentialManagementEnumerateRPsP5(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementEnumerateRPsProvisionStep(fixture, "p-5")) {
		return
	}

	test.Step(conformance.Step{
		ID:         "credential-management-enumerate-rps.p-5.begin",
		Name:       "Begin RP enumeration with a fresh pcmr-only token",
		References: []conformance.RequirementRef{credentialManagementEnumerateRPsCommandReference()},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateRPsAuthorized(
				ctx,
				test,
				fixture,
				protocol.PermissionPersistentCredentialManagementReadOnly,
				protocol.CredentialManagementSubCommandEnumerateRPsBegin,
			)
			if err != nil {
				return err
			}

			_, err = validateCredentialManagementEnumeratedRP(response, fixture, true)

			return err
		},
	})
}

func credentialManagementEnumerateRPsP6(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	credentialManagementEnumerateRPsContinuation(
		test,
		fixture,
		"p-6",
		protocol.PermissionPersistentCredentialManagementReadOnly,
	)
}

func credentialManagementEnumerateRPsContinuation(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
	caseID string,
	permission protocol.Permission,
) {
	if !test.Step(credentialManagementEnumerateRPsProvisionStep(fixture, caseID)) {
		return
	}

	var firstRPID string
	if !test.Step(conformance.Step{
		ID:         conformance.StepID("credential-management-enumerate-rps." + caseID + ".initialize"),
		Name:       "Initialize RP enumeration with a fresh management token",
		References: []conformance.RequirementRef{credentialManagementEnumerateRPsCommandReference()},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateRPsAuthorized(
				ctx,
				test,
				fixture,
				permission,
				protocol.CredentialManagementSubCommandEnumerateRPsBegin,
			)
			if err != nil {
				return err
			}
			firstRPID, err = validateCredentialManagementEnumeratedRP(response, fixture, true)

			return err
		},
	}) {
		return
	}

	test.Step(conformance.Step{
		ID:   conformance.StepID("credential-management-enumerate-rps." + caseID + ".next"),
		Name: "Read the other RP with a subcommand-only continuation",
		References: []conformance.RequirementRef{
			credentialManagementEnumerateRPsCommandReference(),
			credentialManagementEnumerateRPsStateReference(),
		},
		Run: func(ctx context.Context) error {
			response, err := executeCredentialManagement(
				ctx,
				test.CBOR(),
				credentialManagementContinuationRequest(
					protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP,
				),
			)
			if err != nil {
				return err
			}
			secondRPID, err := validateCredentialManagementEnumeratedRP(response, fixture, false)
			if err != nil {
				return err
			}
			if secondRPID == firstRPID {
				return conformance.Fail("enumerateRPsGetNextRP returned the RP from enumerateRPsBegin again")
			}

			return nil
		},
	})
}

func credentialManagementEnumerateRPsProvisionStep(
	fixture *credentialManagementFixture,
	caseID string,
) conformance.Step {
	return conformance.Step{
		ID:   conformance.StepID("credential-management-enumerate-rps." + caseID + ".provision"),
		Name: "Create discoverable credentials for two distinct RPs",
		References: []conformance.RequirementRef{
			authrMakeCredReq1CommandReference(),
			credentialManagementEnumerateRPsCommandReference(),
		},
		Run: func(ctx context.Context) error {
			if _, err := fixture.createDiscoverableCredential(
				ctx,
				credentialManagementEnumerateRPsRP1,
			); err != nil {
				return err
			}
			_, err := fixture.createDiscoverableCredential(
				ctx,
				credentialManagementEnumerateRPsRP2,
			)

			return err
		},
	}
}

func credentialManagementEnumerateRPsCreateStep(
	fixture *credentialManagementFixture,
	id string,
	name string,
	rpID string,
) conformance.Step {
	return conformance.Step{
		ID:         conformance.StepID(id),
		Name:       name,
		References: []conformance.RequirementRef{authrMakeCredReq1CommandReference()},
		Run: func(ctx context.Context) error {
			_, err := fixture.createDiscoverableCredential(ctx, rpID)

			return err
		},
	}
}

func credentialManagementEnumerateRPsAuthorized(
	ctx context.Context,
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
	permission protocol.Permission,
	subCommand protocol.CredentialManagementSubCommand,
) (credentialManagementResponse, error) {
	token, err := fixture.refreshManagementToken(ctx, permission)
	if err != nil {
		return credentialManagementResponse{}, err
	}
	authorized, err := newCredentialManagementAuthorizedRequest(token, subCommand, nil)
	if err != nil {
		return credentialManagementResponse{}, fmt.Errorf(
			"ctap23: build credential-management request: %w",
			err,
		)
	}
	defer authorized.clear()

	return executeCredentialManagement(ctx, test.CBOR(), authorized.Request)
}

func validateCredentialManagementMetadata(
	result credentialManagementResponse,
	wantExisting uint,
	requireMoreThanOneRemaining bool,
) error {
	if len(result.Fields) != 2 || result.Fields[1] == nil || result.Fields[2] == nil {
		return conformance.Fail(
			"getCredsMetadata response must contain exactly existingResidentCredentialsCount and maxPossibleRemainingResidentCredentialsCount",
		)
	}
	if result.Response.ExistingResidentCredentialsCount == nil ||
		*result.Response.ExistingResidentCredentialsCount != wantExisting {
		return conformance.Failf(
			"existingResidentCredentialsCount is not %d",
			wantExisting,
		)
	}
	remaining := result.Response.MaxPossibleRemainingResidentCredentialsCount
	if remaining == nil {
		return conformance.Fail(
			"getCredsMetadata response omits maxPossibleRemainingResidentCredentialsCount",
		)
	}
	if requireMoreThanOneRemaining && *remaining <= 1 {
		return conformance.Fail(
			"maxPossibleRemainingResidentCredentialsCount is not greater than one after creating one credential",
		)
	}

	return nil
}

func validateCredentialManagementEnumeratedRP(
	result credentialManagementResponse,
	fixture *credentialManagementFixture,
	begin bool,
) (string, error) {
	wantFields := 2
	if begin {
		wantFields = 3
	}
	if len(result.Fields) != wantFields || result.Fields[3] == nil || result.Fields[4] == nil {
		return "", conformance.Failf(
			"RP enumeration response contains %d fields, want exactly %d with rp and rpIDHash",
			len(result.Fields),
			wantFields,
		)
	}
	if begin {
		if result.Fields[5] == nil || result.Response.TotalRPs != uint(len(credentialManagementEnumerateRPsExpected(fixture))) {
			return "", conformance.Fail("enumerateRPsBegin totalRPs does not match the provisioned RP count")
		}
	} else if result.Fields[5] != nil {
		return "", conformance.Fail("enumerateRPsGetNextRP response contains totalRPs")
	}

	rpID := result.Response.RP.ID
	if rpID == "" {
		return "", conformance.Fail("RP enumeration response omits rp.id")
	}
	expected, ok := credentialManagementEnumerateRPsExpected(fixture)[rpID]
	if !ok {
		return "", conformance.Fail("RP enumeration response contains an unknown rp.id")
	}
	if len(result.Response.RPIDHash) != sha256.Size ||
		!bytes.Equal(result.Response.RPIDHash, expected) {
		return "", conformance.Fail("RP enumeration response rpIDHash does not equal SHA-256(rp.id)")
	}

	return rpID, nil
}

func credentialManagementEnumerateRPsExpected(
	fixture *credentialManagementFixture,
) map[string][]byte {
	expected := make(map[string][]byte, len(fixture.Credentials))
	for _, credential := range fixture.Credentials {
		expected[credential.RPID] = credential.RPIDHash
	}

	return expected
}

func credentialManagementEnumerateRPsFeatureReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.1:credential-management-feature-detection",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.1",
		Clause:        "credential-management-feature-detection",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#credential-management-feature-detection",
		Level:         conformance.RequirementConstraint,
	}
}

func credentialManagementEnumerateRPsMetadataReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.2:get-credentials-metadata",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.2",
		Clause:        "get-credentials-metadata",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getCredsMetadata",
		Level:         conformance.RequirementMust,
	}
}

func credentialManagementEnumerateRPsCommandReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.3:enumerating-rps",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.3",
		Clause:        "enumerating-rps",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#enumerating-rps",
		Level:         conformance.RequirementMust,
	}
}

func credentialManagementEnumerateRPsStateReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6:stateful-command-sequencing",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6",
		Clause:        "stateful-command-sequencing",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticator-api",
		Level:         conformance.RequirementConstraint,
	}
}
