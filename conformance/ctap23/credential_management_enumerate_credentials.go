package ctap23

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const (
	credentialManagementEnumerateCredentialsSourcePath = "tests/CTAP2/Protocol/CredentialManagement/CredentialManagement-EnumerateCredentials.js"
	credentialManagementEnumerateCredentialsRP         = "enumerate-credentials.ctap23-conformance.example"

	TestIDCredentialManagementEnumerateCredentialsP1 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-credentials.p-1"
	TestIDCredentialManagementEnumerateCredentialsP2 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-credentials.p-2"
	TestIDCredentialManagementEnumerateCredentialsP3 conformance.TestID = "fido.ctap2.3.credential-management-enumerate-credentials.p-3"
)

type credentialManagementEnumerateCredentialsCase struct {
	id                 conformance.TestID
	marker             string
	name               string
	persistentReadOnly bool
	run                func(*conformance.TestContext, *credentialManagementFixture)
}

func credentialManagementEnumerateCredentialsTests(config Config) []conformance.Test {
	cases := []credentialManagementEnumerateCredentialsCase{
		{
			id:     TestIDCredentialManagementEnumerateCredentialsP1,
			marker: "P-1",
			name:   "Begin credential enumeration with a credential-management token",
			run:    credentialManagementEnumerateCredentialsP1,
		},
		{
			id:     TestIDCredentialManagementEnumerateCredentialsP2,
			marker: "P-2",
			name:   "Continue credential enumeration without authorization fields",
			run:    credentialManagementEnumerateCredentialsP2,
		},
		{
			id:                 TestIDCredentialManagementEnumerateCredentialsP3,
			marker:             "P-3",
			name:               "Begin credential enumeration with a persistent read-only token",
			persistentReadOnly: true,
			run:                credentialManagementEnumerateCredentialsP3,
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		tests = append(tests, credentialManagementEnumerateCredentialsTest(config, definition))
	}

	return tests
}

func credentialManagementEnumerateCredentialsTest(
	config Config,
	definition credentialManagementEnumerateCredentialsCase,
) conformance.Test {
	references := []conformance.RequirementRef{
		getInfoReference(),
		credentialManagementEnumerateCredentialsFeatureReference(),
		credentialManagementEnumerateCredentialsCommandReference(),
		clientPIN2KeyAgreementProtocolTwoReference(),
		clientPIN2NewPINPermissionsReference(),
		clientPINSetReference(),
		clientPINPowerCycleReference(),
		resetReference(),
		ctapMessageEncodingReference(),
	}
	if definition.marker == "P-2" {
		references = append(references, credentialManagementEnumerateCredentialsStateReference())
	}
	if definition.marker == "P-3" {
		references = append(references, credentialManagementEnumerateCredentialsPCMRReference())
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Exercises one credential enumeration behavior in an independent reset, PIN, and same-RP credential lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: credentialManagementEnumerateCredentialsSourcePath,
			Case: definition.marker,
		},
		References: references,
		Run: func(test *conformance.TestContext) {
			var fixture *credentialManagementFixture
			if !test.Step(conformance.Step{
				ID:   "credential-management-enumerate-credentials.prepare",
				Name: "Prepare an independent credential-management fixture",
				References: []conformance.RequirementRef{
					credentialManagementEnumerateCredentialsFeatureReference(),
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

func credentialManagementEnumerateCredentialsP1(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementEnumerateCredentialsProvisionStep(fixture, "p-1")) {
		return
	}

	test.Step(conformance.Step{
		ID:         "credential-management-enumerate-credentials.p-1.begin",
		Name:       "Begin credential enumeration with a fresh protocol-two cm-only token",
		References: []conformance.RequirementRef{credentialManagementEnumerateCredentialsCommandReference()},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateCredentialsAuthorizedBegin(
				ctx,
				test,
				fixture,
				protocol.PermissionCredentialManagement,
				fixture.Credentials[0].RPIDHash,
			)
			if err != nil {
				return err
			}

			_, err = validateCredentialManagementEnumeratedCredential(response, fixture, true)

			return err
		},
	})
}

func credentialManagementEnumerateCredentialsP2(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementEnumerateCredentialsProvisionStep(fixture, "p-2")) {
		return
	}

	var firstCredentialID []byte
	if !test.Step(conformance.Step{
		ID:         "credential-management-enumerate-credentials.p-2.initialize",
		Name:       "Initialize credential enumeration with a fresh protocol-two cm-only token",
		References: []conformance.RequirementRef{credentialManagementEnumerateCredentialsCommandReference()},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateCredentialsAuthorizedBegin(
				ctx,
				test,
				fixture,
				protocol.PermissionCredentialManagement,
				fixture.Credentials[0].RPIDHash,
			)
			if err != nil {
				return err
			}
			firstCredentialID, err = validateCredentialManagementEnumeratedCredential(
				response,
				fixture,
				true,
			)

			return err
		},
	}) {
		return
	}

	test.Step(conformance.Step{
		ID:   "credential-management-enumerate-credentials.p-2.next",
		Name: "Read the other credential with a subcommand-only continuation",
		References: []conformance.RequirementRef{
			credentialManagementEnumerateCredentialsCommandReference(),
			credentialManagementEnumerateCredentialsStateReference(),
		},
		Run: func(ctx context.Context) error {
			response, err := executeCredentialManagement(
				ctx,
				test.CBOR(),
				credentialManagementContinuationRequest(
					protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
				),
			)
			if err != nil {
				return err
			}
			secondCredentialID, err := validateCredentialManagementEnumeratedCredential(
				response,
				fixture,
				false,
			)
			if err != nil {
				return err
			}
			if bytes.Equal(secondCredentialID, firstCredentialID) {
				return conformance.Fail(
					"enumerateCredentialsGetNextCredential returned the credential from enumerateCredentialsBegin again",
				)
			}

			return nil
		},
	})
}

func credentialManagementEnumerateCredentialsP3(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementEnumerateCredentialsProvisionStep(fixture, "p-3")) {
		return
	}

	test.Step(conformance.Step{
		ID:   "credential-management-enumerate-credentials.p-3.begin",
		Name: "Begin credential enumeration with a fresh protocol-two pcmr-only token",
		References: []conformance.RequirementRef{
			credentialManagementEnumerateCredentialsCommandReference(),
			credentialManagementEnumerateCredentialsPCMRReference(),
		},
		Run: func(ctx context.Context) error {
			response, err := credentialManagementEnumerateCredentialsAuthorizedBegin(
				ctx,
				test,
				fixture,
				protocol.PermissionPersistentCredentialManagementReadOnly,
				fixture.Credentials[0].RPIDHash,
			)
			if err != nil {
				return err
			}

			_, err = validateCredentialManagementEnumeratedCredential(response, fixture, true)

			return err
		},
	})
}

func credentialManagementEnumerateCredentialsProvisionStep(
	fixture *credentialManagementFixture,
	caseID string,
) conformance.Step {
	return conformance.Step{
		ID:   conformance.StepID("credential-management-enumerate-credentials." + caseID + ".provision"),
		Name: "Create two discoverable credentials for the same RP",
		References: []conformance.RequirementRef{
			authrMakeCredReq1CommandReference(),
			credentialManagementEnumerateCredentialsCommandReference(),
		},
		Run: func(ctx context.Context) error {
			if _, err := fixture.createDiscoverableCredential(
				ctx,
				credentialManagementEnumerateCredentialsRP,
			); err != nil {
				return err
			}
			_, err := fixture.createDiscoverableCredential(
				ctx,
				credentialManagementEnumerateCredentialsRP,
			)

			return err
		},
	}
}

func credentialManagementEnumerateCredentialsAuthorizedBegin(
	ctx context.Context,
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
	permission protocol.Permission,
	rpIDHash []byte,
) (credentialManagementResponse, error) {
	token, err := fixture.refreshManagementToken(ctx, permission)
	if err != nil {
		return credentialManagementResponse{}, err
	}
	params := protocol.CredentialManagementSubCommandParams{RPIDHash: rpIDHash}
	authorized, err := newCredentialManagementAuthorizedRequest(
		token,
		protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
		&params,
	)
	if err != nil {
		return credentialManagementResponse{}, fmt.Errorf(
			"ctap23: build credential-management request: %w",
			err,
		)
	}
	defer authorized.clear()

	return executeCredentialManagement(ctx, test.CBOR(), authorized.Request)
}

func validateCredentialManagementEnumeratedCredential(
	result credentialManagementResponse,
	fixture *credentialManagementFixture,
	begin bool,
) ([]byte, error) {
	defer clear(result.Response.LargeBlobKey)
	defer clear(result.Fields[11])

	for field := range result.Fields {
		switch field {
		case 6, 7, 8, 9, 10, 11, 12:
		default:
			return nil, conformance.Failf(
				"credential enumeration response contains unexpected field 0x%02x",
				field,
			)
		}
	}
	for _, field := range []uint64{6, 7, 8, 10} {
		if result.Fields[field] == nil {
			return nil, conformance.Failf(
				"credential enumeration response omits required field 0x%02x",
				field,
			)
		}
	}

	wantTotal := credentialManagementEnumerateCredentialsCount(fixture)
	if begin {
		if result.Fields[9] == nil || result.Response.TotalCredentials != wantTotal {
			return nil, conformance.Failf(
				"enumerateCredentialsBegin totalCredentials = %d, want %d",
				result.Response.TotalCredentials,
				wantTotal,
			)
		}
	} else if result.Fields[9] != nil {
		return nil, conformance.Fail(
			"enumerateCredentialsGetNextCredential response contains totalCredentials",
		)
	}

	descriptor := result.Response.CredentialID
	if descriptor.Type != credential.PublicKeyCredentialTypePublicKey || len(descriptor.ID) == 0 {
		return nil, conformance.Fail(
			"credential enumeration response credentialID is not a non-empty public-key descriptor",
		)
	}
	expected := credentialManagementEnumerateCredentialsExpected(fixture, descriptor.ID)
	if expected == nil {
		return nil, conformance.Fail(
			"credential enumeration response contains an unknown credentialID",
		)
	}
	if !bytes.Equal(result.Response.User.ID, expected.User.ID) ||
		len(result.Response.User.ID) == 0 {
		return nil, conformance.Fail(
			"credential enumeration response user ID does not equal the provisioned user ID",
		)
	}
	if !reflect.DeepEqual(result.Response.PublicKey, expected.PublicKey) {
		return nil, conformance.Fail(
			"credential enumeration response publicKey does not equal the provisioned COSE key",
		)
	}
	if result.Response.CredProtect < 1 || result.Response.CredProtect > 3 {
		return nil, conformance.Failf(
			"credential enumeration response credProtect = %d, want a value from 1 through 3",
			result.Response.CredProtect,
		)
	}

	largeBlobPresent := result.Fields[11] != nil
	if largeBlobPresent && len(result.Response.LargeBlobKey) != 32 {
		return nil, conformance.Failf(
			"credential enumeration response largeBlobKey length = %d, want 32",
			len(result.Response.LargeBlobKey),
		)
	}
	if expected.LargeBlobKey != nil &&
		(!largeBlobPresent || !bytes.Equal(result.Response.LargeBlobKey, expected.LargeBlobKey)) {
		return nil, conformance.Fail(
			"credential enumeration response largeBlobKey does not equal the stored credential key",
		)
	}

	thirdPartyPaymentSupported := slices.Contains(
		fixture.Info.Extensions,
		extension.ExtensionIdentifierThirdPartyPayment,
	)
	thirdPartyPaymentPresent := result.Fields[12] != nil
	if thirdPartyPaymentPresent != thirdPartyPaymentSupported {
		return nil, conformance.Failf(
			"credential enumeration response thirdPartyPayment presence = %t, authenticator support = %t",
			thirdPartyPaymentPresent,
			thirdPartyPaymentSupported,
		)
	}
	if thirdPartyPaymentPresent {
		if result.Response.ThirdPartyPayment == nil {
			return nil, conformance.Fail("credential enumeration response thirdPartyPayment is not a boolean")
		}
		if *result.Response.ThirdPartyPayment {
			return nil, conformance.Fail(
				"credential enumeration response thirdPartyPayment is true for a credential created without the extension",
			)
		}
	}

	return descriptor.ID, nil
}

func credentialManagementEnumerateCredentialsExpected(
	fixture *credentialManagementFixture,
	credentialID []byte,
) *credentialManagementCredential {
	for index := range fixture.Credentials {
		candidate := &fixture.Credentials[index]
		if candidate.RPID == credentialManagementEnumerateCredentialsRP &&
			bytes.Equal(candidate.Descriptor.ID, credentialID) {
			return candidate
		}
	}

	return nil
}

func credentialManagementEnumerateCredentialsCount(
	fixture *credentialManagementFixture,
) uint {
	var count uint
	for _, candidate := range fixture.Credentials {
		if candidate.RPID == credentialManagementEnumerateCredentialsRP {
			count++
		}
	}

	return count
}

func credentialManagementEnumerateCredentialsCommandReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.4:enumerating-credentials",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.4",
		Clause:        "enumerating-credentials",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#enumerating-credentials",
		Level:         conformance.RequirementMust,
	}
}

func credentialManagementEnumerateCredentialsFeatureReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.1:credential-management-feature-detection",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.1",
		Clause:        "credential-management-feature-detection",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#credential-management-feature-detection",
		Level:         conformance.RequirementConstraint,
	}
}

func credentialManagementEnumerateCredentialsStateReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6:stateful-command-sequencing",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6",
		Clause:        "stateful-command-sequencing",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticator-api",
		Level:         conformance.RequirementConstraint,
	}
}

func credentialManagementEnumerateCredentialsPCMRReference() conformance.RequirementRef {
	return clientPIN2GetPINTokenReference(
		"6.8.4",
		"enumerate-credentials-pcmr-authorization",
		"enumerating-credentials",
	)
}
