package ctap23

import (
	"bytes"
	"context"
	"fmt"
	"reflect"

	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	credentialManagementUpdateAndDeleteSourcePath = "tests/CTAP2/Protocol/CredentialManagement/CredentialManagement-UpdateAndDelete.js"
	credentialManagementUpdateAndDeleteRP         = "update-and-delete.ctap23-conformance.example"

	TestIDCredentialManagementUpdateAndDeleteP1 conformance.TestID = "fido.ctap2.3.credential-management-update-and-delete.p-1"
	TestIDCredentialManagementUpdateAndDeleteP2 conformance.TestID = "fido.ctap2.3.credential-management-update-and-delete.p-2"
)

type credentialManagementUpdateAndDeleteCase struct {
	id     conformance.TestID
	marker string
	name   string
	run    func(*conformance.TestContext, *credentialManagementFixture)
}

func credentialManagementUpdateAndDeleteTests(config Config) []conformance.Test {
	cases := []credentialManagementUpdateAndDeleteCase{
		{
			id:     TestIDCredentialManagementUpdateAndDeleteP1,
			marker: "P-1",
			name:   "Update discoverable credential user information",
			run:    credentialManagementUpdateAndDeleteP1,
		},
		{
			id:     TestIDCredentialManagementUpdateAndDeleteP2,
			marker: "P-2",
			name:   "Delete a discoverable credential",
			run:    credentialManagementUpdateAndDeleteP2,
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		tests = append(tests, credentialManagementUpdateAndDeleteTest(config, definition))
	}

	return tests
}

func credentialManagementUpdateAndDeleteTest(
	config Config,
	definition credentialManagementUpdateAndDeleteCase,
) conformance.Test {
	references := []conformance.RequirementRef{
		getInfoReference(),
		credentialManagementUpdateAndDeleteFeatureReference(),
		clientPIN2KeyAgreementProtocolTwoReference(),
		clientPIN2NewPINPermissionsReference(),
		clientPINSetReference(),
		clientPINPowerCycleReference(),
		resetReference(),
		ctapMessageEncodingReference(),
	}
	if definition.marker == "P-1" {
		references = append(
			references,
			credentialManagementUpdateUserInformationReference(),
			credentialManagementUpdateAndDeleteEnumerationReference(),
		)
	} else {
		references = append(
			references,
			credentialManagementDeleteCredentialReference(),
			authrGetAssertionReq1CommandReference(),
		)
	}

	return conformance.Test{
		ID:          definition.id,
		Name:        definition.name,
		Description: "Exercises one credential-management mutation in an independent reset, PIN, and discoverable-credential lifecycle",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: credentialManagementUpdateAndDeleteSourcePath,
			Case: definition.marker,
		},
		References: references,
		Run: func(test *conformance.TestContext) {
			var fixture *credentialManagementFixture
			if !test.Step(conformance.Step{
				ID:   "credential-management-update-and-delete.prepare",
				Name: "Prepare an independent credential-management fixture",
				References: []conformance.RequirementRef{
					credentialManagementUpdateAndDeleteFeatureReference(),
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
						credentialManagementFixtureRequirements{},
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

func credentialManagementUpdateAndDeleteP1(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementUpdateAndDeleteProvisionStep(fixture, "p-1")) {
		return
	}

	record := fixture.Credentials[0]
	updatedUser := credential.PublicKeyCredentialUserEntity{
		ID:          record.User.ID,
		Name:        "updated-user@update-and-delete.ctap23-conformance.example",
		DisplayName: "Updated credential management user",
	}
	if !test.Step(conformance.Step{
		ID:         "credential-management-update-and-delete.p-1.update",
		Name:       "Update the user entity with a fresh protocol-two cm-only token",
		References: []conformance.RequirementRef{credentialManagementUpdateUserInformationReference()},
		Run: func(ctx context.Context) error {
			before, err := credentialManagementReadOptionalStoreState(ctx, test)
			if err != nil {
				return err
			}

			token, err := fixture.refreshManagementToken(
				ctx,
				protocol.PermissionCredentialManagement,
			)
			if err != nil {
				return err
			}
			params := protocol.CredentialManagementSubCommandParams{
				CredentialID: record.Descriptor,
				User:         updatedUser,
			}
			authorized, err := newCredentialManagementAuthorizedRequest(
				token,
				protocol.CredentialManagementSubCommandUpdateUserInformation,
				&params,
			)
			if err != nil {
				return fmt.Errorf("ctap23: authorize updateUserInformation: %w", err)
			}
			defer authorized.clear()

			if err := executeEmptyCredentialManagement(ctx, test.CBOR(), authorized.Request); err != nil {
				return err
			}

			return credentialManagementValidateStoreStateChanged(ctx, test, before)
		},
	}) {
		return
	}

	test.Step(conformance.Step{
		ID:         "credential-management-update-and-delete.p-1.enumerate",
		Name:       "Enumerate the credential and verify the updated user entity",
		References: []conformance.RequirementRef{credentialManagementUpdateAndDeleteEnumerationReference()},
		Run: func(ctx context.Context) error {
			token, err := fixture.refreshManagementToken(
				ctx,
				protocol.PermissionCredentialManagement,
			)
			if err != nil {
				return err
			}
			params := protocol.CredentialManagementSubCommandParams{RPIDHash: record.RPIDHash}
			authorized, err := newCredentialManagementAuthorizedRequest(
				token,
				protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
				&params,
			)
			if err != nil {
				return fmt.Errorf("ctap23: authorize enumerateCredentialsBegin: %w", err)
			}
			defer authorized.clear()

			response, err := executeCredentialManagement(ctx, test.CBOR(), authorized.Request)
			if err != nil {
				return err
			}

			return credentialManagementValidateUpdatedCredential(response, record, updatedUser)
		},
	})
}

func credentialManagementUpdateAndDeleteP2(
	test *conformance.TestContext,
	fixture *credentialManagementFixture,
) {
	if !test.Step(credentialManagementUpdateAndDeleteProvisionStep(fixture, "p-2")) {
		return
	}

	record := fixture.Credentials[0]
	if !test.Step(conformance.Step{
		ID:         "credential-management-update-and-delete.p-2.delete",
		Name:       "Delete the credential with a fresh protocol-two cm-only token",
		References: []conformance.RequirementRef{credentialManagementDeleteCredentialReference()},
		Run: func(ctx context.Context) error {
			before, err := credentialManagementReadOptionalStoreState(ctx, test)
			if err != nil {
				return err
			}

			token, err := fixture.refreshManagementToken(
				ctx,
				protocol.PermissionCredentialManagement,
			)
			if err != nil {
				return err
			}
			params := protocol.CredentialManagementSubCommandParams{
				CredentialID: record.Descriptor,
			}
			authorized, err := newCredentialManagementAuthorizedRequest(
				token,
				protocol.CredentialManagementSubCommandDeleteCredential,
				&params,
			)
			if err != nil {
				return fmt.Errorf("ctap23: authorize deleteCredential: %w", err)
			}
			defer authorized.clear()

			if err := executeEmptyCredentialManagement(ctx, test.CBOR(), authorized.Request); err != nil {
				return err
			}

			return credentialManagementValidateStoreStateChanged(ctx, test, before)
		},
	}) {
		return
	}

	test.Step(conformance.Step{
		ID:         "credential-management-update-and-delete.p-2.verify",
		Name:       "Verify the deleted credential cannot satisfy GetAssertion",
		References: []conformance.RequirementRef{authrGetAssertionReq1CommandReference()},
		Run: func(ctx context.Context) error {
			token, err := clientPIN2IssuePermissionToken(
				ctx,
				fixture.client,
				fixture.pin,
				protocol.PermissionGetAssertion,
				record.RPID,
			)
			if err != nil {
				clear(token)

				return unexpectedCTAPStatus(
					"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
					err,
				)
			}
			defer clear(token)
			if err := clientPIN2ValidatePermissionToken(token); err != nil {
				return err
			}

			clientDataHash := credentialManagementFixtureBytes("post-delete-get-assertion", 0)
			pinUvAuthParam := ctapcrypto.Authenticate(
				protocol.PinUvAuthProtocolTwo,
				token,
				clientDataHash,
			)
			defer clear(pinUvAuthParam)
			_, err = exchangeRawGetAssertion(
				ctx,
				test.CBOR(),
				map[uint64]any{
					1: record.RPID,
					2: clientDataHash,
					3: []credential.PublicKeyCredentialDescriptor{record.Descriptor},
					6: pinUvAuthParam,
					7: protocol.PinUvAuthProtocolTwo,
				},
			)

			return expectCTAPStatus(err, ctaptransport.CTAP2_ERR_NO_CREDENTIALS)
		},
	})
}

func credentialManagementUpdateAndDeleteProvisionStep(
	fixture *credentialManagementFixture,
	caseID string,
) conformance.Step {
	return conformance.Step{
		ID:   conformance.StepID("credential-management-update-and-delete." + caseID + ".provision"),
		Name: "Create one discoverable credential for the mutation",
		References: []conformance.RequirementRef{
			credentialManagementUpdateAndDeleteFeatureReference(),
			clientPIN2NewPINPermissionsReference(),
		},
		Run: func(ctx context.Context) error {
			_, err := fixture.createDiscoverableCredential(
				ctx,
				credentialManagementUpdateAndDeleteRP,
			)

			return err
		},
	}
}

func credentialManagementReadOptionalStoreState(
	ctx context.Context,
	test *conformance.TestContext,
) ([]byte, error) {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return nil, err
	}
	if fields[30] == nil {
		return nil, nil
	}
	if len(info.EncCredStoreState) != 32 {
		return nil, conformance.Failf(
			"encCredStoreState length is %d, want 32",
			len(info.EncCredStoreState),
		)
	}

	return info.EncCredStoreState, nil
}

func credentialManagementValidateStoreStateChanged(
	ctx context.Context,
	test *conformance.TestContext,
	before []byte,
) error {
	if before == nil {
		return nil
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if fields[30] == nil {
		return conformance.Fail("encCredStoreState disappeared after the credential mutation")
	}
	after := info.EncCredStoreState
	if len(after) != 32 {
		return conformance.Failf("encCredStoreState length is %d after mutation, want 32", len(after))
	}
	if bytes.Equal(before[:16], after[:16]) {
		return conformance.Fail("encCredStoreState reused its encryption IV after the credential mutation")
	}
	if bytes.Equal(before[16:], after[16:]) {
		return conformance.Fail("encCredStoreState ciphertext did not change after the credential mutation")
	}

	return nil
}

func credentialManagementValidateUpdatedCredential(
	result credentialManagementResponse,
	record credentialManagementCredential,
	updatedUser credential.PublicKeyCredentialUserEntity,
) error {
	defer clear(result.Response.LargeBlobKey)
	defer clear(result.Fields[11])

	for _, field := range []uint64{6, 7, 8, 9} {
		if result.Fields[field] == nil {
			return conformance.Failf("enumerateCredentialsBegin response omits required field %d", field)
		}
	}
	if result.Response.TotalCredentials != 1 {
		return conformance.Failf(
			"enumerateCredentialsBegin totalCredentials = %d, want 1",
			result.Response.TotalCredentials,
		)
	}
	descriptor := result.Response.CredentialID
	if descriptor.Type != credential.PublicKeyCredentialTypePublicKey ||
		len(descriptor.ID) == 0 ||
		!bytes.Equal(descriptor.ID, record.Descriptor.ID) {
		return conformance.Fail(
			"enumerateCredentialsBegin credentialID is not the updated public-key credential",
		)
	}
	if !reflect.DeepEqual(result.Response.User, updatedUser) {
		return conformance.Fail(
			"enumerateCredentialsBegin user does not equal the complete updated user entity",
		)
	}
	if !reflect.DeepEqual(result.Response.PublicKey, record.PublicKey) {
		return conformance.Fail(
			"enumerateCredentialsBegin publicKey does not equal the updated credential public key",
		)
	}

	return nil
}

func credentialManagementUpdateAndDeleteFeatureReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.1:credential-management-feature-detection",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.1",
		Clause:        "credential-management-feature-detection",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#credential-management-feature-detection",
		Level:         conformance.RequirementConstraint,
	}
}

func credentialManagementUpdateAndDeleteEnumerationReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.4:enumerating-credentials",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.4",
		Clause:        "enumerating-credentials",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#enumerating-credentials",
		Level:         conformance.RequirementMust,
	}
}

func credentialManagementDeleteCredentialReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.5:delete-credential",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.5",
		Clause:        "delete-credential",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#deleteCredential",
		Level:         conformance.RequirementMust,
	}
}

func credentialManagementUpdateUserInformationReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.6:update-user-information",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.6",
		Clause:        "update-user-information",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#updateUserInformation",
		Level:         conformance.RequirementMust,
	}
}
