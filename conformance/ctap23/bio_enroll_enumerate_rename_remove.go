package ctap23

import (
	"bytes"
	"context"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const bioEnrollEnumerateRenameRemoveSourcePath = "tests/CTAP2/Protocol/BiometricEnrollment/BioEnroll-EnumerateRenameRemove.js"

const (
	TestIDBioEnrollEnumerateRenameRemoveP1 conformance.TestID = "fido.ctap2.3.bio-enroll-enumerate-rename-remove.p-1"
	TestIDBioEnrollEnumerateRenameRemoveP2 conformance.TestID = "fido.ctap2.3.bio-enroll-enumerate-rename-remove.p-2"
	TestIDBioEnrollEnumerateRenameRemoveP3 conformance.TestID = "fido.ctap2.3.bio-enroll-enumerate-rename-remove.p-3"
)

func bioEnrollEnumerateRenameRemoveTests(config Config) []conformance.Test {
	featureReference := bioEnrollmentFeatureReference()
	enrollReference := bioEnrollmentEnrollReference()
	enumerateReference := bioEnrollmentEnumerateReference()
	renameReference := bioEnrollmentRenameReference()
	removeReference := bioEnrollmentRemoveReference()
	sensorReference := bioEnrollmentSensorInfoReference()
	permissionReference := bioEnrollmentPermissionReference()
	protocolReference := bioEnrollmentProtocolTwoReference()
	encodingReference := ctapMessageEncodingReference()

	definitions := []struct {
		id          conformance.TestID
		marker      string
		slug        string
		name        string
		description string
		references  []conformance.RequirementRef
		run         func(*conformance.TestContext, *bioEnrollmentFixture)
	}{
		{
			id:          TestIDBioEnrollEnumerateRenameRemoveP1,
			marker:      "P-1",
			slug:        "p-1",
			name:        "Enumerate one fingerprint enrollment",
			description: "Provisions and enumerates one independently created fingerprint template",
			references:  []conformance.RequirementRef{enumerateReference},
			run: func(test *conformance.TestContext, fixture *bioEnrollmentFixture) {
				test.Step(conformance.Step{
					ID:         "bio-enroll-enumerate-rename-remove.p-1.enumerate",
					Name:       "Enumerate the provisioned fingerprint template",
					References: []conformance.RequirementRef{enumerateReference, permissionReference, protocolReference},
					Run: func(ctx context.Context) error {
						response, err := fixture.enumerate(ctx)
						defer clearBioEnrollmentResponse(&response)
						if err != nil {
							return bioEnrollmentCommandError("authenticatorBioEnrollment enumerateEnrollments", err)
						}
						if len(response.TemplateInfos) != 1 {
							return conformance.Failf(
								"authenticatorBioEnrollment returned %d templateInfos, want exactly one",
								len(response.TemplateInfos),
							)
						}

						info := response.TemplateInfos[0]
						if len(info.TemplateID) == 0 {
							return conformance.Fail("enumerated templateInfo contains an empty templateId")
						}
						if !bytes.Equal(info.TemplateID, fixture.templateID) {
							return conformance.Fail("enumerated templateId does not match the enrolled templateId")
						}

						return nil
					},
				})
			},
		},
		{
			id:          TestIDBioEnrollEnumerateRenameRemoveP2,
			marker:      "P-2",
			slug:        "p-2",
			name:        "Rename one fingerprint enrollment",
			description: "Renames an independently created fingerprint template within the sensor limit and verifies it by template ID",
			references: []conformance.RequirementRef{
				renameReference,
				enumerateReference,
				sensorReference,
			},
			run: func(test *conformance.TestContext, fixture *bioEnrollmentFixture) {
				var friendlyName string
				if !test.Step(conformance.Step{
					ID:   "bio-enroll-enumerate-rename-remove.p-2.rename",
					Name: "Rename the provisioned fingerprint template",
					References: []conformance.RequirementRef{
						sensorReference,
						renameReference,
						permissionReference,
						protocolReference,
					},
					Run: func(ctx context.Context) error {
						sensorInfo, err := test.Client().GetFingerprintSensorInfo(ctx, false)
						defer clearBioEnrollmentResponse(&sensorInfo)
						if err != nil {
							return bioEnrollmentCommandError(
								"authenticatorBioEnrollment getFingerprintSensorInfo",
								err,
							)
						}
						if err := validateFingerprintSensorInfo(sensorInfo); err != nil {
							return err
						}

						friendlyName = bioEnrollmentFriendlyName(sensorInfo.MaxTemplateFriendlyName)
						return fixture.setFriendlyName(ctx, friendlyName)
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "bio-enroll-enumerate-rename-remove.p-2.verify",
					Name:       "Verify the renamed template by identifier",
					References: []conformance.RequirementRef{enumerateReference, permissionReference, protocolReference},
					Run: func(ctx context.Context) error {
						response, err := fixture.enumerate(ctx)
						defer clearBioEnrollmentResponse(&response)
						if err != nil {
							return bioEnrollmentCommandError("authenticatorBioEnrollment enumerateEnrollments", err)
						}

						for _, info := range response.TemplateInfos {
							if bytes.Equal(info.TemplateID, fixture.templateID) {
								if info.TemplateFriendlyName != friendlyName {
									return conformance.Failf(
										"renamed template friendly name is %q, want %q",
										info.TemplateFriendlyName,
										friendlyName,
									)
								}

								return nil
							}
						}

						return conformance.Fail("renamed templateId is absent from enumerateEnrollments")
					},
				})
			},
		},
		{
			id:          TestIDBioEnrollEnumerateRenameRemoveP3,
			marker:      "P-3",
			slug:        "p-3",
			name:        "Remove the only fingerprint enrollment",
			description: "Removes an independently created fingerprint template and requires INVALID_OPTION when enumerating the empty database",
			references:  []conformance.RequirementRef{removeReference, enumerateReference},
			run: func(test *conformance.TestContext, fixture *bioEnrollmentFixture) {
				if !test.Step(conformance.Step{
					ID:         "bio-enroll-enumerate-rename-remove.p-3.remove",
					Name:       "Remove the provisioned fingerprint template",
					References: []conformance.RequirementRef{removeReference, permissionReference, protocolReference},
					Run:        fixture.remove,
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "bio-enroll-enumerate-rename-remove.p-3.verify-empty",
					Name:       "Require INVALID_OPTION for the empty enrollment database",
					References: []conformance.RequirementRef{enumerateReference, permissionReference, protocolReference},
					Run: func(ctx context.Context) error {
						response, err := fixture.enumerate(ctx)
						defer clearBioEnrollmentResponse(&response)

						return expectBioEnrollmentStatus(
							"authenticatorBioEnrollment enumerateEnrollments",
							err,
							ctaptransport.CTAP2_ERR_INVALID_OPTION,
						)
					},
				})
			},
		},
	}

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		definition := definition
		references := []conformance.RequirementRef{
			featureReference,
			enrollReference,
			permissionReference,
			protocolReference,
			encodingReference,
			resetReference(),
			clientPINPowerCycleReference(),
		}
		references = append(references, definition.references...)

		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: definition.description,
			Source: conformance.SourceLocation{
				Path: bioEnrollEnumerateRenameRemoveSourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(bioEnrollmentCaseApplicabilityStep(
					test,
					config,
					conformance.StepID("bio-enroll-enumerate-rename-remove."+definition.slug+".applicability"),
				)) {
					return
				}

				var fixture *bioEnrollmentFixture
				if !test.Step(bioEnrollmentPrepareStep(test, config, &fixture)) {
					return
				}
				if !test.Step(conformance.Step{
					ID:         conformance.StepID("bio-enroll-enumerate-rename-remove." + definition.slug + ".provision"),
					Name:       "Provision one complete fingerprint enrollment",
					References: []conformance.RequirementRef{enrollReference, permissionReference, protocolReference},
					Run: func(ctx context.Context) error {
						return provisionBioEnrollment(ctx, fixture)
					},
				}) {
					return
				}

				definition.run(test, fixture)
			},
		})
	}

	return tests
}

func bioEnrollmentFriendlyName(maximum *uint) string {
	const name = "MostLeftRightHandFingerN"

	limit := uint(64)
	if maximum != nil {
		limit = min(limit, *maximum)
	}

	return name[:min(uint(len(name)), limit)]
}
