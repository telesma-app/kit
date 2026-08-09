package ctap23

import (
	"context"

	"github.com/telesma-app/kit/conformance"
)

const bioEnrollEnrollSourcePath = "tests/CTAP2/Protocol/BiometricEnrollment/BioEnroll-Enroll.js"

const (
	TestIDBioEnrollEnrollP1 conformance.TestID = "fido.ctap2.3.bio-enroll-enroll.p-1"
	TestIDBioEnrollEnrollP2 conformance.TestID = "fido.ctap2.3.bio-enroll-enroll.p-2"
)

func bioEnrollEnrollTests(config Config) []conformance.Test {
	featureReference := bioEnrollmentFeatureReference()
	enrollReference := bioEnrollmentEnrollReference()
	cancelReference := bioEnrollmentCancelReference()
	permissionReference := bioEnrollmentPermissionReference()
	protocolReference := bioEnrollmentProtocolTwoReference()
	encodingReference := ctapMessageEncodingReference()

	return []conformance.Test{
		{
			ID:          TestIDBioEnrollEnrollP1,
			Name:        "Begin and cancel fingerprint enrollment",
			Description: "Begins a fingerprint enrollment, validates its initial feedback, and cancels the partial enrollment",
			Source: conformance.SourceLocation{
				Path: bioEnrollEnrollSourcePath,
				Case: "P-1",
			},
			References: []conformance.RequirementRef{
				featureReference,
				enrollReference,
				cancelReference,
				permissionReference,
				protocolReference,
				encodingReference,
				resetReference(),
				clientPINPowerCycleReference(),
			},
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(bioEnrollmentCaseApplicabilityStep(
					test,
					config,
					"bio-enroll-enroll.p-1.applicability",
				)) {
					return
				}

				var fixture *bioEnrollmentFixture
				if !test.Step(bioEnrollmentPrepareStep(test, config, &fixture)) {
					return
				}
				if !test.Step(conformance.Step{
					ID:         "bio-enroll-enroll.p-1.begin",
					Name:       "Begin fingerprint enrollment",
					References: []conformance.RequirementRef{enrollReference, permissionReference, protocolReference},
					Run: func(ctx context.Context) error {
						response, err := fixture.begin(ctx)
						defer clearBioEnrollmentResponse(&response)
						if err != nil {
							return err
						}

						return validateBioEnrollmentBeginResponse(response)
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         "bio-enroll-enroll.p-1.cancel",
					Name:       "Cancel the partial fingerprint enrollment",
					References: []conformance.RequirementRef{cancelReference},
					Run:        fixture.cancel,
				})
			},
		},
		{
			ID:          TestIDBioEnrollEnrollP2,
			Name:        "Complete fingerprint enrollment",
			Description: "Captures fingerprint samples with fresh biometric-enrollment authorization until enrollment completes",
			Source: conformance.SourceLocation{
				Path: bioEnrollEnrollSourcePath,
				Case: "P-2",
			},
			References: []conformance.RequirementRef{
				featureReference,
				enrollReference,
				cancelReference,
				permissionReference,
				protocolReference,
				encodingReference,
				resetReference(),
				clientPINPowerCycleReference(),
			},
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(bioEnrollmentCaseApplicabilityStep(
					test,
					config,
					"bio-enroll-enroll.p-2.applicability",
				)) {
					return
				}

				var fixture *bioEnrollmentFixture
				if !test.Step(bioEnrollmentPrepareStep(test, config, &fixture)) {
					return
				}

				test.Step(conformance.Step{
					ID:         "bio-enroll-enroll.p-2.enroll",
					Name:       "Capture samples until fingerprint enrollment completes",
					References: []conformance.RequirementRef{enrollReference, permissionReference, protocolReference},
					Run: func(ctx context.Context) error {
						return provisionBioEnrollment(ctx, fixture)
					},
				})
			},
		},
	}
}
