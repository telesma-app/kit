package ctap23

import (
	"context"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const bioEnrollBioModAndSensorInfoSourcePath = "tests/CTAP2/Protocol/BiometricEnrollment/BioEnroll-BioModAndSensorInfo.js"

const (
	TestIDBioEnrollBioModAndSensorInfoP1 conformance.TestID = "fido.ctap2.3.bio-enroll-bio-mod-and-sensor-info.p-1"
	TestIDBioEnrollBioModAndSensorInfoP2 conformance.TestID = "fido.ctap2.3.bio-enroll-bio-mod-and-sensor-info.p-2"
)

func bioEnrollBioModAndSensorInfoTests(config Config) []conformance.Test {
	featureReference := bioEnrollmentFeatureReference()
	modalityReference := bioEnrollmentModalityReference()
	sensorReference := bioEnrollmentSensorInfoReference()
	resetRequirement := resetReference()
	powerCycleRequirement := clientPINPowerCycleReference()

	return []conformance.Test{
		{
			ID:          TestIDBioEnrollBioModAndSensorInfoP1,
			Name:        "Biometric enrollment modality",
			Description: "Requests the authenticator's biometric modality and requires fingerprint",
			Source: conformance.SourceLocation{
				Path: bioEnrollBioModAndSensorInfoSourcePath,
				Case: "P-1",
			},
			References: []conformance.RequirementRef{
				featureReference,
				modalityReference,
				resetRequirement,
				powerCycleRequirement,
			},
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(bioEnrollmentApplicabilityStep(test, featureReference)) {
					return
				}

				test.Cleanup(bioEnrollmentCleanupStep(test, config, resetRequirement, powerCycleRequirement))
				if !test.Step(bioEnrollmentResetStep(test, config, resetRequirement, powerCycleRequirement)) {
					return
				}

				test.Step(conformance.Step{
					ID:         "bio-enroll-bio-mod-and-sensor-info.p-1.get-modality",
					Name:       "Get the biometric modality",
					References: []conformance.RequirementRef{modalityReference},
					Run: func(ctx context.Context) error {
						response, err := test.Client().GetBioModality(ctx, false)
						if err != nil {
							return bioEnrollmentCommandError("authenticatorBioEnrollment getModality", err)
						}
						if response.Modality != protocol.BioModalityFingerprint {
							return conformance.Failf(
								"authenticatorBioEnrollment modality is %d, want fingerprint (%d)",
								response.Modality,
								protocol.BioModalityFingerprint,
							)
						}

						return nil
					},
				})
			},
		},
		{
			ID:          TestIDBioEnrollBioModAndSensorInfoP2,
			Name:        "Fingerprint sensor information",
			Description: "Validates the fingerprint sensor kind, enrollment sample limit, and optional friendly-name limit",
			Source: conformance.SourceLocation{
				Path: bioEnrollBioModAndSensorInfoSourcePath,
				Case: "P-2",
			},
			References: []conformance.RequirementRef{
				featureReference,
				sensorReference,
				resetRequirement,
				powerCycleRequirement,
			},
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(bioEnrollmentApplicabilityStep(test, featureReference)) {
					return
				}

				test.Cleanup(bioEnrollmentCleanupStep(test, config, resetRequirement, powerCycleRequirement))
				if !test.Step(bioEnrollmentResetStep(test, config, resetRequirement, powerCycleRequirement)) {
					return
				}

				test.Step(conformance.Step{
					ID:         "bio-enroll-bio-mod-and-sensor-info.p-2.get-sensor-info",
					Name:       "Get fingerprint sensor information",
					References: []conformance.RequirementRef{sensorReference},
					Run: func(ctx context.Context) error {
						response, err := test.Client().GetFingerprintSensorInfo(ctx, false)
						if err != nil {
							return bioEnrollmentCommandError("authenticatorBioEnrollment getFingerprintSensorInfo", err)
						}

						return validateFingerprintSensorInfo(response)
					},
				})
			},
		},
	}
}

func bioEnrollmentApplicabilityStep(
	test *conformance.TestContext,
	reference conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:         "bio-enroll-bio-mod-and-sensor-info.applicability",
		Name:       "Check biometric enrollment applicability",
		References: []conformance.RequirementRef{reference},
		Run: func(ctx context.Context) error {
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}

			_, present, err := rawGetInfoOption(fields, protocol.OptionBioEnroll)
			if err != nil {
				return err
			}
			if !present {
				return conformance.Skip("authenticator does not advertise the bioEnroll option")
			}

			return nil
		},
	}
}

func bioEnrollmentResetStep(
	test *conformance.TestContext,
	config Config,
	resetRequirement conformance.RequirementRef,
	powerCycleRequirement conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "bio-enroll-bio-mod-and-sensor-info.reset",
		Name: "Reset and rebind the authenticator",
		References: []conformance.RequirementRef{
			resetRequirement,
			powerCycleRequirement,
		},
		Run: func(ctx context.Context) error {
			return bioEnrollmentResetAndRebind(ctx, test, config)
		},
	}
}

func bioEnrollmentCleanupStep(
	test *conformance.TestContext,
	config Config,
	resetRequirement conformance.RequirementRef,
	powerCycleRequirement conformance.RequirementRef,
) conformance.Step {
	return conformance.Step{
		ID:   "bio-enroll-bio-mod-and-sensor-info.cleanup",
		Name: "Reset and rebind the authenticator after the case",
		References: []conformance.RequirementRef{
			resetRequirement,
			powerCycleRequirement,
		},
		Run: func(ctx context.Context) error {
			return bioEnrollmentResetAndRebind(ctx, test, config)
		},
	}
}

func bioEnrollmentResetAndRebind(ctx context.Context, test *conformance.TestContext, config Config) error {
	if config.PowerCycler == nil {
		return errors.New("ctap23: authenticator power cycler is required for biometric sensor information tests")
	}
	if err := config.PowerCycler(ctx); err != nil {
		return err
	}
	if err := resetAuthenticatorForTest(ctx, test.Client(), config.Resetter); err != nil {
		return err
	}

	return config.PowerCycler(ctx)
}

func validateFingerprintSensorInfo(response protocol.AuthenticatorBioEnrollmentResponse) error {
	switch response.FingerprintKind {
	case 1, 2:
	default:
		return conformance.Failf(
			"authenticatorBioEnrollment fingerprintKind is %d, want touch (1) or swipe (2)",
			response.FingerprintKind,
		)
	}
	if response.MaxCaptureSamplesRequiredForEnroll == nil {
		return conformance.Fail("authenticatorBioEnrollment response is missing maxCaptureSamplesRequiredForEnroll")
	}
	if *response.MaxCaptureSamplesRequiredForEnroll == 0 {
		return conformance.Fail("authenticatorBioEnrollment maxCaptureSamplesRequiredForEnroll must be greater than zero")
	}
	if response.MaxTemplateFriendlyName != nil && *response.MaxTemplateFriendlyName == 0 {
		return conformance.Fail("authenticatorBioEnrollment maxTemplateFriendlyName must be greater than zero when present")
	}

	return nil
}

func bioEnrollmentCommandError(operation string, err error) error {
	var ctapErr *ctaptransport.CTAPError
	if errors.As(err, &ctapErr) {
		return conformance.Failf("%s returned %s", operation, ctapErr.StatusCode)
	}

	var typeErr *cbor.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return conformance.Failf("invalid %s response CBOR: %v", operation, err)
	}
	var syntaxErr *cbor.SyntaxError
	if errors.As(err, &syntaxErr) {
		return conformance.Failf("invalid %s response CBOR: %v", operation, err)
	}

	return err
}

func bioEnrollmentFeatureReference() conformance.RequirementRef {
	return bioEnrollmentReference(
		"6.7.1",
		"biometric-enrollment-feature-detection",
		conformance.RequirementConstraint,
	)
}

func bioEnrollmentModalityReference() conformance.RequirementRef {
	return bioEnrollmentReference(
		"6.7.2",
		"get-biometric-modality",
		conformance.RequirementConstraint,
	)
}

func bioEnrollmentSensorInfoReference() conformance.RequirementRef {
	return bioEnrollmentReference(
		"6.7.3",
		"get-fingerprint-sensor-info",
		conformance.RequirementConstraint,
	)
}

func bioEnrollmentReference(
	section string,
	clause string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID(fmt.Sprintf("ctap-2.3-ps-20260226:%s:%s", section, clause)),
		Specification: conformance.SpecificationCTAP23,
		Section:       section,
		Clause:        clause,
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment",
		Level:         level,
	}
}
