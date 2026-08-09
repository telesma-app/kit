package ctap23

import (
	"context"
	"errors"
	"slices"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const bioEnrollmentTimeoutMilliseconds = uint(10_000)

type bioEnrollmentFixture struct {
	client         *client.Client
	config         Config
	pin            []byte
	token          []byte
	templateID     []byte
	enrollmentOpen bool
}

func prepareBioEnrollmentFixture(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) (*bioEnrollmentFixture, error) {
	if config.PowerCycler == nil {
		return nil, errors.New("ctap23: authenticator power cycler is required for biometric enrollment tests")
	}
	if config.TemporaryPINProvider == nil {
		return nil, errors.New("ctap23: temporary PIN provider is required for biometric enrollment tests")
	}
	if config.BiometricSampleProvider == nil {
		return nil, errors.New("ctap23: biometric sample provider is required for biometric enrollment tests")
	}

	fixture := &bioEnrollmentFixture{client: test.Client(), config: config}
	test.Cleanup(fixture.cleanupStep(test))

	if err := bioEnrollmentResetAndRebind(ctx, test, config); err != nil {
		return fixture, err
	}

	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return fixture, err
	}
	if err := validateClientPIN2PermissionsProfile(fields, info, config); err != nil {
		return fixture, err
	}
	if _, present, err := rawGetInfoOption(fields, protocol.OptionBioEnroll); err != nil {
		return fixture, err
	} else if !present {
		return fixture, conformance.Fail("bioEnroll disappeared after authenticator reset")
	}

	pinRequest := temporaryPINRequest(info)
	fixture.pin, err = config.TemporaryPINProvider(ctx, pinRequest)
	if err != nil {
		return fixture, err
	}
	if err := validateTemporaryPIN(fixture.pin, pinRequest); err != nil {
		return fixture, err
	}

	keyAgreement, err := fixture.client.GetKeyAgreement(ctx, protocol.PinUvAuthProtocolTwo)
	if err != nil {
		return fixture, unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
	}
	if err := fixture.client.SetPIN(
		ctx,
		protocol.PinUvAuthProtocolTwo,
		keyAgreement,
		string(fixture.pin),
	); err != nil {
		return fixture, unexpectedCTAPStatus("authenticatorClientPIN setPIN", err)
	}

	fields, info, err = readGetInfo(ctx, test.CBOR())
	if err != nil {
		return fixture, err
	}
	if err := validateClientPIN2PermissionsProfile(fields, info, config); err != nil {
		return fixture, err
	}
	clientPIN, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return fixture, err
	}
	if !present || !clientPIN {
		return fixture, conformance.Fail("clientPin is not true after successful setPIN")
	}

	return fixture, nil
}

func (f *bioEnrollmentFixture) begin(
	ctx context.Context,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	if err := f.refreshToken(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	if err := f.config.BiometricSampleProvider(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	response, err := f.client.EnrollBegin(
		ctx,
		false,
		protocol.PinUvAuthProtocolTwo,
		f.token,
		bioEnrollmentTimeoutMilliseconds,
	)
	if err != nil {
		return response, bioEnrollmentCommandError("authenticatorBioEnrollment enrollBegin", err)
	}

	clear(f.templateID)
	f.templateID = slices.Clone(response.TemplateID)
	f.enrollmentOpen = true

	return response, nil
}

func (f *bioEnrollmentFixture) capture(
	ctx context.Context,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	if err := f.refreshToken(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	if err := f.config.BiometricSampleProvider(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	response, err := f.client.EnrollCaptureNextSample(
		ctx,
		false,
		protocol.PinUvAuthProtocolTwo,
		f.token,
		f.templateID,
		bioEnrollmentTimeoutMilliseconds,
	)
	if err != nil {
		return response, bioEnrollmentCommandError(
			"authenticatorBioEnrollment enrollCaptureNextSample",
			err,
		)
	}

	return response, nil
}

func (f *bioEnrollmentFixture) cancel(ctx context.Context) error {
	if err := f.client.CancelCurrentEnrollment(ctx, false); err != nil {
		return bioEnrollmentCommandError("authenticatorBioEnrollment cancelCurrentEnrollment", err)
	}
	f.enrollmentOpen = false
	clear(f.templateID)
	f.templateID = nil

	return nil
}

func (f *bioEnrollmentFixture) enumerate(
	ctx context.Context,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	if err := f.refreshToken(ctx); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	response, err := f.client.EnumerateEnrollments(
		ctx,
		false,
		protocol.PinUvAuthProtocolTwo,
		f.token,
	)
	return response, err
}

func (f *bioEnrollmentFixture) setFriendlyName(ctx context.Context, name string) error {
	if err := f.refreshToken(ctx); err != nil {
		return err
	}

	return bioEnrollmentCommandError(
		"authenticatorBioEnrollment setFriendlyName",
		f.client.SetFriendlyName(
			ctx,
			false,
			protocol.PinUvAuthProtocolTwo,
			f.token,
			f.templateID,
			name,
		),
	)
}

func (f *bioEnrollmentFixture) remove(ctx context.Context) error {
	if err := f.refreshToken(ctx); err != nil {
		return err
	}

	if err := bioEnrollmentCommandError(
		"authenticatorBioEnrollment removeEnrollment",
		f.client.RemoveEnrollment(
			ctx,
			false,
			protocol.PinUvAuthProtocolTwo,
			f.token,
			f.templateID,
		),
	); err != nil {
		return err
	}

	clear(f.templateID)
	f.templateID = nil

	return nil
}

func (f *bioEnrollmentFixture) refreshToken(ctx context.Context) error {
	clear(f.token)
	f.token = nil

	token, err := clientPIN2IssuePermissionToken(
		ctx,
		f.client,
		f.pin,
		protocol.PermissionBioEnrollment,
		"",
	)
	if err != nil {
		clear(token)

		return unexpectedCTAPStatus(
			"authenticatorClientPIN getPinUvAuthTokenUsingPinWithPermissions",
			err,
		)
	}
	if err := clientPIN2ValidatePermissionToken(token); err != nil {
		clear(token)

		return err
	}

	f.token = token

	return nil
}

func (f *bioEnrollmentFixture) clear() {
	clear(f.pin)
	f.pin = nil
	clear(f.token)
	f.token = nil
	clear(f.templateID)
	f.templateID = nil
	f.enrollmentOpen = false
}

func (f *bioEnrollmentFixture) cleanupStep(test *conformance.TestContext) conformance.Step {
	return conformance.Step{
		ID:   "bio-enrollment-fixture.cleanup",
		Name: "Cancel partial enrollment, wipe secrets, and reset the authenticator",
		References: []conformance.RequirementRef{
			bioEnrollmentCancelReference(),
			resetReference(),
			clientPINPowerCycleReference(),
		},
		Run: func(ctx context.Context) error {
			var cancelErr error
			if f.enrollmentOpen {
				cancelErr = f.cancel(ctx)
			}
			f.clear()

			resetErr := bioEnrollmentResetAndRebind(ctx, test, f.config)
			return errors.Join(cancelErr, resetErr)
		},
	}
}

func validateBioEnrollmentBeginResponse(
	response protocol.AuthenticatorBioEnrollmentResponse,
) error {
	if len(response.TemplateID) == 0 {
		return conformance.Fail("authenticatorBioEnrollment enrollBegin returned an empty templateId")
	}
	if err := validateBioEnrollmentSampleStatus(response.LastEnrollSampleStatus); err != nil {
		return err
	}
	if response.RemainingSamples == nil {
		return conformance.Fail("authenticatorBioEnrollment enrollBegin omitted remainingSamples")
	}
	if *response.RemainingSamples == 0 {
		return conformance.Fail("authenticatorBioEnrollment enrollBegin returned zero remainingSamples")
	}

	return nil
}

func validateBioEnrollmentCaptureResponse(
	response protocol.AuthenticatorBioEnrollmentResponse,
	lastRemaining uint,
) error {
	if err := validateBioEnrollmentSampleStatus(response.LastEnrollSampleStatus); err != nil {
		return err
	}
	if response.RemainingSamples == nil {
		return conformance.Fail("authenticatorBioEnrollment enrollCaptureNextSample omitted remainingSamples")
	}
	if *response.RemainingSamples > lastRemaining {
		return conformance.Failf(
			"authenticatorBioEnrollment remainingSamples increased from %d to %d",
			lastRemaining,
			*response.RemainingSamples,
		)
	}
	if *response.RemainingSamples == 0 &&
		*response.LastEnrollSampleStatus != protocol.LastEnrollSampleStatusFingerprintGood {
		return conformance.Failf(
			"completed enrollment returned lastEnrollSampleStatus %#x, want fingerprint good (0)",
			*response.LastEnrollSampleStatus,
		)
	}

	return nil
}

func validateBioEnrollmentSampleStatus(status *protocol.LastEnrollSampleStatus) error {
	if status == nil {
		return conformance.Fail("authenticatorBioEnrollment response omitted lastEnrollSampleStatus")
	}

	switch *status {
	case protocol.LastEnrollSampleStatusFingerprintGood,
		protocol.LastEnrollSampleStatusFingerprintTooHigh,
		protocol.LastEnrollSampleStatusFingerprintTooLow,
		protocol.LastEnrollSampleStatusFingerprintTooLeft,
		protocol.LastEnrollSampleStatusFingerprintTooRight,
		protocol.LastEnrollSampleStatusFingerprintTooFast,
		protocol.LastEnrollSampleStatusFingerprintTooSlow,
		protocol.LastEnrollSampleStatusFingerprintPoorQuality,
		protocol.LastEnrollSampleStatusFingerprintTooSkewed,
		protocol.LastEnrollSampleStatusFingerprintTooShort,
		protocol.LastEnrollSampleStatusFingerprintMergeFailure,
		protocol.LastEnrollSampleStatusFingerprintExists,
		protocol.LastEnrollSampleStatusNoUserActivity,
		protocol.LastEnrollSampleStatusNoUserPresenceTransition:
		return nil
	default:
		return conformance.Failf(
			"authenticatorBioEnrollment returned unknown lastEnrollSampleStatus %#x",
			*status,
		)
	}
}

func provisionBioEnrollment(ctx context.Context, fixture *bioEnrollmentFixture) error {
	response, err := fixture.begin(ctx)
	if err != nil {
		clearBioEnrollmentResponse(&response)

		return err
	}
	defer clearBioEnrollmentResponse(&response)
	if err := validateBioEnrollmentBeginResponse(response); err != nil {
		return err
	}

	lastRemaining := *response.RemainingSamples
	for lastRemaining > 0 {
		response, err := fixture.capture(ctx)
		if err != nil {
			clearBioEnrollmentResponse(&response)

			return err
		}
		if err := validateBioEnrollmentCaptureResponse(response, lastRemaining); err != nil {
			clearBioEnrollmentResponse(&response)

			return err
		}

		lastRemaining = *response.RemainingSamples
		if lastRemaining == 0 {
			fixture.enrollmentOpen = false
		}
		clearBioEnrollmentResponse(&response)
	}

	return nil
}

func expectBioEnrollmentStatus(operation string, err error, want ctaptransport.StatusCode) error {
	if err == nil {
		return conformance.Failf("%s returned CTAP2_OK, want %s", operation, want)
	}

	var ctapErr *ctaptransport.CTAPError
	if !errors.As(err, &ctapErr) {
		return err
	}
	if ctapErr.StatusCode != want {
		return conformance.Failf("%s returned %s, want %s", operation, ctapErr.StatusCode, want)
	}

	return nil
}

func clearBioEnrollmentResponse(response *protocol.AuthenticatorBioEnrollmentResponse) {
	clear(response.TemplateID)
	response.TemplateID = nil
	for index := range response.TemplateInfos {
		clear(response.TemplateInfos[index].TemplateID)
		response.TemplateInfos[index].TemplateID = nil
	}
	response.TemplateInfos = nil
}

func bioEnrollmentEnrollReference() conformance.RequirementRef {
	return bioEnrollmentReference("6.7.4", "enrolling-fingerprint", conformance.RequirementMust)
}

func bioEnrollmentCancelReference() conformance.RequirementRef {
	return bioEnrollmentReference("6.7.5", "cancel-current-enrollment", conformance.RequirementMust)
}

func bioEnrollmentEnumerateReference() conformance.RequirementRef {
	return bioEnrollmentReference("6.7.6", "enumerate-enrollments", conformance.RequirementMust)
}

func bioEnrollmentRenameReference() conformance.RequirementRef {
	return bioEnrollmentReference("6.7.7", "rename-friendly-name", conformance.RequirementMust)
}

func bioEnrollmentRemoveReference() conformance.RequirementRef {
	return bioEnrollmentReference("6.7.8", "remove-enrollment", conformance.RequirementMust)
}

func bioEnrollmentPermissionReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.5.5.7.2",
		"bio-enrollment-permission-token",
		"getPinUvAuthTokenUsingPinWithPermissions",
		conformance.RequirementMust,
	)
}

func bioEnrollmentProtocolTwoReference() conformance.RequirementRef {
	return clientPIN1NewPINReference(
		"6.5.7",
		"bio-enrollment-protocol-two-authentication",
		"pinProto2",
		conformance.RequirementMust,
	)
}

func bioEnrollmentPrepareStep(
	test *conformance.TestContext,
	config Config,
	fixture **bioEnrollmentFixture,
) conformance.Step {
	return conformance.Step{
		ID:   "bio-enrollment-fixture.prepare",
		Name: "Reset the authenticator and establish an independent protocol 2 PIN",
		References: []conformance.RequirementRef{
			resetReference(),
			clientPINSetReference(),
			clientPINPowerCycleReference(),
			bioEnrollmentProtocolTwoReference(),
		},
		Run: func(ctx context.Context) error {
			var err error
			*fixture, err = prepareBioEnrollmentFixture(ctx, test, config)

			return err
		},
	}
}

func bioEnrollmentCaseApplicabilityStep(
	test *conformance.TestContext,
	config Config,
	id conformance.StepID,
) conformance.Step {
	return conformance.Step{
		ID:         id,
		Name:       "Check biometric enrollment applicability",
		References: []conformance.RequirementRef{bioEnrollmentFeatureReference()},
		Run: func(ctx context.Context) error {
			fields, info, err := readGetInfo(ctx, test.CBOR())
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
			if err := validateClientPIN2PermissionsProfile(fields, info, config); err != nil {
				return err
			}

			return nil
		},
	}
}
