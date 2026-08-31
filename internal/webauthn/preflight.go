package webauthn

import (
	"strings"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/model/safety"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func BuildMakeCredentialPreview(
	device report.DeviceReport,
	info protocol.AuthenticatorGetInfoResponse,
	input appwebauthn.MakeCredentialInput,
) appwebauthn.MakeCredentialPreview {
	warnings := []safety.Warning{{
		Severity: safety.SeverityWarning,
		Code:     "webauthn.make_credential.mutation",
		Message:  "On success, authenticatorMakeCredential creates a new credential key pair.",
	}}
	if input.Options.ResidentKey != nil && *input.Options.ResidentKey {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityDestructive,
			Code:     "webauthn.make_credential.discoverable_overwrite",
			Message:  "With rk=true, an existing discoverable credential for the same RP ID and user ID is overwritten; its old credential ID stops resolving, and its large blob may be erased or orphaned.",
		})
	}
	warnings = append(warnings, makeCredentialExtensionWarnings(info, input.Extensions)...)

	return appwebauthn.MakeCredentialPreview{
		Device:   device,
		Input:    input,
		Warnings: warnings,
	}
}

func BuildGetAssertionPreview(
	device report.DeviceReport,
	info protocol.AuthenticatorGetInfoResponse,
	input appwebauthn.GetAssertionInput,
) appwebauthn.GetAssertionPreview {
	return appwebauthn.GetAssertionPreview{
		Device:   device,
		Input:    input,
		Warnings: getAssertionExtensionWarnings(info, input.Extensions),
	}
}

func NormalizeMakeCredentialInput(
	input appwebauthn.MakeCredentialInput,
) (appwebauthn.MakeCredentialInput, error) {
	input.RP.ID = strings.TrimSpace(input.RP.ID)
	input.RP.Name = strings.TrimSpace(input.RP.Name)
	if input.RP.ID == "" {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeRelyingPartyIDRequired)
	}

	input.User.Name = strings.TrimSpace(input.User.Name)
	input.User.DisplayName = strings.TrimSpace(input.User.DisplayName)
	if len(input.User.ID) == 0 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeUserIDRequired)
	}

	if len(input.User.ID) > 64 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPLengthInvalid)
	}

	if len(input.ClientDataJSON) == 0 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeClientDataJSONRequired)
	}

	if len(input.PubKeyCredParams) == 0 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(
			failure.CodePublicKeyCredentialParametersRequired,
		)
	}

	seenParameters := make(map[credential.PublicKeyCredentialParameters]struct{}, len(input.PubKeyCredParams))
	pubKeyCredParams := make([]credential.PublicKeyCredentialParameters, len(input.PubKeyCredParams))
	for i, param := range input.PubKeyCredParams {
		param.Type = credentialTypeOrDefault(param.Type)
		if param.Algorithm == 0 {
			return appwebauthn.MakeCredentialInput{}, validationFailure(
				failure.CodePublicKeyCredentialAlgorithmRequired,
			)
		}

		if _, duplicate := seenParameters[param]; duplicate {
			return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPParameterInvalid)
		}
		seenParameters[param] = struct{}{}

		pubKeyCredParams[i] = param
	}

	input.PubKeyCredParams = pubKeyCredParams
	if input.Options.UserPresence != nil && !*input.Options.UserPresence {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPOptionInvalid)
	}

	if input.EnterpriseAttestation > 2 {
		return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPOptionInvalid)
	}

	for index, format := range input.AttestationFormatsPreference {
		normalized := attestation.AttestationStatementFormatIdentifier(strings.TrimSpace(string(format)))
		if normalized == "" {
			return appwebauthn.MakeCredentialInput{}, validationFailure(failure.CodeCTAPParameterInvalid)
		}
		input.AttestationFormatsPreference[index] = normalized
	}

	excludeList, err := normalizeDescriptors(input.ExcludeList)
	if err != nil {
		return appwebauthn.MakeCredentialInput{}, err
	}
	input.ExcludeList = excludeList

	return input, nil
}

func NormalizeGetAssertionInput(
	input appwebauthn.GetAssertionInput,
) (appwebauthn.GetAssertionInput, error) {
	input.RPID = strings.TrimSpace(input.RPID)
	if input.RPID == "" {
		return appwebauthn.GetAssertionInput{}, validationFailure(failure.CodeRelyingPartyIDRequired)
	}

	if len(input.ClientDataJSON) == 0 {
		return appwebauthn.GetAssertionInput{}, validationFailure(failure.CodeClientDataJSONRequired)
	}

	allowList, err := normalizeDescriptors(input.AllowList)
	if err != nil {
		return appwebauthn.GetAssertionInput{}, err
	}
	input.AllowList = allowList

	return input, nil
}

func normalizeDescriptors(
	in []credential.PublicKeyCredentialDescriptor,
) ([]credential.PublicKeyCredentialDescriptor, error) {
	descriptors := make([]credential.PublicKeyCredentialDescriptor, len(in))
	for i, descriptor := range in {
		descriptor.Type = credentialTypeOrDefault(descriptor.Type)
		if len(descriptor.ID) == 0 {
			return nil, validationFailure(failure.CodeCredentialIDRequired)
		}

		descriptors[i] = descriptor
	}

	return descriptors, nil
}

func credentialTypeOrDefault(value credential.PublicKeyCredentialType) credential.PublicKeyCredentialType {
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return appwebauthn.PublicKeyCredentialTypePublicKey
	}

	return credential.PublicKeyCredentialType(trimmed)
}

func validationFailure(code failure.Code) error {
	return failure.New(code, failure.WithPhase(failure.PhaseValidation))
}
