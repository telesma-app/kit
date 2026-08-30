// Package webauthn owns runtime WebAuthn preflight and validation behavior.
package webauthn

import (
	"slices"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
	"github.com/telesma-app/kit/model/safety"
)

func makeCredentialExtensionWarnings(
	info protocol.AuthenticatorGetInfoResponse,
	input *ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
) []safety.Warning {
	if input == nil {
		return nil
	}

	warnings := make([]safety.Warning, 0, 9)
	appendMissing := func(included bool, identifier extension.ExtensionIdentifier, code, label string) {
		if included && !slices.Contains(info.Extensions, identifier) {
			warnings = append(warnings, unsupportedExtensionWarning(code, label, string(identifier)))
		}
	}
	appendMissing(input.CreateCredentialProtectionInputs != nil, extension.ExtensionIdentifierCredentialProtection,
		"webauthn.extension.cred_protect.not_advertised", "credProtect")
	appendMissing(input.CreateCredentialBlobInputs != nil, extension.ExtensionIdentifierCredentialBlob,
		"webauthn.extension.cred_blob.not_advertised", "credBlob")
	appendMissing(input.CreateHMACSecretInputs != nil, extension.ExtensionIdentifierHMACSecret,
		"webauthn.extension.hmac_secret.not_advertised", "hmac-secret")
	appendMissing(input.CreateHMACSecretMCInputs != nil, extension.ExtensionIdentifierHMACSecretMC,
		"webauthn.extension.hmac_secret_mc.not_advertised", "hmac-secret-mc")
	appendMissing(input.CreateMinPinLengthInputs != nil, extension.ExtensionIdentifierMinPinLength,
		"webauthn.extension.min_pin_length.not_advertised", "minPinLength")
	appendMissing(input.CreatePinComplexityPolicyInputs != nil, extension.ExtensionIdentifierPinComplexityPolicy,
		"webauthn.extension.pin_complexity_policy.not_advertised", "pinComplexityPolicy")
	appendMissing(input.LargeBlobInputs != nil, extension.ExtensionIdentifierLargeBlobKey,
		"webauthn.extension.large_blob.not_advertised", "largeBlob")
	appendMissing(input.PaymentInputs != nil && input.Payment.IsPayment, extension.ExtensionIdentifierThirdPartyPayment,
		"webauthn.extension.third_party_payment.not_advertised", "thirdPartyPayment")
	appendMissing(input.PreviewSignInputs != nil, extension.ExtensionIdentifierPreviewSign,
		"webauthn.extension.preview_sign.not_advertised", "previewSign")
	if input.PRFInputs != nil {
		appendMissing(true, extension.ExtensionIdentifierHMACSecret,
			"webauthn.extension.prf.not_advertised", "prf")
	}

	return warnings
}

func getAssertionExtensionWarnings(
	info protocol.AuthenticatorGetInfoResponse,
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
) []safety.Warning {
	if input == nil {
		return nil
	}

	warnings := make([]safety.Warning, 0, 6)
	if input.GetCredentialBlobInputs != nil && !slices.Contains(info.Extensions, extension.ExtensionIdentifierCredentialBlob) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.cred_blob.not_advertised", "credBlob", "credBlob"))
	}

	if input.GetHMACSecretInputs != nil && !slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.hmac_secret.not_advertised", "hmac-secret", "hmac-secret"))
	}

	if input.PRFInputs != nil &&
		(!input.PRFInputs.PRF.Eval.IsZero() || len(input.PRFInputs.PRF.EvalByCredential) > 0) &&
		!slices.Contains(info.Extensions, extension.ExtensionIdentifierHMACSecret) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.prf.not_advertised", "prf", "hmac-secret"))
	}

	if input.LargeBlobInputs != nil && !slices.Contains(info.Extensions, extension.ExtensionIdentifierLargeBlobKey) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.large_blob.not_advertised", "largeBlob", "largeBlobKey"))
	}

	if input.PaymentInputs != nil && input.Payment.IsPayment &&
		!slices.Contains(info.Extensions, extension.ExtensionIdentifierThirdPartyPayment) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.third_party_payment.not_advertised", "thirdPartyPayment", "thirdPartyPayment"))
	}

	if input.PreviewSignInputs != nil && !slices.Contains(info.Extensions, extension.ExtensionIdentifierPreviewSign) {
		warnings = append(warnings, unsupportedExtensionWarning(
			"webauthn.extension.preview_sign.not_advertised", "previewSign", "previewSign"))
	}

	return warnings
}

func unsupportedExtensionWarning(code, requested, advertised string) safety.Warning {
	return safety.Warning{
		Severity: safety.SeverityWarning,
		Code:     code,
		Message:  requested + " was requested, but this authenticator does not advertise " + advertised + "; CTAP requires it to ignore unsupported extension inputs.",
	}
}
