package config

import (
	"strconv"

	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

const (
	warningEnterpriseAttestation    = "config.enterprise_attestation.enable"
	warningAlwaysUVEnable           = "config.always_uv.enable"
	warningAlwaysUVDisable          = "config.always_uv.disable"
	warningMinPINLengthPolicy       = "config.min_pin_length.policy"
	warningMinPINLengthIrreversible = "config.min_pin_length.irreversible"
	warningMinPINLengthRPIDs        = "config.min_pin_length.rp_ids"
	warningForcePINChange           = "config.force_pin_change.enable"
	warningPINComplexityPolicy      = "config.pin_complexity_policy.enable"
	warningLongTouchForReset        = "config.long_touch_for_reset.enable"
)

func BuildEnableEnterpriseAttestationPreview(status appconfig.StatusReport, mode safety.PreviewMode) (appconfig.AuthenticatorConfigPreview, error) {
	capability := status.AuthenticatorConfig.EnterpriseAttestation
	if !status.AuthenticatorConfig.Supported || !capability.Supported || capability.Configured == nil {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(
			failure.CodeAuthenticatorConfigUnsupported,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	if *capability.Configured {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(
			failure.CodeAuthenticatorOperationNotAllowed,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	return appconfig.AuthenticatorConfigPreview{
		Operation:                      appconfig.AuthenticatorConfigEnterprise,
		Device:                         status.Device,
		Authenticator:                  status.AuthenticatorConfig,
		CurrentEnterpriseAttestation:   capability.Configured,
		RequestedEnterpriseAttestation: true,
		Mode:                           mode,
		Warnings: []safety.Warning{{
			Severity: safety.SeverityWarning,
			Code:     warningEnterpriseAttestation,
			Message:  "Enabling enterprise attestation permits enterprise-scoped uniquely identifying attestations; CTAP provides no command to disable it, and authenticator reset restores the preconfigured default.",
		}},
	}, nil
}

func BuildAlwaysUVPreview(status appconfig.StatusReport, target appconfig.AlwaysUVTarget, requested bool, mode safety.PreviewMode) (appconfig.AuthenticatorConfigPreview, error) {
	if !status.AuthenticatorConfig.Supported {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeAuthenticatorConfigUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	alwaysUV := status.AuthenticatorConfig.AlwaysUV
	if !alwaysUV.Supported {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeAuthenticatorConfigUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	if alwaysUV.Configured == nil || alwaysUV.State == appconfig.StateUnknown {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeAlwaysUVStateUnknown, failure.WithPhase(failure.PhaseValidation))
	}

	if *alwaysUV.Configured == requested {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeAlwaysUVAlreadyTarget, failure.WithPhase(failure.PhaseValidation))
	}

	return appconfig.AuthenticatorConfigPreview{
		Operation:         appconfig.AuthenticatorConfigAlwaysUV,
		Device:            status.Device,
		Authenticator:     status.AuthenticatorConfig,
		Target:            target,
		CurrentAlwaysUV:   alwaysUV.Configured,
		RequestedAlwaysUV: requested,
		Mode:              mode,
		Warnings:          []safety.Warning{alwaysUVWarning(requested)},
	}, nil
}

func ParseAlwaysUVTarget(target appconfig.AlwaysUVTarget) (bool, error) {
	switch target {
	case appconfig.AlwaysUVTargetEnable:
		return true, nil
	case appconfig.AlwaysUVTargetDisable:
		return false, nil
	default:
		return false, failure.New(failure.CodeCTAPParameterInvalid, failure.WithPhase(failure.PhaseValidation))
	}
}

func alwaysUVWarning(requested bool) safety.Warning {
	if requested {
		return safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningAlwaysUVEnable,
			Message:  "Enabling alwaysUv makes authenticatorMakeCredential and authenticatorGetAssertion require user verification regardless of the relying party request; CTAP1/U2F is disabled unless protected by built-in user verification.",
		}
	}

	return safety.Warning{
		Severity: safety.SeverityWarning,
		Code:     warningAlwaysUVDisable,
		Message:  "Disabling alwaysUv removes its unconditional user-verification requirement; each operation's parameters and the selected credential's protection policy still apply.",
	}
}

func BuildEnableLongTouchForResetPreview(status appconfig.StatusReport, mode safety.PreviewMode) (appconfig.AuthenticatorConfigPreview, error) {
	capability := status.AuthenticatorConfig.LongTouchForReset
	if !status.AuthenticatorConfig.Supported || !capability.Supported || capability.Configured == nil {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(
			failure.CodeAuthenticatorConfigUnsupported,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	if *capability.Configured {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(
			failure.CodeAuthenticatorOperationNotAllowed,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	return appconfig.AuthenticatorConfigPreview{
		Operation:          appconfig.AuthenticatorConfigLongTouch,
		Device:             status.Device,
		Authenticator:      status.AuthenticatorConfig,
		CurrentLongTouch:   capability.Configured,
		RequestedLongTouch: true,
		Mode:               mode,
		Warnings: []safety.Warning{{
			Severity: safety.SeverityWarning,
			Code:     warningLongTouchForReset,
			Message:  "Enabling longTouchForReset makes future CTAP resets require a touch lasting at least five seconds; CTAP provides no command to disable it, and reset restores the authenticator's preconfigured default.",
		}},
	}, nil
}

func BuildMinPINLengthPreview(status appconfig.StatusReport, operation appconfig.SetMinPINLengthOperation, mode safety.PreviewMode) (appconfig.AuthenticatorConfigPreview, error) {
	if !status.AuthenticatorConfig.Supported {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeAuthenticatorConfigUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	if !status.AuthenticatorConfig.SetMinPINLength.Supported {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeMinPINLengthUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	if operation.NewMinPINLength == nil && len(operation.MinPINLengthRPIDs) == 0 && !operation.ForceChangePIN && !operation.PINComplexityPolicy {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeCTAPParameterMissing, failure.WithPhase(failure.PhaseValidation))
	}

	if operation.NewMinPINLength != nil && *operation.NewMinPINLength < status.PIN.MinPINLength {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeMinPINLengthDecreaseNotAllowed,
			failure.WithParams(map[string]string{
				"requested": strconv.FormatUint(uint64(*operation.NewMinPINLength), 10),
				"current":   strconv.FormatUint(uint64(status.PIN.MinPINLength), 10),
			}),
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	if operation.NewMinPINLength != nil && *operation.NewMinPINLength > status.PIN.MaxPINLength {
		return appconfig.AuthenticatorConfigPreview{}, failure.New(failure.CodeCTAPParameterInvalid, failure.WithPhase(failure.PhaseValidation))
	}

	warnings := make([]safety.Warning, 0, 5)
	if operation.NewMinPINLength != nil {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningMinPINLengthPolicy,
			Message:  "The requested minimum applies when setting or changing a ClientPIN or built-in-UV PIN; an existing shorter PIN makes the authenticator require a PIN change.",
		})
	}

	if operation.NewMinPINLength != nil && *operation.NewMinPINLength > status.PIN.MinPINLength {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningMinPINLengthIrreversible,
			Message:  "CTAP permits the minimum PIN length to increase only; restoring the preconfigured minimum requires authenticator reset.",
		})
	}

	if operation.ForceChangePIN {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningForcePINChange,
			Message:  "forceChangePin makes the authenticator reject PIN-authorized operations until the PIN is changed successfully and invalidates existing pinUvAuthTokens.",
		})
	}

	if operation.PINComplexityPolicy {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningPINComplexityPolicy,
			Message:  "pinComplexityPolicy requests authenticator-defined PIN complexity enforcement until reset; the authenticator may ignore it if this setting is not configurable through CTAP.",
		})
	}

	if len(operation.MinPINLengthRPIDs) > 0 {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningMinPINLengthRPIDs,
			Message:  "minPinLengthRPIDs controls which RPs may receive the current minimum through the minPinLength extension; it replaces RP IDs previously added through CTAP and does not limit where the PIN policy is enforced.",
		})
	}

	return appconfig.AuthenticatorConfigPreview{
		Operation:           appconfig.AuthenticatorConfigMinPINLength,
		Device:              status.Device,
		Authenticator:       status.AuthenticatorConfig,
		CurrentMinPINLength: status.PIN.MinPINLength,
		NewMinPINLength:     operation.NewMinPINLength,
		MaxPINLength:        status.PIN.MaxPINLength,
		MinPINLengthRPIDs:   operation.MinPINLengthRPIDs,
		ForceChangePIN:      operation.ForceChangePIN,
		PINComplexityPolicy: operation.PINComplexityPolicy,
		Mode:                mode,
		Warnings:            warnings,
	}, nil
}
