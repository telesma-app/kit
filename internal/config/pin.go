package config

import (
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

const (
	warningPINSetMutation    = "pin.set.mutation"
	warningPINChangeMutation = "pin.change.mutation"
	warningPINDryRunLocal    = "pin.dry_run.local_only"
)

func BuildPINPreview(status appconfig.StatusReport, operation appconfig.PINMutationOperation, mode safety.PreviewMode) (appconfig.PINMutationPreview, error) {
	if !status.PIN.Supported {
		return appconfig.PINMutationPreview{}, failure.New(failure.CodePINUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	configured := status.PIN.Configured != nil && *status.PIN.Configured

	switch operation {
	case appconfig.PINMutationSet:
		if configured {
			return appconfig.PINMutationPreview{}, failure.New(failure.CodePINAlreadyConfigured, failure.WithPhase(failure.PhaseValidation))
		}
	case appconfig.PINMutationChange:
		if !configured {
			return appconfig.PINMutationPreview{}, failure.New(failure.CodePINNotConfigured, failure.WithPhase(failure.PhaseValidation))
		}
	default:
		panic("config: invalid PIN mutation operation: " + string(operation))
	}

	warnings := []safety.Warning{pinMutationWarning(operation)}
	if mode == safety.PreviewModeDryRun {
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityInfo,
			Code:     warningPINDryRunLocal,
			Message:  "Dry-run checks advertised capability and operation state only; it does not validate either PIN value or contact the authenticator.",
		})
	}

	return appconfig.PINMutationPreview{
		Operation: operation,
		Device:    status.Device,
		PIN:       status.PIN,
		Mode:      mode,
		Warnings:  warnings,
	}, nil
}

func pinMutationWarning(operation appconfig.PINMutationOperation) safety.Warning {
	switch operation {
	case appconfig.PINMutationSet:
		return safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningPINSetMutation,
			Message:  "Setting a PIN enables ClientPIN user verification; CTAP provides no command to remove the PIN, so removal requires authenticator reset and invalidates all credentials.",
		}
	case appconfig.PINMutationChange:
		return safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningPINChangeMutation,
			Message:  "Changing the PIN invalidates every existing pinUvAuthToken and clears persistent permissions; an incorrect current PIN consumes a retry and can block PIN use.",
		}
	default:
		panic("config: invalid PIN mutation operation: " + string(operation))
	}
}
