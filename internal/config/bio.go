package config

import (
	"encoding/hex"
	"strings"

	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

const (
	warningBioEnrollMutation = "bio.enroll.mutation"
	warningBioRenameMutation = "bio.rename.mutation"
	warningBioRemoveMutation = "bio.remove.destructive"
)

func BuildBioEnrollPreview(
	status appconfig.StatusReport,
	timeoutMilliseconds uint,
	mode safety.PreviewMode,
) (appconfig.BioEnrollPreview, error) {
	if !status.Bio.Supported {
		return appconfig.BioEnrollPreview{}, failure.New(failure.CodeBioUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	return appconfig.BioEnrollPreview{
		Device:              status.Device,
		PreviewOnly:         status.Bio.PreviewOnly,
		TimeoutMilliseconds: timeoutMilliseconds,
		Mode:                mode,
		Warnings: []safety.Warning{{
			Severity: safety.SeverityWarning,
			Code:     warningBioEnrollMutation,
			Message:  "Starting enrollment cancels any unfinished enrollment and begins capturing a new fingerprint template; completion requires samples until remainingSamples reaches zero.",
		}},
	}, nil
}

func BuildBioMutationPreview(
	status appconfig.StatusReport,
	operation appconfig.BioMutationOperation,
	templateIDHex string,
	friendlyName string,
	mode safety.PreviewMode,
) (appconfig.BioMutationPreview, error) {
	if !status.Bio.Supported {
		return appconfig.BioMutationPreview{}, failure.New(failure.CodeBioUnsupported, failure.WithPhase(failure.PhaseValidation))
	}

	if status.Bio.Configured != nil && !*status.Bio.Configured {
		return appconfig.BioMutationPreview{}, failure.New(failure.CodeBioNoEnrollments, failure.WithPhase(failure.PhaseValidation))
	}

	var warning safety.Warning
	switch operation {
	case appconfig.BioMutationRename:
		warning = safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     warningBioRenameMutation,
			Message:  "Only this fingerprint template's friendly name is changed; the enrolled biometric template itself is unchanged.",
		}
	case appconfig.BioMutationRemove:
		warning = safety.Warning{
			Severity: safety.SeverityDestructive,
			Code:     warningBioRemoveMutation,
			Message:  "The selected fingerprint enrollment is deleted and cannot be restored except by enrolling that fingerprint again.",
		}
	default:
		panic("config: invalid bio mutation operation: " + string(operation))
	}

	return appconfig.BioMutationPreview{
		Operation:     operation,
		Device:        status.Device,
		PreviewOnly:   status.Bio.PreviewOnly,
		TemplateIDHex: templateIDHex,
		FriendlyName:  friendlyName,
		Mode:          mode,
		Warnings:      []safety.Warning{warning},
	}, nil
}

func DecodeTemplateID(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, failure.New(failure.CodeBioTemplateIDRequired, failure.WithPhase(failure.PhaseValidation))
	}

	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, failure.Wrap(failure.CodeBioTemplateIDInvalid, err, failure.WithPhase(failure.PhaseValidation))
	}

	return decoded, nil
}
