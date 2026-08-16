package workflow

import (
	"context"
	"encoding/hex"

	"github.com/samber/lo"
	"github.com/telesma-app/ctap/protocol"
	rtconfig "github.com/telesma-app/kit/internal/config"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
)

func (r Runner) BioList(ctx context.Context, device BioDevice) (appconfig.BioListReport, error) {
	status, err := r.ConfigStatus(ctx, device)
	if err != nil {
		return appconfig.BioListReport{}, err
	}

	var report appconfig.BioListReport
	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
		ReplaySafe: true,
	}, func(token []byte) error {
		current, err := r.bioListReport(ctx, device, status, token)
		if err != nil {
			return err
		}

		report = current

		return nil
	})
	if err != nil {
		return appconfig.BioListReport{}, err
	}

	return report, nil
}

func (r Runner) BioSensorInfo(ctx context.Context, device BioDevice) (appconfig.BioSensorReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.BioSensorReport{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.BioSensorReport{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)
	if !status.Bio.Supported {
		return appconfig.BioSensorReport{}, failure.New(failure.CodeBioUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	modality, err := device.GetBioModality(ctx)
	if err != nil {
		return appconfig.BioSensorReport{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseDiscovery,
			bioEnrollmentCommand(status),
		))
	}

	sensor, err := device.GetFingerprintSensorInfo(ctx)
	if err != nil {
		return appconfig.BioSensorReport{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseDiscovery,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandGetFingerprintSensorInfo,
		))
	}

	report := appconfig.BioSensorReport{
		Device:      status.Device,
		Supported:   true,
		PreviewOnly: status.Bio.PreviewOnly,
	}
	report.Modality = bioModality(modality.Modality)
	report.FingerprintKind = fingerprintKind(sensor.FingerprintKind)

	if sensor.MaxCaptureSamplesRequiredForEnroll != nil {
		report.MaxCaptureSamplesRequiredForEnroll = sensor.MaxCaptureSamplesRequiredForEnroll
	}

	if sensor.MaxTemplateFriendlyName != nil {
		report.MaxTemplateFriendlyName = sensor.MaxTemplateFriendlyName
	}

	return report, nil
}

func bioModality(value protocol.BioModality) appconfig.BioModality {
	switch value {
	case protocol.BioModalityFingerprint:
		return appconfig.BioModalityFingerprint
	default:
		return ""
	}
}

func fingerprintKind(value uint) appconfig.FingerprintKind {
	switch value {
	case 1:
		return appconfig.FingerprintKindTouch
	case 2:
		return appconfig.FingerprintKindSwipe
	default:
		return ""
	}
}

func (r Runner) bioListReport(
	ctx context.Context,
	device BioDevice,
	status appconfig.StatusReport,
	token []byte,
) (appconfig.BioListReport, error) {
	if err := ctx.Err(); err != nil {
		return appconfig.BioListReport{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseDiscovery,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandEnumerateEnrollments,
		))
	}

	if !status.Bio.Supported {
		return appconfig.BioListReport{}, failure.New(failure.CodeBioUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	resp, err := device.EnumerateEnrollments(ctx, token)
	if err != nil {
		return appconfig.BioListReport{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseDiscovery,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandEnumerateEnrollments,
		))
	}

	return appconfig.BioListReport{
		Device:      status.Device,
		Supported:   true,
		PreviewOnly: status.Bio.PreviewOnly,
		Enrollments: lo.Map(resp.TemplateInfos, func(info protocol.TemplateInfo, _ int) appconfig.BioEnrollmentRecord {
			return appconfig.BioEnrollmentRecord{
				TemplateIDHex: hex.EncodeToString(info.TemplateID),
				FriendlyName:  info.TemplateFriendlyName,
			}
		}),
	}, nil
}

func bioEnrollmentCommand(status appconfig.StatusReport) protocol.Command {
	if status.Bio.PreviewOnly {
		return protocol.PrototypeAuthenticatorBioEnrollment
	}

	return protocol.AuthenticatorBioEnrollment
}
