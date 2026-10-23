package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	rtconfig "github.com/telesma-app/kit/internal/config"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

func (r Runner) SetAlwaysUV(
	ctx context.Context,
	device authenticator.ConfigDevice,
	req appconfig.SetAlwaysUVOperation,
) (appconfig.AuthenticatorConfigOutput, error) {
	requested, err := rtconfig.ParseAlwaysUVTarget(req.Target)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := rtconfig.BuildAlwaysUVPreview(
		rtconfig.BuildStatusReport(r.Selected, info),
		req.Target,
		requested,
		mode,
	)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	if req.DryRun {
		return appconfig.AuthenticatorConfigOutput{Preview: preview}, nil
	}

	err = r.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission:      protocol.PermissionAuthenticatorConfiguration,
		TryWithoutToken: true,
	}, func(token []byte) error {
		return device.ToggleAlwaysUV(ctx, token)
	})
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandToggleAlwaysUv,
		))
	}

	return appconfig.AuthenticatorConfigOutput{
		Preview: preview,
		Result: rtconfig.AlwaysUVResult(
			r.Selected.Attachment.ID,
			req.Target,
			requested,
		),
	}, nil
}

func (r Runner) SetMinPINLength(
	ctx context.Context,
	device authenticator.ConfigDevice,
	req appconfig.SetMinPINLengthOperation,
) (appconfig.AuthenticatorConfigOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := rtconfig.BuildMinPINLengthPreview(
		rtconfig.BuildStatusReport(r.Selected, info),
		req,
		mode,
	)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	if req.DryRun {
		return appconfig.AuthenticatorConfigOutput{Preview: preview}, nil
	}

	err = r.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission:      protocol.PermissionAuthenticatorConfiguration,
		TryWithoutToken: true,
	}, func(token []byte) error {
		return device.SetMinPINLength(ctx, token, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength:     req.NewMinPINLength,
			MinPINLengthRPIDs:   req.MinPINLengthRPIDs,
			ForceChangePIN:      req.ForceChangePIN,
			PINComplexityPolicy: req.PINComplexityPolicy,
		})
	})
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandSetMinPINLength,
		))
	}

	return appconfig.AuthenticatorConfigOutput{
		Preview: preview,
		Result: &appconfig.AuthenticatorConfigResult{
			Operation:           appconfig.AuthenticatorConfigMinPINLength,
			AttachmentID:        r.Selected.Attachment.ID,
			NewMinPINLength:     req.NewMinPINLength,
			MinPINLengthRPIDs:   req.MinPINLengthRPIDs,
			ForceChangePIN:      req.ForceChangePIN,
			PINComplexityPolicy: req.PINComplexityPolicy,
			State:               appconfig.StateSupported,
		},
	}, nil
}
