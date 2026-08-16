package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	rtconfig "github.com/telesma-app/kit/internal/config"
	"github.com/telesma-app/kit/internal/errornorm"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

func (r Runner) SetPIN(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.SetPINOperation,
) (appconfig.PINOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.PINOutput{}, err
	}

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := rtconfig.BuildPINPreview(
		rtconfig.BuildStatusReport(r.env.Selected, info),
		appconfig.PINMutationSet,
		mode,
	)
	if err != nil {
		return appconfig.PINOutput{}, err
	}

	if req.DryRun {
		return appconfig.PINOutput{Preview: preview}, nil
	}

	err = device.SetPIN(ctx, req.NewPIN)
	r.env.Tokens.Invalidate()

	if err != nil {
		return appconfig.PINOutput{}, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ClientPINSubCommandSetPIN,
		))
	}
	return appconfig.PINOutput{
		Preview: preview,
		Result: &appconfig.PINMutationResult{
			Operation:    appconfig.PINMutationSet,
			AttachmentID: r.env.Selected.Attachment.ID,
			PINState:     appconfig.StateConfigured,
		},
	}, nil
}

func (r Runner) ChangePIN(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.ChangePINOperation,
) (appconfig.PINOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.PINOutput{}, err
	}

	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	preview, err := rtconfig.BuildPINPreview(
		rtconfig.BuildStatusReport(r.env.Selected, info),
		appconfig.PINMutationChange,
		mode,
	)
	if err != nil {
		return appconfig.PINOutput{}, err
	}

	if req.DryRun {
		return appconfig.PINOutput{Preview: preview}, nil
	}

	err = device.ChangePIN(ctx, req.CurrentPIN, req.NewPIN)
	r.env.Tokens.Invalidate()

	if err != nil {
		return appconfig.PINOutput{}, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ClientPINSubCommandChangePIN,
		))
	}
	return appconfig.PINOutput{
		Preview: preview,
		Result: &appconfig.PINMutationResult{
			Operation:    appconfig.PINMutationChange,
			AttachmentID: r.env.Selected.Attachment.ID,
			PINState:     appconfig.StateConfigured,
		},
	}, nil
}
