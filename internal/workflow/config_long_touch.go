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

func (r Runner) EnableLongTouchForReset(
	ctx context.Context,
	device authenticator.ConfigDevice,
	req appconfig.EnableLongTouchForResetOperation,
) (appconfig.AuthenticatorConfigOutput, error) {
	mode := safety.PreviewModeDryRun
	if !req.DryRun {
		mode = safety.PreviewModeExecute
	}

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, err
	}

	preview, err := rtconfig.BuildEnableLongTouchForResetPreview(rtconfig.BuildStatusReport(r.Selected, info), mode)
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
		return device.EnableLongTouchForReset(ctx, token)
	})
	if err != nil {
		return appconfig.AuthenticatorConfigOutput{}, errornorm.Annotate(err, errornorm.WithConfigSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ConfigSubCommandEnableLongTouchForReset,
		))
	}

	return appconfig.AuthenticatorConfigOutput{
		Preview: preview,
		Result: &appconfig.AuthenticatorConfigResult{
			Operation:    appconfig.AuthenticatorConfigLongTouch,
			AttachmentID: r.Selected.Attachment.ID,
			State:        appconfig.StateConfigured,
		},
	}, nil
}
