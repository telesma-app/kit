package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	rtconfig "github.com/telesma-app/kit/internal/config"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/model"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

func (r Runner) ResetFactory(
	ctx context.Context,
	device ConfigDevice,
	req appconfig.ResetFactoryOperation,
) (appconfig.ResetFactoryOutput, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.ResetFactoryOutput{}, err
	}
	preview := rtconfig.BuildResetFactoryPreview(rtconfig.BuildStatusReport(r.env.Selected, info))

	if req.DryRun {
		preview.Mode = safety.PreviewModeDryRun

		return appconfig.ResetFactoryOutput{Preview: preview}, nil
	}

	if _, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Touch authenticator " + string(r.env.Selected.Attachment.ID) + " to factory reset.",
		Destructive: true,
		Preview:     preview,
	}); err != nil {
		return appconfig.ResetFactoryOutput{}, err
	}

	r.env.Effects.Record(rtruntime.StateEffectAuthenticatorReset)

	err = device.Reset(ctx)
	r.env.Tokens.Invalidate()

	if err != nil {
		return appconfig.ResetFactoryOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorReset,
		))
	}
	return appconfig.ResetFactoryOutput{
		Preview: preview,
		Result: &appconfig.ResetResult{
			AttachmentID: r.env.Selected.Attachment.ID,
			Reset:        true,
		},
	}, nil
}
