package workflow

import (
	"context"
	"encoding/hex"

	"github.com/telesma-app/ctap/protocol"
	rtconfig "github.com/telesma-app/kit/internal/config"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

func (r Runner) BioRename(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioRenameOperation,
) (appconfig.BioMutationOutput, error) {
	templateID, err := rtconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}
	templateIDHex := hex.EncodeToString(templateID)

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := rtconfig.BuildBioMutationPreview(
		status,
		appconfig.BioMutationRename,
		templateIDHex,
		req.FriendlyName,
		mode,
	)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}

	if req.DryRun {
		return appconfig.BioMutationOutput{Preview: preview}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		return device.SetFriendlyName(ctx, token, templateID, req.FriendlyName)
	})
	if err != nil {
		return appconfig.BioMutationOutput{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandSetFriendlyName,
		))
	}

	return appconfig.BioMutationOutput{
		Preview: preview,
		Result: &appconfig.BioMutationResult{
			Operation:     appconfig.BioMutationRename,
			AttachmentID:  r.env.Selected.Attachment.ID,
			PreviewOnly:   preview.PreviewOnly,
			TemplateIDHex: templateIDHex,
			FriendlyName:  req.FriendlyName,
		},
	}, nil
}

func (r Runner) BioRemove(
	ctx context.Context,
	device BioDevice,
	req appconfig.BioRemoveOperation,
) (appconfig.BioMutationOutput, error) {
	templateID, err := rtconfig.DecodeTemplateID(req.TemplateIDHex)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}
	templateIDHex := hex.EncodeToString(templateID)

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}
	status := rtconfig.BuildStatusReport(r.env.Selected, info)

	mode := safety.PreviewModeExecute
	if req.DryRun {
		mode = safety.PreviewModeDryRun
	}

	preview, err := rtconfig.BuildBioMutationPreview(
		status,
		appconfig.BioMutationRemove,
		templateIDHex,
		"",
		mode,
	)
	if err != nil {
		return appconfig.BioMutationOutput{}, err
	}

	if req.DryRun {
		return appconfig.BioMutationOutput{Preview: preview}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: protocol.PermissionBioEnrollment,
	}, func(token []byte) error {
		return device.RemoveEnrollment(ctx, token, templateID)
	})
	if err != nil {
		return appconfig.BioMutationOutput{}, errornorm.Annotate(err, errornorm.WithBioEnrollmentSubCommand(
			failure.PhaseAuthenticatorCommand,
			bioEnrollmentCommand(status),
			protocol.BioEnrollmentSubCommandRemoveEnrollment,
		))
	}
	return appconfig.BioMutationOutput{
		Preview: preview,
		Result: &appconfig.BioMutationResult{
			Operation:     appconfig.BioMutationRemove,
			AttachmentID:  r.env.Selected.Attachment.ID,
			PreviewOnly:   preview.PreviewOnly,
			TemplateIDHex: templateIDHex,
		},
	}, nil
}
