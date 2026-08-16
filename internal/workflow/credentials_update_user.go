package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	rtcredentials "github.com/telesma-app/kit/internal/credentials"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
)

func (r Runner) UpdateCredentialUser(
	ctx context.Context,
	device authenticator.CredentialManager,
	req appcredentials.UpdateUserOperation,
) (appcredentials.UpdateUserOutput, error) {
	plan, err := rtcredentials.PrepareUpdateUser(req)
	if err != nil {
		return appcredentials.UpdateUserOutput{}, err
	}

	if req.DryRun {
		return appcredentials.UpdateUserOutput{Preview: plan.Preview}, nil
	}

	access, err := r.resolveCredentialAccess(
		ctx,
		device,
		protocol.PermissionCredentialManagement,
	)
	if err != nil {
		return appcredentials.UpdateUserOutput{}, err
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: access.mutationPermission,
	}, func(token []byte) error {
		r.env.Effects.Record(rtruntime.StateEffectCredentialInventoryChanged)

		return device.UpdateUserInformation(ctx, token, plan.Descriptor, plan.User)
	})
	if err != nil {
		return appcredentials.UpdateUserOutput{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			access.command,
			protocol.CredentialManagementSubCommandUpdateUserInformation,
		))
	}
	return appcredentials.UpdateUserOutput{
		Preview: plan.Preview,
		Result: &appcredentials.UpdateUserResult{
			AttachmentID:    r.env.Selected.Attachment.ID,
			CredentialIDHex: plan.Preview.CredentialIDHex,
			RPID:            plan.Preview.RPID,
			RPName:          plan.Preview.RPName,
			Previous:        plan.Preview.Current,
			Current:         plan.Preview.Proposed,
		},
	}, nil
}
