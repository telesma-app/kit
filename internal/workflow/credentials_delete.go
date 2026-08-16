package workflow

import (
	"context"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	rtcredentials "github.com/telesma-app/kit/internal/credentials"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
)

func (r Runner) DeleteCredential(
	ctx context.Context,
	device authenticator.CredentialManager,
	req appcredentials.DeleteOperation,
) (appcredentials.DeleteOutput, error) {
	credentialID, credentialIDHex, err := rtcredentials.ParseCredentialID(req.CredentialIDHex)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}

	access, err := r.resolveCredentialAccess(
		ctx,
		device,
		protocol.PermissionCredentialManagement,
	)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}

	report, err := r.credentialInventory(
		ctx,
		device,
		access,
		nil,
	)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}
	publicTarget, err := rtcredentials.FindByCanonicalID(report, credentialIDHex)
	if err != nil {
		return appcredentials.DeleteOutput{}, err
	}
	preview := rtcredentials.BuildDeletePreview(publicTarget)

	if req.DryRun {
		return appcredentials.DeleteOutput{Preview: preview}, nil
	}

	var transports []credential.AuthenticatorTransport
	for _, transport := range publicTarget.Record.CredentialTransports {
		transports = append(transports, credential.AuthenticatorTransport(transport))
	}
	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: access.mutationPermission,
	}, func(token []byte) error {
		r.env.Effects.Record(rtruntime.StateEffectCredentialInventoryChanged)

		return device.DeleteCredential(ctx, token, credential.PublicKeyCredentialDescriptor{
			Type:       credential.PublicKeyCredentialType(publicTarget.Record.CredentialType),
			ID:         credentialID,
			Transports: transports,
		})
	})
	if err != nil {
		return appcredentials.DeleteOutput{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseAuthenticatorCommand,
			access.command,
			protocol.CredentialManagementSubCommandDeleteCredential,
		))
	}
	return appcredentials.DeleteOutput{
		Preview: preview,
		Result: &appcredentials.DeleteResult{
			AttachmentID:    r.env.Selected.Attachment.ID,
			CredentialIDHex: publicTarget.Record.CredentialIDHex,
			RPID:            publicTarget.RP.ID,
			RPName:          publicTarget.RP.Name,
			UserIDHex:       publicTarget.User.UserIDHex,
			UserName:        publicTarget.User.Name,
			DisplayName:     publicTarget.User.DisplayName,
		},
	}, nil
}
