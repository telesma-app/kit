package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/errornorm"
	"github.com/telesma-app/kit/model/failure"
)

func (r Runner) getAuthenticatorInfo(
	ctx context.Context,
	device authenticator.InfoProvider,
) (protocol.AuthenticatorGetInfoResponse, error) {
	info, err := authenticator.ResolveInfo(ctx, device)
	if err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, errornorm.Annotate(
			err,
			errornorm.WithCommand(failure.PhaseAuthenticatorCommand, protocol.AuthenticatorGetInfo),
		)
	}

	return info, nil
}
