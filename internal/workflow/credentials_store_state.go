package workflow

import (
	"context"
	"encoding/hex"

	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
)

func (r Runner) CredentialStoreState(
	ctx context.Context,
	device authenticator.InfoProvider,
) (appcredentials.StoreStateResult, error) {
	r.Tokens.InvalidateUnlessPermission(protocol.PermissionPersistentCredentialManagementReadOnly)

	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return appcredentials.StoreStateResult{}, err
	}

	if !info.Options[protocol.OptionPersistentCredentialManagementReadOnly] {
		return appcredentials.StoreStateResult{}, failure.New(
			failure.CodeCredentialManagementUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	var identifier, state [16]byte

	err = r.Tokens.Use(
		ctx,
		rtruntime.TokenUse{
			Permission: protocol.PermissionPersistentCredentialManagementReadOnly,
			ReplaySafe: true,
		},
		func(token []byte) error {
			info, err := device.GetInfo(ctx)
			if err != nil {
				return err
			}

			if len(info.EncIdentifier) == 0 || len(info.EncCredStoreState) == 0 {
				return failure.New(
					failure.CodeGetInfoUnsupported,
					failure.WithPhase(failure.PhaseAuthenticatorCommand),
				)
			}

			if len(info.EncIdentifier) != 32 || len(info.EncCredStoreState) != 32 {
				return failure.New(
					failure.CodeCTAPSpecViolation,
					failure.WithPhase(failure.PhaseAuthenticatorCommand),
				)
			}

			identifier, err = ctapcrypto.DecryptDeviceIdentifier(token, info.EncIdentifier)
			if err != nil {
				return err
			}

			state, err = ctapcrypto.DecryptCredentialStoreState(token, info.EncCredStoreState)

			return err
		},
	)
	if err != nil {
		return appcredentials.StoreStateResult{}, errornorm.Annotate(
			err,
			errornorm.WithCommand(failure.PhaseAuthenticatorCommand, protocol.AuthenticatorGetInfo),
		)
	}

	return appcredentials.StoreStateResult{
		AuthenticatorIdentifierHex: hex.EncodeToString(identifier[:]),
		CredentialStoreStateHex:    hex.EncodeToString(state[:]),
	}, nil
}
