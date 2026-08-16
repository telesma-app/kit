package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	rtcredentials "github.com/telesma-app/kit/internal/credentials"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func (r Runner) WriteLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.WriteOperation,
) (applargeblobs.MutationOutput, error) {
	_, credentialIDHex, err := rtcredentials.ParseCredentialID(req.CredentialIDHex)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	inventory, err := r.loadLargeBlobInventory(
		ctx,
		device,
		largeBlobState,
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	state, err := r.loadTargetBlobState(inventory, credentialIDHex)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	plan, err := buildWriteMutationPlan(state, req.Payload)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	preview := buildMutationPreview(state, plan)
	if req.DryRun {
		return applargeblobs.MutationOutput{Preview: preview}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: inventory.permissionFor(protocol.PermissionLargeBlobWrite),
	}, func(token []byte) error {
		r.env.Effects.Record(rtruntime.StateEffectLargeBlobArrayChanged)

		return device.SetLargeBlobs(ctx, token, plan.replacement)
	})
	if err != nil {
		return applargeblobs.MutationOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	largeBlobState.replaceBlobs(plan.replacement)
	r.env.Effects.Record(rtruntime.StateEffectLargeBlobSnapshotSynchronized)

	return applargeblobs.MutationOutput{
		Preview: preview,
		Result:  buildMutationResult(state, plan),
	}, nil
}

func (r Runner) DeleteLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.DeleteOperation,
) (applargeblobs.MutationOutput, error) {
	_, credentialIDHex, err := rtcredentials.ParseCredentialID(req.CredentialIDHex)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	inventory, err := r.loadLargeBlobInventory(
		ctx,
		device,
		largeBlobState,
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	state, err := r.loadTargetBlobState(inventory, credentialIDHex)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	plan, err := buildDeleteMutationPlan(state)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	preview := buildMutationPreview(state, plan)
	if req.DryRun {
		return applargeblobs.MutationOutput{Preview: preview}, nil
	}

	if plan.operation == applargeblobs.MutationNoBlob {
		return applargeblobs.MutationOutput{
			Preview: preview,
			Result:  buildMutationResult(state, plan),
		}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: inventory.permissionFor(protocol.PermissionLargeBlobWrite),
	}, func(token []byte) error {
		r.env.Effects.Record(rtruntime.StateEffectLargeBlobArrayChanged)

		return device.SetLargeBlobs(ctx, token, plan.replacement)
	})
	if err != nil {
		return applargeblobs.MutationOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	largeBlobState.replaceBlobs(plan.replacement)
	r.env.Effects.Record(rtruntime.StateEffectLargeBlobSnapshotSynchronized)

	return applargeblobs.MutationOutput{
		Preview: preview,
		Result:  buildMutationResult(state, plan),
	}, nil
}
