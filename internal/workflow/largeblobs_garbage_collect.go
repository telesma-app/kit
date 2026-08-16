package workflow

import (
	"context"

	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
	"github.com/telesma-app/kit/model/safety"
)

type garbageCollectState struct {
	support            applargeblobs.SupportReport
	mutationPermission protocol.Permission
	blobs              []protocol.LargeBlob
	replacement        []protocol.LargeBlob
	matchedCount       int
	orphanedCount      int
	nonconformingCount int
	sizeBefore         int
	sizeAfter          int
}

func (r Runner) GarbageCollectLargeBlobs(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.GarbageCollectOperation,
) (applargeblobs.MutationOutput, error) {
	state, err := r.loadGarbageCollectState(
		ctx,
		device,
		largeBlobState,
		protocol.PermissionLargeBlobWrite,
	)
	if err != nil {
		return applargeblobs.MutationOutput{}, err
	}

	preview := r.buildGarbageCollectPreview(state)

	if req.DryRun {
		return applargeblobs.MutationOutput{Preview: preview}, nil
	}

	if state.orphanedCount == 0 {
		return applargeblobs.MutationOutput{
			Preview: preview,
			Result:  r.buildGarbageCollectResult(state),
		}, nil
	}

	err = r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: state.mutationPermission,
	}, func(token []byte) error {
		r.env.Effects.Record(rtruntime.StateEffectLargeBlobArrayChanged)

		return device.SetLargeBlobs(ctx, token, state.replacement)
	})
	if err != nil {
		return applargeblobs.MutationOutput{}, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	largeBlobState.replaceBlobs(state.replacement)
	r.env.Effects.Record(rtruntime.StateEffectLargeBlobSnapshotSynchronized)

	return applargeblobs.MutationOutput{
		Preview: preview,
		Result:  r.buildGarbageCollectResult(state),
	}, nil
}

func (r Runner) loadGarbageCollectState(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	requiredPermission protocol.Permission,
) (garbageCollectState, error) {
	inventory, err := r.loadLargeBlobInventory(ctx, device, largeBlobState, requiredPermission)
	if err != nil {
		return garbageCollectState{}, err
	}

	support := inventory.support
	if !support.LargeBlobs {
		return garbageCollectState{}, failure.New(failure.CodeLargeBlobUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	sizeBefore, err := serializedLargeBlobArraySize(inventory.blobs)
	if err != nil {
		return garbageCollectState{}, err
	}

	keys := listCredentialKeys(inventory)
	replacement := make([]protocol.LargeBlob, 0, len(inventory.blobs))
	var matchedCount, orphanedCount, nonconformingCount int
	for _, blob := range inventory.blobs {
		if !largeBlobMapConforming(blob) {
			nonconformingCount++
			replacement = append(replacement, blob)

			continue
		}

		if largeBlobAuthenticatesWithAnyKey(blob, keys) {
			matchedCount++
			replacement = append(replacement, blob)

			continue
		}

		orphanedCount++
	}

	sizeAfter, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return garbageCollectState{}, err
	}

	if err := checkSerializedArrayLimit(support.MaxSerializedLargeBlobArray, sizeAfter); err != nil {
		return garbageCollectState{}, err
	}

	return garbageCollectState{
		support:            support,
		mutationPermission: inventory.permissionFor(requiredPermission),
		blobs:              inventory.blobs,
		replacement:        replacement,
		matchedCount:       matchedCount,
		orphanedCount:      orphanedCount,
		nonconformingCount: nonconformingCount,
		sizeBefore:         sizeBefore,
		sizeAfter:          sizeAfter,
	}, nil
}

func (r Runner) buildGarbageCollectPreview(state garbageCollectState) applargeblobs.MutationPreview {
	warning := safety.Warning{
		Severity: safety.SeverityDestructive,
		Code:     "large_blob.garbage_collect_orphaned",
		Message:  "Every conforming large-blob entry that cannot be authenticated with any valid largeBlobKey returned for the enumerated discoverable credentials will be removed; nonconforming entries are retained.",
	}
	if state.orphanedCount == 0 {
		warning = safety.Warning{
			Severity: safety.SeverityInfo,
			Code:     "large_blob.garbage_collect_noop",
			Message:  "No orphaned conforming large-blob entries were found; garbage collection is a no-op.",
		}
	}

	return applargeblobs.MutationPreview{
		Operation:                          applargeblobs.MutationGC,
		Device:                             r.env.Selected,
		Support:                            state.support,
		SerializedLargeBlobArraySizeBefore: state.sizeBefore,
		SerializedLargeBlobArraySizeAfter:  state.sizeAfter,
		SerializedLargeBlobArrayLimit:      state.support.MaxSerializedLargeBlobArray,
		BlobCountBefore:                    len(state.blobs),
		BlobCountAfter:                     len(state.replacement),
		MatchedBlobCount:                   state.matchedCount,
		OrphanedBlobCount:                  state.orphanedCount,
		NonconformingBlobCount:             state.nonconformingCount,
		Noop:                               state.orphanedCount == 0,
		Warnings:                           []safety.Warning{warning},
	}
}

func (r Runner) buildGarbageCollectResult(state garbageCollectState) *applargeblobs.MutationResult {
	return &applargeblobs.MutationResult{
		Operation:                          applargeblobs.MutationGC,
		AttachmentID:                       r.env.Selected.Attachment.ID,
		SerializedLargeBlobArraySizeBefore: state.sizeBefore,
		SerializedLargeBlobArraySizeAfter:  state.sizeAfter,
		SerializedLargeBlobArrayLimit:      state.support.MaxSerializedLargeBlobArray,
		BlobCountBefore:                    len(state.blobs),
		BlobCountAfter:                     len(state.replacement),
		MatchedBlobCount:                   state.matchedCount,
		OrphanedBlobCount:                  state.orphanedCount,
		NonconformingBlobCount:             state.nonconformingCount,
		DeletedBlobCount:                   state.orphanedCount,
		Noop:                               state.orphanedCount == 0,
	}
}

func largeBlobAuthenticatesWithAnyKey(blob protocol.LargeBlob, keys []listCredentialKey) bool {
	for _, candidate := range keys {
		compressed, err := crypto.OpenLargeBlob(candidate.key, blob)
		if err != nil {
			continue
		}

		secret.Zero(compressed)

		return true
	}

	return false
}

func largeBlobMapConforming(blob protocol.LargeBlob) bool {
	return len(blob.Nonce) == 12 && blob.Ciphertext != nil
}
