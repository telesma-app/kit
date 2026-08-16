package workflow

import applargeblobs "github.com/telesma-app/kit/model/largeblobs"

func buildMutationResult(
	state targetBlobState,
	plan largeBlobMutationPlan,
) *applargeblobs.MutationResult {
	return &applargeblobs.MutationResult{
		Operation:                          plan.operation,
		AttachmentID:                       state.selected.Attachment.ID,
		CredentialIDHex:                    state.target.Record.CredentialIDHex,
		RPID:                               state.target.RP.ID,
		RPName:                             state.target.RP.Name,
		UserIDHex:                          state.target.User.UserIDHex,
		UserName:                           state.target.User.Name,
		DisplayName:                        state.target.User.DisplayName,
		CurrentByteCount:                   state.currentByteCount,
		ProposedByteCount:                  plan.byteCount,
		SerializedLargeBlobArraySizeBefore: state.serializedArraySizeBefore,
		SerializedLargeBlobArraySizeAfter:  plan.sizeAfter,
		SerializedLargeBlobArrayLimit:      state.support.MaxSerializedLargeBlobArray,
		BlobCountBefore:                    len(state.blobs),
		BlobCountAfter:                     mutationBlobCountAfter(len(state.blobs), plan.operation),
		NoBlob:                             plan.operation == applargeblobs.MutationNoBlob,
	}
}

func mutationBlobCountAfter(before int, operation applargeblobs.MutationOperation) int {
	switch operation {
	case applargeblobs.MutationCreate:
		return before + 1
	case applargeblobs.MutationDelete:
		return before - 1
	case applargeblobs.MutationReplace, applargeblobs.MutationNoBlob:
		return before
	default:
		panic("workflow: invalid large-blob mutation operation: " + string(operation))
	}
}
