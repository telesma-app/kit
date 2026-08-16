package workflow

import (
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
	"github.com/telesma-app/kit/model/safety"
)

const sharedArrayRewriteWarning = "CTAP updates one credential's blob by rewriting the authenticator's entire shared serialized large-blob array."

func buildMutationPreview(
	state targetBlobState,
	plan largeBlobMutationPlan,
) applargeblobs.MutationPreview {
	warnings := []safety.Warning{
		{
			Severity: safety.SeverityWarning,
			Code:     "large_blob.shared_array_rewrite",
			Message:  sharedArrayRewriteWarning,
		},
	}

	switch plan.operation {
	case applargeblobs.MutationCreate:
	case applargeblobs.MutationReplace:
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityWarning,
			Code:     "large_blob.replace_existing",
			Message:  "The first large-blob entry decryptable with this credential's largeBlobKey will be replaced; any additional matching entries remain unchanged.",
		})
	case applargeblobs.MutationDelete:
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityDestructive,
			Code:     "large_blob.delete_existing",
			Message:  "The first large-blob entry decryptable with this credential's largeBlobKey will be deleted; any additional matching entries remain unchanged.",
		})
	case applargeblobs.MutationNoBlob:
		warnings = append(warnings, safety.Warning{
			Severity: safety.SeverityInfo,
			Code:     "large_blob.delete_noop",
			Message:  "No large blob exists for this credential; delete is a no-op.",
		})
	default:
		panic("workflow: invalid large-blob mutation operation: " + string(plan.operation))
	}

	return applargeblobs.MutationPreview{
		Operation: plan.operation,
		Device:    state.selected,
		Support:   state.support,
		Target: applargeblobs.BlobTarget{
			CredentialIDHex: state.target.Record.CredentialIDHex,
			RP:              state.target.RP,
			User:            state.target.User,
		},
		LargeBlobKeyState:                  applargeblobs.LargeBlobKeyAvailable,
		CurrentByteCount:                   state.currentByteCount,
		ProposedByteCount:                  plan.byteCount,
		SerializedLargeBlobArraySizeBefore: state.serializedArraySizeBefore,
		SerializedLargeBlobArraySizeAfter:  plan.sizeAfter,
		SerializedLargeBlobArrayLimit:      state.support.MaxSerializedLargeBlobArray,
		BlobCountBefore:                    len(state.blobs),
		BlobCountAfter:                     mutationBlobCountAfter(len(state.blobs), plan.operation),
		NoBlob:                             plan.operation == applargeblobs.MutationNoBlob,
		Warnings:                           warnings,
	}
}
