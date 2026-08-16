package workflow

import (
	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

type largeBlobMutationPlan struct {
	replacement []protocol.LargeBlob
	operation   applargeblobs.MutationOperation
	byteCount   int
	sizeAfter   int
}

func buildWriteMutationPlan(state targetBlobState, payload []byte) (largeBlobMutationPlan, error) {
	operation := applargeblobs.MutationCreate
	if state.currentBlobIndex >= 0 {
		operation = applargeblobs.MutationReplace
	}

	encrypted, err := crypto.EncryptLargeBlob(state.key, payload)
	if err != nil {
		return largeBlobMutationPlan{}, err
	}

	replacement := replaceBlob(state.blobs, state.currentBlobIndex, encrypted)

	sizeAfter, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return largeBlobMutationPlan{}, err
	}

	if err := checkSerializedArrayLimit(state.support.MaxSerializedLargeBlobArray, sizeAfter); err != nil {
		return largeBlobMutationPlan{}, err
	}

	return largeBlobMutationPlan{
		replacement: replacement,
		operation:   operation,
		byteCount:   len(payload),
		sizeAfter:   sizeAfter,
	}, nil
}

func buildDeleteMutationPlan(state targetBlobState) (largeBlobMutationPlan, error) {
	if state.currentBlobIndex < 0 {
		return largeBlobMutationPlan{
			operation: applargeblobs.MutationNoBlob,
			sizeAfter: state.serializedArraySizeBefore,
		}, nil
	}

	replacement := removeBlobAt(state.blobs, state.currentBlobIndex)

	sizeAfter, err := serializedLargeBlobArraySize(replacement)
	if err != nil {
		return largeBlobMutationPlan{}, err
	}

	if err := checkSerializedArrayLimit(state.support.MaxSerializedLargeBlobArray, sizeAfter); err != nil {
		return largeBlobMutationPlan{}, err
	}

	return largeBlobMutationPlan{
		replacement: replacement,
		operation:   applargeblobs.MutationDelete,
		sizeAfter:   sizeAfter,
	}, nil
}
