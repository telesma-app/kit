package workflow

import (
	"context"
	"errors"
	"slices"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	ctapauthenticator "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/errornorm"
	"github.com/telesma-app/kit/model/failure"
)

type largeBlobArrayReader interface {
	GetLargeBlobs(ctx context.Context) ([]protocol.LargeBlob, error)
}

func serializedLargeBlobArraySize(blobs []protocol.LargeBlob) (int, error) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return 0, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDecode))
	}

	data, err := encMode.Marshal(blobs)
	if err != nil {
		return 0, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDecode))
	}

	return len(data) + 16, nil
}

func checkSerializedArrayLimit(limit uint, size int) error {
	if limit == 0 || uint(size) <= limit {
		return nil
	}

	return failure.New(failure.CodeLargeBlobArrayTooLarge,
		failure.WithPhase(failure.PhaseValidation),
		failure.WithParams(map[string]string{
			"requested": strconv.FormatUint(uint64(size), 10),
			"limit":     strconv.FormatUint(uint64(limit), 10),
		}),
	)
}

func (r Runner) readLargeBlobArray(
	ctx context.Context,
	device largeBlobArrayReader,
) ([]protocol.LargeBlob, error) {
	blobs, err := device.GetLargeBlobs(ctx)
	if err != nil {
		if errors.Is(err, ctapauthenticator.ErrLargeBlobsIntegrityCheck) {
			return []protocol.LargeBlob{}, nil
		}

		return nil, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorLargeBlobs,
		))
	}

	return blobs, nil
}

func replaceBlob(
	blobs []protocol.LargeBlob,
	index int,
	blob protocol.LargeBlob,
) []protocol.LargeBlob {
	replacement := slices.Clone(blobs)
	if index >= 0 {
		replacement[index] = blob

		return replacement
	}

	return append(replacement, blob)
}

func removeBlobAt(blobs []protocol.LargeBlob, index int) []protocol.LargeBlob {
	out := make([]protocol.LargeBlob, 0, len(blobs)-1)
	for candidateIndex, blob := range blobs {
		if candidateIndex == index {
			continue
		}

		out = append(out, blob)
	}

	return out
}
