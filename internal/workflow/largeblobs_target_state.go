package workflow

import (
	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	rtcredentials "github.com/telesma-app/kit/internal/credentials"
	"github.com/telesma-app/kit/internal/secret"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
	"github.com/telesma-app/kit/model/report"
)

type targetBlobState struct {
	selected                  report.DeviceReport
	support                   applargeblobs.SupportReport
	target                    appcredentials.CredentialTarget
	key                       []byte
	blobs                     []protocol.LargeBlob
	currentBlobIndex          int
	currentByteCount          int
	serializedArraySizeBefore int
}

func (r Runner) loadTargetBlobState(
	inventory *largeBlobInventory,
	credentialIDHex string,
) (targetBlobState, error) {
	target, err := rtcredentials.FindByCanonicalID(inventory.credentials, credentialIDHex)
	if err != nil {
		return targetBlobState{}, err
	}

	support := inventory.support
	if !support.LargeBlobs || !support.LargeBlobKeyExtension {
		return targetBlobState{}, failure.New(failure.CodeLargeBlobUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	largeBlobKey := inventory.keys.get(target.RP.IDHashHex, target.Record.CredentialIDHex)
	if len(largeBlobKey) == 0 {
		return targetBlobState{}, failure.New(failure.CodeLargeBlobKeyMissing,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}
	sizeBefore, err := serializedLargeBlobArraySize(inventory.blobs)
	if err != nil {
		return targetBlobState{}, err
	}

	state := targetBlobState{
		selected:                  r.env.Selected,
		support:                   support,
		target:                    target,
		key:                       largeBlobKey,
		blobs:                     inventory.blobs,
		currentBlobIndex:          -1,
		serializedArraySizeBefore: sizeBefore,
	}

	for index, candidate := range inventory.blobs {
		if !largeBlobMapConforming(candidate) {
			continue
		}

		compressed, err := crypto.OpenLargeBlob(largeBlobKey, candidate)
		if err != nil {
			continue
		}
		secret.Zero(compressed)

		state.currentBlobIndex = index
		state.currentByteCount = int(candidate.OrigSize)

		break
	}

	return state, nil
}
