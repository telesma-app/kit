package workflow

import (
	"context"
	"encoding/hex"

	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	rtcredentials "github.com/telesma-app/kit/internal/credentials"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func (r Runner) ReadLargeBlob(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
	req applargeblobs.ReadOperation,
) (applargeblobs.ReadReport, error) {
	_, credentialIDHex, err := rtcredentials.ParseCredentialID(req.CredentialIDHex)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}

	inventory, err := r.loadLargeBlobCredentialInventory(
		ctx,
		device,
		largeBlobState,
		protocol.PermissionNone,
	)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}
	if !inventory.support.LargeBlobs || !inventory.support.LargeBlobKeyExtension {
		return applargeblobs.ReadReport{}, failure.New(failure.CodeLargeBlobUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	return r.readLargeBlobFromInventory(ctx, device, credentialIDHex, inventory)
}

func (r Runner) readLargeBlobFromInventory(
	ctx context.Context,
	device largeBlobArrayReader,
	credentialIDHex string,
	inventory *largeBlobInventory,
) (applargeblobs.ReadReport, error) {
	target, err := rtcredentials.FindByCanonicalID(inventory.credentials, credentialIDHex)
	if err != nil {
		return applargeblobs.ReadReport{}, err
	}
	largeBlobKey := inventory.keys.get(target.RP.IDHashHex, target.Record.CredentialIDHex)
	state := applargeblobs.ReadStateMissing
	var raw []byte
	if largeBlobKey != nil {
		inventory, err = r.loadLargeBlobArrayIntoInventory(ctx, device, inventory)
		if err != nil {
			return applargeblobs.ReadReport{}, err
		}

		for _, candidate := range inventory.blobs {
			if !largeBlobMapConforming(candidate) {
				continue
			}

			compressed, err := crypto.OpenLargeBlob(largeBlobKey, candidate)
			if err != nil {
				continue
			}

			decrypted, err := crypto.DecompressLargeBlobData(compressed, candidate.OrigSize)
			secret.Zero(compressed)
			if err != nil {
				return applargeblobs.ReadReport{}, failure.Wrap(
					failure.CodeLargeBlobIntegrityFailure,
					err,
					failure.WithPhase(failure.PhaseDecode),
				)
			}

			state = applargeblobs.ReadStatePresent
			raw = decrypted

			break
		}
	}

	return applargeblobs.ReadReport{
		Device: r.env.Selected,
		Target: applargeblobs.BlobTarget{
			CredentialIDHex: target.Record.CredentialIDHex,
			RP:              target.RP,
			User:            target.User,
		},
		State:        state,
		RawHex:       hex.EncodeToString(raw),
		RawByteCount: len(raw),
		RawBytes:     raw,
	}, nil
}
