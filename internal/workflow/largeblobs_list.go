package workflow

import (
	"context"

	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/secret"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func (r Runner) ListLargeBlobs(
	ctx context.Context,
	device LargeBlobDevice,
	largeBlobState *LargeBlobState,
) (applargeblobs.ListReport, error) {
	inventory, err := r.refreshLargeBlobInventory(ctx, device, largeBlobState, protocol.PermissionNone)
	if err != nil {
		return applargeblobs.ListReport{}, err
	}

	return r.listLargeBlobsFromInventory(inventory), nil
}

type listCredentialKey struct {
	target applargeblobs.BlobTarget
	key    []byte
}

func (r Runner) listLargeBlobsFromInventory(
	inventory *largeBlobInventory,
) applargeblobs.ListReport {
	support := inventory.support
	summary := applargeblobs.ListArraySummary{}
	var entries []applargeblobs.ArrayEntry
	if support.LargeBlobs {
		keys := listCredentialKeys(inventory)
		entries = make([]applargeblobs.ArrayEntry, 0, len(inventory.blobs))
		summary.Read = true
		summary.BlobCount = len(inventory.blobs)

		for index, blob := range inventory.blobs {
			entry := classifyLargeBlobEntry(index, blob, keys)
			entries = append(entries, entry)

			switch entry.State {
			case applargeblobs.EntryStateMatched:
				summary.MatchedBlobCount++
			case applargeblobs.EntryStateOrphaned:
				summary.OrphanedBlobCount++
			case applargeblobs.EntryStateNonconforming:
				summary.NonconformingBlobCount++
			case applargeblobs.EntryStateCorrupt:
				summary.CorruptBlobCount++
			}
		}
	}

	return applargeblobs.ListReport{
		Device:  r.env.Selected,
		Support: support,
		Array:   summary,
		Entries: entries,
	}
}

func listCredentialKeys(inventory *largeBlobInventory) []listCredentialKey {
	keys := make([]listCredentialKey, 0, inventory.credentials.Summary.TotalCredentials)
	for _, group := range inventory.credentials.Groups {
		for _, record := range group.Credentials {
			key := inventory.keys.get(group.RPIDHashHex, record.CredentialIDHex)
			if key == nil {
				continue
			}

			keys = append(keys, listCredentialKey{
				target: applargeblobs.BlobTarget{
					CredentialIDHex: record.CredentialIDHex,
					RP: appcredentials.RelyingParty{
						ID:        group.RPID,
						Name:      group.RPName,
						IDHashHex: group.RPIDHashHex,
					},
					User: appcredentials.UserIdentity{
						UserIDHex:   record.UserIDHex,
						Name:        record.UserName,
						DisplayName: record.DisplayName,
					},
				},
				key: key,
			})
		}
	}

	return keys
}

func classifyLargeBlobEntry(
	index int,
	blob protocol.LargeBlob,
	keys []listCredentialKey,
) applargeblobs.ArrayEntry {
	entry := applargeblobs.ArrayEntry{
		Index:                    index,
		State:                    applargeblobs.EntryStateNonconforming,
		CiphertextByteCount:      len(blob.Ciphertext),
		DeclaredPayloadByteCount: blob.OrigSize,
	}
	if !largeBlobMapConforming(blob) {
		return entry
	}

	for _, candidate := range keys {
		compressed, err := crypto.OpenLargeBlob(candidate.key, blob)
		if err != nil {
			continue
		}

		entry.Target = &candidate.target
		raw, err := crypto.DecompressLargeBlobData(compressed, blob.OrigSize)
		secret.Zero(compressed)
		if err != nil {
			entry.State = applargeblobs.EntryStateCorrupt

			return entry
		}

		entry.State = applargeblobs.EntryStateMatched
		entry.PayloadByteCount = len(raw)
		secret.Zero(raw)

		return entry
	}

	entry.State = applargeblobs.EntryStateOrphaned

	return entry
}
