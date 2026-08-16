package workflow

import (
	"context"
	"slices"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/errornorm"
	"github.com/telesma-app/kit/internal/secret"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

// LargeBlobState owns the inventory loaded for the selected authenticator.
// Authenticator operations are serialized, so every large-blob operation uses
// this state directly until an operation effect invalidates it, an explicit
// list refreshes it, or the authenticator closes.
type LargeBlobState struct {
	current *largeBlobInventory
}

type largeBlobKeyID struct {
	rpIDHashHex     string
	credentialIDHex string
}

// largeBlobKeyStore owns key buffers returned by credential enumeration.
type largeBlobKeyStore map[largeBlobKeyID][]byte

type largeBlobInventory struct {
	credentials         appcredentials.InventoryReport
	info                protocol.AuthenticatorGetInfoResponse
	inventoryPermission protocol.Permission
	support             applargeblobs.SupportReport
	keys                largeBlobKeyStore
	blobs               []protocol.LargeBlob
	blobsRead           bool
}

func (r Runner) loadLargeBlobInventory(
	ctx context.Context,
	device LargeBlobDevice,
	state *LargeBlobState,
	requiredPermission protocol.Permission,
) (*largeBlobInventory, error) {
	inventory, err := r.loadLargeBlobCredentialInventory(ctx, device, state, requiredPermission)
	if err != nil {
		return nil, err
	}

	return r.loadLargeBlobArrayIntoInventory(ctx, device, inventory)
}

func (r Runner) loadLargeBlobCredentialInventory(
	ctx context.Context,
	device LargeBlobDevice,
	state *LargeBlobState,
	requiredPermission protocol.Permission,
) (*largeBlobInventory, error) {
	if err := ctx.Err(); err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
	}

	if inventory, ok := state.currentInventory(); ok {
		return inventory, nil
	}

	return r.refreshLargeBlobCredentialInventory(ctx, device, state, requiredPermission)
}

func (r Runner) refreshLargeBlobInventory(
	ctx context.Context,
	device LargeBlobDevice,
	state *LargeBlobState,
	requiredPermission protocol.Permission,
) (*largeBlobInventory, error) {
	inventory, err := r.refreshLargeBlobCredentialInventory(ctx, device, state, requiredPermission)
	if err != nil {
		return nil, err
	}

	return r.loadLargeBlobArrayIntoInventory(ctx, device, inventory)
}

func (r Runner) refreshLargeBlobCredentialInventory(
	ctx context.Context,
	device LargeBlobDevice,
	state *LargeBlobState,
	requiredPermission protocol.Permission,
) (*largeBlobInventory, error) {
	access, err := r.resolveCredentialAccess(ctx, device, requiredPermission)
	if err != nil {
		return nil, err
	}

	keys := make(largeBlobKeyStore)
	credentials, err := r.credentialInventory(ctx, device, access, keys)
	if err != nil {
		return nil, err
	}

	inventory := &largeBlobInventory{
		credentials:         credentials,
		info:                access.info,
		inventoryPermission: access.inventoryPermission,
		support: applargeblobs.SupportReport{
			LargeBlobs:                  access.info.Options[protocol.OptionLargeBlobs],
			MaxSerializedLargeBlobArray: access.info.MaxSerializedLargeBlobArray,
			LargeBlobKeyExtension:       slices.Contains(access.info.Extensions, extension.ExtensionIdentifierLargeBlobKey),
		},
		keys: keys,
	}
	state.replaceInventory(inventory)

	return inventory, nil
}

func (r Runner) loadLargeBlobArrayIntoInventory(
	ctx context.Context,
	device largeBlobArrayReader,
	inventory *largeBlobInventory,
) (*largeBlobInventory, error) {
	if inventory.blobsRead {
		return inventory, nil
	}

	var err error
	if inventory.support.LargeBlobs {
		inventory.blobs, err = r.readLargeBlobArray(ctx, device)
		if err != nil {
			return nil, err
		}
	}
	inventory.blobsRead = true

	return inventory, nil
}

func (state *LargeBlobState) currentInventory() (*largeBlobInventory, bool) {
	if state.current == nil {
		return nil, false
	}

	return state.current, true
}

func (state *LargeBlobState) replaceInventory(inventory *largeBlobInventory) {
	state.Clear()
	state.current = inventory
}

func (state *LargeBlobState) replaceBlobs(blobs []protocol.LargeBlob) {
	state.current.blobs = blobs
	state.current.blobsRead = true
}

// Clear releases the credential keys retained for the selected authenticator.
func (state *LargeBlobState) Clear() {
	if state.current == nil {
		return
	}

	state.current.clear()
	state.current = nil
}

func (inventory *largeBlobInventory) clear() {
	inventory.keys.zero()
	inventory.keys = nil
	inventory.blobs = nil
	inventory.blobsRead = false
}

func (inventory *largeBlobInventory) permissionFor(required protocol.Permission) protocol.Permission {
	return credentialAccessFor(
		inventory.info,
		inventory.inventoryPermission,
		required,
	).mutationPermission
}

func (keys largeBlobKeyStore) add(rpIDHashHex, credentialIDHex string, key []byte) {
	keys[largeBlobKeyID{
		rpIDHashHex:     rpIDHashHex,
		credentialIDHex: credentialIDHex,
	}] = key
}

func (keys largeBlobKeyStore) get(rpIDHashHex, credentialIDHex string) []byte {
	return keys[largeBlobKeyID{
		rpIDHashHex:     rpIDHashHex,
		credentialIDHex: credentialIDHex,
	}]
}

func (keys largeBlobKeyStore) zero() {
	for keyID, key := range keys {
		secret.Zero(key)
		delete(keys, keyID)
	}
}
