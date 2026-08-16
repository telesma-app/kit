package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
)

type credentialAccess struct {
	info                protocol.AuthenticatorGetInfoResponse
	command             protocol.Command
	inventoryPermission protocol.Permission
	grantPermission     protocol.Permission
	mutationPermission  protocol.Permission
}

func (r Runner) resolveCredentialAccess(
	ctx context.Context,
	device authenticator.CredentialInventoryReader,
	required protocol.Permission,
) (credentialAccess, error) {
	info, err := r.getAuthenticatorInfo(ctx, device)
	if err != nil {
		return credentialAccess{}, err
	}

	inventory, err := inventoryPermission(info)
	if err != nil {
		return credentialAccess{}, err
	}

	return credentialAccessFor(info, inventory, required), nil
}

func credentialAccessFor(
	info protocol.AuthenticatorGetInfoResponse,
	inventory protocol.Permission,
	required protocol.Permission,
) credentialAccess {
	command := protocol.AuthenticatorCredentialManagement
	if info.Versions.IsPreviewOnly() {
		command = protocol.PrototypeAuthenticatorCredentialManagement
	}
	access := credentialAccess{
		info:                info,
		command:             command,
		inventoryPermission: inventory,
	}

	if required&protocol.PermissionCredentialManagement != 0 {
		access.grantPermission = required
		access.mutationPermission = required

		return access
	}

	if inventory == protocol.PermissionPersistentCredentialManagementReadOnly {
		access.grantPermission = inventory
		access.mutationPermission = required

		return access
	}

	access.grantPermission = required | protocol.PermissionCredentialManagement
	access.mutationPermission = access.grantPermission

	return access
}
