package runtime

import (
	"fmt"
	"strings"

	"github.com/telesma-app/ctap/protocol"
)

type namedPermission struct {
	value protocol.Permission
	name  string
}

var namedPermissions = [...]namedPermission{
	{protocol.PermissionMakeCredential, "makeCredential"},
	{protocol.PermissionGetAssertion, "getAssertion"},
	{protocol.PermissionCredentialManagement, "credentialManagement"},
	{protocol.PermissionBioEnrollment, "bioEnrollment"},
	{protocol.PermissionLargeBlobWrite, "largeBlobWrite"},
	{protocol.PermissionAuthenticatorConfiguration, "authenticatorConfiguration"},
	{protocol.PermissionPersistentCredentialManagementReadOnly, "persistentCredentialManagementReadOnly"},
}

func permissionLabel(permission protocol.Permission) string {
	if permission == protocol.PermissionNone {
		return "none"
	}

	parts := make([]string, 0, len(namedPermissions)+1)

	known := protocol.PermissionNone
	for _, named := range namedPermissions {
		known |= named.value
		if permission&named.value != 0 {
			parts = append(parts, named.name)
		}
	}

	if unknown := permission &^ known; unknown != protocol.PermissionNone {
		parts = append(parts, fmt.Sprintf("unknown(0x%02x)", uint8(unknown)))
	}

	return strings.Join(parts, ",")
}
