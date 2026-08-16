package runtime

import (
	"testing"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/secret"
)

func TestTokenStoreReplacesAndWipesToken(t *testing.T) {
	store := &TokenStore{}
	previous := secret.New([]byte("previous"))
	store.SetToken(TokenKey{Permission: protocol.PermissionCredentialManagement}, previous)

	store.SetToken(
		TokenKey{Permission: protocol.PermissionLargeBlobWrite},
		secret.New([]byte("next")),
	)

	if _, err := previous.Bytes(); err == nil {
		t.Fatal("replaced token was not invalidated")
	}
}

func TestTokenStoreCompositeGrantCoversSubset(t *testing.T) {
	store := &TokenStore{}
	store.SetToken(TokenKey{
		Permission: protocol.PermissionCredentialManagement |
			protocol.PermissionLargeBlobWrite,
	}, secret.New([]byte("token")))

	token, ok := store.GetToken(TokenKey{Permission: protocol.PermissionLargeBlobWrite})
	defer secret.Zero(token)
	if !ok {
		t.Fatal("composite grant did not cover permission subset")
	}
}

func TestTokenStoreInvalidateUnlessPermissionNarrowsGrant(t *testing.T) {
	store := &TokenStore{}
	store.SetToken(TokenKey{
		Permission: protocol.PermissionCredentialManagement |
			protocol.PermissionLargeBlobWrite,
	}, secret.New([]byte("token")))

	store.InvalidateTokenUnlessPermission(protocol.PermissionLargeBlobWrite)

	if _, ok := store.GetToken(TokenKey{Permission: protocol.PermissionCredentialManagement}); ok {
		t.Fatal("removed permission remained available")
	}
	token, ok := store.GetToken(TokenKey{Permission: protocol.PermissionLargeBlobWrite})
	defer secret.Zero(token)
	if !ok {
		t.Fatal("retained permission was invalidated")
	}
}
