package runtime

import (
	"sync"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/secret"
)

// TokenStore owns the single pinUvAuthToken associated with an opened
// authenticator. Tokens never leave the runtime and are wiped when replaced,
// invalidated, or the authenticator is closed.
type TokenStore struct {
	mu     sync.Mutex
	key    TokenKey
	secret *secret.Handle
}

func (s *TokenStore) GetToken(key TokenKey) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.secret == nil || !s.key.Covers(key) {
		return nil, false
	}

	token, err := s.secret.Bytes()
	if err != nil {
		s.key = TokenKey{}
		s.secret = nil

		return nil, false
	}

	return token, true
}

func (s *TokenStore) SetToken(key TokenKey, token *secret.Handle) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.invalidateLocked()
	s.key = key
	s.secret = token
}

func (s *TokenStore) InvalidateToken() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.invalidateLocked()
}

func (s *TokenStore) InvalidateTokenUnlessPermission(permission protocol.Permission) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.secret == nil {
		return
	}

	if permission == protocol.PermissionPersistentCredentialManagementReadOnly &&
		s.key.Permission != permission {
		s.invalidateLocked()

		return
	}

	remaining := s.key.Permission & permission
	if remaining == protocol.PermissionNone {
		s.invalidateLocked()

		return
	}

	s.key.Permission = remaining
	if !permissionUsesRPID(remaining) {
		s.key.RPID = ""
	}
}

func (s *TokenStore) invalidateLocked() {
	if s.secret == nil {
		return
	}

	s.key = TokenKey{}
	s.secret.Invalidate()
	s.secret = nil
}

func permissionUsesRPID(permission protocol.Permission) bool {
	return permission&(protocol.PermissionMakeCredential|
		protocol.PermissionGetAssertion|
		protocol.PermissionCredentialManagement) != 0
}
