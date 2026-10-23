package runtime

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model"
)

func TestTokenServiceCachedPINFlowPerformsNoInteraction(t *testing.T) {
	var requests []model.InteractionRequest

	cache := &testTokenCache{}
	handle := secret.New([]byte("cached"))
	cache.SetToken(TokenKey{Permission: protocol.PermissionCredentialManagement}, handle)

	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := &TokenService{
		Cache:            cache,
		Authenticator:    authenticator,
		Interactions:     recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		VerificationFlow: VerificationFlowPIN,
	}

	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")

	if len(requests) != 0 {
		t.Fatalf("interactions = %d, want 0", len(requests))
	}

	if len(authenticator.uvRPIDs) != 0 || len(authenticator.pinRPIDs) != 0 {
		t.Fatalf("token commands = UV %d PIN %d, want none", len(authenticator.uvRPIDs), len(authenticator.pinRPIDs))
	}
}

func TestTokenServiceUseReacquiresRejectedTokenOnce(t *testing.T) {
	var requests []model.InteractionRequest

	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := &TokenService{
		Cache:         &testTokenCache{},
		Authenticator: authenticator,
		Interactions:  recordingInteractionHandler(&requests, model.InteractionResponse{}),
	}

	var usedTokens [][]byte

	err := tokens.Use(
		context.Background(),
		TokenUse{
			Permission: protocol.PermissionCredentialManagement,
			ReplaySafe: true,
		},
		func(token []byte) error {
			usedTokens = append(usedTokens, token)
			if len(usedTokens) == 1 {
				return &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorCredentialManagement,
					StatusCode: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
				}
			}

			return nil
		},
	)
	if err != nil {
		t.Fatalf("Use: %v", err)
	}

	if got := len(usedTokens); got != 2 {
		t.Fatalf("token uses = %d, want 2", got)
	}

	if got := len(requests); got != 2 {
		t.Fatalf("interactions = %d, want 2", got)
	}

	if want := []string{"", ""}; !slices.Equal(authenticator.uvRPIDs, want) {
		t.Fatalf("UV token rpIds = %v, want %v", authenticator.uvRPIDs, want)
	}

	for index, token := range usedTokens {
		if !slices.Equal(token, make([]byte, len(token))) {
			t.Fatalf("used token %d was not zeroed", index)
		}
	}
}

func TestTokenServiceUseInvalidatesRejectedTokenWithoutReplayingUnsafeConsumer(t *testing.T) {
	cache := &testTokenCache{}
	key := TokenKey{Permission: protocol.PermissionCredentialManagement}
	cache.SetToken(key, secret.New([]byte("cached-token")))

	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := &TokenService{
		Cache:         cache,
		Authenticator: authenticator,
	}
	consumerErr := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorCredentialManagement,
		StatusCode: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
	}

	var usedToken []byte

	uses := 0

	err := tokens.Use(
		context.Background(),
		TokenUse{Permission: protocol.PermissionCredentialManagement},
		func(token []byte) error {
			uses++
			usedToken = token

			return consumerErr
		},
	)
	if !errors.Is(err, consumerErr) {
		t.Fatalf("Use error = %v, want consumer error", err)
	}

	if uses != 1 {
		t.Fatalf("token uses = %d, want 1", uses)
	}

	if _, present := cache.GetToken(key); present {
		t.Fatal("rejected token remained cached")
	}

	if !slices.Equal(usedToken, make([]byte, len(usedToken))) {
		t.Fatalf("used token was not zeroed: %#v", usedToken)
	}
}

func TestTokenServiceUseKeepsTokenAfterOtherConsumerFailures(t *testing.T) {
	tests := []struct {
		name   string
		status ctaptransport.StatusCode
	}{
		{
			name:   "unauthorized permission",
			status: ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION,
		},
		{
			name:   "blocked auth",
			status: ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED,
		},
		{
			name:   "required token",
			status: ctaptransport.CTAP2_ERR_PUAT_REQUIRED,
		},
		{
			name:   "unrelated error",
			status: ctaptransport.CTAP1_ERR_TIMEOUT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &testTokenCache{}
			key := TokenKey{Permission: protocol.PermissionCredentialManagement}
			cache.SetToken(key, secret.New([]byte("cached-token")))

			authenticator := &recordingTokenDevice{info: uvTokenInfo()}
			tokens := &TokenService{
				Cache:         cache,
				Authenticator: authenticator,
			}
			consumerErr := &ctaptransport.CTAPError{
				Command:    protocol.AuthenticatorCredentialManagement,
				StatusCode: tt.status,
			}

			uses := 0

			err := tokens.Use(
				context.Background(),
				TokenUse{Permission: protocol.PermissionCredentialManagement},
				func([]byte) error {
					uses++

					return consumerErr
				},
			)
			if !errors.Is(err, consumerErr) {
				t.Fatalf("Use error = %v, want consumer error", err)
			}

			if uses != 1 {
				t.Fatalf("token uses = %d, want 1", uses)
			}

			if _, present := cache.GetToken(key); !present {
				t.Fatal("cached token was invalidated")
			}
		})
	}
}
