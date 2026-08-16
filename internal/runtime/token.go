package runtime

import (
	"context"
	"errors"
	"slices"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/errornorm"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
)

type VerificationFlow string

const (
	VerificationFlowDefault VerificationFlow = ""
	VerificationFlowPIN     VerificationFlow = "pin"
)

type TokenKey struct {
	Permission protocol.Permission
	RPID       string
}

// Covers reports whether a cached grant can satisfy the requested token key.
func (granted TokenKey) Covers(requested TokenKey) bool {
	if requested.Permission == protocol.PermissionNone || granted.RPID != requested.RPID {
		return false
	}

	if requested.Permission == protocol.PermissionPersistentCredentialManagementReadOnly &&
		granted.Permission&protocol.PermissionCredentialManagement != 0 {
		return true
	}

	return granted.Permission&requested.Permission == requested.Permission
}

type TokenCache interface {
	GetToken(TokenKey) ([]byte, bool)
	SetToken(TokenKey, *secret.Handle)
	InvalidateToken()
	InvalidateTokenUnlessPermission(protocol.Permission)
}

// TokenUse describes the authorization needed by one token consumer.
type TokenUse struct {
	Permission      protocol.Permission
	RPID            string
	TryWithoutToken bool
	ReplaySafe      bool
}

func (s *TokenService) Invalidate() {
	s.cache.InvalidateToken()
}

func (s *TokenService) InvalidateUnlessPermission(permission protocol.Permission) {
	s.cache.InvalidateTokenUnlessPermission(permission)
}

type TokenService struct {
	authenticator    authenticator.TokenProvider
	cache            TokenCache
	verificationFlow VerificationFlow
	interactions     interface {
		RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
	}
}

func NewTokenService(
	cache TokenCache,
	authenticator authenticator.TokenProvider,
	interactions interface {
		RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
	},
	verificationFlow VerificationFlow,
) *TokenService {
	return &TokenService{
		authenticator:    authenticator,
		cache:            cache,
		verificationFlow: verificationFlow,
		interactions:     interactions,
	}
}

// Use runs a token consumer while owning token acquisition, caller-copy
// wiping, and rejected-token invalidation. TryWithoutToken first runs the
// consumer without a token and acquires one only when the authenticator
// requires it.
//
// ReplaySafe permits one reacquisition after PIN_UV_AUTH_INVALID. Callers must
// enable it only when replaying the entire consumer is safe.
func (s *TokenService) Use(
	ctx context.Context,
	request TokenUse,
	use func([]byte) error,
) error {
	if request.TryWithoutToken {
		err := use(nil)
		if !tokenRequired(err) {
			return err
		}
	}

	retriedRejectedToken := false
	for {
		token, err := s.acquire(ctx, request.Permission, request.RPID)
		if err != nil {
			return err
		}

		err = func() error {
			defer secret.Zero(token)

			return use(token)
		}()
		if err == nil {
			return nil
		}

		if errornorm.Normalize(err, "").Code != failure.CodePINUVAuthInvalid {
			return err
		}

		s.cache.InvalidateToken()

		if !request.ReplaySafe || retriedRejectedToken {
			return err
		}

		retriedRejectedToken = true
	}
}

func (s *TokenService) acquire(
	ctx context.Context,
	permission protocol.Permission,
	rpID string,
) ([]byte, error) {
	key := TokenKey{
		Permission: permission,
		RPID:       rpID,
	}

	if token, ok := s.cache.GetToken(key); ok {
		return token, nil
	}

	var (
		token []byte
		err   error
	)

	info, err := authenticator.ResolveInfo(ctx, s.authenticator)
	if err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseTokenAcquisition,
			protocol.AuthenticatorGetInfo,
		))
	}
	if s.verificationFlow != VerificationFlowPIN &&
		supportsUserVerificationTokenFlow(info, permission) {
		_, err = s.interactions.RequestInteraction(ctx, model.InteractionRequest{
			Kind:       model.InteractionKindUserVerification,
			Permission: permissionLabel(permission),
			UVModality: info.UvModality,
		})
		if err != nil {
			return nil, err
		}

		token, err = s.authenticator.GetPinUvAuthTokenUsingUV(ctx, permission, key.RPID)
		if err == nil {
			return s.storeToken(key, token), nil
		}

		if !fallbackToPIN(err) {
			return nil, errornorm.Annotate(err, errornorm.WithCommand(
				failure.PhaseTokenAcquisition,
				protocol.AuthenticatorClientPIN,
			))
		}
	}

	clientPIN, clientPINSupported := info.Options[protocol.OptionClientPIN]
	if !clientPINSupported {
		return nil, failure.New(
			failure.CodeVerificationFlowUnsupported,
			failure.WithPhase(failure.PhaseTokenAcquisition),
		)
	}
	if !clientPIN {
		return nil, failure.New(
			failure.CodePINNotConfigured,
			failure.WithPhase(failure.PhaseTokenAcquisition),
		)
	}

	previousAttemptInvalid := false
	for {
		pinInteraction, err := s.readPINInteractionState(ctx)
		if err != nil {
			return nil, err
		}
		pinInteraction.PreviousAttemptInvalid = previousAttemptInvalid

		token, err = s.acquireUsingPIN(ctx, permission, key.RPID, pinInteraction)
		if err == nil {
			return s.storeToken(key, token), nil
		}

		normalized := errornorm.Normalize(err, "")
		if !failure.IsCode(normalized, failure.CodePINInvalid) {
			return nil, normalized
		}

		previousAttemptInvalid = true
	}
}

func tokenRequired(err error) bool {
	return errors.Is(err, ctapdevice.ErrPinUvAuthTokenRequired) ||
		errors.Is(err, ctapdevice.ErrBuiltInUVRequired)
}

func (s *TokenService) readPINInteractionState(ctx context.Context) (*model.PINInteractionState, error) {
	retries, powerCycleState, err := s.authenticator.GetPINRetries(ctx)
	if err != nil {
		return nil, errornorm.Normalize(errornorm.Annotate(
			err,
			errornorm.WithClientPINSubCommand(
				failure.PhaseTokenAcquisition,
				protocol.ClientPINSubCommandGetPINRetries,
			)), "")
	}

	return &model.PINInteractionState{
		RetriesRemaining: new(retries),
		PowerCycleState:  powerCycleState,
	}, nil
}

func (s *TokenService) acquireUsingPIN(
	ctx context.Context,
	permission protocol.Permission,
	rpID string,
	pinInteraction *model.PINInteractionState,
) ([]byte, error) {
	response, err := s.interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:       model.InteractionKindPIN,
		Permission: permissionLabel(permission),
		PINState:   pinInteraction,
	})
	if err != nil {
		return nil, err
	}
	defer secret.Zero(response.PIN)

	token, err := s.authenticator.GetPinUvAuthTokenUsingPIN(ctx, string(response.PIN), permission, rpID)
	if err != nil {
		return nil, errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseTokenAcquisition,
			protocol.AuthenticatorClientPIN,
		))
	}

	return token, nil
}

func (s *TokenService) storeToken(key TokenKey, token []byte) []byte {
	out := slices.Clone(token)
	s.cache.SetToken(key, secret.New(token))

	return out
}

func supportsUserVerificationTokenFlow(
	info protocol.AuthenticatorGetInfoResponse,
	permission protocol.Permission,
) bool {
	if !info.Options[protocol.OptionUserVerification] {
		return false
	}

	if info.Versions.IsPreviewOnly() && info.Options[protocol.OptionUvToken] {
		return true
	}

	if !info.Options[protocol.OptionPinUvAuthToken] {
		return false
	}

	if permission&protocol.PermissionBioEnrollment != 0 &&
		!info.Options[protocol.OptionUvBioEnroll] {
		return false
	}

	if permission&protocol.PermissionAuthenticatorConfiguration != 0 &&
		!info.Options[protocol.OptionUvAcfg] {
		return false
	}

	return true
}

func fallbackToPIN(err error) bool {
	if errors.Is(err, ctapdevice.ErrNotSupported) || errors.Is(err, ctapdevice.ErrUvNotConfigured) {
		return true
	}

	ctapErr, ok := errors.AsType[*ctaptransport.CTAPError](err)
	return ok && ctapErr.StatusCode == ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION
}
