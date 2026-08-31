package runtime

import (
	"context"
	"errors"
	"slices"
	"testing"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
)

func TestTokenServiceCachesByPermissionAndRPID(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		authenticator,
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		VerificationFlowDefault,
	)

	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")
	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")
	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "example.com")
	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")

	wantRPIDs := []string{"", "example.com", ""}
	if !slices.Equal(authenticator.uvRPIDs, wantRPIDs) {
		t.Fatalf("UV token rpIds = %v, want %v", authenticator.uvRPIDs, wantRPIDs)
	}

	if len(requests) != len(wantRPIDs) {
		t.Fatalf("interactions = %d, want %d", len(requests), len(wantRPIDs))
	}
}

func TestTokenServiceCompositeGrantCoversPermissionSubsets(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	tokens := NewTokenService(
		&testTokenCache{},
		authenticator,
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		VerificationFlowDefault,
	)
	permissions := protocol.PermissionCredentialManagement |
		protocol.PermissionLargeBlobWrite

	acquireTokenForTest(t, tokens, permissions, "")
	acquireTokenForTest(t, tokens, protocol.PermissionLargeBlobWrite, "")
	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")
	acquireTokenForTest(t, tokens, protocol.PermissionPersistentCredentialManagementReadOnly, "")

	if got := len(authenticator.uvRPIDs); got != 1 {
		t.Fatalf("UV token calls = %d, want 1", got)
	}

	if got := len(requests); got != 1 {
		t.Fatalf("interactions = %d, want 1", got)
	}

	if got, want := requests[0].Permission, "credentialManagement,largeBlobWrite"; got != want {
		t.Fatalf("interaction permission = %q, want %q", got, want)
	}
}

func TestPermissionLabelFormatsMasksDeterministically(t *testing.T) {
	tests := []struct {
		permission protocol.Permission
		want       string
	}{
		{protocol.PermissionNone, "none"},
		{protocol.PermissionCredentialManagement, "credentialManagement"},
		{
			protocol.PermissionCredentialManagement | protocol.PermissionLargeBlobWrite,
			"credentialManagement,largeBlobWrite",
		},
		{protocol.PermissionPersistentCredentialManagementReadOnly, "persistentCredentialManagementReadOnly"},
		{protocol.Permission(0x80), "unknown(0x80)"},
	}

	for _, tt := range tests {
		if got := permissionLabel(tt.permission); got != tt.want {
			t.Errorf("permissionLabel(%#02x) = %q, want %q", tt.permission, got, tt.want)
		}
	}
}

func TestTokenServiceDefaultFlowRequestsUVInteractionBeforeUVCommand(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info: uvTokenInfo(),
	}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		authenticator,
		recordingInteractionHandlerWithEvents(&requests, authenticator, model.InteractionResponse{}),
		VerificationFlowDefault,
	)

	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")

	if len(requests) != 1 {
		t.Fatalf("interactions = %d, want 1", len(requests))
	}

	if requests[0].Kind != model.InteractionKindUserVerification {
		t.Fatalf("interaction kind = %s, want user-verification", requests[0].Kind)
	}

	if requests[0].UVModality == nil || *requests[0].UVModality != protocol.UserVerifyFingerprintInternal {
		t.Fatalf("interaction uv modality = %#v, want fingerprint", requests[0].UVModality)
	}

	wantEvents := []string{"interaction:user-verification", "command:uv"}
	if !slices.Equal(authenticator.events, wantEvents) {
		t.Fatalf("events = %v, want %v", authenticator.events, wantEvents)
	}
}

func TestTokenServiceDefaultFlowCanceledUVInteractionSkipsUVCommand(t *testing.T) {
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		authenticator,
		NewInteractionBroker(noopEventSink{}, interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
			return model.InteractionResponse{Canceled: true}, nil
		})),
		VerificationFlowDefault,
	)

	token, err := tokens.acquire(
		context.Background(),
		protocol.PermissionCredentialManagement,
		"",
	)
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !failure.IsCode(err, failure.CodeInteractionCanceled) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodeInteractionCanceled)
	}

	if len(authenticator.uvRPIDs) != 0 {
		t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
	}
}

func TestTokenServiceDefaultFlowFallsBackToPINAfterUVFallbackError(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info:  uvTokenInfo(),
		uvErr: ctapdevice.ErrUvNotConfigured,
	}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		authenticator,
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		VerificationFlowDefault,
	)

	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")

	wantKinds := []model.InteractionKind{
		model.InteractionKindUserVerification,
		model.InteractionKindPIN,
	}

	if !slices.Equal(interactionKinds(requests), wantKinds) {
		t.Fatalf("interaction kinds = %v, want %v", interactionKinds(requests), wantKinds)
	}

	if len(authenticator.uvRPIDs) != 1 {
		t.Fatalf("UV token calls = %d, want 1", len(authenticator.uvRPIDs))
	}

	if len(authenticator.pinRPIDs) != 1 {
		t.Fatalf("PIN token calls = %d, want 1", len(authenticator.pinRPIDs))
	}
}

func TestTokenServiceRejectsAuthenticatorWithoutUsableVerificationFlow(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info: protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{
				protocol.U2F_V2,
				protocol.FIDO_2_0,
				protocol.FIDO_2_1_PRE,
			},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{
				protocol.PinUvAuthProtocolOne,
			},
			Options: map[protocol.Option]bool{
				protocol.OptionResidentKeys:                true,
				protocol.OptionUserPresence:                true,
				protocol.OptionUserVerification:            true,
				protocol.OptionCredentialManagement:        true,
				protocol.OptionBioEnroll:                   true,
				protocol.OptionCredentialManagementPreview: true,
				protocol.OptionUserVerificationMgmtPreview: true,
			},
		},
	}
	tokens := NewTokenService(
		&testTokenCache{},
		authenticator,
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		VerificationFlowDefault,
	)

	token, err := tokens.acquire(
		context.Background(),
		protocol.PermissionCredentialManagement,
		"",
	)
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !failure.IsCode(err, failure.CodeVerificationFlowUnsupported) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodeVerificationFlowUnsupported)
	}

	if len(requests) != 0 {
		t.Fatalf("interactions = %v, want none", interactionKinds(requests))
	}

	if authenticator.pinRetriesCalls != 0 ||
		len(authenticator.pinRPIDs) != 0 ||
		len(authenticator.uvRPIDs) != 0 {
		t.Fatalf(
			"authenticator calls = retries %d, PIN %d, UV %d; want none",
			authenticator.pinRetriesCalls,
			len(authenticator.pinRPIDs),
			len(authenticator.uvRPIDs),
		)
	}
}

func TestTokenServiceUsesStandardPreviewUVTokenFlow(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info: protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{
				protocol.U2F_V2,
				protocol.FIDO_2_0,
				protocol.FIDO_2_1_PRE,
			},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification:            true,
				protocol.OptionUvToken:                     true,
				protocol.OptionBioEnroll:                   true,
				protocol.OptionUserVerificationMgmtPreview: false,
			},
		},
	}
	tokens := NewTokenService(
		&testTokenCache{},
		authenticator,
		recordingInteractionHandlerWithEvents(&requests, authenticator, model.InteractionResponse{}),
		VerificationFlowDefault,
	)

	token, err := tokens.acquire(
		context.Background(),
		protocol.PermissionBioEnrollment,
		"",
	)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer secret.Zero(token)

	if !slices.Equal(interactionKinds(requests), []model.InteractionKind{
		model.InteractionKindUserVerification,
	}) {
		t.Fatalf("interaction kinds = %v, want user verification", interactionKinds(requests))
	}

	wantEvents := []string{"interaction:user-verification", "command:uv"}
	if !slices.Equal(authenticator.events, wantEvents) {
		t.Fatalf("events = %v, want %v", authenticator.events, wantEvents)
	}

	if authenticator.pinRetriesCalls != 0 || len(authenticator.pinRPIDs) != 0 {
		t.Fatalf(
			"PIN calls = retries %d, token %d; want none",
			authenticator.pinRetriesCalls,
			len(authenticator.pinRPIDs),
		)
	}
}

func TestTokenServiceSkipsUVPromptWhenPermissionCapabilityIsUnsupported(t *testing.T) {
	tests := []struct {
		name       string
		permission protocol.Permission
		option     protocol.Option
	}{
		{"bio enrollment", protocol.PermissionBioEnrollment, protocol.OptionBioEnroll},
		{"authenticator configuration", protocol.PermissionAuthenticatorConfiguration, protocol.OptionAuthenticatorConfig},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests []model.InteractionRequest
			authenticator := &recordingTokenDevice{
				info: protocol.AuthenticatorGetInfoResponse{
					Options: map[protocol.Option]bool{
						tt.option:                       true,
						protocol.OptionClientPIN:        true,
						protocol.OptionPinUvAuthToken:   true,
						protocol.OptionUserVerification: true,
					},
				},
			}
			tokens := NewTokenService(
				&testTokenCache{},
				authenticator,
				recordingInteractionHandler(&requests, model.InteractionResponse{
					PIN: []byte("1234"),
				}),
				VerificationFlowDefault,
			)

			token, err := tokens.acquire(context.Background(), tt.permission, "")
			if err != nil {
				t.Fatalf("Acquire: %v", err)
			}
			defer secret.Zero(token)

			if want := []model.InteractionKind{model.InteractionKindPIN}; !slices.Equal(interactionKinds(requests), want) {
				t.Fatalf("interaction kinds = %v, want %v", interactionKinds(requests), want)
			}
			if len(authenticator.uvRPIDs) != 0 {
				t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
			}
		})
	}
}

func TestTokenServiceDoesNotFallBackToUnavailablePIN(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{
		info: protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionPinUvAuthToken:   true,
				protocol.OptionUserVerification: true,
			},
		},
		uvErr: ctapdevice.ErrUvNotConfigured,
	}
	tokens := NewTokenService(
		&testTokenCache{},
		authenticator,
		recordingInteractionHandler(&requests, model.InteractionResponse{}),
		VerificationFlowDefault,
	)

	token, err := tokens.acquire(
		context.Background(),
		protocol.PermissionCredentialManagement,
		"",
	)
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !failure.IsCode(err, failure.CodeVerificationFlowUnsupported) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodeVerificationFlowUnsupported)
	}

	if want := []model.InteractionKind{model.InteractionKindUserVerification}; !slices.Equal(interactionKinds(requests), want) {
		t.Fatalf("interaction kinds = %v, want %v", interactionKinds(requests), want)
	}

	if len(authenticator.uvRPIDs) != 1 {
		t.Fatalf("UV token calls = %d, want 1", len(authenticator.uvRPIDs))
	}
	if authenticator.pinRetriesCalls != 0 || len(authenticator.pinRPIDs) != 0 {
		t.Fatalf(
			"PIN calls = retries %d, token %d; want none",
			authenticator.pinRetriesCalls,
			len(authenticator.pinRPIDs),
		)
	}
}

func TestTokenServiceReportsUnconfiguredPINBeforeInteraction(t *testing.T) {
	authenticator := &recordingTokenDevice{
		info: protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionClientPIN: false,
			},
		},
	}
	tokens := NewTokenService(
		&testTokenCache{},
		authenticator,
		NewInteractionBroker(noopEventSink{}, nil),
		VerificationFlowDefault,
	)

	token, err := tokens.acquire(
		context.Background(),
		protocol.PermissionCredentialManagement,
		"",
	)
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !failure.IsCode(err, failure.CodePINNotConfigured) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodePINNotConfigured)
	}

	if authenticator.pinRetriesCalls != 0 || len(authenticator.pinRPIDs) != 0 {
		t.Fatalf(
			"PIN calls = retries %d, token %d; want none",
			authenticator.pinRetriesCalls,
			len(authenticator.pinRPIDs),
		)
	}
}

func TestTokenServicePINFlowSkipsUVInteractionAndCommand(t *testing.T) {
	var requests []model.InteractionRequest
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		authenticator,
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		VerificationFlowPIN,
	)

	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")

	if len(authenticator.uvRPIDs) != 0 {
		t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
	}

	if len(requests) != 1 || requests[0].Kind != model.InteractionKindPIN {
		t.Fatalf("interactions = %v, want one PIN interaction", interactionKinds(requests))
	}
}

func TestTokenServiceDelegatesPINValidationToAuthenticator(t *testing.T) {
	var requests []model.InteractionRequest
	validationErr := errors.New("pin rejected by ctap")
	authenticator := &recordingTokenDevice{
		info:    uvTokenInfo(),
		pinErrs: []error{validationErr},
	}
	tokens := NewTokenService(
		&testTokenCache{},
		authenticator,
		recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("123")}),
		VerificationFlowPIN,
	)

	token, err := tokens.acquire(context.Background(), protocol.PermissionCredentialManagement, "")
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !failure.IsCode(err, failure.CodeInternalError) || !errors.Is(err, validationErr) {
		t.Fatalf("Acquire error = %v, want delegated validation error", err)
	}

	if len(authenticator.pinRPIDs) != 1 {
		t.Fatalf("PIN token calls = %d, want 1", len(authenticator.pinRPIDs))
	}
}

func TestTokenServiceMissingHandlerForUVReturnsInvalidStateBeforeUVCommand(t *testing.T) {
	authenticator := &recordingTokenDevice{info: uvTokenInfo()}
	cache := &testTokenCache{}
	tokens := NewTokenService(
		cache,
		authenticator,
		NewInteractionBroker(noopEventSink{}, nil),
		VerificationFlowDefault,
	)

	token, err := tokens.acquire(
		context.Background(),
		protocol.PermissionCredentialManagement,
		"",
	)
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !failure.IsCode(err, failure.CodeInteractionHandlerRequired) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodeInteractionHandlerRequired)
	}

	if len(authenticator.uvRPIDs) != 0 {
		t.Fatalf("UV token calls = %d, want 0", len(authenticator.uvRPIDs))
	}
}

func recordingInteractionHandler(
	requests *[]model.InteractionRequest,
	response model.InteractionResponse,
) *InteractionBroker {
	return NewInteractionBroker(noopEventSink{}, interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		*requests = append(*requests, req)

		out := response
		if req.Kind != model.InteractionKindPIN {
			out.PIN = nil
		} else if len(out.PIN) != 0 {
			out.PIN = slices.Clone(out.PIN)
		}

		return out, nil
	}))
}

func recordingInteractionHandlerWithEvents(
	requests *[]model.InteractionRequest,
	authenticator *recordingTokenDevice,
	response model.InteractionResponse,
) *InteractionBroker {
	return NewInteractionBroker(noopEventSink{}, interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		*requests = append(*requests, req)
		authenticator.events = append(authenticator.events, "interaction:"+string(req.Kind))

		return response, nil
	}))
}

func acquireTokenForTest(
	t *testing.T,
	tokens *TokenService,
	permission protocol.Permission,
	rpID string,
) []byte {
	t.Helper()

	token, err := tokens.acquire(context.Background(), permission, rpID)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer secret.Zero(token)

	return slices.Clone(token)
}

func uvTokenInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		UvModality: new(protocol.UserVerifyFingerprintInternal),
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN:        true,
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
		},
	}
}

type testTokenCache struct {
	key    TokenKey
	secret *secret.Handle
}

func (c *testTokenCache) GetToken(key TokenKey) ([]byte, bool) {
	if c.secret == nil || !c.key.Covers(key) {
		return nil, false
	}

	token, err := c.secret.Bytes()
	if err != nil {
		return nil, false
	}

	return token, true
}

func (c *testTokenCache) SetToken(key TokenKey, token *secret.Handle) {
	if c.secret != nil {
		c.secret.Invalidate()
	}

	c.key = key
	c.secret = token
}

func (c *testTokenCache) InvalidateToken() {
	if c.secret != nil {
		c.secret.Invalidate()
	}

	c.key = TokenKey{}
	c.secret = nil
}

func (c *testTokenCache) InvalidateTokenUnlessPermission(permission protocol.Permission) {
	if c.secret == nil {
		return
	}

	if permission == protocol.PermissionPersistentCredentialManagementReadOnly &&
		c.key.Permission != permission {
		c.InvalidateToken()

		return
	}

	remaining := c.key.Permission & permission
	if remaining == protocol.PermissionNone {
		c.InvalidateToken()

		return
	}

	c.key.Permission = remaining
}

type recordingTokenDevice struct {
	info            protocol.AuthenticatorGetInfoResponse
	uvErr           error
	pinErrs         []error
	pinRetryCounts  []uint
	pinRetries      uint
	powerCycleState *bool
	pinRetriesErrs  []error
	pinRetriesCalls int
	events          []string
	pinRPIDs        []string
	uvRPIDs         []string
}

func (d *recordingTokenDevice) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return d.info, true
}

func (d *recordingTokenDevice) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	return d.info, nil
}

func (d *recordingTokenDevice) GetPinUvAuthTokenUsingPIN(
	_ context.Context,
	_ string,
	_ protocol.Permission,
	rpID string,
) ([]byte, error) {
	d.events = append(d.events, "command:pin")
	d.pinRPIDs = append(d.pinRPIDs, rpID)
	call := len(d.pinRPIDs) - 1
	if call < len(d.pinErrs) && d.pinErrs[call] != nil {
		return nil, d.pinErrs[call]
	}

	return []byte("pin-token-" + rpID), nil
}

func (d *recordingTokenDevice) GetPinUvAuthTokenUsingUV(_ context.Context, _ protocol.Permission, rpID string) ([]byte, error) {
	d.events = append(d.events, "command:uv")
	d.uvRPIDs = append(d.uvRPIDs, rpID)

	if d.uvErr != nil {
		return nil, d.uvErr
	}

	return []byte("uv-token-" + rpID), nil
}

func (d *recordingTokenDevice) GetPINRetries(context.Context) (uint, *bool, error) {
	d.events = append(d.events, "command:pin-retries")
	call := d.pinRetriesCalls
	d.pinRetriesCalls++
	retries := d.pinRetries
	if call < len(d.pinRetryCounts) {
		retries = d.pinRetryCounts[call]
	}

	var err error
	if call < len(d.pinRetriesErrs) {
		err = d.pinRetriesErrs[call]
	}

	return retries, d.powerCycleState, err
}

func interactionKinds(requests []model.InteractionRequest) []model.InteractionKind {
	kinds := make([]model.InteractionKind, len(requests))
	for i, request := range requests {
		kinds[i] = request.Kind
	}

	return kinds
}
