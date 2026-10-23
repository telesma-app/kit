package runtime

import (
	"context"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
)

func TestTokenServicePINInvalidRequestsAnotherPINWithRetryState(t *testing.T) {
	var (
		requests     []model.InteractionRequest
		returnedPINs [][]byte
	)

	powerCycleState := false
	authenticator := &recordingTokenDevice{
		info: uvTokenInfo(),
		pinErrs: []error{&ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorClientPIN,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
		}},
		pinRetryCounts:  []uint{7, 6},
		pinRetries:      6,
		powerCycleState: &powerCycleState,
	}
	interactions := &InteractionBroker{
		Events: EventDispatcher{},
		Handler: interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
			requests = append(requests, req)
			pin := []byte("1234")
			returnedPINs = append(returnedPINs, pin)

			return model.InteractionResponse{PIN: pin}, nil
		}),
	}
	tokens := &TokenService{
		Cache:            &testTokenCache{},
		Authenticator:    authenticator,
		Interactions:     interactions,
		VerificationFlow: VerificationFlowPIN,
	}

	acquireTokenForTest(t, tokens, protocol.PermissionCredentialManagement, "")

	if len(requests) != 2 {
		t.Fatalf("interactions = %d, want 2", len(requests))
	}

	initial := requests[0].PINState
	if initial == nil {
		t.Fatal("initial PIN interaction state = nil")
	}

	if initial.PreviousAttemptInvalid {
		t.Fatal("initial PIN interaction marks a previous attempt invalid")
	}

	if initial.RetriesRemaining == nil || *initial.RetriesRemaining != 7 {
		t.Fatalf("initial retries remaining = %#v, want 7", initial.RetriesRemaining)
	}

	if initial.PowerCycleState == nil || *initial.PowerCycleState {
		t.Fatalf("initial power cycle state = %#v, want false", initial.PowerCycleState)
	}

	retry := requests[1].PINState
	if retry == nil {
		t.Fatal("retry PIN interaction state = nil")
	}

	if !retry.PreviousAttemptInvalid {
		t.Fatal("retry PIN interaction does not mark the previous attempt invalid")
	}

	if retry.RetriesRemaining == nil || *retry.RetriesRemaining != 6 {
		t.Fatalf("retries remaining = %#v, want 6", retry.RetriesRemaining)
	}

	if retry.PowerCycleState == nil || *retry.PowerCycleState {
		t.Fatalf("power cycle state = %#v, want false", retry.PowerCycleState)
	}

	if authenticator.pinRetriesCalls != 2 {
		t.Fatalf("GetPINRetries calls = %d, want 2", authenticator.pinRetriesCalls)
	}

	if len(authenticator.pinRPIDs) != 2 {
		t.Fatalf("PIN token calls = %d, want 2", len(authenticator.pinRPIDs))
	}

	for _, pin := range returnedPINs {
		if !slices.Equal(pin, []byte{0, 0, 0, 0}) {
			t.Fatalf("handler-owned PIN was not wiped: %#v", pin)
		}
	}
}

func TestTokenServicePINBlockedDoesNotRequestAnotherPIN(t *testing.T) {
	var requests []model.InteractionRequest

	authenticator := &recordingTokenDevice{
		info: uvTokenInfo(),
		pinErrs: []error{&ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorClientPIN,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_BLOCKED,
		}},
	}
	tokens := &TokenService{
		Cache:            &testTokenCache{},
		Authenticator:    authenticator,
		Interactions:     recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		VerificationFlow: VerificationFlowPIN,
	}

	token, err := tokens.acquire(context.Background(), protocol.PermissionCredentialManagement, "")
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !failure.IsCode(err, failure.CodePINBlocked) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodePINBlocked)
	}

	if len(requests) != 1 {
		t.Fatalf("interactions = %d, want 1", len(requests))
	}

	if authenticator.pinRetriesCalls != 1 {
		t.Fatalf("GetPINRetries calls = %d, want 1", authenticator.pinRetriesCalls)
	}
}

func TestTokenServicePINRetriesFailureStopsRetryFlow(t *testing.T) {
	var requests []model.InteractionRequest

	authenticator := &recordingTokenDevice{
		info: uvTokenInfo(),
		pinErrs: []error{&ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorClientPIN,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
		}},
		pinRetryCounts: []uint{7},
		pinRetriesErrs: []error{
			nil,
			&ctaptransport.CTAPError{
				Command:    protocol.AuthenticatorClientPIN,
				StatusCode: ctaptransport.CTAP1_ERR_TIMEOUT,
			},
		},
	}
	tokens := &TokenService{
		Cache:            &testTokenCache{},
		Authenticator:    authenticator,
		Interactions:     recordingInteractionHandler(&requests, model.InteractionResponse{PIN: []byte("1234")}),
		VerificationFlow: VerificationFlowPIN,
	}

	token, err := tokens.acquire(context.Background(), protocol.PermissionCredentialManagement, "")
	if token != nil {
		secret.Zero(token)
		t.Fatalf("token = %q, want nil", token)
	}

	if !failure.IsCode(err, failure.CodeAuthenticatorTimeout) {
		t.Fatalf("Acquire error = %v, want %s", err, failure.CodeAuthenticatorTimeout)
	}

	snapshot := failure.Snapshot(err)
	if snapshot.Phase != failure.PhaseTokenAcquisition {
		t.Fatalf("failure phase = %s, want %s", snapshot.Phase, failure.PhaseTokenAcquisition)
	}

	if snapshot.CTAP == nil || snapshot.CTAP.SubCommand != "getPINRetries" {
		t.Fatalf("CTAP detail = %#v, want getPINRetries provenance", snapshot.CTAP)
	}

	if len(requests) != 1 {
		t.Fatalf("interactions = %d, want 1", len(requests))
	}

	if authenticator.pinRetriesCalls != 2 {
		t.Fatalf("GetPINRetries calls = %d, want 2", authenticator.pinRetriesCalls)
	}
}
