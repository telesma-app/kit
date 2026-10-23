package ctapkit

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/telesma-app/kit/model"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func TestTypedOperationDoesNotMarshalSecrets(t *testing.T) {
	req := appconfig.ChangePINOperation{
		CurrentPIN: "1234",
		NewPIN:     "5678",
	}

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if bytes.Contains(raw, []byte("1234")) || bytes.Contains(raw, []byte("5678")) ||
		bytes.Contains(raw, []byte("currentPIN")) || bytes.Contains(raw, []byte("newPIN")) {
		t.Fatalf("marshaled operation exposed PIN: %s", raw)
	}
}

func TestPINInteractionRejectsEmptyPINAtSessionRun(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}

	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		return model.InteractionResponse{}, nil
	})

	_, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	requireFailureCode(t, err, failure.CodePINRequired)

	if got := a.pinCalls.Load(); got != 0 {
		t.Fatalf("PIN token calls = %d, want 0", got)
	}
}

func TestPINInteractionWithoutHandlerReturnsInvalidState(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}

	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	_, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions()...)
	requireFailureCode(t, err, failure.CodeInteractionHandlerRequired)

	if !slices.Contains(eventStages(events.Events()), model.OperationStageInteractionRequired) {
		t.Fatal("interaction-required was not emitted before missing handler error")
	}

	if got := a.pinCalls.Load(); got != 0 {
		t.Fatalf("PIN token calls = %d, want 0", got)
	}
}

func TestLastInteractionHandlerOptionWins(t *testing.T) {
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}

	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	firstCalls := 0
	secondCalls := 0
	first := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		firstCalls++

		return model.InteractionResponse{Canceled: true}, nil
	})
	second := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		secondCalls++

		return model.InteractionResponse{PIN: []byte("1234")}, nil
	})

	_, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(
		WithInteractionHandler(first),
		WithInteractionHandler(second),
	)...)
	if err != nil {
		t.Fatalf("WriteLargeBlob: %v", err)
	}

	if firstCalls != 0 || secondCalls != 1 {
		t.Fatalf("handler calls = (%d, %d), want (0, 1)", firstCalls, secondCalls)
	}
}

func TestCanceledContextDuringInteractionReturnsCanceledFailure(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}

	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	handler := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		cancel()

		return model.InteractionResponse{}, context.Canceled
	})

	_, err := session.WriteLargeBlob(ctx, applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	requireFailureCode(t, err, failure.CodeOperationCanceled)

	if got := a.pinCalls.Load(); got != 0 {
		t.Fatalf("PIN token calls = %d, want 0", got)
	}
}

func TestSetPINExecutesWithoutConfirmationInteraction(t *testing.T) {
	a := &pinMutationCountingAuthenticator{}

	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	_, err := session.SetPIN(context.Background(), appconfig.SetPINOperation{
		NewPIN: "1234",
	}, session.operationOptions()...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := a.setCalls.Load(); got != 1 {
		t.Fatalf("SetPIN calls = %d, want 1", got)
	}
}

func TestResetTouchInteractionCanceledReturnsCanceledFailure(t *testing.T) {
	events := &recordingEventSink{}
	a := &resetCountingAuthenticator{}

	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindTouch {
			t.Fatalf("interaction kind = %s, want touch", req.Kind)
		}

		if !req.Destructive {
			t.Fatal("reset touch interaction destructive = false, want true")
		}

		return model.InteractionResponse{Canceled: true}, nil
	})

	_, err := session.ResetFactory(
		context.Background(),
		appconfig.ResetFactoryOperation{},
		session.operationOptions(WithInteractionHandler(handler))...,
	)
	requireFailureCode(t, err, failure.CodeInteractionCanceled)

	if got := a.resetCount.Load(); got != 0 {
		t.Fatalf("Reset count = %d, want 0", got)
	}
}

func TestPINInteractionHandlerReceivesRequestAndValidPINContinues(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}

	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	var (
		requests     []model.InteractionRequest
		returnedPINs [][]byte
	)

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		requests = append(requests, req)
		pin := []byte("1234")
		returnedPINs = append(returnedPINs, pin)

		return model.InteractionResponse{
			PIN: pin,
		}, nil
	})

	result, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Result == nil {
		t.Fatal("result.Result = nil, want large blob mutation result")
	}

	if len(requests) != 1 {
		t.Fatalf("PIN requests = %d, want 1", len(requests))
	}

	for _, pin := range returnedPINs {
		if !bytes.Equal(pin, []byte{0, 0, 0, 0}) {
			t.Fatalf("handler-owned PIN was not wiped: %#v", pin)
		}
	}

	for _, req := range requests {
		if req.Kind != model.InteractionKindPIN {
			t.Fatalf("unexpected PIN request: %#v", req)
		}
	}

	if got := a.pinCalls.Load(); got != 1 {
		t.Fatalf("PIN token calls = %d, want 1", got)
	}
}
