package ctapkit

import (
	"context"
	"sync"
	"testing"

	"github.com/telesma-app/kit/model"
)

type interactionHandlerFunc func(model.InteractionRequest) (model.InteractionResponse, error)

func (f interactionHandlerFunc) RequestInteraction(_ context.Context, req model.InteractionRequest) (model.InteractionResponse, error) {
	return f(req)
}

func userVerificationHandler(t *testing.T) InteractionHandler {
	t.Helper()

	return interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindUserVerification {
			t.Fatalf("interaction kind = %s, want user-verification", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})
}

type recordingEventSink struct {
	mu     sync.Mutex
	events []model.OperationEvent
}

func (s *recordingEventSink) Emit(_ context.Context, event model.OperationEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, event)
}

func (s *recordingEventSink) Events() []model.OperationEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.events
}

func eventStages(events []model.OperationEvent) []model.OperationStage {
	stages := make([]model.OperationStage, len(events))
	for i, event := range events {
		stages[i] = event.Stage
	}

	return stages
}
