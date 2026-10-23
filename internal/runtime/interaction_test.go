package runtime

import (
	"context"
	"testing"

	"github.com/telesma-app/kit/model"
)

type interactionHandlerFunc func(model.InteractionRequest) (model.InteractionResponse, error)

func (f interactionHandlerFunc) RequestInteraction(_ context.Context, req model.InteractionRequest) (model.InteractionResponse, error) {
	return f(req)
}

type contextualInteractionHandlerFunc func(context.Context, model.InteractionRequest) (model.InteractionResponse, error)

func (f contextualInteractionHandlerFunc) RequestInteraction(
	ctx context.Context,
	req model.InteractionRequest,
) (model.InteractionResponse, error) {
	return f(ctx, req)
}

func TestRequestInteractionPassesPromptAndContext(t *testing.T) {
	events := &recordingEventSink{}

	var got model.InteractionRequest

	ctx := context.WithValue(context.Background(), interactionContextKey{}, "operation-1")

	broker := &InteractionBroker{
		Events: events,
		Handler: contextualInteractionHandlerFunc(func(handlerCtx context.Context, req model.InteractionRequest) (model.InteractionResponse, error) {
			if handlerCtx.Value(interactionContextKey{}) != "operation-1" {
				t.Fatalf("handler context did not preserve operation value")
			}

			got = req

			return model.InteractionResponse{}, nil
		}),
	}

	req := model.InteractionRequest{
		Kind:    model.InteractionKindTouch,
		Message: "touch",
	}

	_, err := broker.RequestInteraction(ctx, req)
	if err != nil {
		t.Fatalf("RequestInteraction: %v", err)
	}

	if got != req {
		t.Fatalf("handler request = %#v, want %#v", got, req)
	}

	if len(events.events) != 1 {
		t.Fatalf("events = %d, want 1", len(events.events))
	}

	if events.contexts[0].Value(interactionContextKey{}) != "operation-1" {
		t.Fatal("event context did not preserve operation value")
	}

	event := events.events[0]
	if event.Kind != req.Kind || event.Message != req.Message {
		t.Fatalf("interaction event = %#v, want kind/message from request", event)
	}
}

type recordingEventSink struct {
	contexts []context.Context
	events   []model.OperationEvent
}

func (s *recordingEventSink) Emit(ctx context.Context, event model.OperationEvent) {
	s.contexts = append(s.contexts, ctx)
	s.events = append(s.events, event)
}

type interactionContextKey struct{}
