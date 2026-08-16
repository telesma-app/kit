package runtime

import (
	"context"

	"github.com/telesma-app/kit/model"
)

type EventDispatcher struct {
	sink EventSink
}

type EventSink interface {
	Emit(context.Context, model.OperationEvent)
}

type noopEventSink struct{}

func (noopEventSink) Emit(context.Context, model.OperationEvent) {}

func NewEventDispatcher(sink EventSink) *EventDispatcher {
	if sink == nil {
		sink = noopEventSink{}
	}

	return &EventDispatcher{sink: sink}
}

func (d *EventDispatcher) Emit(ctx context.Context, event model.OperationEvent) {
	d.sink.Emit(ctx, event)
}
