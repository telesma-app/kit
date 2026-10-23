package runtime

import (
	"context"

	"github.com/telesma-app/kit/model"
)

type EventDispatcher struct {
	Sink EventSink
}

type EventSink interface {
	Emit(context.Context, model.OperationEvent)
}

func (d EventDispatcher) Emit(ctx context.Context, event model.OperationEvent) {
	if d.Sink != nil {
		d.Sink.Emit(ctx, event)
	}
}
