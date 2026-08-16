package runtime

import (
	"context"

	"github.com/telesma-app/kit/internal/errornorm"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
)

type InteractionBroker struct {
	events  EventSink
	handler InteractionHandler
}

type InteractionHandler interface {
	// RequestInteraction returns a zero response on error. On success, ownership
	// of response.PIN transfers to the runtime.
	RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
}

func NewInteractionBroker(events EventSink, handler InteractionHandler) *InteractionBroker {
	return &InteractionBroker{
		events:  events,
		handler: handler,
	}
}

func (b *InteractionBroker) RequestInteraction(
	ctx context.Context,
	req model.InteractionRequest,
) (model.InteractionResponse, error) {
	b.events.Emit(ctx, model.OperationEvent{
		Stage:   model.OperationStageInteractionRequired,
		Kind:    req.Kind,
		Message: req.Message,
	})

	if b.handler == nil {
		return model.InteractionResponse{}, failure.New(failure.CodeInteractionHandlerRequired,
			failure.WithPhase(failure.PhaseInteraction),
		)
	}

	response, err := b.handler.RequestInteraction(ctx, req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}

		return model.InteractionResponse{}, annotateInteractionError(err)
	}

	if err := validateInteractionResponse(req, response); err != nil {
		secret.Zero(response.PIN)

		return model.InteractionResponse{}, err
	}

	if err := ctx.Err(); err != nil {
		secret.Zero(response.PIN)

		return model.InteractionResponse{}, annotateInteractionError(err)
	}

	return response, nil
}

func validateInteractionResponse(req model.InteractionRequest, response model.InteractionResponse) error {
	if response.Canceled {
		return failure.New(failure.CodeInteractionCanceled,
			failure.WithPhase(failure.PhaseInteraction),
		)
	}

	if req.Kind == model.InteractionKindPIN && len(response.PIN) == 0 {
		return failure.New(failure.CodePINRequired,
			failure.WithPhase(failure.PhaseInteraction),
			failure.WithParams(map[string]string{"field": "pin"}),
		)
	}

	return nil
}

func annotateInteractionError(err error) error {
	return errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseInteraction))
}
