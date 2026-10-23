package ctapkit

import (
	"context"
	"errors"

	ctaptransport "github.com/telesma-app/ctap/transport"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/logging"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/internal/workflow"
	"github.com/telesma-app/kit/model"
	appoperation "github.com/telesma-app/kit/model/operation"
)

type workflowCall[T any] func(workflow.Runner, context.Context) (T, error)

func executeOperation[T any](
	a *Authenticator,
	ctx context.Context,
	kind appoperation.Kind,
	call workflowCall[T],
	opts ...OperationOption,
) (T, error) {
	config, err := newOperationConfig(opts...)
	if err != nil {
		var zero T

		return zero, normalizeRunError(err, string(kind))
	}

	result, err := executeSerializedOperation(a, ctx, kind, func(ctx context.Context) (T, error) {
		events := rtruntime.EventDispatcher{Sink: config.events}

		var interactions workflow.InteractionRequester = &rtruntime.InteractionBroker{
			Events:  events,
			Handler: config.handler,
		}
		if a.opened.Card != nil {
			interactions = smartCardInteractions{card: a.opened.Card, next: interactions}
		}

		effects := &rtruntime.StateEffects{}

		result, err := call(workflow.Runner{
			Selected:     a.Endpoint(),
			Events:       events,
			Interactions: interactions,
			Tokens: &rtruntime.TokenService{
				Cache:            &a.tokens,
				Authenticator:    a.opened.Tokens,
				Interactions:     interactions,
				VerificationFlow: rtruntime.VerificationFlow(config.verificationFlow),
			},
			Effects: effects,
		}, ctx)
		if effects.InvalidatesLargeBlobSnapshot() {
			a.largeBlobState.Clear()
		}

		return result, err
	})
	if err != nil {
		if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalidated {
			_ = a.Close()
		}

		var zero T

		return zero, normalizeRunError(err, string(kind))
	}

	return result, nil
}

// executeSerializedOperation preserves partial results for source reads.
// executeOperation discards them when a public workflow fails.
func executeSerializedOperation[T any](
	a *Authenticator,
	ctx context.Context,
	kind appoperation.Kind,
	call func(context.Context) (T, error),
) (T, error) {
	// Close also takes the gate, so invalidation cleanup runs after this returns.
	select {
	case a.runGate <- struct{}{}:
		defer func() { <-a.runGate }()
	case <-ctx.Done():
		var zero T

		return zero, ctx.Err()
	}

	if err := ctx.Err(); err != nil {
		var zero T

		return zero, err
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	childCtx = logging.WithOperation(childCtx, kind)

	if err := a.start(cancel); err != nil {
		var zero T

		return zero, err
	}
	defer a.finish()

	result, err := call(childCtx)
	if a.opened.Card != nil {
		err = errors.Join(err, a.opened.Card.EndFIDO(childCtx))
	}

	return result, err
}

type smartCardInteractions struct {
	card *rtauthenticator.SmartCard
	next workflow.InteractionRequester
}

func (i smartCardInteractions) RequestInteraction(ctx context.Context, request model.InteractionRequest) (model.InteractionResponse, error) {
	if err := i.card.EndFIDO(ctx); err != nil {
		return model.InteractionResponse{}, err
	}

	return i.next.RequestInteraction(ctx, request)
}
