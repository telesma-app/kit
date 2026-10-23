package workflow

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/report"
)

type Runner struct {
	Selected     report.EndpointReport
	Events       EventEmitter
	Interactions InteractionRequester
	Tokens       TokenService
	Effects      *rtruntime.StateEffects
}

type EventEmitter interface {
	Emit(context.Context, model.OperationEvent)
}

type InteractionRequester interface {
	RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
}

type TokenService interface {
	Use(
		context.Context,
		rtruntime.TokenUse,
		func([]byte) error,
	) error
	Invalidate()
	InvalidateUnlessPermission(protocol.Permission)
}
