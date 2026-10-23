package ctapkit

import (
	"context"

	"github.com/telesma-app/kit/internal/workflow"
	"github.com/telesma-app/kit/model/inspect"
	appoperation "github.com/telesma-app/kit/model/operation"
)

func (a *Authenticator) GetInfo(ctx context.Context, opts ...OperationOption) (inspect.Info, error) {
	return executeOperation(a, ctx, appoperation.GetInfo, func(runner workflow.Runner, ctx context.Context) (inspect.Info, error) {
		return runner.GetInfo(ctx, a.opened.Info)
	}, opts...)
}
