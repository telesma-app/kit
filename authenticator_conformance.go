package ctapkit

import (
	"context"

	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/ctap23"
	"github.com/telesma-app/kit/internal/workflow"
	"github.com/telesma-app/kit/model/failure"
	appoperation "github.com/telesma-app/kit/model/operation"
)

// RunCTAP23Conformance executes the selected CTAP 2.3 conformance tests on
// this opened authenticator. The safe zero-value mode excludes every
// destructive case. Full mode may configure a temporary PIN and may
// factory-reset the authenticator more than once.
func (a *Authenticator) RunCTAP23Conformance(
	ctx context.Context,
	request ctap23.RunRequest,
	opts ...OperationOption,
) (conformance.SuiteResult, error) {
	if !request.Mode.Valid() {
		return conformance.SuiteResult{}, failure.New(
			failure.CodeConformanceModeInvalid,
			failure.WithOperation(string(appoperation.ConformanceCTAP23)),
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	return executeOperation(
		a,
		ctx,
		appoperation.ConformanceCTAP23,
		func(runner workflow.Runner, ctx context.Context) (conformance.SuiteResult, error) {
			return runner.RunCTAP23Conformance(ctx, workflow.ConformanceEnvironment{
				CBOR:       a.cbor,
				Current:    a.currentConformanceCapabilities,
				PowerCycle: a.conformancePowerCycler(),
			}, request)
		},
		opts...,
	)
}
