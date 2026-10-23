package ctapkit

import (
	"context"

	"github.com/telesma-app/kit/internal/workflow"
	appoperation "github.com/telesma-app/kit/model/operation"
	"github.com/telesma-app/kit/model/webauthn"
)

func (a *Authenticator) MakeCredential(
	ctx context.Context,
	operation webauthn.MakeCredentialOperation,
	opts ...OperationOption,
) (webauthn.MakeCredentialOutput, error) {
	return executeOperation(a, ctx, appoperation.MakeCredential, func(runner workflow.Runner, ctx context.Context) (webauthn.MakeCredentialOutput, error) {
		return runner.MakeCredential(ctx, a.opened.WebAuthn, operation)
	}, opts...)
}

func (a *Authenticator) GetAssertion(
	ctx context.Context,
	operation webauthn.GetAssertionOperation,
	opts ...OperationOption,
) (webauthn.GetAssertionOutput, error) {
	return executeOperation(a, ctx, appoperation.GetAssertion, func(runner workflow.Runner, ctx context.Context) (webauthn.GetAssertionOutput, error) {
		return runner.GetAssertion(ctx, a.opened.WebAuthn, operation)
	}, opts...)
}
