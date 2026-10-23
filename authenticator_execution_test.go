package ctapkit

import (
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/kit/internal/workflow"
	appoperation "github.com/telesma-app/kit/model/operation"
)

func TestExecuteOperationEnforcesZeroResultOnWorkflowFailure(t *testing.T) {
	session := openContractAuthenticator(t, nil, nil)
	defer func() { _ = session.Close() }()

	type result struct {
		Value string
	}

	cause := errors.New("workflow failed after producing a result")

	got, err := executeOperation(
		session.Authenticator,
		context.Background(),
		appoperation.ConfigStatus,
		func(workflow.Runner, context.Context) (result, error) {
			return result{Value: "partial"}, cause
		},
	)
	if !errors.Is(err, cause) {
		t.Fatalf("executeOperation error = %v, want %v", err, cause)
	}

	requireZero(t, got)
}
