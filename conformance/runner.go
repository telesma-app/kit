package conformance

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/options"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

const cleanupTimeout = 30 * time.Second

// Runner executes suites sequentially against one caller-owned CTAP
// connection. Concurrent Run calls are serialized, and Runner does not close
// the connection.
type Runner struct {
	cbor   ctaptransport.CBOR
	client *client.Client
	runMu  sync.Mutex
}

// NewRunner binds both the raw CBOR and typed CTAP client views of device.
// Client options are applied before the runner-owned transport binding.
func NewRunner(device ctaptransport.CBOR, clientOptions ...options.Option) (*Runner, error) {
	ctapClient, err := client.NewClient(slices.Concat(
		clientOptions,
		[]options.Option{options.WithTransport(device)},
	)...)
	if err != nil {
		return nil, err
	}

	return &Runner{
		cbor:   device,
		client: ctapClient,
	}, nil
}

// TestContext provides one test with raw and typed access to the same
// authenticator connection and records its step results.
type TestContext struct {
	ctx     context.Context
	cbor    ctaptransport.CBOR
	client  *client.Client
	steps   []StepResult
	cleanup []Step
}

// CBOR returns the raw transport-independent CTAP command boundary. Tests use
// it for malformed requests and wire-level assertions.
func (t *TestContext) CBOR() ctaptransport.CBOR {
	return t.cbor
}

// Client returns the typed low-level CTAP client bound to the same connection.
func (t *TestContext) Client() *client.Client {
	return t.client
}

// Step executes and records one test step. It returns true only when the step
// passed, allowing dependent steps to stop with an ordinary return.
func (t *TestContext) Step(step Step) bool {
	return t.runStep(t.ctx, step)
}

// Cleanup registers a visible cleanup step to run in last-in, first-out order
// after the test body. Cleanup callbacks receive a bounded context which
// retains the run context's values but outlives its cancellation, allowing
// release commands while Run still reports the original cancellation.
func (t *TestContext) Cleanup(step Step) {
	t.cleanup = append(t.cleanup, step)
}

func (t *TestContext) runStep(ctx context.Context, step Step) bool {
	result := StepResult{
		ID:         step.ID,
		Name:       step.Name,
		References: step.References,
	}

	err := ctx.Err()
	if err == nil {
		err = step.Run(ctx)
	}

	result.Status = classifyStepError(err)
	if err != nil {
		result.Message = err.Error()
	}
	t.steps = append(t.steps, result)

	return result.Status == StatusPassed
}

func (t *TestContext) runCleanup() {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.ctx), cleanupTimeout)
	defer cancel()

	for index := len(t.cleanup) - 1; index >= 0; index-- {
		t.runStep(ctx, t.cleanup[index])
	}
}

// Run executes every test in declaration order. Test and step errors are
// represented in SuiteResult; a non-nil returned error means the run context
// was canceled or reached its deadline.
func (r *Runner) Run(ctx context.Context, suite Suite) (SuiteResult, error) {
	r.runMu.Lock()
	defer r.runMu.Unlock()

	result := SuiteResult{
		ID:          suite.ID,
		Name:        suite.Name,
		Description: suite.Description,
		Source:      suite.Source,
		Tests:       make([]TestResult, 0, len(suite.Tests)),
	}

	for _, test := range suite.Tests {
		if err := ctx.Err(); err != nil {
			return canceledSuiteResult(result, err)
		}

		testContext := TestContext{
			ctx:     ctx,
			cbor:    r.cbor,
			client:  r.client,
			steps:   make([]StepResult, 0),
			cleanup: make([]Step, 0),
		}
		test.Run(&testContext)
		testContext.runCleanup()

		result.Tests = append(result.Tests, TestResult{
			ID:          test.ID,
			Name:        test.Name,
			Description: test.Description,
			Source:      test.Source,
			References:  test.References,
			Destructive: test.Destructive,
			Status:      aggregateStepResults(testContext.steps),
			Steps:       testContext.steps,
		})

		if err := ctx.Err(); err != nil {
			return canceledSuiteResult(result, err)
		}
	}

	result.Status = aggregateTestResults(result.Tests)

	return result, nil
}

func classifyStepError(err error) Status {
	if err == nil {
		return StatusPassed
	}

	var assertion *AssertionError
	if errors.As(err, &assertion) {
		return StatusFailed
	}

	var skip *SkipError
	if errors.As(err, &skip) {
		return StatusSkipped
	}

	return StatusError
}

func aggregateStepResults(results []StepResult) Status {
	passed := false
	skipped := false
	failed := false
	for _, result := range results {
		switch result.Status {
		case StatusError:
			return StatusError
		case StatusFailed:
			failed = true
		case StatusSkipped:
			skipped = true
		case StatusPassed:
			passed = true
		}
	}
	if failed {
		return StatusFailed
	}
	if skipped {
		return StatusSkipped
	}
	if passed {
		return StatusPassed
	}

	return StatusSkipped
}

func aggregateTestResults(results []TestResult) Status {
	status := StatusSkipped
	for _, result := range results {
		status = higherStatus(status, result.Status)
	}

	return status
}

func higherStatus(current, candidate Status) Status {
	if statusRank(candidate) > statusRank(current) {
		return candidate
	}

	return current
}

func statusRank(status Status) int {
	switch status {
	case StatusError:
		return 4
	case StatusFailed:
		return 3
	case StatusPassed:
		return 2
	case StatusSkipped:
		return 1
	default:
		return 0
	}
}

func canceledSuiteResult(result SuiteResult, err error) (SuiteResult, error) {
	result.Status = StatusError
	result.Error = err.Error()

	return result, err
}
