package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

type cborFunc func(context.Context, []byte) (ctaptransport.CBORResponse, error)

func (f cborFunc) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	return f(ctx, data)
}

func TestRunnerExposesTypedAndRawCTAPToSteps(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	responseData, err := encMode.Marshal(protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
	})
	if err != nil {
		t.Fatal(err)
	}

	var requests [][]byte
	device := cborFunc(func(_ context.Context, data []byte) (ctaptransport.CBORResponse, error) {
		requests = append(requests, bytes.Clone(data))

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       responseData,
		}, nil
	})
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}

	reference := conformance.RequirementRef{
		ID:            "ctap-2.3:6.4:get-info",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.4",
		Clause:        "get-info",
	}
	suite := conformance.Suite{
		ID:   "ctap2.3",
		Name: "CTAP 2.3",
		Source: conformance.Source{
			Artifact: "fido-conformance-tools",
			Version:  "1.9.1",
			Digest:   "sha256:fixture",
		},
		Tests: []conformance.Test{
			{
				ID:   "authr-generic-1.p-1",
				Name: "GetInfo response",
				Source: conformance.SourceLocation{
					Path: "tests/CTAP2/Protocol/Authr-Generic-1.js",
					Case: "P-1",
				},
				References: []conformance.RequirementRef{reference},
				Run: func(test *conformance.TestContext) {
					var info protocol.AuthenticatorGetInfoResponse
					if !test.Step(conformance.Step{
						ID:         "get-info.typed",
						Name:       "Send typed GetInfo",
						References: []conformance.RequirementRef{reference},
						Run: func(ctx context.Context) error {
							var commandErr error
							info, commandErr = test.Client().GetInfo(ctx)

							return commandErr
						},
					}) {
						return
					}

					if !test.Step(conformance.Step{
						ID:   "get-info.version",
						Name: "Check advertised version",
						Run: func(context.Context) error {
							if len(info.Versions) != 1 || info.Versions[0] != protocol.FIDO_2_3 {
								return conformance.Failf("versions = %v, want [FIDO_2_3]", info.Versions)
							}

							return nil
						},
					}) {
						return
					}

					test.Step(conformance.Step{
						ID:   "get-info.raw",
						Name: "Send raw GetInfo",
						Run: func(ctx context.Context) error {
							_, rawErr := test.CBOR().CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})

							return rawErr
						},
					})
				},
			},
		},
	}

	result, err := runner.Run(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusPassed {
		t.Fatalf("suite status = %q, want passed", result.Status)
	}
	if result.Source != suite.Source {
		t.Fatalf("source = %#v, want %#v", result.Source, suite.Source)
	}
	if len(result.Tests) != 1 || result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("tests = %#v, want one passed test", result.Tests)
	}
	if result.Tests[0].Source != suite.Tests[0].Source {
		t.Fatalf("test source = %#v, want %#v", result.Tests[0].Source, suite.Tests[0].Source)
	}
	if len(result.Tests[0].References) != 1 || result.Tests[0].References[0].ID != reference.ID {
		t.Fatalf("test references = %#v, want %q", result.Tests[0].References, reference.ID)
	}
	if len(result.Tests[0].Steps) != 3 {
		t.Fatalf("steps = %#v, want three results", result.Tests[0].Steps)
	}
	for _, step := range result.Tests[0].Steps {
		if step.Status != conformance.StatusPassed {
			t.Fatalf("step %q status = %q, want passed", step.ID, step.Status)
		}
	}

	wantRequest := []byte{byte(protocol.AuthenticatorGetInfo)}
	if len(requests) != 2 || !bytes.Equal(requests[0], wantRequest) || !bytes.Equal(requests[1], wantRequest) {
		t.Fatalf("requests = %x, want two GetInfo commands", requests)
	}
}

func TestRunnerClassifiesStepOutcomesAndAggregatesStatus(t *testing.T) {
	runner, err := conformance.NewRunner(cborFunc(func(context.Context, []byte) (ctaptransport.CBORResponse, error) {
		return ctaptransport.CBORResponse{}, errors.New("unexpected command")
	}))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		id      conformance.TestID
		stepErr error
		want    conformance.Status
	}{
		{id: "passed", want: conformance.StatusPassed},
		{id: "failed", stepErr: fmt.Errorf("assertion: %w", conformance.Fail("versions missing")), want: conformance.StatusFailed},
		{id: "skipped", stepErr: fmt.Errorf("not applicable: %w", conformance.Skip("uv unsupported")), want: conformance.StatusSkipped},
		{id: "error", stepErr: errors.New("transport disconnected"), want: conformance.StatusError},
	}
	suite := conformance.Suite{
		ID:    "outcomes",
		Name:  "Outcomes",
		Tests: make([]conformance.Test, 0, len(tests)),
	}
	for _, fixture := range tests {
		fixture := fixture
		suite.Tests = append(suite.Tests, conformance.Test{
			ID:         fixture.id,
			Name:       string(fixture.id),
			References: []conformance.RequirementRef{},
			Run: func(test *conformance.TestContext) {
				test.Step(conformance.Step{
					ID:         "execute",
					Name:       "Execute",
					References: []conformance.RequirementRef{},
					Run: func(context.Context) error {
						return fixture.stepErr
					},
				})
			},
		})
	}

	result, err := runner.Run(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusError {
		t.Fatalf("suite status = %q, want error", result.Status)
	}
	if len(result.Tests) != len(tests) {
		t.Fatalf("test results = %d, want %d", len(result.Tests), len(tests))
	}
	for index, fixture := range tests {
		testResult := result.Tests[index]
		if testResult.Status != fixture.want {
			t.Errorf("test %q status = %q, want %q", fixture.id, testResult.Status, fixture.want)
		}
		if testResult.Steps[0].Status != fixture.want {
			t.Errorf("test %q step status = %q, want %q", fixture.id, testResult.Steps[0].Status, fixture.want)
		}
	}
	if result.Tests[1].Steps[0].Message != "assertion: versions missing" {
		t.Fatalf("failure message = %q", result.Tests[1].Steps[0].Message)
	}
	if result.Tests[2].Steps[0].Message != "not applicable: uv unsupported" {
		t.Fatalf("skip message = %q", result.Tests[2].Steps[0].Message)
	}
}

func TestRunnerRunsCleanupStepsAfterFailureInLIFOOrder(t *testing.T) {
	runner, err := conformance.NewRunner(cborFunc(func(context.Context, []byte) (ctaptransport.CBORResponse, error) {
		return ctaptransport.CBORResponse{}, errors.New("unexpected command")
	}))
	if err != nil {
		t.Fatal(err)
	}

	var order []string
	suite := conformance.Suite{
		ID:   "cleanup",
		Name: "Cleanup",
		Tests: []conformance.Test{{
			ID:   "test",
			Name: "Test",
			Run: func(test *conformance.TestContext) {
				test.Cleanup(conformance.Step{
					ID:   "cleanup.first",
					Name: "First cleanup",
					Run: func(context.Context) error {
						order = append(order, "first")

						return nil
					},
				})
				test.Cleanup(conformance.Step{
					ID:   "cleanup.second",
					Name: "Second cleanup",
					Run: func(context.Context) error {
						order = append(order, "second")

						return nil
					},
				})
				test.Step(conformance.Step{
					ID:   "execute",
					Name: "Execute",
					Run: func(context.Context) error {
						order = append(order, "execute")

						return conformance.Fail("fixture failure")
					},
				})
			},
		}},
	}

	result, err := runner.Run(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(order) != "[execute second first]" {
		t.Fatalf("order = %v", order)
	}
	if result.Status != conformance.StatusFailed || result.Tests[0].Status != conformance.StatusFailed {
		t.Fatalf("result = %#v, want failed", result)
	}
	wantSteps := []conformance.StepID{"execute", "cleanup.second", "cleanup.first"}
	for index, step := range result.Tests[0].Steps {
		if step.ID != wantSteps[index] {
			t.Fatalf("step %d = %q, want %q", index, step.ID, wantSteps[index])
		}
	}
}

func TestRunnerCleanupErrorPromotesTestAndSuiteStatus(t *testing.T) {
	runner, err := conformance.NewRunner(cborFunc(func(context.Context, []byte) (ctaptransport.CBORResponse, error) {
		return ctaptransport.CBORResponse{}, errors.New("unexpected command")
	}))
	if err != nil {
		t.Fatal(err)
	}

	suite := conformance.Suite{
		ID:   "cleanup-error",
		Name: "Cleanup error",
		Tests: []conformance.Test{{
			ID:   "test",
			Name: "Test",
			Run: func(test *conformance.TestContext) {
				test.Cleanup(conformance.Step{
					ID:   "cleanup",
					Name: "Cleanup",
					Run: func(context.Context) error {
						return errors.New("device remained configured")
					},
				})
				test.Step(conformance.Step{
					ID:   "execute",
					Name: "Execute",
					Run: func(context.Context) error {
						return nil
					},
				})
			},
		}},
	}

	result, err := runner.Run(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
		t.Fatalf("result = %#v, want cleanup error", result)
	}
	cleanup := result.Tests[0].Steps[1]
	if cleanup.Status != conformance.StatusError || cleanup.Message != "device remained configured" {
		t.Fatalf("cleanup = %#v, want visible error", cleanup)
	}
}

func TestRunnerLateSkipOutranksPassedSetupAndCleanup(t *testing.T) {
	runner, err := conformance.NewRunner(cborFunc(func(context.Context, []byte) (ctaptransport.CBORResponse, error) {
		return ctaptransport.CBORResponse{}, errors.New("unexpected command")
	}))
	if err != nil {
		t.Fatal(err)
	}

	suite := conformance.Suite{
		ID:   "late-skip",
		Name: "Late skip",
		Tests: []conformance.Test{{
			ID:   "test",
			Name: "Test",
			Run: func(test *conformance.TestContext) {
				test.Cleanup(conformance.Step{
					ID:   "cleanup",
					Name: "Cleanup",
					Run: func(context.Context) error {
						return nil
					},
				})
				test.Step(conformance.Step{
					ID:   "setup",
					Name: "Setup",
					Run: func(context.Context) error {
						return nil
					},
				})
				test.Step(conformance.Step{
					ID:   "applicability",
					Name: "Applicability",
					Run: func(context.Context) error {
						return conformance.Skip("case does not apply")
					},
				})
			},
		}},
	}

	result, err := runner.Run(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusSkipped || result.Tests[0].Status != conformance.StatusSkipped {
		t.Fatalf("result = %#v, want skipped", result)
	}
	if len(result.Tests[0].Steps) != 3 || result.Tests[0].Steps[2].Status != conformance.StatusPassed {
		t.Fatalf("steps = %#v, want visible passed cleanup", result.Tests[0].Steps)
	}
}

func TestRunnerReturnsPartialResultOnContextCancellation(t *testing.T) {
	runner, err := conformance.NewRunner(cborFunc(func(context.Context, []byte) (ctaptransport.CBORResponse, error) {
		return ctaptransport.CBORResponse{}, errors.New("unexpected command")
	}))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	secondRan := false
	cleanupRan := false
	cleanupHadDeadline := false
	suite := conformance.Suite{
		ID:   "cancel",
		Name: "Cancel",
		Tests: []conformance.Test{
			{
				ID:   "first",
				Name: "First",
				Run: func(test *conformance.TestContext) {
					test.Cleanup(conformance.Step{
						ID:   "cleanup",
						Name: "Cleanup",
						Run: func(ctx context.Context) error {
							cleanupRan = true
							if ctx.Err() != nil {
								return fmt.Errorf("cleanup context is already done: %v", ctx.Err())
							}
							_, cleanupHadDeadline = ctx.Deadline()

							return nil
						},
					})
					test.Step(conformance.Step{
						ID:   "cancel",
						Name: "Cancel",
						Run: func(ctx context.Context) error {
							cancel()

							return ctx.Err()
						},
					})
				},
			},
			{
				ID:   "second",
				Name: "Second",
				Run: func(*conformance.TestContext) {
					secondRan = true
				},
			},
		},
	}

	result, err := runner.Run(ctx, suite)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if result.Status != conformance.StatusError || result.Error != context.Canceled.Error() {
		t.Fatalf("result = %#v, want canceled error", result)
	}
	if len(result.Tests) != 1 || result.Tests[0].Status != conformance.StatusError {
		t.Fatalf("tests = %#v, want one errored test", result.Tests)
	}
	if !cleanupRan || !cleanupHadDeadline || len(result.Tests[0].Steps) != 2 || result.Tests[0].Steps[1].Status != conformance.StatusPassed {
		t.Fatalf("cleanup result = %#v, ran %t, deadline %t", result.Tests[0].Steps, cleanupRan, cleanupHadDeadline)
	}
	if secondRan {
		t.Fatal("second test ran after cancellation")
	}
}

func TestSuiteResultJSONIsStableAndContainsNoCallbacks(t *testing.T) {
	runner, err := conformance.NewRunner(cborFunc(func(context.Context, []byte) (ctaptransport.CBORResponse, error) {
		return ctaptransport.CBORResponse{}, errors.New("unexpected command")
	}))
	if err != nil {
		t.Fatal(err)
	}

	suite := conformance.Suite{
		ID:     "suite",
		Name:   "Suite",
		Source: conformance.Source{Artifact: "fixture", Version: "1"},
		Tests: []conformance.Test{
			{
				ID:         "test",
				Name:       "Test",
				Source:     conformance.SourceLocation{Path: "test.js", Case: "P-1"},
				References: []conformance.RequirementRef{},
				Run: func(test *conformance.TestContext) {
					test.Step(conformance.Step{
						ID:         "step",
						Name:       "Step",
						References: []conformance.RequirementRef{},
						Run: func(context.Context) error {
							return nil
						},
					})
				},
			},
		},
	}
	result, err := runner.Run(context.Background(), suite)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"suite","name":"Suite","source":{"artifact":"fixture","version":"1"},"status":"passed","tests":[{"id":"test","name":"Test","source":{"path":"test.js","case":"P-1"},"references":[],"status":"passed","steps":[{"id":"step","name":"Step","references":[],"status":"passed"}]}]}`
	if string(raw) != want {
		t.Fatalf("JSON = %s, want %s", raw, want)
	}
}
