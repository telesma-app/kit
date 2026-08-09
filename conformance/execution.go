package conformance

import (
	"context"
	"fmt"
)

// SuiteID is the stable identifier of an executable conformance suite.
type SuiteID string

// TestID is the stable identifier of one independently reported test.
type TestID string

// StepID is the stable identifier of one phase within a test.
type StepID string

// Source identifies the upstream artifact from which a suite was adapted.
// Digest is the digest of the complete artifact, including the algorithm
// prefix, for example "sha256:...".
type Source struct {
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
	Digest   string `json:"digest,omitempty"`
}

// SourceLocation maps a test back to its exact upstream case.
type SourceLocation struct {
	Path string `json:"path"`
	Case string `json:"case"`
}

// Suite is an executable collection of conformance tests from one upstream
// source artifact.
type Suite struct {
	ID          SuiteID `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Source      Source  `json:"source"`
	Tests       []Test  `json:"tests"`
}

// Test is one independently reported conformance test. Destructive marks a
// test that can persistently mutate authenticator state. Run declares and
// executes its steps using the supplied TestContext.
type Test struct {
	ID          TestID           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Source      SourceLocation   `json:"source"`
	References  []RequirementRef `json:"references"`
	Destructive bool             `json:"destructive,omitempty"`
	Run         TestFunc         `json:"-"`
}

// TestFunc executes one test against a runner-owned TestContext.
type TestFunc func(*TestContext)

// Step is one named phase of a conformance test.
type Step struct {
	ID         StepID           `json:"id"`
	Name       string           `json:"name"`
	References []RequirementRef `json:"references"`
	Run        StepFunc         `json:"-"`
}

// StepFunc executes one test step. Returning nil passes the step. Fail and
// Skip return classified errors; any other error is an execution error.
type StepFunc func(context.Context) error

// Status is the aggregate outcome of a suite, test, or step.
type Status string

const (
	StatusPassed  Status = "passed"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
)

// SuiteResult is the complete structured result of one suite run.
type SuiteResult struct {
	ID          SuiteID      `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Source      Source       `json:"source"`
	Status      Status       `json:"status"`
	Error       string       `json:"error,omitempty"`
	Tests       []TestResult `json:"tests"`
}

// TestResult is the structured result of one test.
type TestResult struct {
	ID          TestID           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Source      SourceLocation   `json:"source"`
	References  []RequirementRef `json:"references"`
	Destructive bool             `json:"destructive,omitempty"`
	Status      Status           `json:"status"`
	Steps       []StepResult     `json:"steps"`
}

// StepResult is the structured result of one executed step.
type StepResult struct {
	ID         StepID           `json:"id"`
	Name       string           `json:"name"`
	References []RequirementRef `json:"references"`
	Status     Status           `json:"status"`
	Message    string           `json:"message,omitempty"`
}

// AssertionError marks an unmet conformance expectation.
type AssertionError struct {
	message string
}

func (e *AssertionError) Error() string {
	return e.message
}

// Fail returns an error which classifies the current step as failed.
func Fail(message string) error {
	return &AssertionError{message: message}
}

// Failf formats an error which classifies the current step as failed.
func Failf(format string, args ...any) error {
	return Fail(fmt.Sprintf(format, args...))
}

// SkipError marks a conformance step which does not apply to the current
// authenticator or environment.
type SkipError struct {
	reason string
}

func (e *SkipError) Error() string {
	return e.reason
}

// Skip returns an error which classifies the current step as skipped.
func Skip(reason string) error {
	return &SkipError{reason: reason}
}

// Skipf formats an error which classifies the current step as skipped.
func Skipf(format string, args ...any) error {
	return Skip(fmt.Sprintf(format, args...))
}
