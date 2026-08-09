package ctap23

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestBioEnrollEnrollPassesWithIndependentLifecyclesAndExactWire(t *testing.T) {
	authenticator := newBioEnrollmentFixtureAuthenticator(t)
	result := runBioEnrollmentTests(
		t,
		authenticator,
		bioEnrollEnrollTests(bioEnrollmentFixtureConfig(authenticator)),
	)
	if result.Status != conformance.StatusPassed || len(result.Tests) != 2 {
		t.Fatalf("result = %#v, want two passed cases", result)
	}

	wantIDs := []conformance.TestID{TestIDBioEnrollEnrollP1, TestIDBioEnrollEnrollP2}
	wantCases := []string{"P-1", "P-2"}
	for index, testResult := range result.Tests {
		if testResult.Status != conformance.StatusPassed || testResult.ID != wantIDs[index] {
			t.Fatalf("test %d = %#v", index, testResult)
		}
		if testResult.Source.Path != bioEnrollEnrollSourcePath || testResult.Source.Case != wantCases[index] {
			t.Fatalf("test %d source = %#v", index, testResult.Source)
		}
		if !testResult.Destructive || testResult.References[0].Section != "6.7.1" ||
			testResult.References[1].Section != "6.7.4" {
			t.Fatalf("test %d metadata = %#v", index, testResult)
		}
		if cleanup := testResult.Steps[len(testResult.Steps)-1]; cleanup.ID != "bio-enrollment-fixture.cleanup" || cleanup.Status != conformance.StatusPassed {
			t.Fatalf("test %d cleanup = %#v", index, cleanup)
		}
	}

	wantOperations := []string{"begin", "cancel", "begin", "capture", "capture"}
	if !slices.Equal(authenticator.bioOperations, wantOperations) {
		t.Fatalf("bio operations = %v, want %v", authenticator.bioOperations, wantOperations)
	}
	for index := 0; index < len(authenticator.sampleEvents); index += 2 {
		if index+1 >= len(authenticator.sampleEvents) || authenticator.sampleEvents[index] != "sample" ||
			authenticator.sampleEvents[index+1] != wantOperationsWithoutCancel(wantOperations)[index/2] {
			t.Fatalf("sample/command events = %v", authenticator.sampleEvents)
		}
	}
	if authenticator.powerCycles != 8 || authenticator.resets != 4 {
		t.Fatalf("power cycles/resets = %d/%d, want 8/4", authenticator.powerCycles, authenticator.resets)
	}
	if authenticator.maxConcurrentTemplates != 1 || len(authenticator.templates) != 0 {
		t.Fatalf("template lifecycle = max %d, remaining %d", authenticator.maxConcurrentTemplates, len(authenticator.templates))
	}
	assertBioEnrollmentFixtureOwnership(t, authenticator)
}

func TestBioEnrollEnrollRejectsIncreasingRemainingSamplesAndCancelsPartialEnrollment(t *testing.T) {
	authenticator := newBioEnrollmentFixtureAuthenticator(t)
	authenticator.captureRemaining = []uint{3}
	result := runBioEnrollmentTests(
		t,
		authenticator,
		[]conformance.Test{bioEnrollEnrollTests(bioEnrollmentFixtureConfig(authenticator))[1]},
	)
	testResult := result.Tests[0]
	if result.Status != conformance.StatusFailed || testResult.Status != conformance.StatusFailed {
		t.Fatalf("result = %#v, want failed case", result)
	}
	if !strings.Contains(testResult.Steps[2].Message, "remainingSamples increased from 2 to 3") {
		t.Fatalf("enrollment step = %#v", testResult.Steps[2])
	}
	cleanup := testResult.Steps[len(testResult.Steps)-1]
	if cleanup.Status != conformance.StatusPassed || !slices.Contains(authenticator.bioOperations, "cancel") {
		t.Fatalf("cleanup/operations = %#v/%v, want successful cancel", cleanup, authenticator.bioOperations)
	}
	assertBioEnrollmentFixtureOwnership(t, authenticator)
}

func TestBioEnrollEnrollPropagatesSampleCallbackErrorBeforeCommand(t *testing.T) {
	authenticator := newBioEnrollmentFixtureAuthenticator(t)
	callbackErr := errors.New("fingerprint sample unavailable")
	config := bioEnrollmentFixtureConfig(authenticator)
	config.BiometricSampleProvider = func(context.Context) error { return callbackErr }
	result := runBioEnrollmentTests(
		t,
		authenticator,
		[]conformance.Test{bioEnrollEnrollTests(config)[0]},
	)
	step := result.Tests[0].Steps[2]
	if result.Status != conformance.StatusError || step.Status != conformance.StatusError || step.Message != callbackErr.Error() {
		t.Fatalf("result = %#v, want callback execution error", result)
	}
	if len(authenticator.bioOperations) != 0 {
		t.Fatalf("bio operations = %v, want none after callback error", authenticator.bioOperations)
	}
	if len(authenticator.issuedTokens) != 0 || !allZero(authenticator.providedPINBuffers[0]) {
		t.Fatalf("cleanup retained token/PIN: %v/%x", authenticator.issuedTokens, authenticator.providedPINBuffers[0])
	}
}

func TestBioEnrollEnrollClassifiesCTAPStatusAndTransportFailures(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*bioEnrollmentFixtureAuthenticator)
		wantStatus  conformance.Status
		wantMessage string
	}{
		{
			name: "CTAP status",
			configure: func(authenticator *bioEnrollmentFixtureAuthenticator) {
				authenticator.statusSubCommand = protocol.BioEnrollmentSubCommandEnrollBegin
				authenticator.status = ctaptransport.CTAP2_ERR_FP_DATABASE_FULL
			},
			wantStatus:  conformance.StatusFailed,
			wantMessage: "CTAP2_ERR_FP_DATABASE_FULL",
		},
		{
			name: "transport error",
			configure: func(authenticator *bioEnrollmentFixtureAuthenticator) {
				authenticator.transportSubCommand = protocol.BioEnrollmentSubCommandEnrollBegin
			},
			wantStatus:  conformance.StatusError,
			wantMessage: "device disconnected",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator := newBioEnrollmentFixtureAuthenticator(t)
			test.configure(authenticator)
			result := runBioEnrollmentTests(
				t,
				authenticator,
				[]conformance.Test{bioEnrollEnrollTests(bioEnrollmentFixtureConfig(authenticator))[0]},
			)
			step := result.Tests[0].Steps[2]
			if result.Status != test.wantStatus || step.Status != test.wantStatus ||
				!strings.Contains(step.Message, test.wantMessage) {
				t.Fatalf("result = %#v, want %s containing %q", result, test.wantStatus, test.wantMessage)
			}
			if cleanup := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]; cleanup.Status != conformance.StatusPassed {
				t.Fatalf("cleanup = %#v", cleanup)
			}
		})
	}
}

func wantOperationsWithoutCancel(operations []string) []string {
	return slices.DeleteFunc(slices.Clone(operations), func(operation string) bool {
		return operation == "cancel"
	})
}
