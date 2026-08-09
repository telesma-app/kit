package ctap23

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestBioEnrollBioModAndSensorInfoPassesAndPreservesSourceMapping(t *testing.T) {
	maxSamples := uint(4)
	maxFriendlyName := uint(64)
	transport := newScriptedCBORTransport(t,
		bioEnrollmentGetInfoExchange(t, true, true),
		bioEnrollmentResponseExchange(t, bioEnrollmentGetModalityRequest(), map[uint64]any{
			1: protocol.BioModalityFingerprint,
		}),
		bioEnrollmentGetInfoExchange(t, true, true),
		bioEnrollmentResponseExchange(t, bioEnrollmentGetSensorInfoRequest(), map[uint64]any{
			2: uint(1),
			3: maxSamples,
			8: maxFriendlyName,
		}),
	)
	config, lifecycle := bioEnrollmentLifecycleConfig(t)

	result := runBioEnrollBioModAndSensorInfoTests(t, transport, bioEnrollBioModAndSensorInfoTests(config))
	if result.Status != conformance.StatusPassed || len(result.Tests) != 2 {
		t.Fatalf("result = %#v, want two passed cases", result)
	}
	if config.TokenProvider != nil || config.TemporaryPINProvider != nil || config.UVConfigurator != nil {
		t.Fatal("read-only biometric sensor information unexpectedly depends on PIN/UV configuration")
	}

	wantIDs := []conformance.TestID{
		TestIDBioEnrollBioModAndSensorInfoP1,
		TestIDBioEnrollBioModAndSensorInfoP2,
	}
	wantCases := []string{"P-1", "P-2"}
	wantSections := []string{"6.7.2", "6.7.3"}
	for index, testResult := range result.Tests {
		if testResult.Status != conformance.StatusPassed || testResult.ID != wantIDs[index] {
			t.Fatalf("test %d = %#v", index, testResult)
		}
		if testResult.Source.Path != bioEnrollBioModAndSensorInfoSourcePath || testResult.Source.Case != wantCases[index] {
			t.Fatalf("test %d source = %#v", index, testResult.Source)
		}
		if len(testResult.References) != 4 || testResult.References[0].Section != "6.7.1" || testResult.References[1].Section != wantSections[index] || testResult.References[2].Section != "6.6" || testResult.References[3].Section != "6.5.5.1" {
			t.Fatalf("test %d references = %#v", index, testResult.References)
		}
		if !strings.HasSuffix(testResult.References[0].URL, "#authenticatorBioEnrollment") || !testResult.Destructive {
			t.Fatalf("test %d metadata = %#v", index, testResult)
		}

		steps := testResult.Steps
		if len(steps) != 4 || steps[0].ID != "bio-enroll-bio-mod-and-sensor-info.applicability" || steps[1].ID != "bio-enroll-bio-mod-and-sensor-info.reset" || steps[3].ID != "bio-enroll-bio-mod-and-sensor-info.cleanup" {
			t.Fatalf("test %d steps = %#v", index, steps)
		}
		for _, step := range steps {
			if step.Status != conformance.StatusPassed {
				t.Fatalf("test %d step = %#v, want passed", index, step)
			}
		}
	}

	wantLifecycle := []string{
		"power-cycle", "reset", "power-cycle",
		"power-cycle", "reset", "power-cycle",
		"power-cycle", "reset", "power-cycle",
		"power-cycle", "reset", "power-cycle",
	}
	if !slices.Equal(lifecycle.events, wantLifecycle) {
		t.Fatalf("lifecycle = %v, want %v", lifecycle.events, wantLifecycle)
	}
}

func TestBioEnrollBioModAndSensorInfoP2AcceptsSwipeAndAbsentFriendlyNameLimit(t *testing.T) {
	transport := newScriptedCBORTransport(t,
		bioEnrollmentGetInfoExchange(t, true, false),
		bioEnrollmentResponseExchange(t, bioEnrollmentGetSensorInfoRequest(), map[uint64]any{
			2: uint(2),
			3: uint(1),
		}),
	)
	config, _ := bioEnrollmentLifecycleConfig(t)
	test := bioEnrollBioModAndSensorInfoTests(config)[1]

	result := runBioEnrollBioModAndSensorInfoTests(t, transport, []conformance.Test{test})
	if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
		t.Fatalf("result = %#v, want passed", result)
	}
}

func TestBioEnrollBioModAndSensorInfoUsesRawApplicability(t *testing.T) {
	t.Run("missing option skips before lifecycle", func(t *testing.T) {
		transport := newScriptedCBORTransport(t, bioEnrollmentGetInfoExchange(t, false, false))
		config, lifecycle := bioEnrollmentLifecycleConfig(t)

		result := runBioEnrollBioModAndSensorInfoTests(
			t,
			transport,
			[]conformance.Test{bioEnrollBioModAndSensorInfoTests(config)[0]},
		)
		testResult := result.Tests[0]
		if result.Status != conformance.StatusSkipped || testResult.Status != conformance.StatusSkipped || len(testResult.Steps) != 1 {
			t.Fatalf("result = %#v, want one skipped applicability step", result)
		}
		if len(lifecycle.events) != 0 {
			t.Fatalf("lifecycle = %v, want none", lifecycle.events)
		}
	})

	t.Run("present false option remains applicable", func(t *testing.T) {
		transport := newScriptedCBORTransport(t,
			bioEnrollmentGetInfoExchange(t, true, false),
			bioEnrollmentResponseExchange(t, bioEnrollmentGetModalityRequest(), map[uint64]any{
				1: protocol.BioModalityFingerprint,
			}),
		)
		config, _ := bioEnrollmentLifecycleConfig(t)

		result := runBioEnrollBioModAndSensorInfoTests(
			t,
			transport,
			[]conformance.Test{bioEnrollBioModAndSensorInfoTests(config)[0]},
		)
		if result.Status != conformance.StatusPassed {
			t.Fatalf("result = %#v, want present bioEnroll=false to remain applicable", result)
		}
	})

	t.Run("wrong option type is nonconformance", func(t *testing.T) {
		transport := newScriptedCBORTransport(t, bioEnrollmentGetInfoExchange(t, true, "yes"))
		config, lifecycle := bioEnrollmentLifecycleConfig(t)

		result := runBioEnrollBioModAndSensorInfoTests(
			t,
			transport,
			[]conformance.Test{bioEnrollBioModAndSensorInfoTests(config)[0]},
		)
		step := result.Tests[0].Steps[0]
		if result.Status != conformance.StatusFailed || step.Status != conformance.StatusFailed || !strings.Contains(step.Message, "invalid authenticatorGetInfo CBOR") {
			t.Fatalf("result = %#v, want failed raw option type", result)
		}
		if len(lifecycle.events) != 0 {
			t.Fatalf("lifecycle = %v, want none", lifecycle.events)
		}
	})
}

func TestBioEnrollBioModAndSensorInfoRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name    string
		caseIdx int
		fields  map[uint64]any
		message string
	}{
		{
			name:    "missing modality",
			fields:  map[uint64]any{},
			message: "modality is 0",
		},
		{
			name:    "unsupported modality",
			fields:  map[uint64]any{1: uint(2)},
			message: "want fingerprint",
		},
		{
			name:    "modality has wrong type",
			fields:  map[uint64]any{1: "fingerprint"},
			message: "invalid authenticatorBioEnrollment getModality response CBOR",
		},
		{
			name:    "missing fingerprint kind",
			caseIdx: 1,
			fields:  map[uint64]any{3: uint(4)},
			message: "fingerprintKind is 0",
		},
		{
			name:    "unsupported fingerprint kind",
			caseIdx: 1,
			fields:  map[uint64]any{2: uint(3), 3: uint(4)},
			message: "want touch (1) or swipe (2)",
		},
		{
			name:    "missing maximum samples",
			caseIdx: 1,
			fields:  map[uint64]any{2: uint(1)},
			message: "missing maxCaptureSamplesRequiredForEnroll",
		},
		{
			name:    "zero maximum samples",
			caseIdx: 1,
			fields:  map[uint64]any{2: uint(1), 3: uint(0)},
			message: "maxCaptureSamplesRequiredForEnroll must be greater than zero",
		},
		{
			name:    "zero friendly name limit",
			caseIdx: 1,
			fields:  map[uint64]any{2: uint(1), 3: uint(4), 8: uint(0)},
			message: "maxTemplateFriendlyName must be greater than zero when present",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := bioEnrollmentGetModalityRequest()
			if test.caseIdx == 1 {
				request = bioEnrollmentGetSensorInfoRequest()
			}
			transport := newScriptedCBORTransport(t,
				bioEnrollmentGetInfoExchange(t, true, true),
				bioEnrollmentResponseExchange(t, request, test.fields),
			)
			config, _ := bioEnrollmentLifecycleConfig(t)
			definition := bioEnrollBioModAndSensorInfoTests(config)[test.caseIdx]

			result := runBioEnrollBioModAndSensorInfoTests(t, transport, []conformance.Test{definition})
			testResult := result.Tests[0]
			commandStep := testResult.Steps[2]
			if result.Status != conformance.StatusFailed || commandStep.Status != conformance.StatusFailed || !strings.Contains(commandStep.Message, test.message) {
				t.Fatalf("result = %#v, want failed command containing %q", result, test.message)
			}
			if cleanup := testResult.Steps[3]; cleanup.Status != conformance.StatusPassed {
				t.Fatalf("cleanup = %#v, want passed", cleanup)
			}
		})
	}
}

func TestBioEnrollBioModAndSensorInfoClassifiesCommandFailures(t *testing.T) {
	t.Run("CTAP status is nonconformance", func(t *testing.T) {
		transport := newScriptedCBORTransport(t,
			bioEnrollmentGetInfoExchange(t, true, true),
			scriptedCBORExchange{
				request: bioEnrollmentGetModalityRequest(),
				response: ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP2_ERR_INVALID_SUBCOMMAND,
				},
			},
		)
		config, _ := bioEnrollmentLifecycleConfig(t)
		result := runBioEnrollBioModAndSensorInfoTests(
			t,
			transport,
			[]conformance.Test{bioEnrollBioModAndSensorInfoTests(config)[0]},
		)

		step := result.Tests[0].Steps[2]
		if result.Status != conformance.StatusFailed || step.Status != conformance.StatusFailed || !strings.Contains(step.Message, "CTAP2_ERR_INVALID_SUBCOMMAND") {
			t.Fatalf("result = %#v, want CTAP status failure", result)
		}
	})

	t.Run("transport failure is execution error", func(t *testing.T) {
		transportFailure := errors.New("device disconnected")
		transport := newScriptedCBORTransport(t,
			bioEnrollmentGetInfoExchange(t, true, true),
			scriptedCBORExchange{
				request: bioEnrollmentGetSensorInfoRequest(),
				err:     transportFailure,
			},
		)
		config, _ := bioEnrollmentLifecycleConfig(t)
		result := runBioEnrollBioModAndSensorInfoTests(
			t,
			transport,
			[]conformance.Test{bioEnrollBioModAndSensorInfoTests(config)[1]},
		)

		step := result.Tests[0].Steps[2]
		if result.Status != conformance.StatusError || step.Status != conformance.StatusError || step.Message != transportFailure.Error() {
			t.Fatalf("result = %#v, want transport execution error", result)
		}
	})
}

func TestBioEnrollBioModAndSensorInfoClassifiesLifecycleFailures(t *testing.T) {
	t.Run("missing power-cycle boundary is execution error", func(t *testing.T) {
		transport := newScriptedCBORTransport(t, bioEnrollmentGetInfoExchange(t, true, true))
		config := Config{}
		result := runBioEnrollBioModAndSensorInfoTests(
			t,
			transport,
			[]conformance.Test{bioEnrollBioModAndSensorInfoTests(config)[0]},
		)

		if result.Status != conformance.StatusError || result.Tests[0].Steps[1].Status != conformance.StatusError {
			t.Fatalf("result = %#v, want lifecycle execution error", result)
		}
	})

	t.Run("reset CTAP status is nonconformance", func(t *testing.T) {
		transport := newScriptedCBORTransport(t, bioEnrollmentGetInfoExchange(t, true, true))
		config := Config{
			PowerCycler: func(context.Context) error { return nil },
			Resetter: func(context.Context, *client.Client) error {
				return &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorReset,
					StatusCode: ctaptransport.CTAP2_ERR_OPERATION_DENIED,
				}
			},
		}
		result := runBioEnrollBioModAndSensorInfoTests(
			t,
			transport,
			[]conformance.Test{bioEnrollBioModAndSensorInfoTests(config)[0]},
		)

		if result.Status != conformance.StatusFailed || result.Tests[0].Steps[1].Status != conformance.StatusFailed {
			t.Fatalf("result = %#v, want reset nonconformance", result)
		}
	})
}

type bioEnrollmentLifecycle struct {
	events []string
}

func bioEnrollmentLifecycleConfig(t *testing.T) (Config, *bioEnrollmentLifecycle) {
	t.Helper()

	lifecycle := &bioEnrollmentLifecycle{}
	config := Config{
		PowerCycler: func(context.Context) error {
			lifecycle.events = append(lifecycle.events, "power-cycle")

			return nil
		},
		Resetter: func(_ context.Context, ctapClient *client.Client) error {
			if ctapClient == nil {
				t.Fatal("resetter received nil client")
			}
			lifecycle.events = append(lifecycle.events, "reset")

			return nil
		},
	}

	return config, lifecycle
}

func runBioEnrollBioModAndSensorInfoTests(
	t *testing.T,
	transport *scriptedCBORTransport,
	tests []conformance.Test,
) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(transport)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runner.Run(context.Background(), conformance.Suite{
		ID:    "bio-enroll-bio-mod-and-sensor-info-test",
		Name:  "biometric modality and sensor information test",
		Tests: tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func bioEnrollmentGetInfoExchange(t *testing.T, present bool, value any) scriptedCBORExchange {
	t.Helper()

	fields := map[uint64]any{}
	if present {
		fields[4] = map[string]any{string(protocol.OptionBioEnroll): value}
	}

	return scriptedCBORExchange{
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalBioEnrollmentFixture(t, fields),
		},
	}
}

func bioEnrollmentResponseExchange(
	t *testing.T,
	request []byte,
	fields map[uint64]any,
) scriptedCBORExchange {
	t.Helper()

	return scriptedCBORExchange{
		request: request,
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalBioEnrollmentFixture(t, fields),
		},
	}
}

func bioEnrollmentGetModalityRequest() []byte {
	return []byte{byte(protocol.AuthenticatorBioEnrollment), 0xa1, 0x06, 0xf5}
}

func bioEnrollmentGetSensorInfoRequest() []byte {
	return []byte{
		byte(protocol.AuthenticatorBioEnrollment),
		0xa2,
		0x01, byte(protocol.BioModalityFingerprint),
		0x02, byte(protocol.BioEnrollmentSubCommandGetFingerprintSensorInfo),
	}
}

func marshalBioEnrollmentFixture(t *testing.T, value any) []byte {
	t.Helper()

	data, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
