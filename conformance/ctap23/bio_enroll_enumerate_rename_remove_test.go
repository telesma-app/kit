package ctap23

import (
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestBioEnrollEnumerateRenameRemovePassesWithIndependentProvisioning(t *testing.T) {
	authenticator := newBioEnrollmentFixtureAuthenticator(t)
	authenticator.maxFriendlyName = 8
	authenticator.sensorInfoTemplateID = []byte{0x41, 0x42}
	authenticator.sensorInfoTemplateInfos = []protocol.TemplateInfo{{
		TemplateID: []byte{0x43, 0x44},
	}}
	result := runBioEnrollmentTests(
		t,
		authenticator,
		bioEnrollEnumerateRenameRemoveTests(bioEnrollmentFixtureConfig(authenticator)),
	)
	if result.Status != conformance.StatusPassed || len(result.Tests) != 3 {
		t.Fatalf("result = %#v, want three passed cases", result)
	}

	wantIDs := []conformance.TestID{
		TestIDBioEnrollEnumerateRenameRemoveP1,
		TestIDBioEnrollEnumerateRenameRemoveP2,
		TestIDBioEnrollEnumerateRenameRemoveP3,
	}
	wantCases := []string{"P-1", "P-2", "P-3"}
	wantSections := []string{"6.7.6", "6.7.7", "6.7.8"}
	for index, testResult := range result.Tests {
		if testResult.Status != conformance.StatusPassed || testResult.ID != wantIDs[index] {
			t.Fatalf("test %d = %#v", index, testResult)
		}
		if testResult.Source.Path != bioEnrollEnumerateRenameRemoveSourcePath ||
			testResult.Source.Case != wantCases[index] {
			t.Fatalf("test %d source = %#v", index, testResult.Source)
		}
		if !testResult.Destructive || testResult.References[0].Section != "6.7.1" ||
			!hasBioEnrollmentReference(testResult.References, wantSections[index]) {
			t.Fatalf("test %d metadata = %#v", index, testResult)
		}
		if index == 1 {
			wantReferenceSections := []string{
				"6.7.1",
				"6.7.4",
				"6.5.5.7.2",
				"6.5.7",
				"8",
				"6.6",
				"6.5.5.1",
				"6.7.7",
				"6.7.6",
				"6.7.3",
			}
			if !slices.Equal(bioEnrollmentReferenceSections(testResult.References), wantReferenceSections) {
				t.Fatalf("P-2 references = %#v", testResult.References)
			}
			wantStepSections := []string{"6.7.3", "6.7.7", "6.5.5.7.2", "6.5.7"}
			if !slices.Equal(
				bioEnrollmentReferenceSections(testResult.Steps[3].References),
				wantStepSections,
			) {
				t.Fatalf("P-2 sensor/rename step references = %#v", testResult.Steps[3].References)
			}
		}
		if cleanup := testResult.Steps[len(testResult.Steps)-1]; cleanup.ID != "bio-enrollment-fixture.cleanup" || cleanup.Status != conformance.StatusPassed {
			t.Fatalf("test %d cleanup = %#v", index, cleanup)
		}
	}

	wantOperations := []string{
		"begin", "capture", "capture", "enumerate",
		"begin", "capture", "capture", "sensor-info", "rename", "enumerate",
		"begin", "capture", "capture", "remove", "enumerate",
	}
	if !slices.Equal(authenticator.bioOperations, wantOperations) {
		t.Fatalf("bio operations = %v, want %v", authenticator.bioOperations, wantOperations)
	}
	if !slices.Equal(authenticator.friendlyNames, []string{"MostLeft"}) {
		t.Fatalf("friendly names = %q, want sensor-limited name", authenticator.friendlyNames)
	}
	if authenticator.maxConcurrentTemplates != 1 || len(authenticator.templates) != 0 {
		t.Fatalf("template lifecycle = max %d, remaining %d", authenticator.maxConcurrentTemplates, len(authenticator.templates))
	}
	if authenticator.powerCycles != 12 || authenticator.resets != 6 {
		t.Fatalf("power cycles/resets = %d/%d, want 12/6", authenticator.powerCycles, authenticator.resets)
	}
	assertBioEnrollmentFixtureOwnership(t, authenticator)
}

func TestBioEnrollEnumerateP1AcceptsAbsentFriendlyNameAndRejectsWrongType(t *testing.T) {
	t.Run("absent optional friendly name", func(t *testing.T) {
		authenticator := newBioEnrollmentFixtureAuthenticator(t)
		result := runBioEnrollmentTests(
			t,
			authenticator,
			[]conformance.Test{bioEnrollEnumerateRenameRemoveTests(bioEnrollmentFixtureConfig(authenticator))[0]},
		)
		if result.Status != conformance.StatusPassed {
			t.Fatalf("result = %#v, want absent friendly name accepted", result)
		}
		assertBioEnrollmentFixtureOwnership(t, authenticator)
	})

	t.Run("wrong friendly name type", func(t *testing.T) {
		authenticator := newBioEnrollmentFixtureAuthenticator(t)
		authenticator.malformedFriendlyName = true
		result := runBioEnrollmentTests(
			t,
			authenticator,
			[]conformance.Test{bioEnrollEnumerateRenameRemoveTests(bioEnrollmentFixtureConfig(authenticator))[0]},
		)
		step := result.Tests[0].Steps[3]
		if result.Status != conformance.StatusFailed || step.Status != conformance.StatusFailed ||
			!strings.Contains(step.Message, "invalid authenticatorBioEnrollment enumerateEnrollments response CBOR") {
			t.Fatalf("result = %#v, want malformed friendly name failure", result)
		}
	})
}

func TestBioEnrollRemoveRequiresExactInvalidOptionAfterRemoval(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*bioEnrollmentFixtureAuthenticator)
		wantMessage string
	}{
		{
			name: "different CTAP status",
			configure: func(authenticator *bioEnrollmentFixtureAuthenticator) {
				authenticator.statusSubCommand = protocol.BioEnrollmentSubCommandEnumerateEnrollments
				authenticator.status = ctaptransport.CTAP2_ERR_NO_CREDENTIALS
			},
			wantMessage: "CTAP2_ERR_NO_CREDENTIALS, want CTAP2_ERR_INVALID_OPTION",
		},
		{
			name: "unexpected success",
			configure: func(authenticator *bioEnrollmentFixtureAuthenticator) {
				authenticator.enumerateEmptySuccess = true
			},
			wantMessage: "returned CTAP2_OK, want CTAP2_ERR_INVALID_OPTION",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator := newBioEnrollmentFixtureAuthenticator(t)
			test.configure(authenticator)
			result := runBioEnrollmentTests(
				t,
				authenticator,
				[]conformance.Test{bioEnrollEnumerateRenameRemoveTests(bioEnrollmentFixtureConfig(authenticator))[2]},
			)
			step := result.Tests[0].Steps[4]
			if result.Status != conformance.StatusFailed || step.Status != conformance.StatusFailed ||
				!strings.Contains(step.Message, test.wantMessage) {
				t.Fatalf("result = %#v, want failure containing %q", result, test.wantMessage)
			}
			if cleanup := result.Tests[0].Steps[len(result.Tests[0].Steps)-1]; cleanup.Status != conformance.StatusPassed {
				t.Fatalf("cleanup = %#v", cleanup)
			}
		})
	}
}

func hasBioEnrollmentReference(references []conformance.RequirementRef, section string) bool {
	return slices.ContainsFunc(references, func(reference conformance.RequirementRef) bool {
		return reference.Section == section
	})
}

func bioEnrollmentReferenceSections(references []conformance.RequirementRef) []string {
	sections := make([]string, len(references))
	for index, reference := range references {
		sections[index] = reference.Section
	}

	return sections
}
