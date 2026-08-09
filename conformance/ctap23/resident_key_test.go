package ctap23

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

func TestResidentKeyDefinitions(t *testing.T) {
	tests := residentKeyTests(Config{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDResidentKeyP1, "P-1"},
		{TestIDResidentKeyP2, "P-2"},
		{TestIDResidentKeyP3, "P-3"},
		{TestIDResidentKeyP4, "P-4"},
		{TestIDResidentKeyP5, "P-5"},
		{TestIDResidentKeyP6, "P-6"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != residentKeySourcePath ||
			test.Source.Case != expected.marker || !test.Destructive || len(test.References) == 0 {
			t.Errorf("test[%d] = %#v", index, test)
		}
		for _, reference := range test.References {
			if reference.Specification != conformance.SpecificationCTAP23 ||
				!strings.HasPrefix(string(reference.ID), "ctap-2.3-ps-20260226:") ||
				!strings.Contains(reference.URL, "fido-v2.3-ps-20260226") ||
				reference.Level == "" {
				t.Errorf("test[%d] reference = %#v", index, reference)
			}
		}
	}
	assertResidentKeyReference(t, tests[0].References[0], "6.1.2", "#authenticatorMakeCredential")
	assertResidentKeyReference(t, tests[0].References[1], "6.1.3", "#sctn-discoverable-credentials")
	assertResidentKeyReference(t, tests[1].References[1], "6.2.2", "#authenticatorGetAssertion")
	assertResidentKeyReference(t, tests[1].References[2], "6.3", "#authenticatorGetNextAssertion")
	assertResidentKeyReference(t, tests[4].References[1], "6.4", "#authenticatorGetInfo")
}

func TestResidentKeyAllCasesRunAndPass(t *testing.T) {
	for index, marker := range []string{"P-1", "P-2", "P-3", "P-4", "P-5", "P-6"} {
		t.Run(marker, func(t *testing.T) {
			device := newResidentKeyTestDevice(t)
			environment := &residentKeyTestEnvironment{device: device}
			config := environment.config()
			if marker == "P-4" {
				config.AccountSelectionDisplay = AccountSelectionDisplayPresent
			}

			result := runResidentKeyTest(t, device, config, index)
			if result.Status != conformance.StatusPassed || result.Tests[0].Status != conformance.StatusPassed {
				t.Fatalf("result = %#v, want passed", result)
			}
			if len(result.Tests[0].Steps) != 4 {
				t.Fatalf("steps = %#v", result.Tests[0].Steps)
			}
			for _, step := range result.Tests[0].Steps {
				if step.Status != conformance.StatusPassed {
					t.Fatalf("step = %#v", step)
				}
			}
			assertResidentKeyCaseTranscript(t, marker, device, environment)
			assertResidentKeyWipes(t, device, environment)
		})
	}
}

func TestResidentKeyApplicabilitySkipsBeforeMutation(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		index int
		apply func(*residentKeyTestDevice, *Config)
	}{
		{
			name:  "rk absent P1",
			index: 0,
			apply: func(device *residentKeyTestDevice, _ *Config) { device.residentKeys = false },
		},
		{
			name:  "display unspecified P2",
			index: 1,
			apply: func(_ *residentKeyTestDevice, config *Config) {
				config.AccountSelectionDisplay = AccountSelectionDisplayUnspecified
			},
		},
		{
			name:  "protocol2 absent P3",
			index: 2,
			apply: func(device *residentKeyTestDevice, config *Config) {
				device.protocolTwo = false
				config.Featureful = false
			},
		},
		{
			name:  "display absent P4",
			index: 3,
			apply: func(_ *residentKeyTestDevice, _ *Config) {},
		},
		{
			name:  "state absent P5",
			index: 4,
			apply: func(device *residentKeyTestDevice, _ *Config) { device.storeStatePresent = false },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newResidentKeyTestDevice(t)
			environment := &residentKeyTestEnvironment{device: device}
			config := environment.config()
			testCase.apply(device, &config)

			result := runResidentKeyTest(t, device, config, testCase.index)
			if result.Status != conformance.StatusSkipped || result.Tests[0].Status != conformance.StatusSkipped {
				t.Fatalf("result = %#v, want skipped", result)
			}
			if len(environment.events) != 0 || len(device.operations) != 0 ||
				len(environment.tokenRequests) != 0 {
				t.Fatalf("inapplicable case mutated state: events=%v operations=%v tokens=%v", environment.events, device.operations, environment.tokenRequests)
			}
		})
	}
}

func TestResidentKeyFreshAlwaysUVSkipsOnlyUnauthenticatedP2(t *testing.T) {
	device := newResidentKeyTestDevice(t)
	device.alwaysUV = true
	environment := &residentKeyTestEnvironment{device: device}
	result := runResidentKeyTest(t, device, environment.config(), 1)
	if result.Status != conformance.StatusSkipped {
		t.Fatalf("result = %#v, want skipped", result)
	}
	if len(device.operations) != 0 || len(environment.tokenRequests) != 0 {
		t.Fatalf("fresh alwaysUv skip executed commands/tokens: %v/%v", device.operations, environment.tokenRequests)
	}
	if !slices.Equal(environment.events, []string{
		"power-cycle", "reset", "power-cycle",
		"power-cycle", "reset", "power-cycle",
	}) {
		t.Fatalf("lifecycle = %v", environment.events)
	}
}

func TestResidentKeyValidationFailureIsFailedAndCleansUp(t *testing.T) {
	device := newResidentKeyTestDevice(t)
	device.badCount = true
	environment := &residentKeyTestEnvironment{device: device}

	result := runResidentKeyTest(t, device, environment.config(), 1)
	if result.Status != conformance.StatusFailed || result.Tests[0].Status != conformance.StatusFailed {
		t.Fatalf("result = %#v, want failed", result)
	}
	if result.Tests[0].Steps[2].Status != conformance.StatusFailed ||
		result.Tests[0].Steps[3].Status != conformance.StatusPassed {
		t.Fatalf("steps = %#v", result.Tests[0].Steps)
	}
	assertResidentKeyWipes(t, device, environment)
}

func TestResidentKeyTransportAndHookFailuresRemainErrors(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		device := newResidentKeyTestDevice(t)
		device.transportError = errResidentKeyTransport
		environment := &residentKeyTestEnvironment{device: device}
		result := runResidentKeyTest(t, device, environment.config(), 0)
		if result.Status != conformance.StatusError ||
			!strings.Contains(result.Tests[0].Steps[2].Message, errResidentKeyTransport.Error()) {
			t.Fatalf("result = %#v, want transport error", result)
		}
		assertResidentKeyWipes(t, device, environment)
	})

	t.Run("account selection hook", func(t *testing.T) {
		device := newResidentKeyTestDevice(t)
		environment := &residentKeyTestEnvironment{device: device, hookError: errors.New("selection UI unavailable")}
		config := environment.config()
		config.AccountSelectionDisplay = AccountSelectionDisplayPresent
		result := runResidentKeyTest(t, device, config, 3)
		if result.Status != conformance.StatusError ||
			!strings.Contains(result.Tests[0].Steps[2].Message, "selection UI unavailable") {
			t.Fatalf("result = %#v, want hook error", result)
		}
		if device.getNextCalls != 0 {
			t.Fatalf("GetNextAssertion calls = %d", device.getNextCalls)
		}
		assertResidentKeyWipes(t, device, environment)
	})
}

func TestResidentKeyP4RequiresDeclaredHookBeforeMutation(t *testing.T) {
	device := newResidentKeyTestDevice(t)
	environment := &residentKeyTestEnvironment{device: device}
	config := environment.config()
	config.AccountSelectionDisplay = AccountSelectionDisplayPresent
	config.PrepareAccountSelection = nil

	result := runResidentKeyTest(t, device, config, 3)
	if result.Status != conformance.StatusError {
		t.Fatalf("result = %#v, want error", result)
	}
	if len(environment.events) != 0 || len(device.operations) != 0 {
		t.Fatalf("missing hook touched lifecycle: %v/%v", environment.events, device.operations)
	}
}

func TestResidentKeySelectedAccountRequiresClosedUserEntity(t *testing.T) {
	expected := residentKeyCredential{
		ID:          []byte{0x01},
		UserID:      []byte{0x02},
		Name:        "account",
		DisplayName: "Account",
	}
	valid := residentKeyAssertion{
		CredentialType:  credential.PublicKeyCredentialTypePublicKey,
		CredentialID:    []byte{0x01},
		UserPresent:     true,
		UserID:          []byte{0x02},
		UserFieldKeys:   map[string]struct{}{"id": {}},
		UV:              true,
		SelectedPresent: true,
		Selected:        true,
	}
	if err := residentKeyValidateSelected(expected, valid); err != nil {
		t.Fatalf("valid selection = %v", err)
	}

	missingUser := valid
	missingUser.UserPresent = false
	if err := residentKeyValidateSelected(expected, missingUser); err == nil {
		t.Fatal("selection without user entity passed")
	}

	unknownMember := valid
	unknownMember.UserFieldKeys = map[string]struct{}{"id": {}, "unknown": {}}
	if err := residentKeyValidateSelected(expected, unknownMember); err == nil {
		t.Fatal("selection with unknown user member passed")
	}
}

func assertResidentKeyCaseTranscript(
	t *testing.T,
	marker string,
	device *residentKeyTestDevice,
	environment *residentKeyTestEnvironment,
) {
	t.Helper()
	wantOperations := map[string][]string{
		"P-1": {"makeCredential"},
		"P-2": {"makeCredential", "makeCredential", "makeCredential", "getAssertion", "getNextAssertion", "getNextAssertion"},
		"P-3": {"makeCredential", "makeCredential", "getAssertion", "getNextAssertion"},
		"P-4": {"makeCredential", "makeCredential", "makeCredential", "getAssertion", "getAssertion", "getAssertion"},
		"P-5": {"makeCredential"},
		"P-6": {"makeCredential", "makeCredential", "getAssertion", "getAssertion"},
	}
	if !slices.Equal(device.operations, wantOperations[marker]) {
		t.Fatalf("operations = %v, want %v", device.operations, wantOperations[marker])
	}
	wantNext := map[string]int{"P-2": 2, "P-3": 1}
	if device.getNextCalls != wantNext[marker] {
		t.Fatalf("GetNextAssertion calls = %d, want %d", device.getNextCalls, wantNext[marker])
	}

	wantScopes := map[string][]protocol.Permission{
		"P-3": {
			protocol.PermissionMakeCredential,
			protocol.PermissionMakeCredential,
			protocol.PermissionGetAssertion,
		},
		"P-4": {
			protocol.PermissionMakeCredential,
			protocol.PermissionMakeCredential,
			protocol.PermissionMakeCredential,
			protocol.PermissionGetAssertion,
			protocol.PermissionGetAssertion,
			protocol.PermissionGetAssertion,
		},
	}
	permissions := make([]protocol.Permission, len(environment.tokenRequests))
	for index, request := range environment.tokenRequests {
		permissions[index] = request.Permission
		if request.RPID != residentKeyRPID {
			t.Fatalf("token request %d RP ID = %q", index, request.RPID)
		}
	}
	if !slices.Equal(permissions, wantScopes[marker]) {
		t.Fatalf("token permissions = %v, want %v", permissions, wantScopes[marker])
	}
	if marker == "P-4" {
		hooks := slices.DeleteFunc(slices.Clone(environment.events), func(event string) bool {
			return !strings.HasPrefix(event, "hook:")
		})
		if len(hooks) != 3 || device.getNextCalls != 0 {
			t.Fatalf("selection hooks/GetNext = %v/%d", hooks, device.getNextCalls)
		}
	}
}

func assertResidentKeyWipes(
	t *testing.T,
	device *residentKeyTestDevice,
	environment *residentKeyTestEnvironment,
) {
	t.Helper()
	for index, value := range environment.pinBuffers {
		if !allZeroResidentKey(value) {
			t.Fatalf("temporary PIN %d was not wiped: %x", index, value)
		}
	}
	for index, value := range environment.tokenBuffers {
		if !allZeroResidentKey(value) {
			t.Fatalf("token %d was not wiped: %x", index, value)
		}
	}
	for index, value := range device.responseBuffers {
		if !allZeroResidentKey(value) {
			t.Fatalf("wire response %d was not wiped: %x", index, value)
		}
	}
}

func assertResidentKeyReference(
	t *testing.T,
	reference conformance.RequirementRef,
	section string,
	anchor string,
) {
	t.Helper()
	if reference.Section != section || !strings.HasSuffix(reference.URL, anchor) {
		t.Fatalf("reference = %#v, want section %s anchor %s", reference, section, anchor)
	}
}

func runResidentKeyTest(
	t *testing.T,
	device *residentKeyTestDevice,
	config Config,
	index int,
) conformance.SuiteResult {
	t.Helper()
	tests := residentKeyTests(config)
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "resident-key-test",
		Name:  "Resident key test",
		Tests: []conformance.Test{tests[index]},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
