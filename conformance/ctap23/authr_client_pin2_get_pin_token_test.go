package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN2GetPINTokenExactMatrixAndReferences(t *testing.T) {
	tests := authrClientPIN2GetPINTokenTests(Config{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrClientPIN2GetPINTokenP1, "P-1"},
		{TestIDAuthrClientPIN2GetPINTokenP2, "P-2"},
		{TestIDAuthrClientPIN2GetPINTokenP3, "P-3"},
		{TestIDAuthrClientPIN2GetPINTokenF1, "F-1"},
		{TestIDAuthrClientPIN2GetPINTokenF2, "F-2"},
		{TestIDAuthrClientPIN2GetPINTokenF3, "F-3"},
		{TestIDAuthrClientPIN2GetPINTokenF4, "F-4"},
		{TestIDAuthrClientPIN2GetPINTokenF5, "F-5"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrClientPIN2GetPINTokenSourcePath ||
			test.Source.Case != want[index].marker {
			t.Fatalf("test %d identity/source = %q/%#v", index, test.ID, test.Source)
		}
		if !test.Destructive {
			t.Fatalf("test %d is not destructive", index)
		}
		for _, reference := range test.References {
			if reference.Specification != conformance.SpecificationCTAP23 || reference.Section == "" ||
				!strings.HasPrefix(reference.URL, "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/") {
				t.Fatalf("test %d reference = %#v", index, reference)
			}
		}
	}

	baseURL := "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
		"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#"
	exact := map[conformance.TestID][]conformance.RequirementRef{
		TestIDAuthrClientPIN2GetPINTokenF1: {{
			ID:            "ctap-2.3-ps-20260226:6.8.2:get-creds-metadata-authorization",
			Specification: conformance.SpecificationCTAP23,
			Section:       "6.8.2",
			Clause:        "get-creds-metadata-authorization",
			URL:           baseURL + "getCredsMetadata",
			Level:         conformance.RequirementConstraint,
		}},
		TestIDAuthrClientPIN2GetPINTokenF2: {{
			ID:            "ctap-2.3-ps-20260226:6.7.4:enroll-begin-authorization",
			Specification: conformance.SpecificationCTAP23,
			Section:       "6.7.4",
			Clause:        "enroll-begin-authorization",
			URL:           baseURL + "enrollingFingerprint",
			Level:         conformance.RequirementConstraint,
		}},
		TestIDAuthrClientPIN2GetPINTokenF3: {{
			ID:            "ctap-2.3-ps-20260226:6.10.2:large-blob-write-authorization",
			Specification: conformance.SpecificationCTAP23,
			Section:       "6.10.2",
			Clause:        "large-blob-write-authorization",
			URL:           baseURL + "largeBlobsRW",
			Level:         conformance.RequirementConstraint,
		}},
		TestIDAuthrClientPIN2GetPINTokenF4: {
			{
				ID:            "ctap-2.3-ps-20260226:6.11:authenticator-config-authorization",
				Specification: conformance.SpecificationCTAP23,
				Section:       "6.11",
				Clause:        "authenticator-config-authorization",
				URL:           baseURL + "authenticatorConfig",
				Level:         conformance.RequirementConstraint,
			},
			{
				ID:            "ctap-2.3-ps-20260226:6.11.4:set-min-pin-length-force-change",
				Specification: conformance.SpecificationCTAP23,
				Section:       "6.11.4",
				Clause:        "set-min-pin-length-force-change",
				URL:           baseURL + "setMinPINLength",
				Level:         conformance.RequirementConstraint,
			},
			{
				ID:            "ctap-2.3-ps-20260226:7.4.3:min-pin-length-extension-advertisement",
				Specification: conformance.SpecificationCTAP23,
				Section:       "7.4.3",
				Clause:        "min-pin-length-extension-advertisement",
				URL:           baseURL + "sctn-feature-descriptions-minPinLength-authnr-actions",
				Level:         conformance.RequirementMust,
			},
		},
		TestIDAuthrClientPIN2GetPINTokenF5: {{
			ID:            "ctap-2.3-ps-20260226:7.4.3:min-pin-length-extension-advertisement",
			Specification: conformance.SpecificationCTAP23,
			Section:       "7.4.3",
			Clause:        "min-pin-length-extension-advertisement",
			URL:           baseURL + "sctn-feature-descriptions-minPinLength-authnr-actions",
			Level:         conformance.RequirementMust,
		}},
	}
	for _, test := range tests {
		for _, reference := range exact[test.ID] {
			assertClientPIN2GetPINTokenReference(t, test.References, reference)
		}
	}
}

func TestAuthrClientPIN2GetPINTokenP1AppliesWithNoMcGaAndWipesPIN(t *testing.T) {
	fixture := newClientPIN2GetPINTokenAuthenticator(t)
	fixture.noMcGaPresent = true
	fixture.noMcGa = true

	result, suppliedPIN := runClientPIN2GetPINToken(t, fixture, TestIDAuthrClientPIN2GetPINTokenP1)
	assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusPassed)
	assertClientPIN2GetPINTokenLifecycle(t, fixture, suppliedPIN)
	if fixture.legacyTokenCalls != 1 {
		t.Fatalf("legacy token calls = %d, want 1", fixture.legacyTokenCalls)
	}
}

func TestAuthrClientPIN2GetPINTokenP2ExactWireAndUV(t *testing.T) {
	fixture := newClientPIN2GetPINTokenAuthenticator(t)
	result, suppliedPIN := runClientPIN2GetPINToken(t, fixture, TestIDAuthrClientPIN2GetPINTokenP2)
	assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusPassed)
	assertClientPIN2GetPINTokenLifecycle(t, fixture, suppliedPIN)
	if fixture.legacyTokenCalls != 1 || fixture.makeCredentialCalls != 1 || !fixture.makeCredentialWireValid {
		t.Fatalf(
			"token/make/wire = %d/%d/%t, want 1/1/true",
			fixture.legacyTokenCalls,
			fixture.makeCredentialCalls,
			fixture.makeCredentialWireValid,
		)
	}

	withoutUV := newClientPIN2GetPINTokenAuthenticator(t)
	withoutUV.makeCredentialFlags = protocol.AuthDataFlagUserPresent
	result, suppliedPIN = runClientPIN2GetPINToken(t, withoutUV, TestIDAuthrClientPIN2GetPINTokenP2)
	assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusFailed)
	assertClientPIN2GetPINTokenMessage(t, result, "does not set the UV flag")
	assertClientPIN2GetPINTokenLifecycle(t, withoutUV, suppliedPIN)
}

func TestAuthrClientPIN2GetPINTokenP3UsesFreshTokensSameRPAndExactAllowList(t *testing.T) {
	fixture := newClientPIN2GetPINTokenAuthenticator(t)
	result, suppliedPIN := runClientPIN2GetPINToken(t, fixture, TestIDAuthrClientPIN2GetPINTokenP3)
	assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusPassed)
	assertClientPIN2GetPINTokenLifecycle(t, fixture, suppliedPIN)
	if fixture.legacyTokenCalls != 2 || fixture.makeCredentialCalls != 1 || fixture.getAssertionCalls != 1 {
		t.Fatalf(
			"token/make/get calls = %d/%d/%d, want 2/1/1",
			fixture.legacyTokenCalls,
			fixture.makeCredentialCalls,
			fixture.getAssertionCalls,
		)
	}
	if !fixture.makeCredentialWireValid || !fixture.getAssertionWireValid {
		t.Fatalf("MakeCredential/GetAssertion wire valid = %t/%t", fixture.makeCredentialWireValid, fixture.getAssertionWireValid)
	}

	withoutUV := newClientPIN2GetPINTokenAuthenticator(t)
	withoutUV.getAssertionFlags = protocol.AuthDataFlagUserPresent
	result, suppliedPIN = runClientPIN2GetPINToken(t, withoutUV, TestIDAuthrClientPIN2GetPINTokenP3)
	assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusFailed)
	assertClientPIN2GetPINTokenMessage(t, result, "does not set the UV flag")
	assertClientPIN2GetPINTokenLifecycle(t, withoutUV, suppliedPIN)
}

func TestAuthrClientPIN2GetPINTokenLegacyMCGAPreflightSkipsWithoutMutation(t *testing.T) {
	for _, id := range []conformance.TestID{
		TestIDAuthrClientPIN2GetPINTokenP2,
		TestIDAuthrClientPIN2GetPINTokenP3,
	} {
		t.Run(string(id), func(t *testing.T) {
			fixture := newClientPIN2GetPINTokenAuthenticator(t)
			fixture.noMcGaPresent = true
			fixture.noMcGa = true

			result, _ := runClientPIN2GetPINToken(t, fixture, id)
			assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusSkipped)
			assertClientPIN2GetPINTokenNoMutation(t, fixture)
		})
	}
}

func TestAuthrClientPIN2GetPINTokenForbiddenCommandWireAndHMACMatrix(t *testing.T) {
	tests := []struct {
		id         conformance.TestID
		stepID     conformance.StepID
		references []conformance.RequirementRef
		validated  func(*clientPIN2GetPINTokenAuthenticator) bool
	}{
		{
			id:         TestIDAuthrClientPIN2GetPINTokenF1,
			stepID:     "client-pin2-get-pin-token.f-1.credential-management",
			references: []conformance.RequirementRef{clientPIN2GetPINTokenReference("6.8.2", "get-creds-metadata-authorization", "getCredsMetadata")},
			validated: func(f *clientPIN2GetPINTokenAuthenticator) bool {
				return f.credentialManagementWireValid
			},
		},
		{
			id:         TestIDAuthrClientPIN2GetPINTokenF2,
			stepID:     "client-pin2-get-pin-token.f-2.bio-enrollment",
			references: []conformance.RequirementRef{clientPIN2GetPINTokenReference("6.7.4", "enroll-begin-authorization", "enrollingFingerprint")},
			validated: func(f *clientPIN2GetPINTokenAuthenticator) bool {
				return f.bioEnrollmentWireValid
			},
		},
		{
			id:         TestIDAuthrClientPIN2GetPINTokenF3,
			stepID:     "client-pin2-get-pin-token.f-3.large-blob",
			references: []conformance.RequirementRef{clientPIN2GetPINTokenReference("6.10.2", "large-blob-write-authorization", "largeBlobsRW")},
			validated: func(f *clientPIN2GetPINTokenAuthenticator) bool {
				return f.largeBlobsWireValid
			},
		},
		{
			id:     TestIDAuthrClientPIN2GetPINTokenF4,
			stepID: "client-pin2-get-pin-token.f-4.authenticator-config",
			references: []conformance.RequirementRef{
				clientPIN2GetPINTokenReference("6.11", "authenticator-config-authorization", "authenticatorConfig"),
				clientPIN2GetPINTokenSetMinPINLengthReference(),
			},
			validated: func(f *clientPIN2GetPINTokenAuthenticator) bool {
				return f.wrongConfigMACValid
			},
		},
	}
	for _, test := range tests {
		t.Run(string(test.id), func(t *testing.T) {
			fixture := newClientPIN2GetPINTokenAuthenticator(t)
			result, suppliedPIN := runClientPIN2GetPINToken(t, fixture, test.id)
			assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusPassed)
			assertClientPIN2GetPINTokenLifecycle(t, fixture, suppliedPIN)
			if fixture.legacyTokenCalls != 1 || !test.validated(fixture) {
				t.Fatalf("legacy token calls/wire valid = %d/%t, want 1/true", fixture.legacyTokenCalls, test.validated(fixture))
			}
			for _, reference := range test.references {
				assertClientPIN2GetPINTokenStepReference(t, result, test.stepID, reference)
			}
		})
	}
}

func TestAuthrClientPIN2GetPINTokenF2AppliesWhenBioEnrollIsFalse(t *testing.T) {
	fixture := newClientPIN2GetPINTokenAuthenticator(t)
	fixture.bioEnroll = false

	result, suppliedPIN := runClientPIN2GetPINToken(t, fixture, TestIDAuthrClientPIN2GetPINTokenF2)
	assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusPassed)
	assertClientPIN2GetPINTokenLifecycle(t, fixture, suppliedPIN)
	if !fixture.bioEnrollmentWireValid {
		t.Fatal("bioEnrollment request was not validated")
	}
}

func TestAuthrClientPIN2GetPINTokenF5UsesACFGTokenThenGetsPINInvalid(t *testing.T) {
	fixture := newClientPIN2GetPINTokenAuthenticator(t)
	result, suppliedPIN := runClientPIN2GetPINToken(t, fixture, TestIDAuthrClientPIN2GetPINTokenF5)
	assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusPassed)
	assertClientPIN2GetPINTokenLifecycle(t, fixture, suppliedPIN)
	if fixture.permissionTokenCalls != 1 ||
		len(fixture.permissionScopes) != 1 ||
		fixture.permissionScopes[0] != protocol.PermissionAuthenticatorConfiguration {
		t.Fatalf("permission calls/scopes = %d/%v, want one acfg", fixture.permissionTokenCalls, fixture.permissionScopes)
	}
	if !fixture.correctConfigMACValid || !fixture.forceWasSet || fixture.legacyTokenCalls != 1 {
		t.Fatalf(
			"correct MAC/force/token calls = %t/%t/%d, want true/true/1",
			fixture.correctConfigMACValid,
			fixture.forceWasSet,
			fixture.legacyTokenCalls,
		)
	}
	assertClientPIN2GetPINTokenStepReference(
		t,
		result,
		"client-pin2-get-pin-token.configuration-profile",
		clientPIN2GetPINTokenMinPINLengthExtensionReference(),
	)
	assertClientPIN2GetPINTokenStepReference(
		t,
		result,
		"client-pin2-get-pin-token.f-5.force-change",
		clientPIN2GetPINTokenSetMinPINLengthReference(),
	)
}

func TestAuthrClientPIN2GetPINTokenFeaturePreflightsSkipBeforeMutation(t *testing.T) {
	tests := []struct {
		name      string
		id        conformance.TestID
		configure func(*clientPIN2GetPINTokenAuthenticator)
	}{
		{
			name: "F1 credMgmt false",
			id:   TestIDAuthrClientPIN2GetPINTokenF1,
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.credMgmt = false
			},
		},
		{
			name: "F1 rk false",
			id:   TestIDAuthrClientPIN2GetPINTokenF1,
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.residentKeys = false
			},
		},
		{
			name: "F2 bioEnroll absent",
			id:   TestIDAuthrClientPIN2GetPINTokenF2,
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.bioEnrollPresent = false
			},
		},
		{
			name: "F3 largeBlobs false",
			id:   TestIDAuthrClientPIN2GetPINTokenF3,
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.largeBlobs = false
			},
		},
		{
			name: "F4 setMinPINLength absent",
			id:   TestIDAuthrClientPIN2GetPINTokenF4,
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.setMinPresent = false
			},
		},
		{
			name: "F5 setMinPINLength false",
			id:   TestIDAuthrClientPIN2GetPINTokenF5,
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.setMinEnabled = false
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2GetPINTokenAuthenticator(t)
			test.configure(fixture)

			result, _ := runClientPIN2GetPINToken(t, fixture, test.id)
			assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusSkipped)
			assertClientPIN2GetPINTokenNoMutation(t, fixture)
		})
	}
}

func TestAuthrClientPIN2GetPINTokenMalformedConfigurationProfileFailsBeforeMutation(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*clientPIN2GetPINTokenAuthenticator)
		message   string
	}{
		{
			name: "setMinPINLength is not boolean",
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.malformedSetMin = true
			},
			message: "invalid authenticatorGetInfo CBOR",
		},
		{
			name: "authnrCfg false",
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.authenticatorConfigEnabled = false
			},
			message: "authnrCfg must be present and true",
		},
		{
			name: "pinUvAuthToken absent",
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.pinUvAuthTokenPresent = false
			},
			message: "pinUvAuthToken must be present and true",
		},
		{
			name: "commands miss setMinPINLength",
			configure: func(f *clientPIN2GetPINTokenAuthenticator) {
				f.configCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandToggleAlwaysUv}
			},
			message: "does not contain setMinPINLength",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2GetPINTokenAuthenticator(t)
			test.configure(fixture)

			result, _ := runClientPIN2GetPINToken(t, fixture, TestIDAuthrClientPIN2GetPINTokenF4)
			assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusFailed)
			assertClientPIN2GetPINTokenMessage(t, result, test.message)
			assertClientPIN2GetPINTokenNoMutation(t, fixture)
		})
	}
}

func TestAuthrClientPIN2GetPINTokenConfigurationRequiresMinPINLengthExtensionBeforeMutation(t *testing.T) {
	for _, id := range []conformance.TestID{
		TestIDAuthrClientPIN2GetPINTokenF4,
		TestIDAuthrClientPIN2GetPINTokenF5,
	} {
		t.Run(string(id), func(t *testing.T) {
			fixture := newClientPIN2GetPINTokenAuthenticator(t)
			fixture.minPINLengthExtensionPresent = false

			result, _ := runClientPIN2GetPINToken(t, fixture, id)
			assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusFailed)
			assertClientPIN2GetPINTokenMessage(t, result, "does not contain minPinLength")
			assertClientPIN2GetPINTokenNoMutation(t, fixture)
			assertClientPIN2GetPINTokenStepReference(
				t,
				result,
				"client-pin2-get-pin-token.configuration-profile",
				clientPIN2GetPINTokenMinPINLengthExtensionReference(),
			)
		})
	}
}

func TestAuthrClientPIN2GetPINTokenStatusClassificationAndCleanup(t *testing.T) {
	t.Run("nonmatching CTAP status is failed", func(t *testing.T) {
		fixture := newClientPIN2GetPINTokenAuthenticator(t)
		fixture.credentialManagementStatus = ctaptransport.CTAP2_ERR_PIN_INVALID

		result, suppliedPIN := runClientPIN2GetPINToken(t, fixture, TestIDAuthrClientPIN2GetPINTokenF1)
		assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusFailed)
		assertClientPIN2GetPINTokenLifecycle(t, fixture, suppliedPIN)
	})

	t.Run("transport failure is error", func(t *testing.T) {
		fixture := newClientPIN2GetPINTokenAuthenticator(t)
		fixture.transportErrorCommand = protocol.AuthenticatorLargeBlobs

		result, suppliedPIN := runClientPIN2GetPINToken(t, fixture, TestIDAuthrClientPIN2GetPINTokenF3)
		assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusError)
		assertClientPIN2GetPINTokenLifecycle(t, fixture, suppliedPIN)
	})
}

func TestAuthrClientPIN2GetPINTokenEnvironmentErrorsDoNotMutate(t *testing.T) {
	fixture := newClientPIN2GetPINTokenAuthenticator(t)
	result := runClientPIN2GetPINTokenWithConfig(
		t,
		fixture,
		Config{Transport: AuthenticatorTransportHID},
		TestIDAuthrClientPIN2GetPINTokenP1,
	)
	assertClientPIN2GetPINTokenStatus(t, result, conformance.StatusError)
	assertClientPIN2GetPINTokenNoMutation(t, fixture)
}

func runClientPIN2GetPINToken(
	t *testing.T,
	fixture *clientPIN2GetPINTokenAuthenticator,
	id conformance.TestID,
) (conformance.SuiteResult, []byte) {
	t.Helper()

	var suppliedPIN []byte
	config := Config{
		Transport: AuthenticatorTransportHID,
		PowerCycler: func(context.Context) error {
			fixture.powerCycles++

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			fixture.reset()

			return nil
		},
		TemporaryPINProvider: func(_ context.Context, request TemporaryPINRequest) ([]byte, error) {
			if request.MinCodePoints != 4 || request.MaxCodePoints != 63 {
				return nil, fmt.Errorf("temporary PIN request = %#v, want 4..63", request)
			}
			suppliedPIN = []byte("1234")

			return suppliedPIN, nil
		},
	}

	return runClientPIN2GetPINTokenWithConfig(t, fixture, config, id), suppliedPIN
}

func runClientPIN2GetPINTokenWithConfig(
	t *testing.T,
	fixture *clientPIN2GetPINTokenAuthenticator,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrClientPIN2GetPINTokenTests(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("test %q not found", id)
	}

	runner, err := conformance.NewRunner(fixture)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "client-pin2-get-pin-token-test",
		Name:  "ClientPIN protocol 2 getPinToken test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertClientPIN2GetPINTokenStatus(t *testing.T, result conformance.SuiteResult, want conformance.Status) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertClientPIN2GetPINTokenMessage(t *testing.T, result conformance.SuiteResult, substring string) {
	t.Helper()

	for _, step := range result.Tests[0].Steps {
		if strings.Contains(step.Message, substring) {
			return
		}
	}
	t.Fatalf("steps = %#v, want message containing %q", result.Tests[0].Steps, substring)
}

func assertClientPIN2GetPINTokenReference(
	t *testing.T,
	references []conformance.RequirementRef,
	want conformance.RequirementRef,
) {
	t.Helper()

	if !slices.Contains(references, want) {
		t.Fatalf("references = %#v, want exact reference %#v", references, want)
	}
}

func assertClientPIN2GetPINTokenStepReference(
	t *testing.T,
	result conformance.SuiteResult,
	stepID conformance.StepID,
	want conformance.RequirementRef,
) {
	t.Helper()

	for _, step := range result.Tests[0].Steps {
		if step.ID == stepID {
			assertClientPIN2GetPINTokenReference(t, step.References, want)

			return
		}
	}
	t.Fatalf("steps = %#v, want step %q", result.Tests[0].Steps, stepID)
}

func assertClientPIN2GetPINTokenLifecycle(
	t *testing.T,
	fixture *clientPIN2GetPINTokenAuthenticator,
	suppliedPIN []byte,
) {
	t.Helper()

	if fixture.powerCycles != 2 || fixture.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 2/2", fixture.powerCycles, fixture.resets)
	}
	for index, value := range suppliedPIN {
		if value != 0 {
			t.Fatalf("temporary PIN byte %d = %x, want wiped", index, value)
		}
	}
	if fixture.pin != nil {
		t.Fatalf("authenticator PIN retained after cleanup: %x", fixture.pin)
	}
}

func assertClientPIN2GetPINTokenNoMutation(t *testing.T, fixture *clientPIN2GetPINTokenAuthenticator) {
	t.Helper()

	if fixture.powerCycles != 0 || fixture.resets != 0 || fixture.setPINCalls != 0 ||
		fixture.legacyTokenCalls != 0 || fixture.permissionTokenCalls != 0 || fixture.configCalls != 0 {
		t.Fatalf(
			"preflight mutated state: cycles=%d resets=%d setPIN=%d legacyToken=%d permissionToken=%d config=%d",
			fixture.powerCycles,
			fixture.resets,
			fixture.setPINCalls,
			fixture.legacyTokenCalls,
			fixture.permissionTokenCalls,
			fixture.configCalls,
		)
	}
}

type clientPIN2GetPINTokenAuthenticator struct {
	*clientPIN2NewPINAuthenticator

	legacyToken  []byte
	credentialID []byte

	noMcGaPresent                bool
	noMcGa                       bool
	credMgmtPresent              bool
	credMgmt                     bool
	rkPresent                    bool
	residentKeys                 bool
	bioEnrollPresent             bool
	bioEnroll                    bool
	largeBlobsPresent            bool
	largeBlobs                   bool
	minPINLengthExtensionPresent bool
	malformedSetMin              bool

	makeCredentialFlags protocol.AuthDataFlag
	getAssertionFlags   protocol.AuthDataFlag

	credentialManagementStatus ctaptransport.StatusCode
	bioEnrollmentStatus        ctaptransport.StatusCode
	largeBlobsStatus           ctaptransport.StatusCode
	configStatus               ctaptransport.StatusCode
	transportErrorCommand      protocol.Command

	legacyTokenCalls              int
	makeCredentialCalls           int
	getAssertionCalls             int
	makeCredentialWireValid       bool
	getAssertionWireValid         bool
	credentialManagementWireValid bool
	bioEnrollmentWireValid        bool
	largeBlobsWireValid           bool
	wrongConfigMACValid           bool
	correctConfigMACValid         bool
	hasCredential                 bool
}

func newClientPIN2GetPINTokenAuthenticator(t *testing.T) *clientPIN2GetPINTokenAuthenticator {
	t.Helper()

	base := newClientPIN2NewPINAuthenticator(t)
	fixture := &clientPIN2GetPINTokenAuthenticator{
		clientPIN2NewPINAuthenticator: base,
		legacyToken:                   bytes.Repeat([]byte{0x5a}, 32),
		credentialID:                  []byte{0x91, 0x27, 0x4b, 0xe0, 0x18, 0x63},
		credMgmtPresent:               true,
		credMgmt:                      true,
		rkPresent:                     true,
		residentKeys:                  true,
		bioEnrollPresent:              true,
		largeBlobsPresent:             true,
		largeBlobs:                    true,
		minPINLengthExtensionPresent:  true,
		makeCredentialFlags:           protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified,
		getAssertionFlags:             protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified,
		credentialManagementStatus:    ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
		bioEnrollmentStatus:           ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
		largeBlobsStatus:              ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
		configStatus:                  ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
	}
	t.Cleanup(func() {
		clear(fixture.legacyToken)
	})

	return fixture
}

func (a *clientPIN2GetPINTokenAuthenticator) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	a.t.Helper()

	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		a.t.Fatal("empty CTAP request")
	}
	command := protocol.Command(request[0])
	if command == a.transportErrorCommand {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected")
	}

	var response ctaptransport.CBORResponse
	switch command {
	case protocol.AuthenticatorGetInfo:
		response = a.getInfoResponse()
	case protocol.AuthenticatorClientPIN:
		var body protocol.AuthenticatorClientPINRequest
		if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
			a.t.Fatal(err)
		}
		if body.SubCommand == protocol.ClientPINSubCommandGetPinToken {
			response = a.getPinTokenResponse(body)
		} else {
			response = a.clientPINResponse(request[1:])
		}
	case protocol.AuthenticatorMakeCredential:
		response = a.makeCredentialResponse(request[1:])
	case protocol.AuthenticatorGetAssertion:
		response = a.getAssertionResponse(request[1:])
	case protocol.AuthenticatorCredentialManagement:
		response = a.credentialManagementResponse(request[1:])
	case protocol.AuthenticatorBioEnrollment:
		response = a.bioEnrollmentResponse(request[1:])
	case protocol.AuthenticatorLargeBlobs:
		response = a.largeBlobsResponse(request[1:])
	case protocol.AuthenticatorConfig:
		response = a.configResponse(request[1:])
	default:
		a.t.Fatalf("unexpected command %s", command)
	}

	return ctaptransport.ValidateCBORResponse(command, response)
}

func (a *clientPIN2GetPINTokenAuthenticator) getInfoResponse() ctaptransport.CBORResponse {
	options := map[protocol.Option]any{
		protocol.OptionClientPIN: a.pin != nil,
	}
	if a.noMcGaPresent {
		options[protocol.OptionNoMcGaPermissionsWithClientPin] = a.noMcGa
	}
	if a.credMgmtPresent {
		options[protocol.OptionCredentialManagement] = a.credMgmt
	}
	if a.rkPresent {
		options[protocol.OptionResidentKeys] = a.residentKeys
	}
	if a.bioEnrollPresent {
		options[protocol.OptionBioEnroll] = a.bioEnroll
	}
	if a.largeBlobsPresent {
		options[protocol.OptionLargeBlobs] = a.largeBlobs
	}
	if a.setMinPresent {
		if a.malformedSetMin {
			options[protocol.OptionSetMinPINLength] = uint64(1)
		} else {
			options[protocol.OptionSetMinPINLength] = a.setMinEnabled
		}
	}
	if a.authenticatorConfigPresent {
		options[protocol.OptionAuthenticatorConfig] = a.authenticatorConfigEnabled
	}
	if a.pinUvAuthTokenPresent {
		options[protocol.OptionPinUvAuthToken] = a.pinUvAuthTokenEnabled
	}

	extensions := []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret}
	if a.minPINLengthExtensionPresent {
		extensions = append(extensions, extension.ExtensionIdentifierMinPinLength)
	}

	fields := map[uint64]any{
		1: []protocol.Version{protocol.FIDO_2_3},
		2: extensions,
		3: uuid.Nil,
		4: options,
		6: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		10: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		13: uint(4),
		29: uint(63),
	}
	if a.configCommandsPresent {
		fields[31] = a.configCommands
	}

	return a.success(fields)
}

func (a *clientPIN2GetPINTokenAuthenticator) getPinTokenResponse(
	request protocol.AuthenticatorClientPINRequest,
) ctaptransport.CBORResponse {
	a.legacyTokenCalls++
	if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
		a.t.Fatalf("getPinToken protocol = %d, want 2", request.PinUvAuthProtocol)
	}

	sharedSecret := a.sharedSecret(request.KeyAgreement)
	defer clear(sharedSecret)
	pinHash := a.decrypt(sharedSecret, request.PinHashEnc)
	defer clear(pinHash)
	wantHash := sha256.Sum256(a.pin)
	defer clear(wantHash[:])
	if !bytes.Equal(pinHash, wantHash[:16]) || a.forcePINChange {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID}
	}
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolTwo)
	if err != nil {
		a.t.Fatal(err)
	}
	encryptedToken, err := pinProtocol.Encrypt(sharedSecret, a.legacyToken)
	if err != nil {
		a.t.Fatal(err)
	}

	return a.success(map[uint64]any{2: encryptedToken})
}

func (a *clientPIN2GetPINTokenAuthenticator) makeCredentialResponse(body []byte) ctaptransport.CBORResponse {
	a.makeCredentialCalls++

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	wantAuth := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, a.legacyToken, request.ClientDataHash)
	defer clear(wantAuth)
	a.makeCredentialWireValid = request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		request.RP.ID == clientPINRetryRPID &&
		bytes.Equal(request.PinUvAuthParam, wantAuth)
	if !a.makeCredentialWireValid {
		a.t.Fatalf("MakeCredential request = %#v", request)
	}
	a.hasCredential = true

	return a.success(protocol.AuthenticatorMakeCredentialResponse{
		Format: attestation.AttestationStatementFormatIdentifierNone,
		AuthDataRaw: clientPIN1NewPINMakeCredentialAuthData(
			a.t,
			a.makeCredentialFlags,
			a.credentialID,
		),
		AttestationStatement: map[string]any{},
	})
}

func (a *clientPIN2GetPINTokenAuthenticator) getAssertionResponse(body []byte) ctaptransport.CBORResponse {
	a.getAssertionCalls++

	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	wantAuth := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, a.legacyToken, request.ClientDataHash)
	defer clear(wantAuth)
	a.getAssertionWireValid = a.hasCredential &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		request.RPID == clientPINRetryRPID &&
		bytes.Equal(request.ClientDataHash, clientPIN2GetPINTokenAssertionHash[:]) &&
		bytes.Equal(request.PinUvAuthParam, wantAuth) &&
		len(request.AllowList) == 1 &&
		request.AllowList[0].Type == credential.PublicKeyCredentialTypePublicKey &&
		bytes.Equal(request.AllowList[0].ID, a.credentialID)
	if !a.getAssertionWireValid {
		a.t.Fatalf("GetAssertion request = %#v", request)
	}

	return a.success(protocol.AuthenticatorGetAssertionResponse{
		Credential: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   a.credentialID,
		},
		AuthDataRaw: clientPIN1NewPINGetAssertionAuthData(a.getAssertionFlags),
		Signature:   []byte{0x30, 0x00},
	})
}

func (a *clientPIN2GetPINTokenAuthenticator) credentialManagementResponse(
	body []byte,
) ctaptransport.CBORResponse {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		a.t.Fatal(err)
	}
	var request protocol.AuthenticatorCredentialManagementRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	want := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		a.legacyToken,
		[]byte{byte(protocol.CredentialManagementSubCommandGetCredsMetadata)},
	)
	defer clear(want)
	a.credentialManagementWireValid =
		request.SubCommand == protocol.CredentialManagementSubCommandGetCredsMetadata &&
			fields[2] == nil &&
			request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
			bytes.Equal(request.PinUvAuthParam, want)
	if !a.credentialManagementWireValid {
		a.t.Fatalf("credentialManagement request = %#v", request)
	}

	return ctaptransport.CBORResponse{StatusCode: a.credentialManagementStatus}
}

func (a *clientPIN2GetPINTokenAuthenticator) bioEnrollmentResponse(body []byte) ctaptransport.CBORResponse {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		a.t.Fatal(err)
	}
	var request protocol.AuthenticatorBioEnrollmentRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	message := slices.Concat(
		[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnrollBegin)},
		[]byte(fields[3]),
	)
	want := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, a.legacyToken, message)
	defer clear(want)
	a.bioEnrollmentWireValid =
		request.Modality == protocol.BioModalityFingerprint &&
			request.SubCommand == protocol.BioEnrollmentSubCommandEnrollBegin &&
			request.SubCommandParams.TimeoutMilliseconds == 10000 &&
			request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
			bytes.Equal(request.PinUvAuthParam, want)
	if !a.bioEnrollmentWireValid {
		a.t.Fatalf("bioEnrollment request = %#v", request)
	}

	return ctaptransport.CBORResponse{StatusCode: a.bioEnrollmentStatus}
}

func (a *clientPIN2GetPINTokenAuthenticator) largeBlobsResponse(body []byte) ctaptransport.CBORResponse {
	var request protocol.AuthenticatorLargeBlobsRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	dataHash := sha256.Sum256(request.Set)
	message := bytes.Repeat([]byte{0xff}, 32)
	message = append(message, 0x0c, 0x00)
	message = binary.LittleEndian.AppendUint32(message, uint32(request.Offset))
	message = append(message, dataHash[:]...)
	want := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, a.legacyToken, message)
	defer clear(want)
	a.largeBlobsWireValid =
		len(request.Set) >= 20 && len(request.Set) <= 100 &&
			request.Offset == 0 &&
			request.Length == uint(len(request.Set)) &&
			request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
			bytes.Equal(request.PinUvAuthParam, want)
	if !a.largeBlobsWireValid {
		a.t.Fatalf("largeBlobs request = %#v", request)
	}

	return ctaptransport.CBORResponse{StatusCode: a.largeBlobsStatus}
}

func (a *clientPIN2GetPINTokenAuthenticator) configResponse(body []byte) ctaptransport.CBORResponse {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		a.t.Fatal(err)
	}
	var request protocol.AuthenticatorConfigRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	var params protocol.SetMinPINLengthConfigSubCommandParams
	if err := getInfoDecMode.Unmarshal(fields[2], &params); err != nil {
		a.t.Fatal(err)
	}
	if request.SubCommand != protocol.ConfigSubCommandSetMinPINLength ||
		request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo ||
		!params.ForceChangePIN {
		a.t.Fatalf("authenticatorConfig request = %#v/%#v", request, params)
	}

	correctMessage := slices.Concat(
		bytes.Repeat([]byte{0xff}, 32),
		[]byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)},
		[]byte(fields[2]),
	)
	correct := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, a.configToken, correctMessage)
	defer clear(correct)
	wrongMessage := slices.Concat(
		bytes.Repeat([]byte{0xff}, 32),
		[]byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)},
	)
	wrong := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, a.legacyToken, wrongMessage)
	defer clear(wrong)

	switch {
	case bytes.Equal(request.PinUvAuthParam, correct):
		a.correctConfigMACValid = true
		a.forceWasSet = true
		a.forcePINChange = true

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
	case bytes.Equal(request.PinUvAuthParam, wrong):
		a.wrongConfigMACValid = !bytes.Equal(request.PinUvAuthParam, correct)

		return ctaptransport.CBORResponse{StatusCode: a.configStatus}
	default:
		a.t.Fatalf("unexpected authenticatorConfig pinUvAuthParam")

		return ctaptransport.CBORResponse{}
	}
}

func (a *clientPIN2GetPINTokenAuthenticator) reset() {
	a.clientPIN2NewPINAuthenticator.reset()
	a.hasCredential = false
}

var _ ctaptransport.CBOR = (*clientPIN2GetPINTokenAuthenticator)(nil)
