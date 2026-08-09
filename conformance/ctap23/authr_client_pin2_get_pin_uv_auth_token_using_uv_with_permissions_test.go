package ctap23

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN2UVPermissionsExactCasesAndReferences(t *testing.T) {
	tests := authrClientPIN2GetPinUvAuthTokenUsingUvWithPermissionsTests(Config{})
	want := []struct {
		id       conformance.TestID
		marker   string
		sections []string
	}{
		{id: TestIDAuthrClientPIN2UVPermissionsP1, marker: "P-1", sections: []string{"6.5.5.7.3", "6.5.7"}},
		{id: TestIDAuthrClientPIN2UVPermissionsP2, marker: "P-2", sections: []string{"6.5.5.7.3", "6.5.7", "6.1.2"}},
		{id: TestIDAuthrClientPIN2UVPermissionsP3, marker: "P-3", sections: []string{"6.5.5.7.3", "6.5.7", "6.1.2", "6.2.2"}},
		{id: TestIDAuthrClientPIN2UVPermissionsP4, marker: "P-4", sections: []string{"6.5.5.7.3", "6.5.7", "6.8.2"}},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrClientPIN2UVPermissionsSourcePath ||
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
		for _, section := range want[index].sections {
			assertClientPIN2HasReferenceSection(t, test, section)
		}
	}
}

func TestAuthrClientPIN2UVPermissionsP1ExactWireCryptoMaskAndToken(t *testing.T) {
	t.Run("all advertised UV permissions", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP1)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusPassed)
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)

		want := protocol.PermissionMakeCredential |
			protocol.PermissionGetAssertion |
			protocol.PermissionCredentialManagement |
			protocol.PermissionBioEnrollment |
			protocol.PermissionLargeBlobWrite |
			protocol.PermissionAuthenticatorConfiguration
		if !slices.Equal(fixture.permissionScopes, []protocol.Permission{want}) ||
			!slices.Equal(fixture.permissionRPIDs, []string{clientPIN2UVPermissionsRPID}) {
			t.Fatalf("permission requests = %v/%v, want [%d]/[%q]", fixture.permissionScopes, fixture.permissionRPIDs, want, clientPIN2UVPermissionsRPID)
		}
		if !fixture.permissionWiresExact || !fixture.permissionCryptoExact {
			t.Fatalf("wire/crypto exact = %t/%t", fixture.permissionWiresExact, fixture.permissionCryptoExact)
		}
	})

	t.Run("only mandatory permissions when optional capabilities are disabled", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		fixture.credentialManagementEnabled = false
		fixture.largeBlobsEnabled = false
		fixture.uvBioEnrollEnabled = false
		fixture.uvAcfgEnabled = false
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP1)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusPassed)
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)

		want := protocol.PermissionMakeCredential | protocol.PermissionGetAssertion
		if !slices.Equal(fixture.permissionScopes, []protocol.Permission{want}) ||
			!fixture.permissionWiresExact || !fixture.permissionCryptoExact {
			t.Fatalf("permission request/wire/crypto = %v/%t/%t, want [%d]/true/true", fixture.permissionScopes, fixture.permissionWiresExact, fixture.permissionCryptoExact, want)
		}
	})

	t.Run("wrong decrypted token length fails", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		fixture.permissionTokenLength = 16
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP1)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusFailed)
		assertClientPIN2UVPermissionsMessage(t, result, "16 bytes, want 32")
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
	})

	t.Run("client PIN status is conformance failure", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		fixture.permissionTokenStatus = ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP1)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusFailed)
		assertClientPIN2UVPermissionsMessage(t, result, "CTAP2_ERR_UNAUTHORIZED_PERMISSION")
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
	})

	t.Run("built-in UV token transport failure is an environment error", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		fixture.uvTokenTransportError = true
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP1)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusError)
		assertClientPIN2UVPermissionsMessage(t, result, "device disconnected during built-in UV")
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
	})
}

func TestAuthrClientPIN2UVPermissionsP2OwnCredentialAndFailureClassifications(t *testing.T) {
	t.Run("makeCredential-only token", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		fixture.credentialID = []byte("uv-permissions-p2-credential")
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP2)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusPassed)
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)

		if !slices.Equal(fixture.permissionScopes, []protocol.Permission{protocol.PermissionMakeCredential}) ||
			!slices.Equal(fixture.permissionRPIDs, []string{clientPIN2UVPermissionsRPID}) ||
			!slices.Equal(fixture.operations, []string{"token:1", "makeCredential"}) ||
			fixture.makeCredentialCalls != 1 || !fixture.makeCredentialExact {
			t.Fatalf("P-2 scope/RP/flow = %v/%v/%v make=%d exact=%t", fixture.permissionScopes, fixture.permissionRPIDs, fixture.operations, fixture.makeCredentialCalls, fixture.makeCredentialExact)
		}
	})

	for _, test := range []struct {
		name      string
		configure func(*clientPIN2UVPermissionsAuthenticator)
		status    conformance.Status
		message   string
	}{
		{
			name: "MakeCredential CTAP failure",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator) {
				fixture.makeCredentialStatus = ctaptransport.CTAP2_ERR_OPERATION_DENIED
			},
			status:  conformance.StatusFailed,
			message: "CTAP2_ERR_OPERATION_DENIED",
		},
		{
			name: "MakeCredential missing UV",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator) {
				fixture.makeCredentialUV = false
			},
			status:  conformance.StatusFailed,
			message: "no UV-verified credential ID",
		},
		{
			name: "MakeCredential transport failure",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator) {
				fixture.transportErrorCommand = protocol.AuthenticatorMakeCredential
			},
			status:  conformance.StatusError,
			message: "device disconnected",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2UVPermissionsAuthenticator(t)
			test.configure(fixture)
			result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP2)
			assertClientPIN2UVPermissionsStatus(t, result, test.status)
			assertClientPIN2UVPermissionsMessage(t, result, test.message)
			assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
		})
	}
}

func TestAuthrClientPIN2UVPermissionsP3IndependentCredentialAndTokenInvalidationOrder(t *testing.T) {
	p2 := newClientPIN2UVPermissionsAuthenticator(t)
	p2.credentialID = []byte("uv-permissions-p2-independent")
	p2Result, p2PIN := runClientPIN2UVPermissions(t, p2, TestIDAuthrClientPIN2UVPermissionsP2)
	assertClientPIN2UVPermissionsStatus(t, p2Result, conformance.StatusPassed)
	assertClientPIN2UVPermissionsLifecycle(t, p2Result, p2, p2PIN)

	p3 := newClientPIN2UVPermissionsAuthenticator(t)
	p3.credentialID = []byte("uv-permissions-p3-independent")
	p3Result, p3PIN := runClientPIN2UVPermissions(t, p3, TestIDAuthrClientPIN2UVPermissionsP3)
	assertClientPIN2UVPermissionsStatus(t, p3Result, conformance.StatusPassed)
	assertClientPIN2UVPermissionsLifecycle(t, p3Result, p3, p3PIN)

	if bytes.Equal(p2.credentialID, p3.credentialID) {
		t.Fatal("P-2 and P-3 credentials are not independent")
	}
	if !slices.Equal(p3.permissionScopes, []protocol.Permission{
		protocol.PermissionMakeCredential,
		protocol.PermissionGetAssertion,
	}) || !slices.Equal(p3.permissionRPIDs, []string{
		clientPIN2UVPermissionsRPID,
		clientPIN2UVPermissionsRPID,
	}) {
		t.Fatalf("P-3 permission requests = %v/%v", p3.permissionScopes, p3.permissionRPIDs)
	}
	if !slices.Equal(p3.operations, []string{"token:1", "makeCredential", "token:2", "getAssertion"}) ||
		!slices.Equal(p3.invalidatedAfterUse, []bool{true}) ||
		p3.makeCredentialCalls != 1 || p3.getAssertionCalls != 1 || !p3.getAssertionExact {
		t.Fatalf("P-3 flow/invalidation = %v/%v make=%d get=%d exact=%t", p3.operations, p3.invalidatedAfterUse, p3.makeCredentialCalls, p3.getAssertionCalls, p3.getAssertionExact)
	}

	for _, test := range []struct {
		name      string
		configure func(*clientPIN2UVPermissionsAuthenticator)
		message   string
	}{
		{
			name: "GetAssertion CTAP failure",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator) {
				fixture.getAssertionStatus = ctaptransport.CTAP2_ERR_NO_CREDENTIALS
			},
			message: "CTAP2_ERR_NO_CREDENTIALS",
		},
		{
			name: "GetAssertion missing UV",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator) {
				fixture.getAssertionUV = false
			},
			message: "UV flag is false",
		},
		{
			name: "successful status without assertion",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator) {
				fixture.emptyGetAssertion = true
			},
			message: "invalid authenticatorGetAssertion authData",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2UVPermissionsAuthenticator(t)
			test.configure(fixture)
			result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP3)
			assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusFailed)
			assertClientPIN2UVPermissionsMessage(t, result, test.message)
			assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
		})
	}
}

func TestAuthrClientPIN2UVPermissionsP4PCMROProofAndPrecondition(t *testing.T) {
	t.Run("pcmr token has no RP binding and authorizes GetCredsMetadata", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP4)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusPassed)
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
		assertClientPIN2UVPermissionsPCMRPreconditionReference(t, result)

		if !slices.Equal(fixture.permissionScopes, []protocol.Permission{protocol.PermissionPersistentCredentialManagementReadOnly}) ||
			!slices.Equal(fixture.permissionRPIDs, []string{""}) || fixture.credentialsMetadataCalls != 1 ||
			!fixture.credentialsMetadataExact || !fixture.permissionWiresExact || !fixture.permissionCryptoExact {
			t.Fatalf("P-4 scope/RP/metadata/wire/crypto = %v/%v/%d/%t/%t/%t", fixture.permissionScopes, fixture.permissionRPIDs, fixture.credentialsMetadataCalls, fixture.credentialsMetadataExact, fixture.permissionWiresExact, fixture.permissionCryptoExact)
		}
	})

	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprintf("perCredMgmtRO-present-%t-disabled", present), func(t *testing.T) {
			fixture := newClientPIN2UVPermissionsAuthenticator(t)
			fixture.perCredROPresent = present
			fixture.perCredROEnabled = false
			result, _ := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP4)
			assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusSkipped)
			assertClientPIN2UVPermissionsNoMutation(t, fixture)
		})
	}

	t.Run("malformed perCredMgmtRO fails before mutation", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		fixture.malformedPerCredRO = true
		result, _ := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP4)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusFailed)
		assertClientPIN2UVPermissionsNoMutation(t, fixture)
	})

	t.Run("GetCredsMetadata CTAP failure", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		fixture.credentialsMetadataStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP4)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusFailed)
		assertClientPIN2UVPermissionsMessage(t, result, "CTAP2_ERR_PIN_AUTH_INVALID")
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
	})
}

func TestAuthrClientPIN2UVPermissionsRawApplicabilityAndConfiguration(t *testing.T) {
	for _, test := range []struct {
		name       string
		configure  func(*clientPIN2UVPermissionsAuthenticator, *Config)
		wantStatus conformance.Status
		message    string
	}{
		{
			name: "uv absent skips",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator, _ *Config) {
				fixture.uvPresent = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "uv wrong wire type fails",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator, _ *Config) {
				fixture.malformedUV = true
			},
			wantStatus: conformance.StatusFailed,
			message:    "invalid authenticatorGetInfo CBOR",
		},
		{
			name: "non-featureful protocol 2 absent skips",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator, _ *Config) {
				fixture.protocolTwo = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "featureful protocol 2 absent fails",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator, config *Config) {
				fixture.protocolTwo = false
				config.Featureful = true
			},
			wantStatus: conformance.StatusFailed,
			message:    "featureful profile requires PIN/UV protocol 2",
		},
		{
			name: "missing power cycler is environment error",
			configure: func(_ *clientPIN2UVPermissionsAuthenticator, config *Config) {
				config.PowerCycler = nil
			},
			wantStatus: conformance.StatusError,
			message:    "power cycler is required",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2UVPermissionsAuthenticator(t)
			config, suppliedPIN := clientPIN2UVPermissionsConfig(fixture)
			test.configure(fixture, &config)
			result := runClientPIN2UVPermissionsWithConfig(t, fixture, config, TestIDAuthrClientPIN2UVPermissionsP1)
			assertClientPIN2UVPermissionsStatus(t, result, test.wantStatus)
			assertClientPIN2UVPermissionsNoMutation(t, fixture)
			if test.message != "" {
				assertClientPIN2UVPermissionsMessage(t, result, test.message)
			}
			assertClearedClientPIN2Buffer(t, suppliedPIN)
		})
	}

	t.Run("uv false is configured and refreshed to true", func(t *testing.T) {
		fixture := newClientPIN2UVPermissionsAuthenticator(t)
		result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP1)
		assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusPassed)
		assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
		if len(fixture.uvHistory) < 3 || fixture.uvHistory[len(fixture.uvHistory)-2] ||
			!fixture.uvHistory[len(fixture.uvHistory)-1] || fixture.uvConfiguratorCalls != 1 {
			t.Fatalf("uv history/configurator calls = %v/%d", fixture.uvHistory, fixture.uvConfiguratorCalls)
		}
	})

	for _, test := range []struct {
		name      string
		configure func(*clientPIN2UVPermissionsAuthenticator)
		message   string
	}{
		{
			name: "UV configurator failure is an environment error",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator) {
				fixture.uvConfiguratorError = errors.New("UV enrollment failed")
			},
			message: "UV enrollment failed",
		},
		{
			name: "UV configurator success without refreshed uv is an environment error",
			configure: func(fixture *clientPIN2UVPermissionsAuthenticator) {
				fixture.uvConfiguratorLeavesFalse = true
			},
			message: "UV configurator completed but GetInfo uv is not true",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2UVPermissionsAuthenticator(t)
			test.configure(fixture)
			result, suppliedPIN := runClientPIN2UVPermissions(t, fixture, TestIDAuthrClientPIN2UVPermissionsP1)
			assertClientPIN2UVPermissionsStatus(t, result, conformance.StatusError)
			assertClientPIN2UVPermissionsMessage(t, result, test.message)
			assertClientPIN2UVPermissionsLifecycle(t, result, fixture, suppliedPIN)
		})
	}
}

func runClientPIN2UVPermissions(
	t *testing.T,
	fixture *clientPIN2UVPermissionsAuthenticator,
	id conformance.TestID,
) (conformance.SuiteResult, []byte) {
	t.Helper()

	config, suppliedPIN := clientPIN2UVPermissionsConfig(fixture)

	return runClientPIN2UVPermissionsWithConfig(t, fixture, config, id), suppliedPIN
}

func runClientPIN2UVPermissionsWithConfig(
	t *testing.T,
	fixture *clientPIN2UVPermissionsAuthenticator,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrClientPIN2GetPinUvAuthTokenUsingUvWithPermissionsTests(config) {
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
		ID:    "client-pin2-uv-permissions-test",
		Name:  "ClientPIN protocol 2 built-in-UV permission-token test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func clientPIN2UVPermissionsConfig(fixture *clientPIN2UVPermissionsAuthenticator) (Config, []byte) {
	var suppliedPIN []byte
	config := clientPIN2NewPINConfig(fixture.clientPIN2NewPINAuthenticator, &suppliedPIN)
	config.Resetter = func(context.Context, *client.Client) error {
		fixture.reset()

		return nil
	}
	config.UVConfigurator = func(_ context.Context, pin []byte) error {
		fixture.uvConfiguratorCalls++
		fixture.uvConfiguratorPIN = pin
		if fixture.uvConfiguratorError != nil {
			return fixture.uvConfiguratorError
		}
		if !fixture.uvConfiguratorLeavesFalse {
			fixture.uvConfigured = true
		}

		return nil
	}

	return config, suppliedPIN
}

func assertClientPIN2UVPermissionsStatus(t *testing.T, result conformance.SuiteResult, want conformance.Status) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertClientPIN2UVPermissionsMessage(t *testing.T, result conformance.SuiteResult, substring string) {
	t.Helper()

	for _, step := range result.Tests[0].Steps {
		if strings.Contains(step.Message, substring) {
			return
		}
	}
	t.Fatalf("steps = %#v, want message containing %q", result.Tests[0].Steps, substring)
}

func assertClientPIN2UVPermissionsPCMRPreconditionReference(t *testing.T, result conformance.SuiteResult) {
	t.Helper()

	stepID := conformance.StepID("client-pin2-uv-permissions.per-cred-ro")
	want := conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.2:get-creds-metadata-pcmr-authorization",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.2",
		Clause:        "get-creds-metadata-pcmr-authorization",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getCredsMetadata",
		Level:         conformance.RequirementConstraint,
	}
	for _, step := range result.Tests[0].Steps {
		if step.ID == stepID {
			if len(step.References) != 2 || step.References[1] != want {
				t.Fatalf("step %s references = %#v, want %#v", stepID, step.References, want)
			}

			return
		}
	}
	t.Fatalf("steps = %#v, want step %s", result.Tests[0].Steps, stepID)
}

func assertClientPIN2UVPermissionsLifecycle(
	t *testing.T,
	result conformance.SuiteResult,
	fixture *clientPIN2UVPermissionsAuthenticator,
	suppliedPIN []byte,
) {
	t.Helper()

	if fixture.powerCycles != 2 || fixture.resets != 2 || fixture.setPINCalls != 1 ||
		fixture.uvConfiguratorCalls != 1 {
		t.Fatalf("power cycles/resets/setPIN/UV config = %d/%d/%d/%d, want 2/2/1/1", fixture.powerCycles, fixture.resets, fixture.setPINCalls, fixture.uvConfiguratorCalls)
	}
	steps := result.Tests[0].Steps
	if len(steps) == 0 || steps[len(steps)-1].ID != "client-pin2-uv-permissions.cleanup" ||
		steps[len(steps)-1].Status != conformance.StatusPassed {
		t.Fatalf("cleanup = %#v", steps)
	}
	assertClearedClientPIN2Buffer(t, suppliedPIN)
	assertClearedClientPIN2Buffer(t, fixture.uvConfiguratorPIN)
	if fixture.pin != nil {
		t.Fatalf("authenticator PIN retained after cleanup: %x", fixture.pin)
	}
	if fixture.activeToken != nil {
		t.Fatalf("active token retained after cleanup: %x", fixture.activeToken)
	}
	for index, secret := range fixture.tokenSecretBuffers {
		for _, value := range secret {
			if value != 0 {
				t.Fatalf("token secret %d was not wiped", index)
			}
		}
	}
}

func assertClientPIN2UVPermissionsNoMutation(t *testing.T, fixture *clientPIN2UVPermissionsAuthenticator) {
	t.Helper()

	if fixture.powerCycles != 0 || fixture.resets != 0 || fixture.setPINCalls != 0 ||
		fixture.uvConfiguratorCalls != 0 || len(fixture.permissionScopes) != 0 {
		t.Fatalf("preflight mutated state: cycles=%d resets=%d setPIN=%d UV config=%d tokens=%v", fixture.powerCycles, fixture.resets, fixture.setPINCalls, fixture.uvConfiguratorCalls, fixture.permissionScopes)
	}
}

type clientPIN2UVPermissionsAuthenticator struct {
	*clientPIN2PermissionsAuthenticator

	uvPresent                 bool
	uvConfigured              bool
	malformedUV               bool
	uvBioEnrollEnabled        bool
	uvAcfgEnabled             bool
	uvConfiguratorLeavesFalse bool
	uvConfiguratorError       error
	uvConfiguratorCalls       int
	uvConfiguratorPIN         []byte
	uvHistory                 []bool
	permissionCryptoExact     bool
	activePermission          protocol.Permission
	activeToken               []byte
	activeTokenUsed           bool
	invalidatedAfterUse       []bool
	tokenSecretBuffers        [][]byte
	makeCredentialUV          bool
	getAssertionUV            bool
	emptyGetAssertion         bool
	uvTokenTransportError     bool
}

func newClientPIN2UVPermissionsAuthenticator(t *testing.T) *clientPIN2UVPermissionsAuthenticator {
	t.Helper()

	return &clientPIN2UVPermissionsAuthenticator{
		clientPIN2PermissionsAuthenticator: newClientPIN2PermissionsAuthenticator(t),
		uvPresent:                          true,
		uvBioEnrollEnabled:                 true,
		uvAcfgEnabled:                      true,
		permissionCryptoExact:              true,
		makeCredentialUV:                   true,
		getAssertionUV:                     true,
	}
}

func (a *clientPIN2UVPermissionsAuthenticator) CBOR(
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
		if body.SubCommand != protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions {
			return a.clientPIN2PermissionsAuthenticator.CBOR(ctx, request)
		}
		if a.uvTokenTransportError {
			return ctaptransport.CBORResponse{}, errors.New("device disconnected during built-in UV")
		}
		response = a.permissionTokenResponse(request[1:], body)
	case protocol.AuthenticatorMakeCredential:
		a.useActiveToken(protocol.PermissionMakeCredential)
		response = a.makeCredentialResponse(request[1:])
		if response.StatusCode == ctaptransport.CTAP2_OK && !a.makeCredentialUV {
			response = a.withResponseUV(response, false)
		}
	case protocol.AuthenticatorGetAssertion:
		a.useActiveToken(protocol.PermissionGetAssertion)
		response = a.getAssertionResponse(request[1:])
		if response.StatusCode == ctaptransport.CTAP2_OK {
			switch {
			case a.emptyGetAssertion:
				response = a.success(map[uint64]any{})
			case !a.getAssertionUV:
				response = a.withResponseUV(response, false)
			}
		}
	case protocol.AuthenticatorCredentialManagement:
		a.useActiveToken(protocol.PermissionPersistentCredentialManagementReadOnly)
		response = a.clientPIN2PermissionsAuthenticator.credentialsMetadataResponse(request[1:])
	default:
		a.t.Fatalf("unexpected command %s", command)
	}

	return ctaptransport.ValidateCBORResponse(command, response)
}

func (a *clientPIN2UVPermissionsAuthenticator) getInfoResponse() ctaptransport.CBORResponse {
	base := a.clientPIN2PermissionsAuthenticator.permissionsGetInfoResponse()
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(base.Data, &fields); err != nil {
		a.t.Fatal(err)
	}
	var options map[string]any
	if err := getInfoDecMode.Unmarshal(fields[4], &options); err != nil {
		a.t.Fatal(err)
	}
	if a.uvPresent {
		if a.malformedUV {
			options[string(protocol.OptionUserVerification)] = uint64(1)
		} else {
			options[string(protocol.OptionUserVerification)] = a.uvConfigured
			a.uvHistory = append(a.uvHistory, a.uvConfigured)
		}
	}
	options[string(protocol.OptionUvBioEnroll)] = a.uvBioEnrollEnabled
	options[string(protocol.OptionUvAcfg)] = a.uvAcfgEnabled
	encodedOptions, err := ctap2EncMode.Marshal(options)
	if err != nil {
		a.t.Fatal(err)
	}
	fields[4] = encodedOptions
	data, err := ctap2EncMode.Marshal(fields)
	if err != nil {
		a.t.Fatal(err)
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

func (a *clientPIN2UVPermissionsAuthenticator) permissionTokenResponse(
	bodyBytes []byte,
	body protocol.AuthenticatorClientPINRequest,
) ctaptransport.CBORResponse {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(bodyBytes, &fields); err != nil {
		a.t.Fatal(err)
	}
	_, rpPresent := fields[10]
	wantRP := body.Permissions&(protocol.PermissionMakeCredential|protocol.PermissionGetAssertion) != 0
	wantFields := 4
	if wantRP {
		wantFields++
	}
	a.permissionWiresExact = a.permissionWiresExact &&
		body.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions &&
		fields[1] != nil && fields[2] != nil && fields[3] != nil && fields[9] != nil &&
		fields[4] == nil && fields[5] == nil && fields[6] == nil &&
		len(fields) == wantFields && rpPresent == wantRP
	a.permissionScopes = append(a.permissionScopes, body.Permissions)
	a.permissionRPIDs = append(a.permissionRPIDs, body.RPID)
	a.operations = append(a.operations, fmt.Sprintf("token:%d", body.Permissions))

	if a.permissionTokenStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.permissionTokenStatus}
	}

	sharedSecret := a.sharedSecret(body.KeyAgreement)
	defer clear(sharedSecret)
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolTwo)
	if err != nil {
		a.t.Fatal(err)
	}
	token := bytes.Repeat([]byte{byte(0x80 + len(a.permissionScopes))}, a.permissionTokenLength)
	defer clear(token)
	encryptedToken, err := pinProtocol.Encrypt(sharedSecret, token)
	if err != nil {
		a.t.Fatal(err)
	}
	defer clear(encryptedToken)
	decryptedToken, err := pinProtocol.Decrypt(sharedSecret, encryptedToken)
	if err != nil {
		a.t.Fatal(err)
	}
	a.permissionCryptoExact = a.permissionCryptoExact && len(sharedSecret) == 64 &&
		len(encryptedToken) == len(token)+16 && bytes.Equal(decryptedToken, token)
	clear(decryptedToken)

	if a.activeToken != nil {
		a.invalidatedAfterUse = append(a.invalidatedAfterUse, a.activeTokenUsed)
	}
	for _, previous := range a.issuedTokens {
		clear(previous)
	}
	issued := slices.Clone(token)
	a.tokenSecretBuffers = append(a.tokenSecretBuffers, issued)
	a.issuedTokens = map[protocol.Permission][]byte{body.Permissions: issued}
	a.activePermission = body.Permissions
	a.activeToken = issued
	a.activeTokenUsed = false

	return a.success(map[uint64]any{2: encryptedToken})
}

func (a *clientPIN2UVPermissionsAuthenticator) useActiveToken(permission protocol.Permission) {
	a.t.Helper()

	if a.activePermission != permission || a.activeToken == nil {
		a.t.Fatalf("active permission/token = %d/%x, want %d/non-empty", a.activePermission, a.activeToken, permission)
	}
	a.activeTokenUsed = true
}

func (a *clientPIN2UVPermissionsAuthenticator) makeCredentialResponse(bodyBytes []byte) ctaptransport.CBORResponse {
	a.makeCredentialCalls++
	a.operations = append(a.operations, "makeCredential")
	if a.makeCredentialStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.makeCredentialStatus}
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(bodyBytes, &fields); err != nil {
		a.t.Fatal(err)
	}
	if _, optionsPresent := fields[7]; optionsPresent {
		a.t.Fatal("MakeCredential request includes options key 7")
	}
	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(bodyBytes, &request); err != nil {
		a.t.Fatal(err)
	}
	wantAuth := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		a.issuedTokens[protocol.PermissionMakeCredential],
		request.ClientDataHash,
	)
	defer clear(wantAuth)
	a.makeCredentialExact = request.RP.ID == clientPIN2UVPermissionsRPID &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(request.PinUvAuthParam, wantAuth) &&
		len(request.ExcludeList) == 0
	if !a.makeCredentialExact {
		a.t.Fatalf("MakeCredential request = %#v", request)
	}

	authData := getAssertionFixtureMakeCredentialAuthData(a.t, a.credentialID)
	authData[32] |= byte(protocol.AuthDataFlagUserVerified)

	return a.success(map[uint64]any{
		1: "none",
		2: authData,
		3: map[string]any{},
	})
}

func (a *clientPIN2UVPermissionsAuthenticator) getAssertionResponse(bodyBytes []byte) ctaptransport.CBORResponse {
	a.getAssertionCalls++
	a.operations = append(a.operations, "getAssertion")
	if a.getAssertionStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.getAssertionStatus}
	}

	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(bodyBytes, &request); err != nil {
		a.t.Fatal(err)
	}
	wantAuth := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		a.issuedTokens[protocol.PermissionGetAssertion],
		request.ClientDataHash,
	)
	defer clear(wantAuth)
	a.getAssertionExact = request.RPID == clientPIN2UVPermissionsRPID &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(request.PinUvAuthParam, wantAuth) &&
		len(request.AllowList) == 1 &&
		request.AllowList[0].Type == credential.PublicKeyCredentialTypePublicKey &&
		bytes.Equal(request.AllowList[0].ID, a.credentialID)
	if !a.getAssertionExact {
		a.t.Fatalf("GetAssertion request = %#v", request)
	}

	authData := getAssertionFixtureAuthData()
	authData[32] |= byte(protocol.AuthDataFlagUserVerified)

	return a.success(map[uint64]any{
		1: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   slices.Clone(a.credentialID),
		},
		2: authData,
		3: []byte{0x30, 0x00},
	})
}

func (a *clientPIN2UVPermissionsAuthenticator) withResponseUV(
	response ctaptransport.CBORResponse,
	enabled bool,
) ctaptransport.CBORResponse {
	a.t.Helper()

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(response.Data, &fields); err != nil {
		a.t.Fatal(err)
	}
	var authData []byte
	if err := getInfoDecMode.Unmarshal(fields[2], &authData); err != nil {
		a.t.Fatal(err)
	}
	if enabled {
		authData[32] |= byte(protocol.AuthDataFlagUserVerified)
	} else {
		authData[32] &^= byte(protocol.AuthDataFlagUserVerified)
	}
	encodedAuthData, err := ctap2EncMode.Marshal(authData)
	if err != nil {
		a.t.Fatal(err)
	}
	fields[2] = encodedAuthData
	data, err := ctap2EncMode.Marshal(fields)
	if err != nil {
		a.t.Fatal(err)
	}

	return ctaptransport.CBORResponse{StatusCode: response.StatusCode, Data: data}
}

func (a *clientPIN2UVPermissionsAuthenticator) reset() {
	a.clientPIN2NewPINAuthenticator.reset()
	a.uvConfigured = false
	for _, token := range a.issuedTokens {
		clear(token)
	}
	a.issuedTokens = make(map[protocol.Permission][]byte)
	a.activePermission = protocol.PermissionNone
	a.activeToken = nil
	a.activeTokenUsed = false
}

var _ ctaptransport.CBOR = (*clientPIN2UVPermissionsAuthenticator)(nil)
