package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN2PermissionsExactMarkersReferencesAndLifecycleContract(t *testing.T) {
	tests := authrClientPIN2GetPinUvAuthTokenUsingPinWithPermissionsTests(Config{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{id: TestIDAuthrClientPIN2PermissionsP1, marker: "P-1"},
		{id: TestIDAuthrClientPIN2PermissionsP2, marker: "P-2"},
		{id: TestIDAuthrClientPIN2PermissionsP3, marker: "P-3"},
		{id: TestIDAuthrClientPIN2PermissionsP4, marker: "P-4"},
		{id: TestIDAuthrClientPIN2PermissionsF1, marker: "F-1"},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrClientPIN2PermissionsSourcePath ||
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

	for _, test := range tests {
		assertClientPIN2HasReferenceSection(t, test, "6.5.5.7.2")
		assertClientPIN2HasReferenceSection(t, test, "6.5.7")
	}
	assertClientPIN2HasReferenceSection(t, tests[1], "6.1.2")
	assertClientPIN2HasReferenceSection(t, tests[2], "6.1.2")
	assertClientPIN2HasReferenceSection(t, tests[2], "6.2.2")
	assertClientPIN2HasReferenceSection(t, tests[3], "6.8.2")
	assertClientPIN2HasReferenceSection(t, tests[4], "6.11.4")
	for _, reference := range tests[3].References {
		if reference.Section == "6.8.3" {
			t.Fatalf("P-4 retains obsolete enumerate-RPs reference: %#v", reference)
		}
	}

	exact := []struct {
		got     conformance.RequirementRef
		section string
		clause  string
		anchor  string
		level   conformance.RequirementLevel
	}{
		{
			got:     clientPIN2PermissionsOperationReference(),
			section: "6.5.5.7.2",
			clause:  "get-pin-uv-auth-token-using-pin-with-permissions",
			anchor:  "#getPinUvAuthTokenUsingPinWithPermissions",
			level:   conformance.RequirementConstraint,
		},
		{
			got:     clientPIN2PermissionsTokenLengthReference(),
			section: "6.5.7",
			clause:  "protocol-two-pin-uv-auth-token-length",
			anchor:  "#pinProto2",
			level:   conformance.RequirementMust,
		},
		{
			got:     clientPIN2PermissionsMakeCredentialUVReference(),
			section: "6.1.2",
			clause:  "pin-uv-authenticated-make-credential-sets-uv",
			anchor:  "#op-makecred-step-performBuiltInUv",
			level:   conformance.RequirementMust,
		},
		{
			got:     clientPIN2PermissionsGetAssertionUVReference(),
			section: "6.2.2",
			clause:  "pin-uv-authenticated-get-assertion-sets-uv",
			anchor:  "#op-getassert-step-performBuiltInUv",
			level:   conformance.RequirementMust,
		},
		{
			got:     clientPIN2PermissionsPCMRReference(),
			section: "6.8.2",
			clause:  "get-creds-metadata-pcmr-authorization",
			anchor:  "#getCredsMetadata",
			level:   conformance.RequirementConstraint,
		},
	}
	for _, want := range exact {
		if want.got.Section != want.section || want.got.Clause != want.clause ||
			!strings.HasSuffix(want.got.URL, want.anchor) || want.got.Level != want.level {
			t.Fatalf("reference = %#v, want section/clause/anchor/level %s/%s/%s/%s", want.got, want.section, want.clause, want.anchor, want.level)
		}
	}
}

func TestAuthrClientPIN2PermissionsP1UsesExactAdvertisedMaskAndRPID(t *testing.T) {
	fixture := newClientPIN2PermissionsAuthenticator(t)
	result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP1)
	assertClientPIN2PermissionsStatus(t, result, conformance.StatusPassed)
	assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	assertClientPIN2PermissionsStepReferences(t, result, "client-pin2-permissions.p-1.issue", "6.5.5.7.2", "6.5.7")

	want := protocol.PermissionMakeCredential |
		protocol.PermissionGetAssertion |
		protocol.PermissionCredentialManagement |
		protocol.PermissionBioEnrollment |
		protocol.PermissionLargeBlobWrite |
		protocol.PermissionAuthenticatorConfiguration
	if !slices.Equal(fixture.permissionScopes, []protocol.Permission{want}) ||
		!slices.Equal(fixture.permissionRPIDs, []string{clientPIN2PermissionsRPID}) {
		t.Fatalf("permission requests = %v/%v, want [%d]/[%q]", fixture.permissionScopes, fixture.permissionRPIDs, want, clientPIN2PermissionsRPID)
	}
	if !fixture.permissionWiresExact {
		t.Fatal("permission request did not use the exact protocol 2 wire shape")
	}
}

func TestAuthrClientPIN2PermissionsP1PresenceAndZeroMaskSemantics(t *testing.T) {
	t.Run("bioEnroll false remains available and noMcGa removes RP scope", func(t *testing.T) {
		fixture := newClientPIN2PermissionsAuthenticator(t)
		fixture.noMCGAPresent = true
		fixture.noMCGAEnabled = true
		fixture.credentialManagementEnabled = false
		fixture.largeBlobsEnabled = false
		fixture.clientPIN2NewPINAuthenticator.authenticatorConfigEnabled = false

		result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP1)
		assertClientPIN2PermissionsStatus(t, result, conformance.StatusPassed)
		assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
		if !slices.Equal(fixture.permissionScopes, []protocol.Permission{protocol.PermissionBioEnrollment}) ||
			!slices.Equal(fixture.permissionRPIDs, []string{""}) {
			t.Fatalf("permission requests = %v/%v, want bioEnroll/empty RP ID", fixture.permissionScopes, fixture.permissionRPIDs)
		}
	})

	t.Run("no advertised non-pcmr permission skips", func(t *testing.T) {
		fixture := newClientPIN2PermissionsAuthenticator(t)
		fixture.noMCGAPresent = true
		fixture.noMCGAEnabled = true
		fixture.credentialManagementEnabled = false
		fixture.bioEnrollPresent = false
		fixture.largeBlobsEnabled = false
		fixture.clientPIN2NewPINAuthenticator.authenticatorConfigEnabled = false

		result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP1)
		assertClientPIN2PermissionsStatus(t, result, conformance.StatusSkipped)
		assertClientPIN2PermissionsNoMutation(t, fixture)
		if suppliedPIN != nil {
			t.Fatalf("TemporaryPIN provider returned %x before zero-mask skip", suppliedPIN)
		}
		if len(fixture.permissionScopes) != 0 {
			t.Fatalf("permission requests = %v, want none", fixture.permissionScopes)
		}
	})
}

func TestAuthrClientPIN2PermissionsP2UsesMCOnlyImmediatelyForDiscoverableCredential(t *testing.T) {
	fixture := newClientPIN2PermissionsAuthenticator(t)
	result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP2)
	assertClientPIN2PermissionsStatus(t, result, conformance.StatusPassed)
	assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	assertClientPIN2PermissionsStepReferences(t, result, "client-pin2-permissions.p-2.make-credential", "6.5.5.7.2", "6.5.7", "6.1.2")

	if !slices.Equal(fixture.permissionScopes, []protocol.Permission{protocol.PermissionMakeCredential}) ||
		!slices.Equal(fixture.permissionRPIDs, []string{clientPIN2PermissionsRPID}) {
		t.Fatalf("permission requests = %v/%v, want mc/%q", fixture.permissionScopes, fixture.permissionRPIDs, clientPIN2PermissionsRPID)
	}
	if !slices.Equal(fixture.operations, []string{"token:1", "makeCredential"}) ||
		fixture.makeCredentialCalls != 1 || !fixture.makeCredentialExact {
		t.Fatalf("operations/make exact = %v/%d/%t", fixture.operations, fixture.makeCredentialCalls, fixture.makeCredentialExact)
	}
}

func TestAuthrClientPIN2PermissionsP2NoMCGASkipsBeforeMutation(t *testing.T) {
	fixture := newClientPIN2PermissionsAuthenticator(t)
	fixture.noMCGAPresent = true
	fixture.noMCGAEnabled = true
	result, _ := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP2)
	assertClientPIN2PermissionsStatus(t, result, conformance.StatusSkipped)
	assertClientPIN2PermissionsNoMutation(t, fixture)
}

func TestAuthrClientPIN2PermissionsP3OwnCredentialAndFreshGAToken(t *testing.T) {
	fixture := newClientPIN2PermissionsAuthenticator(t)
	result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP3)
	assertClientPIN2PermissionsStatus(t, result, conformance.StatusPassed)
	assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	assertClientPIN2PermissionsStepReferences(t, result, "client-pin2-permissions.p-3.make-credential", "6.5.5.7.2", "6.5.7", "6.1.2")
	assertClientPIN2PermissionsStepReferences(t, result, "client-pin2-permissions.p-3.get-assertion", "6.5.5.7.2", "6.5.7", "6.2.2")

	if !slices.Equal(fixture.permissionScopes, []protocol.Permission{
		protocol.PermissionMakeCredential,
		protocol.PermissionGetAssertion,
	}) || !slices.Equal(fixture.permissionRPIDs, []string{
		clientPIN2PermissionsRPID,
		clientPIN2PermissionsRPID,
	}) {
		t.Fatalf("permission requests = %v/%v", fixture.permissionScopes, fixture.permissionRPIDs)
	}
	if !slices.Equal(fixture.operations, []string{"token:1", "makeCredential", "token:2", "getAssertion"}) ||
		fixture.makeCredentialCalls != 1 || fixture.getAssertionCalls != 1 || !fixture.getAssertionExact {
		t.Fatalf("independent P-3 flow = %v make=%d get=%d exact=%t", fixture.operations, fixture.makeCredentialCalls, fixture.getAssertionCalls, fixture.getAssertionExact)
	}
}

func TestAuthrClientPIN2PermissionsP4UsesPCMROnlyWithoutRPID(t *testing.T) {
	fixture := newClientPIN2PermissionsAuthenticator(t)
	result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP4)
	assertClientPIN2PermissionsStatus(t, result, conformance.StatusPassed)
	assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	assertClientPIN2PermissionsStepReferences(t, result, "client-pin2-permissions.p-4.credentials-metadata", "6.5.5.7.2", "6.5.7", "6.8.2")

	if !slices.Equal(fixture.permissionScopes, []protocol.Permission{protocol.PermissionPersistentCredentialManagementReadOnly}) ||
		!slices.Equal(fixture.permissionRPIDs, []string{""}) || fixture.credentialsMetadataCalls != 1 ||
		!fixture.credentialsMetadataExact {
		t.Fatalf("P-4 scope/RP/metadata = %v/%v/%d/%t", fixture.permissionScopes, fixture.permissionRPIDs, fixture.credentialsMetadataCalls, fixture.credentialsMetadataExact)
	}
}

func TestAuthrClientPIN2PermissionsP4PreconditionSkipsBeforeMutation(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprintf("present-%t", present), func(t *testing.T) {
			fixture := newClientPIN2PermissionsAuthenticator(t)
			fixture.clientPIN2NewPINAuthenticator.perCredROPresent = present
			fixture.clientPIN2NewPINAuthenticator.perCredROEnabled = false
			result, _ := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP4)
			assertClientPIN2PermissionsStatus(t, result, conformance.StatusSkipped)
			assertClientPIN2PermissionsNoMutation(t, fixture)
		})
	}

	t.Run("malformed", func(t *testing.T) {
		fixture := newClientPIN2PermissionsAuthenticator(t)
		fixture.clientPIN2NewPINAuthenticator.malformedPerCredRO = true
		result, _ := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP4)
		assertClientPIN2PermissionsStatus(t, result, conformance.StatusFailed)
		assertClientPIN2PermissionsNoMutation(t, fixture)
	})
}

func TestAuthrClientPIN2PermissionsF1RequiresExactPolicyViolation(t *testing.T) {
	t.Run("policy violation passes", func(t *testing.T) {
		fixture := newClientPIN2PermissionsAuthenticator(t)
		result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsF1)
		assertClientPIN2PermissionsStatus(t, result, conformance.StatusPassed)
		assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
		assertClientPIN2PermissionsStepReferences(t, result, "client-pin2-permissions.f-1.force-change", "6.5.5.7.2", "6.5.7", "6.11.4")
		if !slices.Equal(fixture.permissionScopes, []protocol.Permission{
			protocol.PermissionAuthenticatorConfiguration,
			protocol.PermissionAuthenticatorConfiguration,
		}) || fixture.configCalls != 1 || !fixture.forceWasSet {
			t.Fatalf("F-1 token/config flow = %v/%d/%t", fixture.permissionScopes, fixture.configCalls, fixture.forceWasSet)
		}
	})

	t.Run("PIN_INVALID is not accepted", func(t *testing.T) {
		fixture := newClientPIN2PermissionsAuthenticator(t)
		fixture.forcePINChangeStatus = ctaptransport.CTAP2_ERR_PIN_INVALID
		result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsF1)
		assertClientPIN2PermissionsStatus(t, result, conformance.StatusFailed)
		assertClientPIN2PermissionsMessage(t, result, "want CTAP2_ERR_PIN_POLICY_VIOLATION")
		assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	})
}

func TestAuthrClientPIN2PermissionsF1FullSetMinProfilePreflight(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*clientPIN2PermissionsAuthenticator)
		wantStatus conformance.Status
		message    string
		mutates    bool
	}{
		{
			name: "initial clientPin false is applicable",
			configure: func(*clientPIN2PermissionsAuthenticator) {
			},
			wantStatus: conformance.StatusPassed,
			mutates:    true,
		},
		{
			name: "setMinPINLength disabled",
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.setMinEnabled = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "authnrCfg disabled",
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.authenticatorConfigEnabled = false
			},
			wantStatus: conformance.StatusFailed,
			message:    "authnrCfg must be present and true",
		},
		{
			name: "setMin command absent",
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.configCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandToggleAlwaysUv}
			},
			wantStatus: conformance.StatusFailed,
			message:    "does not contain setMinPINLength",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2PermissionsAuthenticator(t)
			test.configure(fixture)
			result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsF1)
			assertClientPIN2PermissionsStatus(t, result, test.wantStatus)
			if test.mutates {
				assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
			} else {
				assertClientPIN2PermissionsNoMutation(t, fixture)
			}
			if test.message != "" {
				assertClientPIN2PermissionsMessage(t, result, test.message)
			}
		})
	}
}

func TestAuthrClientPIN2PermissionsCommonProfileAndEnvironmentPreflight(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*clientPIN2PermissionsAuthenticator, *Config)
		wantStatus conformance.Status
		message    string
	}{
		{
			name: "clientPin absent",
			configure: func(fixture *clientPIN2PermissionsAuthenticator, _ *Config) {
				fixture.clientPINPresent = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "non-featureful protocol 2 absent",
			configure: func(fixture *clientPIN2PermissionsAuthenticator, _ *Config) {
				fixture.protocolTwo = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "featureful protocol 2 absent",
			configure: func(fixture *clientPIN2PermissionsAuthenticator, config *Config) {
				fixture.protocolTwo = false
				config.Featureful = true
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name: "non-featureful pinUvAuthToken false",
			configure: func(fixture *clientPIN2PermissionsAuthenticator, _ *Config) {
				fixture.pinUvAuthTokenEnabled = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "featureful pinUvAuthToken absent",
			configure: func(fixture *clientPIN2PermissionsAuthenticator, config *Config) {
				fixture.pinUvAuthTokenPresent = false
				config.Featureful = true
			},
			wantStatus: conformance.StatusFailed,
			message:    "pinUvAuthToken",
		},
		{
			name: "power cycler missing",
			configure: func(_ *clientPIN2PermissionsAuthenticator, config *Config) {
				config.PowerCycler = nil
			},
			wantStatus: conformance.StatusError,
		},
		{
			name: "temporary PIN provider missing",
			configure: func(_ *clientPIN2PermissionsAuthenticator, config *Config) {
				config.TemporaryPINProvider = nil
			},
			wantStatus: conformance.StatusError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2PermissionsAuthenticator(t)
			config := clientPIN2NewPINConfig(fixture.clientPIN2NewPINAuthenticator, nil)
			test.configure(fixture, &config)
			result := runClientPIN2PermissionsWithConfig(t, fixture, config, TestIDAuthrClientPIN2PermissionsP2)
			assertClientPIN2PermissionsStatus(t, result, test.wantStatus)
			assertClientPIN2PermissionsNoMutation(t, fixture)
			if test.message != "" {
				assertClientPIN2PermissionsMessage(t, result, test.message)
			}
		})
	}
}

func TestAuthrClientPIN2PermissionsTokenLengthStatusAndTransportClassification(t *testing.T) {
	t.Run("wrong token length fails before downstream", func(t *testing.T) {
		fixture := newClientPIN2PermissionsAuthenticator(t)
		fixture.permissionTokenLength = 16
		result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP2)
		assertClientPIN2PermissionsStatus(t, result, conformance.StatusFailed)
		assertClientPIN2PermissionsMessage(t, result, "16 bytes, want 32")
		assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
		if fixture.makeCredentialCalls != 0 {
			t.Fatalf("MakeCredential calls = %d, want 0", fixture.makeCredentialCalls)
		}
	})

	t.Run("unexpected CTAP status fails", func(t *testing.T) {
		fixture := newClientPIN2PermissionsAuthenticator(t)
		fixture.permissionTokenStatus = ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION
		result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP2)
		assertClientPIN2PermissionsStatus(t, result, conformance.StatusFailed)
		assertClientPIN2PermissionsMessage(t, result, "CTAP2_ERR_UNAUTHORIZED_PERMISSION")
		assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	})

	t.Run("transport failure is an error", func(t *testing.T) {
		fixture := newClientPIN2PermissionsAuthenticator(t)
		fixture.transportErrorCommand = protocol.AuthenticatorMakeCredential
		result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP2)
		assertClientPIN2PermissionsStatus(t, result, conformance.StatusError)
		assertClientPIN2PermissionsMessage(t, result, "device disconnected")
		assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	})
}

func TestAuthrClientPIN2PermissionsDownstreamNonconformance(t *testing.T) {
	tests := []struct {
		name               string
		id                 conformance.TestID
		configure          func(*clientPIN2PermissionsAuthenticator)
		message            string
		wantMakeCalls      int
		wantAssertionCalls int
	}{
		{
			name: "P-2 MakeCredential CTAP failure",
			id:   TestIDAuthrClientPIN2PermissionsP2,
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.makeCredentialStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
			},
			message:       "CTAP2_ERR_PIN_AUTH_INVALID",
			wantMakeCalls: 1,
		},
		{
			name: "P-2 MakeCredential missing UV",
			id:   TestIDAuthrClientPIN2PermissionsP2,
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.makeCredentialMissingUV = true
			},
			message:       "no UV-verified credential ID",
			wantMakeCalls: 1,
		},
		{
			name: "P-3 MakeCredential CTAP failure",
			id:   TestIDAuthrClientPIN2PermissionsP3,
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.makeCredentialStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
			},
			message:       "CTAP2_ERR_PIN_AUTH_INVALID",
			wantMakeCalls: 1,
		},
		{
			name: "P-3 MakeCredential missing UV",
			id:   TestIDAuthrClientPIN2PermissionsP3,
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.makeCredentialMissingUV = true
			},
			message:       "no UV-verified credential ID",
			wantMakeCalls: 1,
		},
		{
			name: "P-3 GetAssertion CTAP failure",
			id:   TestIDAuthrClientPIN2PermissionsP3,
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.getAssertionStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
			},
			message:            "CTAP2_ERR_PIN_AUTH_INVALID",
			wantMakeCalls:      1,
			wantAssertionCalls: 1,
		},
		{
			name: "P-3 GetAssertion missing UV",
			id:   TestIDAuthrClientPIN2PermissionsP3,
			configure: func(fixture *clientPIN2PermissionsAuthenticator) {
				fixture.getAssertionMissingUV = true
			},
			message:            "UV flag is false",
			wantMakeCalls:      1,
			wantAssertionCalls: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2PermissionsAuthenticator(t)
			test.configure(fixture)
			result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, test.id)
			assertClientPIN2PermissionsStatus(t, result, conformance.StatusFailed)
			assertClientPIN2PermissionsMessage(t, result, test.message)
			assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
			if fixture.makeCredentialCalls != test.wantMakeCalls || fixture.getAssertionCalls != test.wantAssertionCalls {
				t.Fatalf("downstream calls = make %d/get %d, want %d/%d", fixture.makeCredentialCalls, fixture.getAssertionCalls, test.wantMakeCalls, test.wantAssertionCalls)
			}
		})
	}
}

func TestClientPIN2ValidateAssertionsRejectsEmptySequence(t *testing.T) {
	var assertions iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] = func(func(protocol.AuthenticatorGetAssertionResponse, error) bool) {}
	err := clientPIN2ValidateAssertions(assertions)
	var assertion *conformance.AssertionError
	if !errors.As(err, &assertion) {
		t.Fatalf("error = %v, want assertion failure for no assertion", err)
	}
	if !strings.Contains(fmt.Sprint(err), "returned no assertion") {
		t.Fatalf("error = %v, want assertion failure for no assertion", err)
	}
}

func TestAuthrClientPIN2PermissionsP4GetCredsMetadataFailure(t *testing.T) {
	fixture := newClientPIN2PermissionsAuthenticator(t)
	fixture.credentialsMetadataStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
	result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsP4)
	assertClientPIN2PermissionsStatus(t, result, conformance.StatusFailed)
	assertClientPIN2PermissionsMessage(t, result, "CTAP2_ERR_PIN_AUTH_INVALID")
	assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	if fixture.credentialsMetadataCalls != 1 {
		t.Fatalf("GetCredsMetadata calls = %d, want 1", fixture.credentialsMetadataCalls)
	}
}

func TestAuthrClientPIN2PermissionsF1AuthenticatorConfigFailure(t *testing.T) {
	fixture := newClientPIN2PermissionsAuthenticator(t)
	fixture.authenticatorConfigStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
	result, suppliedPIN := runClientPIN2Permissions(t, fixture, Config{}, TestIDAuthrClientPIN2PermissionsF1)
	assertClientPIN2PermissionsStatus(t, result, conformance.StatusFailed)
	assertClientPIN2PermissionsMessage(t, result, "CTAP2_ERR_PIN_AUTH_INVALID")
	assertClientPIN2PermissionsLifecycle(t, result, fixture, suppliedPIN)
	if fixture.configCalls != 0 || !slices.Equal(fixture.operations, []string{"token:32", "config"}) {
		t.Fatalf("config failure flow = calls %d/operations %v", fixture.configCalls, fixture.operations)
	}
}

func runClientPIN2Permissions(
	t *testing.T,
	fixture *clientPIN2PermissionsAuthenticator,
	override Config,
	id conformance.TestID,
) (conformance.SuiteResult, []byte) {
	t.Helper()

	var suppliedPIN []byte
	config := clientPIN2NewPINConfig(fixture.clientPIN2NewPINAuthenticator, &suppliedPIN)
	config.Featureful = override.Featureful
	config.Transport = override.Transport

	return runClientPIN2PermissionsWithConfig(t, fixture, config, id), suppliedPIN
}

func runClientPIN2PermissionsWithConfig(
	t *testing.T,
	fixture *clientPIN2PermissionsAuthenticator,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrClientPIN2GetPinUvAuthTokenUsingPinWithPermissionsTests(config) {
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
		ID:    "client-pin2-permissions-test",
		Name:  "ClientPIN protocol 2 PIN permission-token test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertClientPIN2PermissionsStatus(t *testing.T, result conformance.SuiteResult, want conformance.Status) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertClientPIN2PermissionsMessage(t *testing.T, result conformance.SuiteResult, substring string) {
	t.Helper()

	for _, step := range result.Tests[0].Steps {
		if strings.Contains(step.Message, substring) {
			return
		}
	}
	t.Fatalf("steps = %#v, want message containing %q", result.Tests[0].Steps, substring)
}

func assertClientPIN2PermissionsStepReferences(
	t *testing.T,
	result conformance.SuiteResult,
	stepID conformance.StepID,
	sections ...string,
) {
	t.Helper()

	for _, step := range result.Tests[0].Steps {
		if step.ID != stepID {
			continue
		}
		for _, section := range sections {
			found := false
			for _, reference := range step.References {
				if reference.Section == section {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("step %s references = %#v, want section %s", stepID, step.References, section)
			}
		}

		return
	}
	t.Fatalf("steps = %#v, want step %s", result.Tests[0].Steps, stepID)
}

func assertClientPIN2PermissionsLifecycle(
	t *testing.T,
	result conformance.SuiteResult,
	fixture *clientPIN2PermissionsAuthenticator,
	suppliedPIN []byte,
) {
	t.Helper()

	if fixture.powerCycles != 2 || fixture.resets != 2 || fixture.setPINCalls != 1 {
		t.Fatalf("power cycles/resets/setPIN = %d/%d/%d, want 2/2/1", fixture.powerCycles, fixture.resets, fixture.setPINCalls)
	}
	steps := result.Tests[0].Steps
	if len(steps) == 0 || steps[len(steps)-1].ID != "client-pin2-permissions.cleanup" ||
		steps[len(steps)-1].Status != conformance.StatusPassed {
		t.Fatalf("cleanup = %#v", steps)
	}
	assertClearedClientPIN2Buffer(t, suppliedPIN)
	if fixture.pin != nil {
		t.Fatalf("authenticator PIN retained after cleanup: %x", fixture.pin)
	}
}

func assertClientPIN2PermissionsNoMutation(t *testing.T, fixture *clientPIN2PermissionsAuthenticator) {
	t.Helper()

	if fixture.powerCycles != 0 || fixture.resets != 0 || fixture.setPINCalls != 0 ||
		fixture.configCalls != 0 || fixture.makeCredentialCalls != 0 || fixture.getAssertionCalls != 0 ||
		fixture.credentialsMetadataCalls != 0 || len(fixture.permissionScopes) != 0 || len(fixture.operations) != 0 {
		t.Fatalf(
			"preflight mutated state: cycles=%d resets=%d setPIN=%d config=%d make=%d get=%d metadata=%d scopes=%v operations=%v",
			fixture.powerCycles,
			fixture.resets,
			fixture.setPINCalls,
			fixture.configCalls,
			fixture.makeCredentialCalls,
			fixture.getAssertionCalls,
			fixture.credentialsMetadataCalls,
			fixture.permissionScopes,
			fixture.operations,
		)
	}
}

type clientPIN2PermissionsAuthenticator struct {
	*clientPIN2NewPINAuthenticator

	noMCGAPresent               bool
	noMCGAEnabled               bool
	credentialManagementPresent bool
	credentialManagementEnabled bool
	bioEnrollPresent            bool
	bioEnrollEnabled            bool
	largeBlobsPresent           bool
	largeBlobsEnabled           bool
	permissionTokenStatus       ctaptransport.StatusCode
	permissionTokenLength       int
	forcePINChangeStatus        ctaptransport.StatusCode
	makeCredentialStatus        ctaptransport.StatusCode
	getAssertionStatus          ctaptransport.StatusCode
	credentialsMetadataStatus   ctaptransport.StatusCode
	authenticatorConfigStatus   ctaptransport.StatusCode
	transportErrorCommand       protocol.Command
	permissionScopes            []protocol.Permission
	permissionRPIDs             []string
	permissionWiresExact        bool
	operations                  []string
	issuedTokens                map[protocol.Permission][]byte
	credentialID                []byte
	makeCredentialCalls         int
	getAssertionCalls           int
	credentialsMetadataCalls    int
	makeCredentialExact         bool
	getAssertionExact           bool
	credentialsMetadataExact    bool
	makeCredentialMissingUV     bool
	getAssertionMissingUV       bool
}

func newClientPIN2PermissionsAuthenticator(t *testing.T) *clientPIN2PermissionsAuthenticator {
	t.Helper()

	return &clientPIN2PermissionsAuthenticator{
		clientPIN2NewPINAuthenticator: newClientPIN2NewPINAuthenticator(t),
		credentialManagementPresent:   true,
		credentialManagementEnabled:   true,
		bioEnrollPresent:              true,
		largeBlobsPresent:             true,
		largeBlobsEnabled:             true,
		permissionTokenLength:         32,
		forcePINChangeStatus:          ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION,
		permissionWiresExact:          true,
		issuedTokens:                  make(map[protocol.Permission][]byte),
		credentialID:                  []byte("permission-credential"),
	}
}

func (a *clientPIN2PermissionsAuthenticator) CBOR(
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
		response = a.permissionsGetInfoResponse()
	case protocol.AuthenticatorClientPIN:
		var body protocol.AuthenticatorClientPINRequest
		if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
			a.t.Fatal(err)
		}
		if body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions {
			response = a.permissionTokenResponse(request[1:], body)
		} else {
			return a.clientPIN2NewPINAuthenticator.CBOR(ctx, request)
		}
	case protocol.AuthenticatorMakeCredential:
		response = a.makeCredentialResponse(request[1:])
	case protocol.AuthenticatorGetAssertion:
		response = a.getAssertionResponse(request[1:])
	case protocol.AuthenticatorCredentialManagement:
		response = a.credentialsMetadataResponse(request[1:])
	case protocol.AuthenticatorConfig:
		a.operations = append(a.operations, "config")
		if a.authenticatorConfigStatus != ctaptransport.CTAP2_OK {
			response = ctaptransport.CBORResponse{StatusCode: a.authenticatorConfigStatus}
			break
		}

		return a.clientPIN2NewPINAuthenticator.CBOR(ctx, request)
	default:
		a.t.Fatalf("unexpected command %s", command)
	}

	return ctaptransport.ValidateCBORResponse(command, response)
}

func (a *clientPIN2PermissionsAuthenticator) permissionsGetInfoResponse() ctaptransport.CBORResponse {
	base := a.clientPIN2NewPINAuthenticator.getInfoResponse()
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(base.Data, &fields); err != nil {
		a.t.Fatal(err)
	}
	var options map[string]any
	if err := getInfoDecMode.Unmarshal(fields[4], &options); err != nil {
		a.t.Fatal(err)
	}
	if a.noMCGAPresent {
		options[string(protocol.OptionNoMcGaPermissionsWithClientPin)] = a.noMCGAEnabled
	}
	if a.credentialManagementPresent {
		options[string(protocol.OptionCredentialManagement)] = a.credentialManagementEnabled
	}
	if a.bioEnrollPresent {
		options[string(protocol.OptionBioEnroll)] = a.bioEnrollEnabled
	}
	if a.largeBlobsPresent {
		options[string(protocol.OptionLargeBlobs)] = a.largeBlobsEnabled
	}
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

func (a *clientPIN2PermissionsAuthenticator) permissionTokenResponse(
	bodyBytes []byte,
	body protocol.AuthenticatorClientPINRequest,
) ctaptransport.CBORResponse {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(bodyBytes, &fields); err != nil {
		a.t.Fatal(err)
	}
	wantFields := 5
	_, rpPresent := fields[10]
	if body.RPID != "" {
		wantFields++
	}
	a.permissionWiresExact = a.permissionWiresExact &&
		body.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		body.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions &&
		fields[1] != nil && fields[2] != nil && fields[3] != nil && fields[6] != nil && fields[9] != nil &&
		len(fields) == wantFields && rpPresent == (body.RPID != "")
	a.permissionScopes = append(a.permissionScopes, body.Permissions)
	a.permissionRPIDs = append(a.permissionRPIDs, body.RPID)
	a.operations = append(a.operations, fmt.Sprintf("token:%d", body.Permissions))

	if a.forcePINChange {
		return ctaptransport.CBORResponse{StatusCode: a.forcePINChangeStatus}
	}
	if a.permissionTokenStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.permissionTokenStatus}
	}

	sharedSecret := a.sharedSecret(body.KeyAgreement)
	defer clear(sharedSecret)
	decryptedHash := a.decrypt(sharedSecret, body.PinHashEnc)
	defer clear(decryptedHash)
	wantHash := sha256.Sum256(a.pin)
	defer clear(wantHash[:])
	if !bytes.Equal(decryptedHash, wantHash[:16]) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID}
	}

	token := bytes.Repeat([]byte{byte(body.Permissions)}, a.permissionTokenLength)
	switch body.Permissions {
	case protocol.PermissionAuthenticatorConfiguration:
		token = slices.Clone(a.configToken)
	case protocol.PermissionPersistentCredentialManagementReadOnly:
		token = slices.Clone(a.pcmrToken)
	}
	if a.permissionTokenLength != 32 {
		token = bytes.Repeat([]byte{byte(body.Permissions)}, a.permissionTokenLength)
	}
	clear(a.issuedTokens[body.Permissions])
	a.issuedTokens[body.Permissions] = slices.Clone(token)
	defer clear(token)

	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolTwo)
	if err != nil {
		a.t.Fatal(err)
	}
	encryptedToken, err := pinProtocol.Encrypt(sharedSecret, token)
	if err != nil {
		a.t.Fatal(err)
	}

	return a.success(map[uint64]any{2: encryptedToken})
}

func (a *clientPIN2PermissionsAuthenticator) makeCredentialResponse(bodyBytes []byte) ctaptransport.CBORResponse {
	a.makeCredentialCalls++
	a.operations = append(a.operations, "makeCredential")
	if a.makeCredentialStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.makeCredentialStatus}
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(bodyBytes, &request); err != nil {
		a.t.Fatal(err)
	}
	token := a.issuedTokens[protocol.PermissionMakeCredential]
	wantAuth := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, request.ClientDataHash)
	defer clear(wantAuth)
	a.makeCredentialExact = request.RP.ID == clientPIN2PermissionsRPID &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(request.PinUvAuthParam, wantAuth) &&
		len(request.Options) == 1 && request.Options[protocol.OptionResidentKeys] &&
		len(request.ExcludeList) == 0
	if !a.makeCredentialExact {
		a.t.Fatalf("MakeCredential request = %#v", request)
	}

	authData := getAssertionFixtureMakeCredentialAuthData(a.t, a.credentialID)
	if !a.makeCredentialMissingUV {
		authData[32] |= byte(protocol.AuthDataFlagUserVerified)
	}

	return a.success(map[uint64]any{
		1: "none",
		2: authData,
		3: map[string]any{},
	})
}

func (a *clientPIN2PermissionsAuthenticator) getAssertionResponse(bodyBytes []byte) ctaptransport.CBORResponse {
	a.getAssertionCalls++
	a.operations = append(a.operations, "getAssertion")
	if a.getAssertionStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.getAssertionStatus}
	}

	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(bodyBytes, &request); err != nil {
		a.t.Fatal(err)
	}
	token := a.issuedTokens[protocol.PermissionGetAssertion]
	wantAuth := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, token, request.ClientDataHash)
	defer clear(wantAuth)
	a.getAssertionExact = request.RPID == clientPIN2PermissionsRPID &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(request.PinUvAuthParam, wantAuth) &&
		len(request.AllowList) == 1 &&
		request.AllowList[0].Type == credential.PublicKeyCredentialTypePublicKey &&
		bytes.Equal(request.AllowList[0].ID, a.credentialID)
	if !a.getAssertionExact {
		a.t.Fatalf("GetAssertion request = %#v", request)
	}

	authData := getAssertionFixtureAuthData()
	if !a.getAssertionMissingUV {
		authData[32] |= byte(protocol.AuthDataFlagUserVerified)
	}

	return a.success(map[uint64]any{
		1: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   slices.Clone(a.credentialID),
		},
		2: authData,
		3: []byte{0x30, 0x00},
	})
}

func (a *clientPIN2PermissionsAuthenticator) credentialsMetadataResponse(bodyBytes []byte) ctaptransport.CBORResponse {
	a.credentialsMetadataCalls++
	if a.credentialsMetadataStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.credentialsMetadataStatus}
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(bodyBytes, &fields); err != nil {
		a.t.Fatal(err)
	}
	var request protocol.AuthenticatorCredentialManagementRequest
	if err := getInfoDecMode.Unmarshal(bodyBytes, &request); err != nil {
		a.t.Fatal(err)
	}
	token := a.issuedTokens[protocol.PermissionPersistentCredentialManagementReadOnly]
	wantAuth := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		[]byte{byte(protocol.CredentialManagementSubCommandGetCredsMetadata)},
	)
	defer clear(wantAuth)
	a.credentialsMetadataExact = request.SubCommand == protocol.CredentialManagementSubCommandGetCredsMetadata &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(request.PinUvAuthParam, wantAuth) && fields[2] == nil
	if !a.credentialsMetadataExact {
		a.t.Fatalf("GetCredsMetadata request = %#v", request)
	}
	zero := uint(0)

	return a.success(protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             &zero,
		MaxPossibleRemainingResidentCredentialsCount: &zero,
	})
}

var _ ctaptransport.CBOR = (*clientPIN2PermissionsAuthenticator)(nil)
