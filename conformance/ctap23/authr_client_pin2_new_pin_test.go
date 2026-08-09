package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN2NewPINExactMarkersReferencesAndLifecycleContract(t *testing.T) {
	tests := authrClientPIN2NewPINTests(Config{})
	wantIDs := []conformance.TestID{
		TestIDAuthrClientPIN2NewPINP1,
		TestIDAuthrClientPIN2NewPINP2,
		TestIDAuthrClientPIN2NewPINP3,
		TestIDAuthrClientPIN2NewPINP4,
	}
	if len(tests) != len(wantIDs) {
		t.Fatalf("tests = %d, want %d", len(tests), len(wantIDs))
	}

	for index, test := range tests {
		if test.ID != wantIDs[index] || test.Source.Path != authrClientPIN2NewPINSourcePath ||
			test.Source.Case != fmt.Sprintf("P-%d", index+1) {
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

	assertClientPIN2HasReferenceSection(t, tests[1], "6.5.5.6")
	assertClientPIN2HasReferenceSection(t, tests[2], "6.11.4")
	assertClientPIN2HasReferenceSection(t, tests[3], "6.5.5.6")
	assertClientPIN2HasReferenceSection(t, tests[3], "6.8.3")
}

func TestAuthrClientPIN2NewPINP1SetsPINAndCleansUp(t *testing.T) {
	fixture := newClientPIN2NewPINAuthenticator(t)
	result, suppliedPIN := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP1)
	assertClientPIN2NewPINStatus(t, result, conformance.StatusPassed)
	assertClientPIN2NewPINLifecycle(t, result, fixture, suppliedPIN)

	if fixture.setPINCalls != 1 || fixture.changePINCalls != 0 {
		t.Fatalf("set/change PIN calls = %d/%d, want 1/0", fixture.setPINCalls, fixture.changePINCalls)
	}
	if !slices.Equal(fixture.pinProtocols, []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolTwo,
		protocol.PinUvAuthProtocolTwo,
	}) {
		t.Fatalf("ClientPIN protocols = %v, want protocol 2 getKeyAgreement/setPIN", fixture.pinProtocols)
	}
}

func TestAuthrClientPIN2NewPINP2ChangesToDistinctPIN(t *testing.T) {
	fixture := newClientPIN2NewPINAuthenticator(t)
	result, suppliedPIN := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP2)
	assertClientPIN2NewPINStatus(t, result, conformance.StatusPassed)
	assertClientPIN2NewPINLifecycle(t, result, fixture, suppliedPIN)

	if fixture.changePINCalls != 1 || !fixture.changedToDifferentPIN {
		t.Fatalf("change calls/distinct = %d/%t, want 1/true", fixture.changePINCalls, fixture.changedToDifferentPIN)
	}
	if fixture.permissionTokenCalls != 0 || fixture.configCalls != 0 || fixture.credentialManagementCalls != 0 {
		t.Fatalf("unrelated calls = permission %d config %d credman %d",
			fixture.permissionTokenCalls, fixture.configCalls, fixture.credentialManagementCalls)
	}
}

func TestAuthrClientPIN2NewPINP3UsesACFGForceChangeAndClearsIt(t *testing.T) {
	fixture := newClientPIN2NewPINAuthenticator(t)
	result, suppliedPIN := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP3)
	assertClientPIN2NewPINStatus(t, result, conformance.StatusPassed)
	assertClientPIN2NewPINLifecycle(t, result, fixture, suppliedPIN)

	if fixture.permissionTokenCalls != 1 || fixture.permissionScopes[0] != protocol.PermissionAuthenticatorConfiguration {
		t.Fatalf("permission token calls/scopes = %d/%v, want one acfg", fixture.permissionTokenCalls, fixture.permissionScopes)
	}
	if fixture.configCalls != 1 || !fixture.forceWasSet || fixture.forceAfterChange {
		t.Fatalf("config/force set/after change = %d/%t/%t", fixture.configCalls, fixture.forceWasSet, fixture.forceAfterChange)
	}
	if fixture.changePINCalls != 1 || !fixture.changedToDifferentPIN {
		t.Fatalf("change calls/distinct = %d/%t", fixture.changePINCalls, fixture.changedToDifferentPIN)
	}
}

func TestAuthrClientPIN2NewPINP3RejectsForcePINChangeRetainedAfterChange(t *testing.T) {
	fixture := newClientPIN2NewPINAuthenticator(t)
	fixture.retainForcePINChange = true
	result, suppliedPIN := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP3)
	assertClientPIN2NewPINStatus(t, result, conformance.StatusFailed)
	assertClientPIN2NewPINMessage(t, result, "forcePINChange is true")
	assertClientPIN2NewPINLifecycle(t, result, fixture, suppliedPIN)
}

func TestAuthrClientPIN2NewPINP3RequiresForcePINChangeBeforeChangePIN(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*clientPIN2NewPINAuthenticator)
		message   string
	}{
		{
			name: "config succeeds but force is ignored",
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.ignoreForcePINChange = true
			},
			message: "forcePINChange is false",
		},
		{
			name: "force field is absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.forcePINChangePresent = false
			},
			message: "forcePINChange is missing",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2NewPINAuthenticator(t)
			test.configure(fixture)

			result, suppliedPIN := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP3)
			assertClientPIN2NewPINStatus(t, result, conformance.StatusFailed)
			assertClientPIN2NewPINMessage(t, result, test.message)
			assertClientPIN2NewPINLifecycle(t, result, fixture, suppliedPIN)
			if fixture.configCalls != 1 || !fixture.forceWasSet || fixture.changePINCalls != 0 {
				t.Fatalf("config/force request/change calls = %d/%t/%d, want 1/true/0",
					fixture.configCalls, fixture.forceWasSet, fixture.changePINCalls)
			}
		})
	}
}

func TestAuthrClientPIN2NewPINP3ProfilePreflightMatrixDoesNotMutate(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*clientPIN2NewPINAuthenticator)
		wantStatus conformance.Status
		message    string
	}{
		{
			name: "setMinPINLength absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.setMinPresent = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "setMinPINLength false",
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.setMinEnabled = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "authnrCfg absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.authenticatorConfigPresent = false
			},
			wantStatus: conformance.StatusFailed,
			message:    "authnrCfg must be present and true",
		},
		{
			name: "pinUvAuthToken false",
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.pinUvAuthTokenEnabled = false
			},
			wantStatus: conformance.StatusFailed,
			message:    "pinUvAuthToken must be present and true",
		},
		{
			name: "commands absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.configCommandsPresent = false
			},
			wantStatus: conformance.StatusFailed,
			message:    "authenticatorConfigCommands is missing",
		},
		{
			name: "setMin command absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.configCommands = []protocol.ConfigSubCommand{protocol.ConfigSubCommandToggleAlwaysUv}
			},
			wantStatus: conformance.StatusFailed,
			message:    "does not contain setMinPINLength",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2NewPINAuthenticator(t)
			test.configure(fixture)
			result, _ := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP3)
			assertClientPIN2NewPINStatus(t, result, test.wantStatus)
			if fixture.powerCycles != 0 || fixture.resets != 0 || fixture.setPINCalls != 0 {
				t.Fatalf("preflight mutated state: cycles=%d resets=%d setPIN=%d",
					fixture.powerCycles, fixture.resets, fixture.setPINCalls)
			}
			if test.message != "" {
				assertClientPIN2NewPINMessage(t, result, test.message)
			}
		})
	}
}

func TestAuthrClientPIN2NewPINP4UsesOldTokenWithFreshCredentialManagementMAC(t *testing.T) {
	fixture := newClientPIN2NewPINAuthenticator(t)
	result, suppliedPIN := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP4)
	assertClientPIN2NewPINStatus(t, result, conformance.StatusPassed)
	assertClientPIN2NewPINLifecycle(t, result, fixture, suppliedPIN)

	if fixture.permissionTokenCalls != 1 ||
		fixture.permissionScopes[0] != protocol.PermissionPersistentCredentialManagementReadOnly {
		t.Fatalf("permission token calls/scopes = %d/%v, want one pcmr", fixture.permissionTokenCalls, fixture.permissionScopes)
	}
	if fixture.changePINCalls != 1 || fixture.credentialManagementCalls != 1 || !fixture.freshCredentialManagementMAC {
		t.Fatalf("change/credman/fresh MAC = %d/%d/%t",
			fixture.changePINCalls, fixture.credentialManagementCalls, fixture.freshCredentialManagementMAC)
	}
	if fixture.credentialManagementNextCalls != 0 {
		t.Fatalf("enumerateRPsGetNextRP calls = %d, want 0", fixture.credentialManagementNextCalls)
	}
}

func TestAuthrClientPIN2NewPINP4RejectsOldTokenUnexpectedSuccess(t *testing.T) {
	fixture := newClientPIN2NewPINAuthenticator(t)
	fixture.credentialManagementStatus = ctaptransport.CTAP2_OK
	result, suppliedPIN := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP4)
	assertClientPIN2NewPINStatus(t, result, conformance.StatusFailed)
	assertClientPIN2NewPINMessage(t, result, "old pinUvAuthToken authorized")
	assertClientPIN2NewPINLifecycle(t, result, fixture, suppliedPIN)
}

func TestAuthrClientPIN2NewPINP4ApplicabilitySkipsBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name      string
		present   bool
		enabled   bool
		malformed bool
		want      conformance.Status
	}{
		{name: "absent", present: false, want: conformance.StatusSkipped},
		{name: "false", present: true, want: conformance.StatusSkipped},
		{name: "malformed", present: true, enabled: true, malformed: true, want: conformance.StatusFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2NewPINAuthenticator(t)
			fixture.perCredROPresent = test.present
			fixture.perCredROEnabled = test.enabled
			fixture.malformedPerCredRO = test.malformed
			result, _ := runAuthrClientPIN2NewPIN(t, fixture, Config{}, TestIDAuthrClientPIN2NewPINP4)
			assertClientPIN2NewPINStatus(t, result, test.want)
			if fixture.powerCycles != 0 || fixture.resets != 0 || fixture.setPINCalls != 0 {
				t.Fatalf("inapplicable P-4 mutated state: cycles=%d resets=%d setPIN=%d",
					fixture.powerCycles, fixture.resets, fixture.setPINCalls)
			}
		})
	}
}

func TestAuthrClientPIN2NewPINSupportAndEnvironmentMatrix(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*clientPIN2NewPINAuthenticator, *Config)
		wantStatus conformance.Status
		wantCycles int
	}{
		{
			name: "ClientPIN absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator, _ *Config) {
				fixture.clientPINPresent = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "non-featureful protocol 2 absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator, _ *Config) {
				fixture.protocolTwo = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "featureful protocol 2 absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator, config *Config) {
				fixture.protocolTwo = false
				config.Featureful = true
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name: "featureful extensions absent",
			configure: func(fixture *clientPIN2NewPINAuthenticator, config *Config) {
				fixture.extensionsPresent = false
				config.Featureful = true
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name: "power cycler missing",
			configure: func(_ *clientPIN2NewPINAuthenticator, config *Config) {
				config.PowerCycler = nil
			},
			wantStatus: conformance.StatusError,
		},
		{
			name: "temporary PIN provider missing",
			configure: func(_ *clientPIN2NewPINAuthenticator, config *Config) {
				config.TemporaryPINProvider = nil
			},
			wantStatus: conformance.StatusError,
		},
		{
			name: "HID lifecycle",
			configure: func(_ *clientPIN2NewPINAuthenticator, config *Config) {
				config.Transport = AuthenticatorTransportHID
			},
			wantStatus: conformance.StatusPassed,
			wantCycles: 2,
		},
		{
			name: "NFC lifecycle",
			configure: func(_ *clientPIN2NewPINAuthenticator, config *Config) {
				config.Transport = AuthenticatorTransportNFC
			},
			wantStatus: conformance.StatusPassed,
			wantCycles: 2,
		},
		{
			name: "BLE lifecycle",
			configure: func(_ *clientPIN2NewPINAuthenticator, config *Config) {
				config.Transport = AuthenticatorTransportBLE
			},
			wantStatus: conformance.StatusPassed,
			wantCycles: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2NewPINAuthenticator(t)
			config := clientPIN2NewPINConfig(fixture, nil)
			test.configure(fixture, &config)
			result := runAuthrClientPIN2NewPINWithConfig(t, fixture, config, TestIDAuthrClientPIN2NewPINP1)
			assertClientPIN2NewPINStatus(t, result, test.wantStatus)
			if fixture.powerCycles != test.wantCycles {
				t.Fatalf("power cycles = %d, want %d", fixture.powerCycles, test.wantCycles)
			}
			if test.wantCycles == 0 && (fixture.resets != 0 || fixture.setPINCalls != 0) {
				t.Fatalf("non-running case mutated state: resets=%d setPIN=%d", fixture.resets, fixture.setPINCalls)
			}
		})
	}
}

func TestAuthrClientPIN2NewPINStatusTransportCleanupAndInputPreservation(t *testing.T) {
	tests := []struct {
		name       string
		id         conformance.TestID
		configure  func(*clientPIN2NewPINAuthenticator)
		wantStatus conformance.Status
		message    string
	}{
		{
			name: "SetPIN CTAP status",
			id:   TestIDAuthrClientPIN2NewPINP1,
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.setPINStatus = ctaptransport.CTAP2_ERR_OPERATION_DENIED
			},
			wantStatus: conformance.StatusFailed,
			message:    "CTAP2_ERR_OPERATION_DENIED",
		},
		{
			name: "ChangePIN CTAP status",
			id:   TestIDAuthrClientPIN2NewPINP2,
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.changePINStatus = ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION
			},
			wantStatus: conformance.StatusFailed,
			message:    "CTAP2_ERR_PIN_POLICY_VIOLATION",
		},
		{
			name: "credential-management wrong status",
			id:   TestIDAuthrClientPIN2NewPINP4,
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.credentialManagementStatus = ctaptransport.CTAP2_ERR_OPERATION_DENIED
			},
			wantStatus: conformance.StatusFailed,
			message:    "want CTAP2_ERR_PIN_AUTH_INVALID",
		},
		{
			name: "ChangePIN transport error",
			id:   TestIDAuthrClientPIN2NewPINP2,
			configure: func(fixture *clientPIN2NewPINAuthenticator) {
				fixture.transportErrorSubCommand = protocol.ClientPINSubCommandChangePIN
			},
			wantStatus: conformance.StatusError,
			message:    "device disconnected",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2NewPINAuthenticator(t)
			test.configure(fixture)
			result, suppliedPIN := runAuthrClientPIN2NewPIN(t, fixture, Config{}, test.id)
			assertClientPIN2NewPINStatus(t, result, test.wantStatus)
			assertClientPIN2NewPINMessage(t, result, test.message)
			assertClientPIN2NewPINLifecycle(t, result, fixture, suppliedPIN)
		})
	}

	t.Run("invalid provider PIN is wiped", func(t *testing.T) {
		fixture := newClientPIN2NewPINAuthenticator(t)
		invalidPIN := []byte("1")
		config := clientPIN2NewPINConfig(fixture, nil)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
			return invalidPIN, nil
		}
		result := runAuthrClientPIN2NewPINWithConfig(t, fixture, config, TestIDAuthrClientPIN2NewPINP1)
		assertClientPIN2NewPINStatus(t, result, conformance.StatusError)
		assertClearedClientPIN2Buffer(t, invalidPIN)
	})
}

func runAuthrClientPIN2NewPIN(
	t *testing.T,
	fixture *clientPIN2NewPINAuthenticator,
	override Config,
	id conformance.TestID,
) (conformance.SuiteResult, []byte) {
	t.Helper()

	var suppliedPIN []byte
	config := clientPIN2NewPINConfig(fixture, &suppliedPIN)
	config.Transport = override.Transport
	config.Featureful = override.Featureful

	return runAuthrClientPIN2NewPINWithConfig(t, fixture, config, id), suppliedPIN
}

func runAuthrClientPIN2NewPINWithConfig(
	t *testing.T,
	fixture *clientPIN2NewPINAuthenticator,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrClientPIN2NewPINTests(config) {
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
		ID:    "client-pin2-new-pin-test",
		Name:  "ClientPIN protocol 2 new PIN test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func clientPIN2NewPINConfig(fixture *clientPIN2NewPINAuthenticator, suppliedPIN *[]byte) Config {
	return Config{
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
				return nil, fmt.Errorf("PIN request = %#v, want 4..63", request)
			}
			pin := []byte("1234")
			if suppliedPIN != nil {
				*suppliedPIN = pin
			}

			return pin, nil
		},
	}
}

func assertClientPIN2NewPINStatus(t *testing.T, result conformance.SuiteResult, want conformance.Status) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertClientPIN2NewPINMessage(t *testing.T, result conformance.SuiteResult, substring string) {
	t.Helper()

	for _, step := range result.Tests[0].Steps {
		if strings.Contains(step.Message, substring) {
			return
		}
	}
	t.Fatalf("steps = %#v, want message containing %q", result.Tests[0].Steps, substring)
}

func assertClientPIN2NewPINLifecycle(
	t *testing.T,
	result conformance.SuiteResult,
	fixture *clientPIN2NewPINAuthenticator,
	suppliedPIN []byte,
) {
	t.Helper()

	if fixture.powerCycles != 2 || fixture.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 2/2", fixture.powerCycles, fixture.resets)
	}
	steps := result.Tests[0].Steps
	if len(steps) == 0 || steps[len(steps)-1].ID != "client-pin2-new-pin.cleanup" ||
		steps[len(steps)-1].Status != conformance.StatusPassed {
		t.Fatalf("cleanup = %#v", steps)
	}
	assertClearedClientPIN2Buffer(t, suppliedPIN)
	if fixture.pin != nil {
		t.Fatalf("authenticator PIN retained after cleanup: %x", fixture.pin)
	}
}

type clientPIN2NewPINAuthenticator struct {
	t *testing.T

	authenticatorPrivate       *clientPIN2RetryAuthenticator
	pin                        []byte
	configToken                []byte
	pcmrToken                  []byte
	clientPINPresent           bool
	protocolTwo                bool
	extensionsPresent          bool
	setMinPresent              bool
	setMinEnabled              bool
	authenticatorConfigPresent bool
	authenticatorConfigEnabled bool
	pinUvAuthTokenPresent      bool
	pinUvAuthTokenEnabled      bool
	configCommandsPresent      bool
	configCommands             []protocol.ConfigSubCommand
	perCredROPresent           bool
	perCredROEnabled           bool
	malformedPerCredRO         bool
	forcePINChange             bool
	forcePINChangePresent      bool
	ignoreForcePINChange       bool
	retainForcePINChange       bool

	setPINStatus               ctaptransport.StatusCode
	changePINStatus            ctaptransport.StatusCode
	credentialManagementStatus ctaptransport.StatusCode
	transportErrorSubCommand   protocol.ClientPINSubCommand

	powerCycles                   int
	resets                        int
	setPINCalls                   int
	changePINCalls                int
	permissionTokenCalls          int
	configCalls                   int
	credentialManagementCalls     int
	credentialManagementNextCalls int
	changedToDifferentPIN         bool
	forceWasSet                   bool
	forceAfterChange              bool
	freshCredentialManagementMAC  bool
	pinProtocols                  []protocol.PinUvAuthProtocol
	permissionScopes              []protocol.Permission
	lastChangePINAuthParam        []byte
}

func newClientPIN2NewPINAuthenticator(t *testing.T) *clientPIN2NewPINAuthenticator {
	t.Helper()

	return &clientPIN2NewPINAuthenticator{
		t:                          t,
		authenticatorPrivate:       newClientPIN2RetryAuthenticator(t, 8),
		configToken:                bytes.Repeat([]byte{0x63}, 32),
		pcmrToken:                  bytes.Repeat([]byte{0x72}, 32),
		clientPINPresent:           true,
		protocolTwo:                true,
		extensionsPresent:          true,
		setMinPresent:              true,
		setMinEnabled:              true,
		authenticatorConfigPresent: true,
		authenticatorConfigEnabled: true,
		pinUvAuthTokenPresent:      true,
		pinUvAuthTokenEnabled:      true,
		configCommandsPresent:      true,
		configCommands:             []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength},
		perCredROPresent:           true,
		perCredROEnabled:           true,
		forcePINChangePresent:      true,
		credentialManagementStatus: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
	}
}

func (a *clientPIN2NewPINAuthenticator) CBOR(
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
	var response ctaptransport.CBORResponse
	switch command {
	case protocol.AuthenticatorGetInfo:
		response = a.getInfoResponse()
	case protocol.AuthenticatorClientPIN:
		var body protocol.AuthenticatorClientPINRequest
		if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
			a.t.Fatal(err)
		}
		if body.SubCommand == a.transportErrorSubCommand {
			return ctaptransport.CBORResponse{}, errors.New("device disconnected")
		}
		response = a.clientPINResponse(request[1:])
	case protocol.AuthenticatorConfig:
		response = a.configResponse(request[1:])
	case protocol.AuthenticatorCredentialManagement:
		response = a.credentialManagementResponse(request[1:])
	default:
		a.t.Fatalf("unexpected command %s", command)
	}

	return ctaptransport.ValidateCBORResponse(command, response)
}

func (a *clientPIN2NewPINAuthenticator) getInfoResponse() ctaptransport.CBORResponse {
	options := map[protocol.Option]any{}
	if a.clientPINPresent {
		options[protocol.OptionClientPIN] = a.pin != nil
	}
	if a.setMinPresent {
		options[protocol.OptionSetMinPINLength] = a.setMinEnabled
	}
	if a.authenticatorConfigPresent {
		options[protocol.OptionAuthenticatorConfig] = a.authenticatorConfigEnabled
	}
	if a.pinUvAuthTokenPresent {
		options[protocol.OptionPinUvAuthToken] = a.pinUvAuthTokenEnabled
	}
	if a.perCredROPresent {
		if a.malformedPerCredRO {
			options[protocol.OptionPersistentCredentialManagementReadOnly] = uint64(1)
		} else {
			options[protocol.OptionPersistentCredentialManagementReadOnly] = a.perCredROEnabled
		}
	}

	fields := map[uint64]any{
		1: []protocol.Version{protocol.FIDO_2_3},
		3: uuid.Nil,
		4: options,
		10: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		13: uint(4),
		29: uint(63),
	}
	if a.forcePINChangePresent {
		fields[12] = a.forcePINChange
	}
	if a.extensionsPresent {
		fields[2] = []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret}
	}
	if a.protocolTwo {
		fields[6] = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo}
	}
	if a.configCommandsPresent {
		fields[31] = a.configCommands
	}
	if a.changePINCalls != 0 {
		a.forceAfterChange = a.forcePINChange
	}

	return a.success(fields)
}

func (a *clientPIN2NewPINAuthenticator) clientPINResponse(bodyBytes []byte) ctaptransport.CBORResponse {
	var body protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(bodyBytes, &body); err != nil {
		a.t.Fatal(err)
	}
	a.pinProtocols = append(a.pinProtocols, body.PinUvAuthProtocol)
	if body.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
		a.t.Fatalf("pinUvAuthProtocol = %d, want 2", body.PinUvAuthProtocol)
	}
	switch body.SubCommand {
	case protocol.ClientPINSubCommandGetKeyAgreement:
		return a.success(map[uint64]any{1: a.authenticatorPrivate.authenticatorKey})
	case protocol.ClientPINSubCommandSetPIN:
		a.setPINCalls++
		if a.setPINStatus != ctaptransport.CTAP2_OK {
			return ctaptransport.CBORResponse{StatusCode: a.setPINStatus}
		}
		sharedSecret := a.sharedSecret(body.KeyAgreement)
		defer clear(sharedSecret)
		a.requireAuthParam(sharedSecret, body.NewPinEnc, body.PinUvAuthParam, "setPIN")
		pin := a.decryptPIN(sharedSecret, body.NewPinEnc)
		clear(a.pin)
		a.pin = pin

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
	case protocol.ClientPINSubCommandChangePIN:
		a.changePINCalls++
		if a.changePINStatus != ctaptransport.CTAP2_OK {
			return ctaptransport.CBORResponse{StatusCode: a.changePINStatus}
		}

		return a.changePINResponse(body)
	case protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions:
		a.permissionTokenCalls++

		return a.permissionTokenResponse(body)
	default:
		a.t.Fatalf("unexpected ClientPIN subcommand %s", body.SubCommand)

		return ctaptransport.CBORResponse{}
	}
}

func (a *clientPIN2NewPINAuthenticator) changePINResponse(
	body protocol.AuthenticatorClientPINRequest,
) ctaptransport.CBORResponse {
	sharedSecret := a.sharedSecret(body.KeyAgreement)
	defer clear(sharedSecret)
	message := slices.Concat(body.NewPinEnc, body.PinHashEnc)
	defer clear(message)
	a.requireAuthParam(sharedSecret, message, body.PinUvAuthParam, "changePIN")
	clear(a.lastChangePINAuthParam)
	a.lastChangePINAuthParam = slices.Clone(body.PinUvAuthParam)

	oldHash := sha256.Sum256(a.pin)
	defer clear(oldHash[:])
	decryptedHash := a.decrypt(sharedSecret, body.PinHashEnc)
	defer clear(decryptedHash)
	if !bytes.Equal(decryptedHash, oldHash[:16]) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID}
	}

	newPIN := a.decryptPIN(sharedSecret, body.NewPinEnc)
	a.changedToDifferentPIN = !bytes.Equal(a.pin, newPIN)
	clear(a.pin)
	a.pin = newPIN
	if !a.retainForcePINChange {
		a.forcePINChange = false
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
}

func (a *clientPIN2NewPINAuthenticator) permissionTokenResponse(
	body protocol.AuthenticatorClientPINRequest,
) ctaptransport.CBORResponse {
	if body.RPID != "" {
		a.t.Fatalf("permissions RP ID = %q, want empty", body.RPID)
	}
	switch body.Permissions {
	case protocol.PermissionAuthenticatorConfiguration,
		protocol.PermissionPersistentCredentialManagementReadOnly:
	default:
		a.t.Fatalf("permissions = %s", body.Permissions)
	}
	a.permissionScopes = append(a.permissionScopes, body.Permissions)

	sharedSecret := a.sharedSecret(body.KeyAgreement)
	defer clear(sharedSecret)
	decryptedHash := a.decrypt(sharedSecret, body.PinHashEnc)
	defer clear(decryptedHash)
	wantHash := sha256.Sum256(a.pin)
	defer clear(wantHash[:])
	if !bytes.Equal(decryptedHash, wantHash[:16]) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID}
	}

	token := a.configToken
	if body.Permissions == protocol.PermissionPersistentCredentialManagementReadOnly {
		token = a.pcmrToken
	}
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

func (a *clientPIN2NewPINAuthenticator) configResponse(bodyBytes []byte) ctaptransport.CBORResponse {
	a.configCalls++

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(bodyBytes, &fields); err != nil {
		a.t.Fatal(err)
	}
	var subCommand protocol.ConfigSubCommand
	if err := getInfoDecMode.Unmarshal(fields[1], &subCommand); err != nil {
		a.t.Fatal(err)
	}
	var params protocol.SetMinPINLengthConfigSubCommandParams
	if err := getInfoDecMode.Unmarshal(fields[2], &params); err != nil {
		a.t.Fatal(err)
	}
	var pinProtocol protocol.PinUvAuthProtocol
	if err := getInfoDecMode.Unmarshal(fields[3], &pinProtocol); err != nil {
		a.t.Fatal(err)
	}
	var authParam []byte
	if err := getInfoDecMode.Unmarshal(fields[4], &authParam); err != nil {
		a.t.Fatal(err)
	}
	if subCommand != protocol.ConfigSubCommandSetMinPINLength || !params.ForceChangePIN ||
		params.NewMinPINLength != nil || len(params.MinPINLengthRPIDs) != 0 || params.PINComplexityPolicy ||
		pinProtocol != protocol.PinUvAuthProtocolTwo {
		a.t.Fatalf("setMinPINLength request = %s/%#v/protocol %d", subCommand, params, pinProtocol)
	}
	message := slices.Concat(
		bytes.Repeat([]byte{0xff}, 32),
		[]byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)},
		[]byte(fields[2]),
	)
	defer clear(message)
	want := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, a.configToken, message)
	defer clear(want)
	if !bytes.Equal(authParam, want) {
		a.t.Fatalf("setMinPINLength pinUvAuthParam = %x, want %x", authParam, want)
	}
	a.forceWasSet = true
	if !a.ignoreForcePINChange {
		a.forcePINChange = true
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
}

func (a *clientPIN2NewPINAuthenticator) credentialManagementResponse(
	bodyBytes []byte,
) ctaptransport.CBORResponse {
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(bodyBytes, &fields); err != nil {
		a.t.Fatal(err)
	}
	var request protocol.AuthenticatorCredentialManagementRequest
	if err := getInfoDecMode.Unmarshal(bodyBytes, &request); err != nil {
		a.t.Fatal(err)
	}
	if request.SubCommand == protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP {
		a.credentialManagementNextCalls++

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED}
	}
	a.credentialManagementCalls++
	if request.SubCommand != protocol.CredentialManagementSubCommandEnumerateRPsBegin ||
		request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo ||
		fields[2] != nil {
		a.t.Fatalf("credentialManagement request = %#v", request)
	}
	want := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		a.pcmrToken,
		[]byte{byte(protocol.CredentialManagementSubCommandEnumerateRPsBegin)},
	)
	defer clear(want)
	a.freshCredentialManagementMAC = bytes.Equal(request.PinUvAuthParam, want) &&
		!bytes.Equal(request.PinUvAuthParam, a.lastChangePINAuthParam)
	if !a.freshCredentialManagementMAC {
		a.t.Fatalf("credentialManagement pinUvAuthParam = %x, want fresh %x", request.PinUvAuthParam, want)
	}

	if a.credentialManagementStatus == ctaptransport.CTAP2_OK {
		return a.success(protocol.AuthenticatorCredentialManagementResponse{TotalRPs: 1})
	}

	return ctaptransport.CBORResponse{StatusCode: a.credentialManagementStatus}
}

func (a *clientPIN2NewPINAuthenticator) reset() {
	a.resets++
	clear(a.pin)
	a.pin = nil
	a.forcePINChange = false
}

func (a *clientPIN2NewPINAuthenticator) sharedSecret(platformKey cose.Key) []byte {
	a.t.Helper()

	return a.authenticatorPrivate.clientPINSharedSecret(platformKey)
}

func (a *clientPIN2NewPINAuthenticator) decrypt(sharedSecret []byte, ciphertext []byte) []byte {
	a.t.Helper()

	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolTwo)
	if err != nil {
		a.t.Fatal(err)
	}
	plaintext, err := pinProtocol.Decrypt(sharedSecret, ciphertext)
	if err != nil {
		a.t.Fatal(err)
	}

	return plaintext
}

func (a *clientPIN2NewPINAuthenticator) decryptPIN(sharedSecret []byte, ciphertext []byte) []byte {
	a.t.Helper()

	plaintext := a.decrypt(sharedSecret, ciphertext)
	defer clear(plaintext)
	length := bytes.IndexByte(plaintext, 0)
	if length < 0 {
		a.t.Fatal("encrypted PIN has no zero padding")
	}

	return slices.Clone(plaintext[:length])
}

func (a *clientPIN2NewPINAuthenticator) requireAuthParam(
	sharedSecret []byte,
	message []byte,
	authParam []byte,
	operation string,
) {
	a.t.Helper()

	want := ctapcrypto.Authenticate(protocol.PinUvAuthProtocolTwo, sharedSecret, message)
	defer clear(want)
	if !bytes.Equal(authParam, want) {
		a.t.Fatalf("%s pinUvAuthParam = %x, want %x", operation, authParam, want)
	}
}

func (a *clientPIN2NewPINAuthenticator) success(value any) ctaptransport.CBORResponse {
	a.t.Helper()

	data, err := ctap2EncMode.Marshal(value)
	if err != nil {
		a.t.Fatal(err)
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

var _ ctaptransport.CBOR = (*clientPIN2NewPINAuthenticator)(nil)
