package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrClientPIN2GetRetriesExactMarkersSourceReferencesAndDestructiveFlag(t *testing.T) {
	tests := authrClientPIN2GetRetriesTests(Config{})
	wantIDs := []conformance.TestID{
		TestIDAuthrClientPIN2GetRetriesP1,
		TestIDAuthrClientPIN2GetRetriesP2,
		TestIDAuthrClientPIN2GetRetriesP3,
		TestIDAuthrClientPIN2GetRetriesP4,
		TestIDAuthrClientPIN2GetRetriesP5,
	}
	if len(tests) != len(wantIDs) {
		t.Fatalf("tests = %d, want %d", len(tests), len(wantIDs))
	}

	for index, test := range tests {
		if test.ID != wantIDs[index] {
			t.Fatalf("test %d ID = %q, want %q", index, test.ID, wantIDs[index])
		}
		wantMarker := fmt.Sprintf("P-%d", index+1)
		if test.Source.Path != authrClientPIN2GetRetriesSourcePath || test.Source.Case != wantMarker {
			t.Fatalf("test %d source = %#v, want %s %s", index, test.Source, authrClientPIN2GetRetriesSourcePath, wantMarker)
		}
		if !test.Destructive {
			t.Fatalf("test %d is not marked destructive", index)
		}
		if len(test.References) < 7 {
			t.Fatalf("test %d references = %#v, want setup and case requirements", index, test.References)
		}
		for _, reference := range test.References {
			if reference.Specification != conformance.SpecificationCTAP23 || reference.URL == "" || reference.Section == "" {
				t.Fatalf("test %d reference = %#v", index, reference)
			}
		}
	}

	assertClientPIN2HasReferenceSection(t, tests[0], "6.5.5.2")
	assertClientPIN2HasReferenceSection(t, tests[1], "6.5.5.3")
	assertClientPIN2HasReferenceSection(t, tests[2], "6.1")
	assertClientPIN2HasReferenceSection(t, tests[3], "6.5.5.7.1")
	assertClientPIN2HasReferenceSection(t, tests[4], "6.5.2.3")
	assertClientPIN2HasReference(t, tests[0], "6.5.2.3", "pin-retries-maximum", conformance.RequirementMust)
	assertClientPIN2HasReference(t, tests[1], "6.5.2.3", "uv-retries-range", conformance.RequirementMust)
	assertClientPIN2HasReference(t, tests[0], "6.5.5.2", "get-pin-retries-response", conformance.RequirementConstraint)
	assertClientPIN2HasReference(t, tests[1], "6.5.5.3", "get-uv-retries-response", conformance.RequirementConstraint)
	setPINReference := clientPINSetReference()
	if setPINReference.Level != conformance.RequirementConstraint || !strings.HasSuffix(setPINReference.URL, "#settingNewPin") {
		t.Fatalf("SetPIN reference = %#v", setPINReference)
	}
}

func TestAuthrClientPIN2GetRetriesP1PassesAndCleansUpSecretsAndState(t *testing.T) {
	fixture := newClientPIN2RetryAuthenticator(t, 8)
	result, suppliedPIN := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 0)
	assertClientPIN2MarkerStatus(t, result, conformance.StatusPassed)

	if !slices.Equal(fixture.retryReads, []uint{8}) {
		t.Fatalf("retry reads = %v, want [8]", fixture.retryReads)
	}
	if fixture.powerCycles != 2 || fixture.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 2/2", fixture.powerCycles, fixture.resets)
	}
	assertClearedClientPIN2Buffer(t, suppliedPIN)
	assertClientPIN2CleanupStep(t, result)
}

func TestAuthrClientPIN2GetRetriesP1RejectsCounterAboveEight(t *testing.T) {
	fixture := newClientPIN2RetryAuthenticator(t, 8)
	override := uint(9)
	fixture.pinRetriesOverride = &override

	result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 0)
	assertClientPIN2MarkerStatus(t, result, conformance.StatusFailed)
	assertClientPIN2StepMessage(t, result, "client-pin2.get-pin-retries", "want 0..8")
}

func TestAuthrClientPIN2GetRetriesP1SupportMatrixDoesNotMutateInapplicableAuthenticator(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*clientPIN2RetryAuthenticator, *Config)
		wantStatus conformance.Status
	}{
		{
			name: "client PIN absent",
			configure: func(fixture *clientPIN2RetryAuthenticator, _ *Config) {
				fixture.clientPINPresent = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "non-featureful protocol two absent",
			configure: func(fixture *clientPIN2RetryAuthenticator, _ *Config) {
				fixture.protocolTwo = false
			},
			wantStatus: conformance.StatusSkipped,
		},
		{
			name: "featureful protocol two absent",
			configure: func(fixture *clientPIN2RetryAuthenticator, config *Config) {
				fixture.protocolTwo = false
				config.Featureful = true
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name: "featureful extensions absent",
			configure: func(fixture *clientPIN2RetryAuthenticator, config *Config) {
				fixture.extensionsPresent = false
				config.Featureful = true
			},
			wantStatus: conformance.StatusFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2RetryAuthenticator(t, 8)
			config := Config{}
			test.configure(fixture, &config)

			result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, config, 0)
			assertClientPIN2MarkerStatus(t, result, test.wantStatus)
			if fixture.powerCycles != 0 || fixture.resets != 0 || fixture.setPINCalls != 0 {
				t.Fatalf("inapplicable case mutated state: cycles=%d resets=%d setPIN=%d", fixture.powerCycles, fixture.resets, fixture.setPINCalls)
			}
		})
	}
}

func TestAuthrClientPIN2GetRetriesP2ApplicabilityConfigurationAndRange(t *testing.T) {
	t.Run("UV absent skips before mutation", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 1)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusSkipped)
		if fixture.powerCycles != 0 || fixture.resets != 0 {
			t.Fatalf("cycles/resets = %d/%d, want 0/0", fixture.powerCycles, fixture.resets)
		}
	})

	t.Run("unconfigured UV uses configurator", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		fixture.uvSupported = true
		fixture.uvRetries = 25
		result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 1)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusPassed)
		if fixture.uvConfigurations != 1 || fixture.uvRetryReads != 1 {
			t.Fatalf("UV configurations/reads = %d/%d, want 1/1", fixture.uvConfigurations, fixture.uvRetryReads)
		}
	})

	t.Run("already configured UV avoids redundant enrollment", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		fixture.uvSupported = true
		fixture.uvConfigured = true
		fixture.preserveUVOnReset = true
		config := Config{UVConfigurator: nil}
		result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, config, 1)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusPassed)
		if fixture.uvConfigurations != 0 {
			t.Fatalf("UV configurations = %d, want 0", fixture.uvConfigurations)
		}
	})

	t.Run("zero UV retries fails", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		fixture.uvSupported = true
		fixture.uvRetries = 0
		result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 1)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusFailed)
		assertClientPIN2StepMessage(t, result, "client-pin2.get-uv-retries", "want 1..25")
	})
}

func TestAuthrClientPIN2GetRetriesP3DecrementsAndRestoresCounter(t *testing.T) {
	fixture := newClientPIN2RetryAuthenticator(t, 8)
	result, suppliedPIN := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 2)
	assertClientPIN2MarkerStatus(t, result, conformance.StatusPassed)

	if !slices.Equal(fixture.retryReads, []uint{8, 6, 8}) {
		t.Fatalf("retry reads = %v, want [8 6 8]", fixture.retryReads)
	}
	if !slices.Equal(fixture.tokenStatuses, []ctaptransport.StatusCode{
		ctaptransport.CTAP2_ERR_PIN_INVALID,
		ctaptransport.CTAP2_ERR_PIN_INVALID,
		ctaptransport.CTAP2_OK,
	}) {
		t.Fatalf("token statuses = %v", fixture.tokenStatuses)
	}
	if fixture.makeCredentialCalls != 1 {
		t.Fatalf("MakeCredential calls = %d, want 1", fixture.makeCredentialCalls)
	}
	assertClearedClientPIN2Buffer(t, suppliedPIN)
}

func TestAuthrClientPIN2GetRetriesP3RejectsMissingDecrementAndPreservesTransportErrors(t *testing.T) {
	t.Run("counter does not decrement", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		fixture.decrementInvalidPIN = false
		result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 2)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusFailed)
		assertClientPIN2StepMessage(t, result, "client-pin2.verify-decrement", "want 6")
	})

	t.Run("transport failure", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		fixture.tokenTransportError = errors.New("device disconnected")
		result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 2)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusError)
		assertClientPIN2StepMessage(t, result, "client-pin2.invalid-pin-1", "device disconnected")
	})
}

func TestAuthrClientPIN2GetRetriesP4ChecksThirdConsecutiveMismatchStatus(t *testing.T) {
	for _, test := range []struct {
		name         string
		maxRetries   uint
		wantStatuses []ctaptransport.StatusCode
	}{
		{
			name:       "temporary block",
			maxRetries: 8,
			wantStatuses: []ctaptransport.StatusCode{
				ctaptransport.CTAP2_ERR_PIN_INVALID,
				ctaptransport.CTAP2_ERR_PIN_INVALID,
				ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED,
			},
		},
		{
			name:       "permanent block at three retries",
			maxRetries: 3,
			wantStatuses: []ctaptransport.StatusCode{
				ctaptransport.CTAP2_ERR_PIN_INVALID,
				ctaptransport.CTAP2_ERR_PIN_INVALID,
				ctaptransport.CTAP2_ERR_PIN_BLOCKED,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2RetryAuthenticator(t, test.maxRetries)
			result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 3)
			assertClientPIN2MarkerStatus(t, result, conformance.StatusPassed)
			if !slices.Equal(fixture.tokenStatuses, test.wantStatuses) {
				t.Fatalf("token statuses = %v, want %v", fixture.tokenStatuses, test.wantStatuses)
			}
		})
	}
}

func TestAuthrClientPIN2GetRetriesP4RejectsThirdPINInvalid(t *testing.T) {
	fixture := newClientPIN2RetryAuthenticator(t, 8)
	fixture.temporaryBlockAfter = 4
	result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 3)
	assertClientPIN2MarkerStatus(t, result, conformance.StatusFailed)
	assertClientPIN2StepMessage(t, result, "client-pin2.blocking-invalid-pin-3", "want CTAP2_ERR_PIN_AUTH_BLOCKED")
}

func TestAuthrClientPIN2GetRetriesP5ExhaustsRetriesAcrossTransportCycles(t *testing.T) {
	for _, test := range []struct {
		name       string
		transport  AuthenticatorTransport
		wantCycles int
	}{
		{name: "HID cycles on temporary block", transport: AuthenticatorTransportHID, wantCycles: 5},
		{name: "NFC resets the card session between remaining requests", transport: AuthenticatorTransportNFC, wantCycles: 10},
		{name: "BLE cycles on temporary block", transport: AuthenticatorTransportBLE, wantCycles: 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newClientPIN2RetryAuthenticator(t, 8)
			result, suppliedPIN := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{Transport: test.transport}, 4)
			assertClientPIN2MarkerStatus(t, result, conformance.StatusPassed)
			if fixture.powerCycles != test.wantCycles {
				t.Fatalf("power cycles = %d, want %d", fixture.powerCycles, test.wantCycles)
			}
			if fixture.resets != 2 {
				t.Fatalf("resets = %d, want 2", fixture.resets)
			}
			if len(fixture.tokenStatuses) != 9 || fixture.tokenStatuses[len(fixture.tokenStatuses)-1] != ctaptransport.CTAP2_ERR_PIN_BLOCKED {
				t.Fatalf("token statuses = %v, want eight exhausting attempts and final correct-PIN block", fixture.tokenStatuses)
			}
			assertClearedClientPIN2Buffer(t, suppliedPIN)
		})
	}
}

func TestAuthrClientPIN2GetRetriesP5SkipsAtThreeOrFewerRetriesAndStillCleansUp(t *testing.T) {
	fixture := newClientPIN2RetryAuthenticator(t, 3)
	result, suppliedPIN := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{Transport: AuthenticatorTransportHID}, 4)
	assertClientPIN2MarkerStatus(t, result, conformance.StatusSkipped)
	if len(fixture.tokenStatuses) != 0 {
		t.Fatalf("token statuses = %v, want no exhaustion attempts", fixture.tokenStatuses)
	}
	if fixture.powerCycles != 2 || fixture.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want setup and cleanup", fixture.powerCycles, fixture.resets)
	}
	assertClearedClientPIN2Buffer(t, suppliedPIN)
}

func TestAuthrClientPIN2GetRetriesP5RejectsRetryThatDoesNotDecrease(t *testing.T) {
	fixture := newClientPIN2RetryAuthenticator(t, 8)
	fixture.decrementInvalidPIN = false
	result, _ := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{Transport: AuthenticatorTransportHID}, 4)
	assertClientPIN2MarkerStatus(t, result, conformance.StatusFailed)
	assertClientPIN2StepMessage(t, result, "client-pin2.exhaust-decrement-1", "want a decrement of one")
}

func TestAuthrClientPIN2GetRetriesP5RejectsUnknownTransportBeforeMutation(t *testing.T) {
	for _, transport := range []AuthenticatorTransport{"", "future"} {
		t.Run(string(transport), func(t *testing.T) {
			fixture := newClientPIN2RetryAuthenticator(t, 8)
			config := clientPIN2RetryConfig(fixture, nil)
			config.Transport = transport
			result := runAuthrClientPIN2GetRetriesWithConfig(t, fixture, config, 4)
			assertClientPIN2MarkerStatus(t, result, conformance.StatusError)
			if fixture.powerCycles != 0 || fixture.resets != 0 || fixture.setPINCalls != 0 {
				t.Fatalf("unknown transport mutated state: cycles=%d resets=%d setPIN=%d", fixture.powerCycles, fixture.resets, fixture.setPINCalls)
			}
		})
	}
}

func TestAuthrClientPIN2GetRetriesEnvironmentErrorsAndAmbiguousSetPINCleanup(t *testing.T) {
	t.Run("power cycler missing", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		config := clientPIN2RetryConfig(fixture, nil)
		config.PowerCycler = nil
		result := runAuthrClientPIN2GetRetriesWithConfig(t, fixture, config, 0)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusError)
		if fixture.resets != 0 {
			t.Fatalf("resets = %d, want 0", fixture.resets)
		}
	})

	t.Run("temporary PIN provider missing", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		config := clientPIN2RetryConfig(fixture, nil)
		config.TemporaryPINProvider = nil
		result := runAuthrClientPIN2GetRetriesWithConfig(t, fixture, config, 0)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusError)
		if fixture.powerCycles != 0 || fixture.resets != 0 {
			t.Fatalf("cycles/resets = %d/%d, want 0/0", fixture.powerCycles, fixture.resets)
		}
	})

	t.Run("invalid temporary PIN is cleared", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		pin := []byte("1")
		config := clientPIN2RetryConfig(fixture, nil)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
			return pin, nil
		}
		result := runAuthrClientPIN2GetRetriesWithConfig(t, fixture, config, 0)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusError)
		assertClearedClientPIN2Buffer(t, pin)
	})

	t.Run("UV configurator missing when needed", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		fixture.uvSupported = true
		config := clientPIN2RetryConfig(fixture, nil)
		config.UVConfigurator = nil
		result := runAuthrClientPIN2GetRetriesWithConfig(t, fixture, config, 1)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusError)
		assertClientPIN2CleanupStep(t, result)
	})

	t.Run("set PIN CTAP status fails and cleanup runs", func(t *testing.T) {
		fixture := newClientPIN2RetryAuthenticator(t, 8)
		fixture.setPINStatus = ctaptransport.CTAP2_ERR_OPERATION_DENIED
		result, suppliedPIN := runAuthrClientPIN2GetRetriesMarker(t, fixture, Config{}, 0)
		assertClientPIN2MarkerStatus(t, result, conformance.StatusFailed)
		if fixture.powerCycles != 2 || fixture.resets != 2 {
			t.Fatalf("power cycles/resets = %d/%d, want 2/2", fixture.powerCycles, fixture.resets)
		}
		assertClearedClientPIN2Buffer(t, suppliedPIN)
		assertClientPIN2CleanupStep(t, result)
	})
}

func runAuthrClientPIN2GetRetriesMarker(
	t *testing.T,
	fixture *clientPIN2RetryAuthenticator,
	override Config,
	markerIndex int,
) (conformance.SuiteResult, []byte) {
	t.Helper()

	var suppliedPIN []byte
	config := clientPIN2RetryConfig(fixture, &suppliedPIN)
	config.Transport = override.Transport
	config.Featureful = override.Featureful
	if override.UVConfigurator == nil && fixture.uvSupported && fixture.preserveUVOnReset {
		config.UVConfigurator = nil
	}

	return runAuthrClientPIN2GetRetriesWithConfig(t, fixture, config, markerIndex), suppliedPIN
}

func runAuthrClientPIN2GetRetriesWithConfig(
	t *testing.T,
	fixture *clientPIN2RetryAuthenticator,
	config Config,
	markerIndex int,
) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(fixture)
	if err != nil {
		t.Fatal(err)
	}
	tests := authrClientPIN2GetRetriesTests(config)
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "client-pin2-get-retries-test",
		Name:  "ClientPIN protocol 2 retries test",
		Tests: []conformance.Test{tests[markerIndex]},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func clientPIN2RetryConfig(fixture *clientPIN2RetryAuthenticator, suppliedPIN *[]byte) Config {
	config := Config{
		Transport: AuthenticatorTransportHID,
		PowerCycler: func(context.Context) error {
			fixture.powerCycle()

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
		UVConfigurator: func(_ context.Context, pin []byte) error {
			if !bytes.Equal(pin, fixture.validPIN) {
				return errors.New("UV configurator received wrong PIN")
			}
			fixture.uvConfigurations++
			fixture.uvConfigured = true

			return nil
		},
	}

	return config
}

func assertClientPIN2MarkerStatus(t *testing.T, result conformance.SuiteResult, want conformance.Status) {
	t.Helper()

	if len(result.Tests) != 1 || result.Tests[0].Status != want || result.Status != want {
		t.Fatalf("result = %#v, want one %s test", result, want)
	}
}

func assertClientPIN2StepMessage(t *testing.T, result conformance.SuiteResult, id conformance.StepID, substring string) {
	t.Helper()

	for _, step := range result.Tests[0].Steps {
		if step.ID == id {
			if !bytes.Contains([]byte(step.Message), []byte(substring)) {
				t.Fatalf("step %q message = %q, want containing %q", id, step.Message, substring)
			}

			return
		}
	}
	t.Fatalf("step %q not found in %#v", id, result.Tests[0].Steps)
}

func assertClientPIN2CleanupStep(t *testing.T, result conformance.SuiteResult) {
	t.Helper()

	steps := result.Tests[0].Steps
	if len(steps) == 0 || steps[len(steps)-1].ID != "client-pin2.cleanup" || steps[len(steps)-1].Status != conformance.StatusPassed {
		t.Fatalf("last step = %#v, want passed cleanup", steps)
	}
}

func assertClearedClientPIN2Buffer(t *testing.T, pin []byte) {
	t.Helper()

	if !bytes.Equal(pin, make([]byte, len(pin))) {
		t.Fatalf("temporary PIN was not cleared: %x", pin)
	}
}

func assertClientPIN2HasReferenceSection(t *testing.T, test conformance.Test, section string) {
	t.Helper()

	for _, reference := range test.References {
		if reference.Section == section {
			return
		}
	}
	t.Fatalf("test %q references = %#v, want section %s", test.ID, test.References, section)
}

func assertClientPIN2HasReference(
	t *testing.T,
	test conformance.Test,
	section string,
	clause string,
	level conformance.RequirementLevel,
) {
	t.Helper()

	for _, reference := range test.References {
		if reference.Section == section && reference.Clause == clause && reference.Level == level {
			return
		}
	}
	t.Fatalf("test %q references = %#v, want section %s clause %s level %s", test.ID, test.References, section, clause, level)
}

type clientPIN2RetryAuthenticator struct {
	t *testing.T

	authenticatorPrivate *ecdh.PrivateKey
	authenticatorKey     cose.Key
	validPIN             []byte
	token                []byte
	maxRetries           uint
	retries              uint
	consecutiveInvalid   int
	temporaryBlocked     bool
	temporaryBlockAfter  int
	decrementInvalidPIN  bool
	clientPINPresent     bool
	protocolTwo          bool
	extensionsPresent    bool
	uvSupported          bool
	uvConfigured         bool
	preserveUVOnReset    bool
	uvRetries            uint
	pinRetriesOverride   *uint
	setPINStatus         ctaptransport.StatusCode
	tokenTransportError  error

	powerCycles         int
	resets              int
	setPINCalls         int
	uvConfigurations    int
	uvRetryReads        int
	makeCredentialCalls int
	retryReads          []uint
	tokenStatuses       []ctaptransport.StatusCode
}

func newClientPIN2RetryAuthenticator(t *testing.T, maxRetries uint) *clientPIN2RetryAuthenticator {
	t.Helper()

	privateBytes := make([]byte, 32)
	privateBytes[len(privateBytes)-1] = 1
	privateKey, err := ecdh.P256().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	return &clientPIN2RetryAuthenticator{
		t:                    t,
		authenticatorPrivate: privateKey,
		authenticatorKey:     key,
		validPIN:             []byte("1234"),
		token:                bytes.Repeat([]byte{0x5a}, 32),
		maxRetries:           maxRetries,
		retries:              maxRetries,
		temporaryBlockAfter:  3,
		decrementInvalidPIN:  true,
		clientPINPresent:     true,
		protocolTwo:          true,
		extensionsPresent:    true,
		uvRetries:            5,
	}
}

func (a *clientPIN2RetryAuthenticator) CBOR(ctx context.Context, request []byte) (ctaptransport.CBORResponse, error) {
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
		response = ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       a.getInfoResponse(),
		}
	case protocol.AuthenticatorClientPIN:
		var body protocol.AuthenticatorClientPINRequest
		if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
			a.t.Fatal(err)
		}
		if body.SubCommand == protocol.ClientPINSubCommandGetPinToken && a.tokenTransportError != nil {
			return ctaptransport.CBORResponse{}, a.tokenTransportError
		}
		response = a.clientPINResponse(request[1:])
	case protocol.AuthenticatorMakeCredential:
		a.makeCredentialCalls++
		response = ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalClientPINRetryFixture(a.t, protocol.AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AuthDataRaw:          make([]byte, 37),
				AttestationStatement: map[string]any{},
			}),
		}
	default:
		a.t.Fatalf("unexpected command %s", command)
	}

	return ctaptransport.ValidateCBORResponse(command, response)
}

func (a *clientPIN2RetryAuthenticator) getInfoResponse() []byte {
	options := map[protocol.Option]bool{}
	if a.clientPINPresent {
		options[protocol.OptionClientPIN] = a.setPINCalls != 0
	}
	if a.uvSupported {
		options[protocol.OptionUserVerification] = a.uvConfigured
	}

	fields := map[uint64]any{
		1: []protocol.Version{protocol.FIDO_2_3},
		3: make([]byte, 16),
		4: options,
		10: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
	}
	if a.extensionsPresent {
		fields[2] = []string{"credProtect"}
	}
	if a.protocolTwo {
		fields[6] = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo}
	}

	return marshalClientPINRetryFixture(a.t, fields)
}

func (a *clientPIN2RetryAuthenticator) clientPINResponse(bodyBytes []byte) ctaptransport.CBORResponse {
	var body protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(bodyBytes, &body); err != nil {
		a.t.Fatal(err)
	}
	if body.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
		a.t.Fatalf("protocol = %d, want 2", body.PinUvAuthProtocol)
	}

	switch body.SubCommand {
	case protocol.ClientPINSubCommandGetPINRetries:
		value := a.retries
		if a.pinRetriesOverride != nil {
			value = *a.pinRetriesOverride
		}
		a.retryReads = append(a.retryReads, value)

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalClientPINRetryFixture(a.t, map[uint64]any{3: value}),
		}
	case protocol.ClientPINSubCommandGetUVRetries:
		a.uvRetryReads++

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalClientPINRetryFixture(a.t, map[uint64]any{5: a.uvRetries}),
		}
	case protocol.ClientPINSubCommandGetKeyAgreement:
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalClientPINRetryFixture(a.t, map[uint64]any{1: a.authenticatorKey}),
		}
	case protocol.ClientPINSubCommandSetPIN:
		a.setPINCalls++
		if a.setPINStatus != ctaptransport.CTAP2_OK {
			return ctaptransport.CBORResponse{StatusCode: a.setPINStatus}
		}
		plaintext := a.decryptClientPINValue(body.KeyAgreement, body.NewPinEnc)
		if !bytes.Equal(bytes.TrimRight(plaintext, "\x00"), a.validPIN) {
			a.t.Fatalf("set PIN plaintext = %x, want %x", plaintext, a.validPIN)
		}
		a.retries = a.maxRetries
		a.consecutiveInvalid = 0
		a.temporaryBlocked = false

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
	case protocol.ClientPINSubCommandGetPinToken:
		return a.getPINTokenResponse(body)
	default:
		a.t.Fatalf("unexpected ClientPIN subcommand %s", body.SubCommand)

		return ctaptransport.CBORResponse{}
	}
}

func (a *clientPIN2RetryAuthenticator) getPINTokenResponse(body protocol.AuthenticatorClientPINRequest) ctaptransport.CBORResponse {
	if a.retries == 0 {
		return a.recordTokenStatus(ctaptransport.CTAP2_ERR_PIN_BLOCKED)
	}
	if a.temporaryBlocked {
		return a.recordTokenStatus(ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED)
	}

	pinHash := a.decryptClientPINValue(body.KeyAgreement, body.PinHashEnc)
	wantHash := sha256.Sum256(a.validPIN)
	if !bytes.Equal(pinHash, wantHash[:16]) {
		if a.decrementInvalidPIN {
			a.retries--
		}
		a.consecutiveInvalid++
		if a.retries == 0 {
			return a.recordTokenStatus(ctaptransport.CTAP2_ERR_PIN_BLOCKED)
		}
		if a.consecutiveInvalid == a.temporaryBlockAfter {
			a.temporaryBlocked = true

			return a.recordTokenStatus(ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED)
		}

		return a.recordTokenStatus(ctaptransport.CTAP2_ERR_PIN_INVALID)
	}

	a.retries = a.maxRetries
	a.consecutiveInvalid = 0
	a.temporaryBlocked = false
	sharedSecret := a.clientPINSharedSecret(body.KeyAgreement)
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolTwo)
	if err != nil {
		a.t.Fatal(err)
	}
	encryptedToken, err := pinProtocol.Encrypt(sharedSecret, a.token)
	if err != nil {
		a.t.Fatal(err)
	}
	a.tokenStatuses = append(a.tokenStatuses, ctaptransport.CTAP2_OK)

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       marshalClientPINRetryFixture(a.t, map[uint64]any{2: encryptedToken}),
	}
}

func (a *clientPIN2RetryAuthenticator) recordTokenStatus(status ctaptransport.StatusCode) ctaptransport.CBORResponse {
	a.tokenStatuses = append(a.tokenStatuses, status)

	return ctaptransport.CBORResponse{StatusCode: status}
}

func (a *clientPIN2RetryAuthenticator) decryptClientPINValue(key cose.Key, ciphertext []byte) []byte {
	a.t.Helper()

	sharedSecret := a.clientPINSharedSecret(key)
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

func (a *clientPIN2RetryAuthenticator) clientPINSharedSecret(key cose.Key) []byte {
	a.t.Helper()

	publicKey, err := key.P256PublicKey()
	if err != nil {
		a.t.Fatal(err)
	}
	secret, err := a.authenticatorPrivate.ECDH(publicKey)
	if err != nil {
		a.t.Fatal(err)
	}
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(protocol.PinUvAuthProtocolTwo)
	if err != nil {
		a.t.Fatal(err)
	}
	secret, err = pinProtocol.KDF(secret)
	if err != nil {
		a.t.Fatal(err)
	}

	return secret
}

func (a *clientPIN2RetryAuthenticator) powerCycle() {
	a.powerCycles++
	a.consecutiveInvalid = 0
	a.temporaryBlocked = false
}

func (a *clientPIN2RetryAuthenticator) reset() {
	a.resets++
	a.setPINCalls = 0
	a.retries = a.maxRetries
	a.consecutiveInvalid = 0
	a.temporaryBlocked = false
	if !a.preserveUVOnReset {
		a.uvConfigured = false
	}
}

var _ ctaptransport.CBOR = (*clientPIN2RetryAuthenticator)(nil)
