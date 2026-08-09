package ctap23

import (
	"context"
	"fmt"
	"slices"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/upstream"
)

const (
	SuiteIDAuthenticator  conformance.SuiteID = "fido.ctap2.3.authenticator"
	TestIDAuthrGeneric1P1 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-1"
	TestIDAuthrGeneric1P2 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-2"
	TestIDAuthrGeneric1P3 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-3"
	TestIDAuthrGeneric1P4 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-4"
	TestIDAuthrGeneric1P5 conformance.TestID  = "fido.ctap2.3.authr-generic-1.p-5"
)

// RunMode selects the non-destructive or complete CTAP 2.3 test set.
type RunMode string

const (
	// RunModeSafe is the zero-value mode and excludes tests that can
	// persistently mutate authenticator state.
	RunModeSafe RunMode = ""
	// RunModeFull runs every implemented case, including tests that may
	// factory-reset the authenticator.
	RunModeFull RunMode = "full"
)

// Valid reports whether mode is a supported CTAP 2.3 conformance run mode.
func (mode RunMode) Valid() bool {
	return mode == RunModeSafe || mode == RunModeFull
}

// String returns the external name of mode.
func (mode RunMode) String() string {
	if mode == RunModeSafe {
		return "safe"
	}

	return string(mode)
}

// RunRequest selects a CTAP 2.3 test set and supplies its metadata statement.
type RunRequest struct {
	Mode RunMode `json:"mode,omitempty"`
	// Featureful applies the upstream CTAP 2.3 featureful-profile requirements.
	Featureful bool     `json:"featureful,omitempty"`
	Metadata   Metadata `json:"metadata"`
}

// AuthenticatorTransport identifies the CTAP transport observed by the
// runtime. Transport-specific cases use it only for normative preconditions.
type AuthenticatorTransport string

const (
	AuthenticatorTransportHID AuthenticatorTransport = "hid"
	AuthenticatorTransportNFC AuthenticatorTransport = "nfc"
	AuthenticatorTransportBLE AuthenticatorTransport = "ble"
)

// Metadata is the expected authenticator declaration used by metadata-bound
// conformance checks. GetInfoFields records exact CBOR field presence so false
// and zero values remain distinguishable from absent fields.
type Metadata struct {
	GetInfo                 protocol.AuthenticatorGetInfoResponse `json:"getInfo"`
	GetInfoFields           []uint64                              `json:"getInfoFields"`
	UserVerificationMethods protocol.UserVerify                   `json:"userVerificationMethods"`
	StatementJSON           string                                `json:"statementJson,omitempty"`
}

// PinUvAuthTokenRequest describes the authorization scope for one suite-owned
// token. RPID is required for permissions whose CTAP scope is RP-bound.
type PinUvAuthTokenRequest struct {
	Permission protocol.Permission `json:"permission"`
	RPID       string              `json:"rpId,omitempty"`
}

// PinUvAuthToken binds a pinUvAuthToken to the protocol that created it.
// Value is suite-owned and must be wiped after use.
type PinUvAuthToken struct {
	Protocol protocol.PinUvAuthProtocol
	Value    []byte
}

// PinUvAuthTokenProvider obtains a pinUvAuthToken with the requested scope.
// Ownership of the returned Value transfers to the suite, which wipes it
// after the current test. The provider may use PIN or built-in UV and may
// configure verification when the authenticator was previously reset.
type PinUvAuthTokenProvider func(
	ctx context.Context,
	client *client.Client,
	request PinUvAuthTokenRequest,
) (PinUvAuthToken, error)

// AuthenticatorResetter performs resets required by destructive cases. The
// callback allows an owning runtime to route reset through its state and cache
// lifecycle. A nil callback uses the test context's low-level CTAP client.
type AuthenticatorResetter func(context.Context, *client.Client) error

// TemporaryPINRequest describes the PIN length accepted by a destructive
// ClientPIN conformance session.
type TemporaryPINRequest struct {
	MinCodePoints uint `json:"minCodePoints"`
	MaxCodePoints uint `json:"maxCodePoints"`
}

// TemporaryPINProvider supplies a user-known PIN for one destructive
// ClientPIN conformance test. Ownership of the returned buffer transfers to
// the suite, which wipes it after the test. The provider must not retain a
// reference to the returned buffer.
type TemporaryPINProvider func(context.Context, TemporaryPINRequest) ([]byte, error)

// AuthenticatorPowerCycler physically power-cycles an HID or BLE authenticator,
// or resets the NFC card session as the transport-specific equivalent. It
// returns only after rebinding the runner's CBOR and client path to a usable
// session; a transport reconnect alone is not a power cycle.
type AuthenticatorPowerCycler func(context.Context) error

// UserVerificationConfigurator prepares built-in user verification for a
// ClientPIN conformance test. PIN is borrowed for the duration of the call and
// must not be retained. On return the runner-bound transport path must remain
// usable, including after any enrollment-driven reconnect.
type UserVerificationConfigurator func(context.Context, []byte) error

// Config supplies authenticator metadata and execution prerequisites for the
// CTAP 2.3 suite.
type Config struct {
	Metadata  Metadata
	Transport AuthenticatorTransport
	// Featureful applies the upstream CTAP 2.3 featureful-profile requirements.
	Featureful           bool
	TokenProvider        PinUvAuthTokenProvider
	Resetter             AuthenticatorResetter
	TemporaryPINProvider TemporaryPINProvider
	PowerCycler          AuthenticatorPowerCycler
	UVConfigurator       UserVerificationConfigurator
}

// Suite returns the currently implemented CTAP 2.3 authenticator tests.
func Suite(config Config) conformance.Suite {
	source := upstream.Current().Source
	tests := []conformance.Test{
		getInfoTest(config.Metadata),
		getInfoOptionsTest(config.Metadata),
		getInfoPinUvAuthProtocolsTest(config.Metadata),
		encryptedIdentifierTest(config.TokenProvider, config.Resetter),
		encryptedCredentialStoreStateTest(config.TokenProvider, config.Resetter),
	}
	tests = append(tests, authrMakeCredReq1Tests(config)...)
	tests = append(tests, authrMakeCredReq2Tests(config)...)
	tests = append(tests, authrMakeCredReq3Tests(config)...)
	tests = append(tests, authrMakeCredReq4Tests(config)...)
	tests = append(tests, authrMakeCredReq5PositiveTests(config)...)
	tests = append(tests, authrMakeCredReq5AttestationTypeTests(config)...)
	tests = append(tests, authrMakeCredReq5NegativeTests(config)...)
	tests = append(tests, authrMakeCredReq6Tests(config)...)
	tests = append(tests, authrMakeCredResp1Tests(config)...)
	tests = append(tests, authrGetAssertionReq1Tests(config)...)
	tests = append(tests, authrGetAssertionReq2Tests(config)...)
	tests = append(tests, authrGetAssertionReq3Tests(config)...)
	tests = append(tests, authrGetAssertionResp1Tests(config)...)
	tests = append(tests, authrClientPIN1KeyAgreementTest(config))
	tests = append(tests, authrClientPIN1NewPINTests(config)...)
	tests = append(tests, authrClientPIN1PinPolicyTests(config)...)
	tests = append(tests, authrClientPIN1GetRetriesTests(config)...)
	tests = append(tests, authrClientPIN2KeyAgreementTest(config))
	tests = append(tests, authrClientPIN2NewPINTests(config)...)
	tests = append(tests, authrClientPIN2GetPINTokenTests(config)...)
	tests = append(tests, authrClientPIN2PinPolicyTests(config)...)
	tests = append(tests, authrClientPIN2GetRetriesTests(config)...)
	tests = append(tests, metadataStatementTests(config.Metadata)...)
	tests = append(tests, metadataStatementTestsP15ThroughP24(config.Metadata)...)
	tests = append(tests, metadataStatementTestsP25ThroughP31(config.Metadata)...)
	tests = append(tests, metadataStatementTestsP32ThroughP36(config.Metadata)...)
	tests = append(tests, metadataStatementTestsP37ThroughP43(config.Metadata)...)

	return conformance.Suite{
		ID:          SuiteIDAuthenticator,
		Name:        "CTAP 2.3 authenticator",
		Description: "Executable CTAP 2.3 authenticator conformance tests",
		Source:      source,
		Tests:       tests,
	}
}

// SuiteFor returns the tests selected by mode.
func SuiteFor(mode RunMode, config Config) (conformance.Suite, error) {
	if !mode.Valid() {
		return conformance.Suite{}, fmt.Errorf("ctap23: unsupported run mode %q", mode)
	}

	suite := Suite(config)
	if mode == RunModeSafe {
		suite.Description = "Non-destructive CTAP 2.3 authenticator conformance tests"
		suite.Tests = slices.DeleteFunc(suite.Tests, func(test conformance.Test) bool {
			return test.Destructive
		})
	}

	return suite, nil
}
