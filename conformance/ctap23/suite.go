package ctap23

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/iso7816"
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
	Featureful bool `json:"featureful,omitempty"`
	// AccountSelectionDisplay declares whether the authenticator has an account
	// selection display. Unspecified leaves display-dependent cases inapplicable.
	AccountSelectionDisplay AccountSelectionDisplay `json:"accountSelectionDisplay,omitempty"`
	// SecurityProfile selects the consumer or enterprise conformance profile.
	// Unspecified leaves profile-dependent cases inapplicable.
	SecurityProfile SecurityProfile `json:"securityProfile,omitempty"`
	// LargeBlobEnabledByDefault declares whether credentials created without a
	// largeBlob input support later blob writes. Nil leaves that device policy
	// undeclared and skips only tests whose expected result depends on it.
	LargeBlobEnabledByDefault *bool    `json:"largeBlobEnabledByDefault,omitempty"`
	Metadata                  Metadata `json:"metadata"`
	// Raw transport providers lend exclusive observation sessions for the
	// transport-specific cases. They are runtime capabilities, not JSON DTOs.
	HIDSessionProvider HIDSessionProvider `json:"-"`
	NFCCardProvider    NFCCardProvider    `json:"-"`
	BLESessionProvider BLESessionProvider `json:"-"`
}

// AuthenticatorTransport identifies the CTAP transport observed by the
// runtime. Transport-specific cases use it only for normative preconditions.
type AuthenticatorTransport string

const (
	AuthenticatorTransportHID AuthenticatorTransport = "hid"
	AuthenticatorTransportNFC AuthenticatorTransport = "nfc"
	AuthenticatorTransportBLE AuthenticatorTransport = "ble"
)

// AccountSelectionDisplay describes the authenticator's account-selection UI.
type AccountSelectionDisplay string

const (
	AccountSelectionDisplayUnspecified AccountSelectionDisplay = ""
	AccountSelectionDisplayAbsent      AccountSelectionDisplay = "absent"
	AccountSelectionDisplayPresent     AccountSelectionDisplay = "present"
)

// SecurityProfile selects mutually exclusive consumer and enterprise cases.
type SecurityProfile string

const (
	SecurityProfileUnspecified SecurityProfile = ""
	SecurityProfileConsumer    SecurityProfile = "consumer"
	SecurityProfileEnterprise  SecurityProfile = "enterprise"
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

// BiometricSampleProvider asks the environment to present one biometric sample
// before an enrollment command. The command remains responsible for reporting
// capture feedback and whether another sample is required.
type BiometricSampleProvider func(context.Context) error

// AccountSelectionRequest describes the account the operator must select on
// an authenticator display. Its fields are borrowed for the callback duration.
type AccountSelectionRequest struct {
	RPID        string `json:"rpId"`
	UserID      []byte `json:"userId"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// AccountSelectionPreparer presents one account-selection instruction before
// the suite dispatches the corresponding GetAssertion request.
type AccountSelectionPreparer func(context.Context, AccountSelectionRequest) error

// NFCCardProvider temporarily lends an exclusive raw NFC card session. The
// card is valid only for the callback. The provider owns detaching the normal
// CTAP connection, closing the raw session, and rebinding the normal connection
// before returning.
type NFCCardProvider func(context.Context, func(context.Context, iso7816.Card) error) error

// BLECharacteristic describes one GATT characteristic exposed by a raw BLE
// conformance session. Properties contains the lower-case Bluetooth property
// names reported by the platform, such as read, write, writeWithoutResponse,
// and notify.
type BLECharacteristic struct {
	Properties []string
}

// BLEService describes one GATT service exposed by a raw BLE conformance
// session. UUID keys use the canonical lower-case, unhyphenated form.
type BLEService struct {
	Primary         bool
	Characteristics map[string]BLECharacteristic
}

// BLESession is the observation and framed-command boundary required by the
// CTAP BLE transport cases. Returned maps and byte slices are borrowed for the
// callback duration.
type BLESession interface {
	Services(context.Context) (map[string]BLEService, error)
	ControlPointLength(context.Context) (uint16, error)
	ServiceRevisionBitfield(context.Context) (byte, error)
	Ping(context.Context, []byte) ([]byte, error)
}

// BLESessionProvider temporarily lends an exclusive raw BLE session. The
// provider owns detaching the normal CTAP connection, closing the raw session,
// and rebinding the normal connection before returning.
type BLESessionProvider func(context.Context, func(context.Context, BLESession) error) error

// HIDReport is one 65-byte USB HID output report, including report ID zero.
// It is a value so conformance cases can deliberately drop, reorder, or
// corrupt reports without aliasing provider-owned storage.
type HIDReport [65]byte

// HIDMessage is one decoded CTAPHID message observed on a raw session.
type HIDMessage struct {
	CID            ctaphid.ChannelID
	Command        ctaphid.Command
	DeclaredLength uint16
	Payload        []byte
}

// HIDSession is the exact report/message boundary required by the CTAPHID
// transport cases. ReadMessage reports received=false on timeout with no data.
type HIDSession interface {
	WriteReports(context.Context, []HIDReport) error
	ReadMessage(context.Context, time.Duration) (message HIDMessage, received bool, err error)
}

// HIDSessionProvider temporarily lends an exclusive raw HID session. The
// provider owns detaching and rebinding the normal CTAP connection.
type HIDSessionProvider func(context.Context, func(context.Context, HIDSession) error) error

// Config supplies authenticator metadata and execution prerequisites for the
// CTAP 2.3 suite.
type Config struct {
	Metadata  Metadata
	Transport AuthenticatorTransport
	// Featureful applies the upstream CTAP 2.3 featureful-profile requirements.
	Featureful              bool
	AccountSelectionDisplay AccountSelectionDisplay
	SecurityProfile         SecurityProfile
	// LargeBlobEnabledByDefault is the externally declared device policy used
	// only by cases that omit the largeBlob creation input.
	LargeBlobEnabledByDefault *bool
	TokenProvider             PinUvAuthTokenProvider
	Resetter                  AuthenticatorResetter
	TemporaryPINProvider      TemporaryPINProvider
	PowerCycler               AuthenticatorPowerCycler
	UVConfigurator            UserVerificationConfigurator
	BiometricSampleProvider   BiometricSampleProvider
	PrepareAccountSelection   AccountSelectionPreparer
	NFCCardProvider           NFCCardProvider
	BLESessionProvider        BLESessionProvider
	HIDSessionProvider        HIDSessionProvider
}

// Suite returns the currently implemented CTAP 2.3 authenticator tests.
func Suite(config Config) conformance.Suite {
	source := upstream.Current().Source
	tests := make([]conformance.Test, 0, 295)
	tests = append(tests, hid1Tests(config)...)
	tests = append(tests, nfc1Tests(config)...)
	tests = append(tests, ble1Tests(config)...)
	tests = append(tests,
		getInfoTest(config.Metadata),
		getInfoOptionsTest(config.Metadata),
		getInfoPinUvAuthProtocolsTest(config.Metadata),
		encryptedIdentifierTest(config.TokenProvider, config.Resetter),
		encryptedCredentialStoreStateTest(config.TokenProvider, config.Resetter),
	)
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
	tests = append(tests, authrReset1Tests(config)...)
	tests = append(tests, residentKeyTests(config)...)
	tests = append(tests, enterpriseAttestationTests(config)...)
	tests = append(tests, hmacSecretTests(config)...)
	tests = append(tests, hmacSecret2Tests(config)...)
	tests = append(tests, hmacSecretMCTests(config)...)
	tests = append(tests, credProtectTests(config)...)
	tests = append(tests, credBlobTests(config)...)
	tests = append(tests, largeBlobTests(config)...)
	tests = append(tests, largeBlobKeyTests(config)...)
	tests = append(tests, minPINLengthTests(config)...)
	tests = append(tests, pinComplexityPolicyTests(config)...)
	tests = append(tests, thirdPartyPaymentTests(config)...)
	tests = append(tests, uvmTests(config)...)
	tests = append(tests, authrClientPIN1KeyAgreementTest(config))
	tests = append(tests, authrClientPIN1NewPINTests(config)...)
	tests = append(tests, authrClientPIN1PinPolicyTests(config)...)
	tests = append(tests, authrClientPIN1GetRetriesTests(config)...)
	tests = append(tests, authrClientPIN2KeyAgreementTest(config))
	tests = append(tests, authrClientPIN2NewPINTests(config)...)
	tests = append(tests, authrClientPIN2GetPINTokenTests(config)...)
	tests = append(tests, authrClientPIN2GetPinUvAuthTokenUsingPinWithPermissionsTests(config)...)
	tests = append(tests, authrClientPIN2GetPinUvAuthTokenUsingUvWithPermissionsTests(config)...)
	tests = append(tests, authrClientPIN2PinPolicyTests(config)...)
	tests = append(tests, authrClientPIN2GetRetriesTests(config)...)
	tests = append(tests, credentialManagementEnumerateRPsTests(config)...)
	tests = append(tests, credentialManagementEnumerateCredentialsTests(config)...)
	tests = append(tests, credentialManagementUpdateAndDeleteTests(config)...)
	tests = append(tests, authenticatorConfigTests(config)...)
	tests = append(tests, bioEnrollBioModAndSensorInfoTests(config)...)
	tests = append(tests, bioEnrollEnrollTests(config)...)
	tests = append(tests, bioEnrollEnumerateRenameRemoveTests(config)...)
	tests = append(tests, largeBlobs1Tests(config)...)
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
