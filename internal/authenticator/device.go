package authenticator

import (
	"context"
	"iter"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/ctap/webauthn"
)

type Lifecycle interface {
	Close() error
}

type InfoProvider interface {
	GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error)
	GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool)
}

type VendorProvider interface {
	Vendor(
		context.Context,
		ctaphid.Command,
		[]byte,
	) (ctaphid.VendorResponse, error)
}

type TokenProvider interface {
	InfoProvider
	GetPinUvAuthTokenUsingPIN(ctx context.Context, pin string, permission protocol.Permission, rpID string) ([]byte, error)
	GetPinUvAuthTokenUsingUV(ctx context.Context, permission protocol.Permission, rpID string) ([]byte, error)
	GetPINRetries(ctx context.Context) (uint, *bool, error)
}

type CredentialInventoryReader interface {
	InfoProvider
	GetCredsMetadata(ctx context.Context, pinUvAuthToken []byte) (protocol.AuthenticatorCredentialManagementResponse, error)
	EnumerateRPs(ctx context.Context, pinUvAuthToken []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error]
	EnumerateCredentials(ctx context.Context, pinUvAuthToken []byte, rpIDHash []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error]
}

type CredentialManager interface {
	CredentialInventoryReader
	DeleteCredential(ctx context.Context, pinUvAuthToken []byte, credentialID credential.PublicKeyCredentialDescriptor) error
	UpdateUserInformation(ctx context.Context, pinUvAuthToken []byte, credentialID credential.PublicKeyCredentialDescriptor, user credential.PublicKeyCredentialUserEntity) error
}

type WebAuthnManager interface {
	InfoProvider
	MakeCredential(
		ctx context.Context,
		pinUvAuthToken []byte,
		clientData []byte,
		rp credential.PublicKeyCredentialRpEntity,
		user credential.PublicKeyCredentialUserEntity,
		pubKeyCredParams []credential.PublicKeyCredentialParameters,
		excludeList []credential.PublicKeyCredentialDescriptor,
		extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
		options map[protocol.Option]bool,
		enterpriseAttestation uint,
		attestationFormatsPreference []attestation.AttestationStatementFormatIdentifier,
	) (protocol.AuthenticatorMakeCredentialResponse, error)
	GetAssertion(
		ctx context.Context,
		pinUvAuthToken []byte,
		rpID string,
		clientData []byte,
		allowList []credential.PublicKeyCredentialDescriptor,
		extInputs *webauthn.GetAuthenticationExtensionsClientInputs,
		options map[protocol.Option]bool,
	) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error]
}

type LargeBlobManager interface {
	InfoProvider
	GetLargeBlobs(ctx context.Context) ([]protocol.LargeBlob, error)
	SetLargeBlobs(ctx context.Context, pinUvAuthToken []byte, blobs []protocol.LargeBlob) error
}

type RetryProvider interface {
	GetPINRetries(ctx context.Context) (uint, *bool, error)
	GetUVRetries(ctx context.Context) (uint, error)
}

type ConfigManager interface {
	RetryProvider
	SetPIN(ctx context.Context, pin string) error
	ChangePIN(ctx context.Context, currentPin, newPin string) error
	Reset(ctx context.Context) error
	EnableEnterpriseAttestation(ctx context.Context, pinUvAuthToken []byte) error
	ToggleAlwaysUV(ctx context.Context, pinUvAuthToken []byte) error
	SetMinPINLength(ctx context.Context, pinUvAuthToken []byte, params protocol.SetMinPINLengthConfigSubCommandParams) error
	EnableLongTouchForReset(ctx context.Context, pinUvAuthToken []byte) error
}

type BioEnrollmentManager interface {
	GetBioModality(ctx context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error)
	GetFingerprintSensorInfo(ctx context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error)
	EnrollBegin(ctx context.Context, pinUvAuthToken []byte, timeoutMilliseconds uint) (protocol.AuthenticatorBioEnrollmentResponse, error)
	EnrollCaptureNextSample(ctx context.Context, pinUvAuthToken []byte, templateID []byte, timeoutMilliseconds uint) (protocol.AuthenticatorBioEnrollmentResponse, error)
	CancelCurrentEnrollment(ctx context.Context) error
	EnumerateEnrollments(ctx context.Context, pinUvAuthToken []byte) (protocol.AuthenticatorBioEnrollmentResponse, error)
	SetFriendlyName(ctx context.Context, pinUvAuthToken []byte, templateID []byte, name string) error
	RemoveEnrollment(ctx context.Context, pinUvAuthToken []byte, templateID []byte) error
}

type LargeBlobDevice interface {
	CredentialInventoryReader
	LargeBlobManager
}

type ConfigStatusDevice interface {
	InfoProvider
	RetryProvider
}

type ConfigDevice interface {
	ConfigStatusDevice
	ConfigManager
}

type BioDevice interface {
	ConfigStatusDevice
	BioEnrollmentManager
}

// Opened is the private capability bundle returned by the authenticator
// opener. The concrete upstream device is adapted once at the transport
// boundary; facade code retains only the capability needed by each domain.
type Opened struct {
	Lifecycle           Lifecycle
	Info                InfoProvider
	Vendor              VendorProvider
	Tokens              TokenProvider
	CredentialInventory CredentialInventoryReader
	Credentials         CredentialManager
	WebAuthn            WebAuthnManager
	LargeBlobs          LargeBlobDevice
	ConfigStatus        ConfigStatusDevice
	Config              ConfigDevice
	Bio                 BioDevice
}
