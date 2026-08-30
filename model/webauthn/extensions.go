package webauthn

import (
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/extension"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
)

type CredentialProtectionOutput struct {
	Policy extension.CredentialProtectionPolicy `json:"policy"`
}

type CredentialBlobCreateOutput struct {
	Accepted bool `json:"accepted"`
}

type CredentialBlobGetOutput struct {
	ValueHex string `json:"valueHex"`
}

type HMACSecretCreateOutput struct {
	Enabled bool `json:"enabled"`
}

type HMACSecretOutput struct {
	Output1Hex string `json:"output1Hex"`
	Output2Hex string `json:"output2Hex,omitempty"`
}

type MinPINLengthOutput struct {
	Value uint `json:"value"`
}

type PINComplexityPolicyOutput struct {
	Enabled bool `json:"enabled"`
}

type LargeBlobCreateOutput struct {
	Supported bool `json:"supported"`
}

type LargeBlobGetOutput struct {
	BlobHex *string `json:"blobHex,omitempty"`
	Written *bool   `json:"written,omitempty"`
}

type MakeCredentialPRFOutput struct {
	Enabled bool                                           `json:"enabled"`
	Results ctapwebauthn.AuthenticationExtensionsPRFValues `json:"results,omitzero"`
}

type GetAssertionPRFOutput struct {
	Results ctapwebauthn.AuthenticationExtensionsPRFValues `json:"results,omitzero"`
}

type PreviewSignGeneratedKey struct {
	KeyHandleHex             string         `json:"keyHandleHex"`
	PublicKeyCOSEHex         string         `json:"publicKeyCOSEHex"`
	Algorithm                cose.Algorithm `json:"algorithm"`
	AttestationObjectCBORHex string         `json:"attestationObjectCBORHex"`
}

type MakeCredentialPreviewSignOutput struct {
	GeneratedKey *PreviewSignGeneratedKey `json:"generatedKey,omitempty"`
}

type GetAssertionPreviewSignOutput struct {
	SignatureHex string `json:"signatureHex"`
}

type MakeCredentialClientExtensionResults struct {
	CredentialProperties *ctapwebauthn.CredentialPropertiesOutput `json:"credProps,omitempty"`
	CredentialBlob       *CredentialBlobCreateOutput              `json:"credBlob,omitempty"`
	HMACSecret           *HMACSecretCreateOutput                  `json:"hmac-secret,omitempty"`
	HMACSecretMC         *HMACSecretOutput                        `json:"hmac-secret-mc,omitempty"`
	PRF                  *MakeCredentialPRFOutput                 `json:"prf,omitempty"`
	LargeBlob            *LargeBlobCreateOutput                   `json:"largeBlob,omitempty"`
	PreviewSign          *MakeCredentialPreviewSignOutput         `json:"previewSign,omitempty"`
}

type MakeCredentialAuthenticatorExtensionOutputs struct {
	CredentialProtection *CredentialProtectionOutput `json:"credProtect,omitempty"`
	MinPINLength         *MinPINLengthOutput         `json:"minPinLength,omitempty"`
	PINComplexityPolicy  *PINComplexityPolicyOutput  `json:"pinComplexityPolicy,omitempty"`
}

type MakeCredentialExtensionResults struct {
	Client        *MakeCredentialClientExtensionResults        `json:"client,omitempty"`
	Authenticator *MakeCredentialAuthenticatorExtensionOutputs `json:"authenticator,omitempty"`
}

type GetAssertionClientExtensionResults struct {
	CredentialBlob *CredentialBlobGetOutput       `json:"getCredBlob,omitempty"`
	HMACSecret     *HMACSecretOutput              `json:"hmac-secret,omitempty"`
	PRF            *GetAssertionPRFOutput         `json:"prf,omitempty"`
	LargeBlob      *LargeBlobGetOutput            `json:"largeBlob,omitempty"`
	PreviewSign    *GetAssertionPreviewSignOutput `json:"previewSign,omitempty"`
}

type GetAssertionAuthenticatorExtensionOutputs struct {
	ThirdPartyPayment *bool `json:"thirdPartyPayment,omitempty"`
}

type GetAssertionExtensionResults struct {
	Client        *GetAssertionClientExtensionResults        `json:"client,omitempty"`
	Authenticator *GetAssertionAuthenticatorExtensionOutputs `json:"authenticator,omitempty"`
}
