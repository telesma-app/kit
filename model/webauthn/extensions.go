package webauthn

import (
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/extension"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
)

// PreviewSignKeyMaterialKind classifies the COSE_Key-shaped previewSign output.
type PreviewSignKeyMaterialKind string

const (
	PreviewSignKeyMaterialPublicKey      PreviewSignKeyMaterialKind = "public-key"
	PreviewSignKeyMaterialARKGPublicSeed PreviewSignKeyMaterialKind = "arkg-public-seed"
)

// PreviewSignSigningPolicy describes the user interaction encoded in the signing-key authData.
type PreviewSignSigningPolicy string

const (
	PreviewSignSigningPolicyUnattended       PreviewSignSigningPolicy = "unattended"
	PreviewSignSigningPolicyUserPresence     PreviewSignSigningPolicy = "user-presence"
	PreviewSignSigningPolicyUserVerification PreviewSignSigningPolicy = "user-verification"
)

// PreviewSignSignatureEncoding describes an algorithm output that the toolkit can inspect.
type PreviewSignSignatureEncoding string

const (
	PreviewSignSignatureEncodingOpaque       PreviewSignSignatureEncoding = "opaque"
	PreviewSignSignatureEncodingASN1DERECDSA PreviewSignSignatureEncoding = "asn1-der-ecdsa"
)

// PreviewSignCOSEKeyInspection exposes semantic fields from previewSign COSE key material.
type PreviewSignCOSEKeyInspection struct {
	Kind             PreviewSignKeyMaterialKind    `json:"kind"`
	KeyType          int64                         `json:"keyType"`
	Algorithm        *cose.Algorithm               `json:"algorithm,omitempty"`
	Curve            *int64                        `json:"curve,omitempty"`
	DerivedAlgorithm *cose.Algorithm               `json:"derivedAlgorithm,omitempty"`
	BlindingKey      *PreviewSignCOSEKeyInspection `json:"blindingKey,omitempty"`
	KEMKey           *PreviewSignCOSEKeyInspection `json:"kemKey,omitempty"`
	PublicKeyPEM     string                        `json:"publicKeyPEM,omitempty"`
}

// PreviewSignAttestationInspection summarizes and cross-checks the signing-key attestation.
type PreviewSignAttestationInspection struct {
	Format                      attestation.AttestationStatementFormatIdentifier `json:"format"`
	Type                        attestation.Type                                 `json:"type"`
	CertificateCount            int                                              `json:"certificateCount"`
	AAGUID                      string                                           `json:"aaguid"`
	SigningPolicy               PreviewSignSigningPolicy                         `json:"signingPolicy"`
	KeyHandleMatchesAttestation bool                                             `json:"keyHandleMatchesAttestation"`
	PublicKeyMatchesAttestation bool                                             `json:"publicKeyMatchesAttestation"`
}

// PreviewSignGeneratedKeyInspection groups signing-key material and its attestation.
type PreviewSignGeneratedKeyInspection struct {
	Key         PreviewSignCOSEKeyInspection     `json:"key"`
	Attestation PreviewSignAttestationInspection `json:"attestation"`
}

// PreviewSignSignatureInspection exposes structure known for the selected signing algorithm.
type PreviewSignSignatureInspection struct {
	Algorithm             *cose.Algorithm              `json:"algorithm,omitempty"`
	VerificationAlgorithm *cose.Algorithm              `json:"verificationAlgorithm,omitempty"`
	Encoding              PreviewSignSignatureEncoding `json:"encoding"`
	StructureValid        *bool                        `json:"structureValid,omitempty"`
	RHex                  string                       `json:"rHex,omitempty"`
	SHex                  string                       `json:"sHex,omitempty"`
}

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
	KeyHandleHex             string                             `json:"keyHandleHex"`
	PublicKeyCOSEHex         string                             `json:"publicKeyCOSEHex"`
	Algorithm                cose.Algorithm                     `json:"algorithm"`
	AttestationObjectCBORHex string                             `json:"attestationObjectCBORHex"`
	Inspection               *PreviewSignGeneratedKeyInspection `json:"inspection,omitempty"`
}

type PreviewSignARKGP256Derivation struct {
	AdditionalArgumentsHex string `json:"additionalArgumentsHex"`
	VerificationKeyCOSEHex string `json:"verificationKeyCOSEHex"`
}

type MakeCredentialPreviewSignOutput struct {
	GeneratedKey *PreviewSignGeneratedKey `json:"generatedKey,omitempty"`
}

type GetAssertionPreviewSignOutput struct {
	SignatureHex string                          `json:"signatureHex"`
	Inspection   *PreviewSignSignatureInspection `json:"inspection,omitempty"`
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
