package webauthn

import (
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/model/safety"
)

const PublicKeyCredentialTypePublicKey = credential.PublicKeyCredentialTypePublicKey

type AuthenticatorOptions struct {
	ResidentKey      *bool `json:"residentKey,omitempty"`
	UserPresence     *bool `json:"userPresence,omitempty"`
	UserVerification *bool `json:"userVerification,omitempty"`
}

type MakeCredentialInput struct {
	RP                           credential.PublicKeyCredentialRpEntity                   `json:"rp"`
	User                         credential.PublicKeyCredentialUserEntity                 `json:"user"`
	ClientDataJSON               []byte                                                   `json:"clientDataJSON"`
	PubKeyCredParams             []credential.PublicKeyCredentialParameters               `json:"pubKeyCredParams"`
	ExcludeList                  []credential.PublicKeyCredentialDescriptor               `json:"excludeList,omitempty"`
	Options                      AuthenticatorOptions                                     `json:"options,omitempty"`
	Extensions                   *ctapwebauthn.CreateAuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
	EnterpriseAttestation        uint                                                     `json:"enterpriseAttestation,omitempty"`
	AttestationFormatsPreference []attestation.AttestationStatementFormatIdentifier       `json:"attestationFormatsPreference,omitempty"`
}

type GetAssertionInput struct {
	RPID           string                                                `json:"rpID"`
	ClientDataJSON []byte                                                `json:"clientDataJSON"`
	AllowList      []credential.PublicKeyCredentialDescriptor            `json:"allowList,omitempty"`
	Options        AuthenticatorOptions                                  `json:"options,omitempty"`
	Extensions     *ctapwebauthn.GetAuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

type MakeCredentialPreview struct {
	Device   report.EndpointReport `json:"device"`
	Input    MakeCredentialInput   `json:"input"`
	Warnings []safety.Warning      `json:"warnings,omitempty"`
}

type GetAssertionPreview struct {
	Device   report.EndpointReport `json:"device"`
	Input    GetAssertionInput     `json:"input"`
	Warnings []safety.Warning      `json:"warnings,omitempty"`
}

type MakeCredentialResult struct {
	AttachmentID             report.AttachmentID                              `json:"attachmentId"`
	RPID                     string                                           `json:"rpID"`
	Format                   attestation.AttestationStatementFormatIdentifier `json:"fmt"`
	CredentialIDHex          string                                           `json:"credentialIDHex"`
	PublicKeyCOSEHex         string                                           `json:"publicKeyCOSEHex"`
	AuthenticatorDataHex     string                                           `json:"authenticatorDataHex"`
	AttestationObjectCBORHex string                                           `json:"attestationObjectCBORHex"`
	AAGUID                   string                                           `json:"aaguid,omitempty"`
	SignCount                uint32                                           `json:"signCount"`
	UserPresent              bool                                             `json:"userPresent"`
	UserVerified             bool                                             `json:"userVerified"`
	EnterpriseAttestation    bool                                             `json:"enterpriseAttestation,omitempty"`
	ExtensionResults         *MakeCredentialExtensionResults                  `json:"extensionResults,omitempty"`
}

type GetAssertionResult struct {
	AttachmentID report.AttachmentID `json:"attachmentId"`
	RPID         string              `json:"rpID"`
	Assertions   []Assertion         `json:"assertions,omitempty"`
}

type Assertion struct {
	Index                uint                                      `json:"index"`
	Credential           credential.PublicKeyCredentialDescriptor  `json:"credential"`
	AuthenticatorDataHex string                                    `json:"authenticatorDataHex"`
	SignatureHex         string                                    `json:"signatureHex"`
	User                 *credential.PublicKeyCredentialUserEntity `json:"user,omitempty"`
	NumberOfCredentials  uint                                      `json:"numberOfCredentials,omitempty"`
	UserSelected         bool                                      `json:"userSelected,omitempty"`
	SignCount            uint32                                    `json:"signCount"`
	UserPresent          bool                                      `json:"userPresent"`
	UserVerified         bool                                      `json:"userVerified"`
	ExtensionResults     *GetAssertionExtensionResults             `json:"extensionResults,omitempty"`
}
