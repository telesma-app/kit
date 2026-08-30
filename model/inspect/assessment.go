package inspect

// Assessment is the deterministic, presentation-neutral interpretation of an
// authenticatorGetInfo response.
type Assessment struct {
	Facts []Fact `json:"facts"`
}

// Fact describes one stable GetInfo capability or observation.
type Fact struct {
	ID     FactID     `json:"id"`
	Source FactSource `json:"source"`
	State  FactState  `json:"state"`
	Origin FactOrigin `json:"origin"`
	Value  FactValue  `json:"value"`
}

type FactSource string

type FactID string

const (
	FactIDAAGUID                           FactID = "aaguid"
	FactIDTransports                       FactID = "transports"
	FactIDPlatformAttachment               FactID = "platform_attachment"
	FactIDEncryptedDeviceIdentifier        FactID = "encrypted_device_identifier"
	FactIDVersions                         FactID = "versions"
	FactIDVersionU2FV2                     FactID = "version_u2f_v2"
	FactIDVersionFIDO20                    FactID = "version_fido_2_0"
	FactIDVersionFIDO21Preview             FactID = "version_fido_2_1_pre"
	FactIDVersionFIDO21                    FactID = "version_fido_2_1"
	FactIDVersionFIDO23                    FactID = "version_fido_2_3"
	FactIDAlgorithms                       FactID = "algorithms"
	FactIDUserPresence                     FactID = "user_presence"
	FactIDResidentCredentials              FactID = "resident_credentials"
	FactIDClientPIN                        FactID = "client_pin"
	FactIDUserVerification                 FactID = "user_verification"
	FactIDPinUvAuthToken                   FactID = "pin_uv_auth_token"
	FactIDClientPINMCGAPermissions         FactID = "client_pin_mc_ga_permissions"
	FactIDPinUvAuthProtocols               FactID = "pin_uv_auth_protocols"
	FactIDBioEnrollment                    FactID = "bio_enrollment"
	FactIDBioEnrollmentPreview             FactID = "bio_enrollment_preview"
	FactIDUvBioEnroll                      FactID = "uv_bio_enroll"
	FactIDUvModality                       FactID = "uv_modality"
	FactIDPreferredPlatformUVAttempts      FactID = "preferred_platform_uv_attempts"
	FactIDUVCountSinceLastPINEntry         FactID = "uv_count_since_last_pin_entry"
	FactIDLargeBlobs                       FactID = "large_blobs"
	FactIDLargeBlobKey                     FactID = "large_blob_key"
	FactIDMaxSerializedLargeBlobArray      FactID = "max_serialized_large_blob_array"
	FactIDMaxCredBlobLength                FactID = "max_cred_blob_length"
	FactIDEncryptedCredentialStoreState    FactID = "encrypted_credential_store_state"
	FactIDCredentialManagement             FactID = "credential_management"
	FactIDCredentialManagementPreview      FactID = "credential_management_preview"
	FactIDCredentialManagementReadOnly     FactID = "credential_management_read_only"
	FactIDAuthenticatorConfig              FactID = "authenticator_config"
	FactIDUvAuthenticatorConfig            FactID = "uv_authenticator_config"
	FactIDAuthenticatorConfigCommands      FactID = "authenticator_config_commands"
	FactIDVendorPrototypeConfigCommands    FactID = "vendor_prototype_config_commands"
	FactIDLongTouchForReset                FactID = "long_touch_for_reset"
	FactIDTransportsForReset               FactID = "transports_for_reset"
	FactIDEnterpriseAttestation            FactID = "enterprise_attestation"
	FactIDAlwaysUV                         FactID = "always_uv"
	FactIDSetMinPINLength                  FactID = "set_min_pin_length"
	FactIDMakeCredentialUVRequirement      FactID = "make_credential_uv_requirement"
	FactIDForcePINChange                   FactID = "force_pin_change"
	FactIDPINComplexityPolicy              FactID = "pin_complexity_policy"
	FactIDPINComplexityPolicyURL           FactID = "pin_complexity_policy_url"
	FactIDMaxRPIDsForSetMinPINLength       FactID = "max_rp_ids_for_set_min_pin_length"
	FactIDExtensionCredProtect             FactID = "extension_cred_protect"
	FactIDExtensionCredBlob                FactID = "extension_cred_blob"
	FactIDExtensionLargeBlobKey            FactID = "extension_large_blob_key"
	FactIDExtensionLargeBlob               FactID = "extension_large_blob"
	FactIDExtensionMinPINLength            FactID = "extension_min_pin_length"
	FactIDExtensionPINComplexityPolicy     FactID = "extension_pin_complexity_policy"
	FactIDExtensionHMACSecret              FactID = "extension_hmac_secret"
	FactIDExtensionHMACSecretMC            FactID = "extension_hmac_secret_mc"
	FactIDExtensionThirdPartyPayment       FactID = "extension_third_party_payment"
	FactIDExtensionPreviewSign             FactID = "extension_preview_sign"
	FactIDEffectiveMaxMessageSize          FactID = "effective_max_message_size"
	FactIDMaxCredentialCountInList         FactID = "max_credential_count_in_list"
	FactIDMaxCredentialIDLength            FactID = "max_credential_id_length"
	FactIDEffectiveMinPINLength            FactID = "effective_min_pin_length"
	FactIDEffectiveMaxPINLength            FactID = "effective_max_pin_length"
	FactIDRemainingDiscoverableCredentials FactID = "remaining_discoverable_credentials"
	FactIDAttestationFormats               FactID = "attestation_formats"
	FactIDCertifications                   FactID = "certifications"
	FactIDFirmwareVersion                  FactID = "firmware_version"
)

type FactState string

const (
	FactStateObserved      FactState = "observed"
	FactStateUnknown       FactState = "unknown"
	FactStateSupported     FactState = "supported"
	FactStateUnsupported   FactState = "unsupported"
	FactStateConfigured    FactState = "configured"
	FactStateNotConfigured FactState = "not_configured"
	FactStateEnabled       FactState = "enabled"
	FactStateDisabled      FactState = "disabled"
	FactStateRequired      FactState = "required"
	FactStateNotRequired   FactState = "not_required"
	FactStateWarning       FactState = "warning"
)

type FactOrigin string

const (
	FactOriginReported    FactOrigin = "reported"
	FactOriginSpecDefault FactOrigin = "spec_default"
	FactOriginDerived     FactOrigin = "derived"
	FactOriginAbsent      FactOrigin = "absent"
)

type FactValueKind string

const (
	FactValueBoolean FactValueKind = "boolean"
	FactValueInteger FactValueKind = "integer"
	FactValueText    FactValueKind = "text"
	FactValueList    FactValueKind = "list"
)

type FactUnit string

const (
	FactUnitBytes      FactUnit = "bytes"
	FactUnitCodePoints FactUnit = "code_points"
)

// FactValue is a JSON-friendly tagged union. Exactly one value field is set
// for observed, derived, or defaulted facts; unknown facts carry only Kind.
type FactValue struct {
	Kind    FactValueKind `json:"kind"`
	Boolean *bool         `json:"boolean,omitempty"`
	Integer *uint64       `json:"integer,omitempty"`
	Text    *string       `json:"text,omitempty"`
	List    *[]string     `json:"list,omitempty"`
	Unit    FactUnit      `json:"unit,omitempty"`
}
