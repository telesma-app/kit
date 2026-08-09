package conformance

// Profile is an authenticator protocol profile advertised in GetInfo. A
// profile is deliberately distinct from SpecificationID: the former is a
// runtime claim while the latter identifies an immutable normative document.
type Profile string

const (
	ProfileFIDO20    Profile = "FIDO_2_0"
	ProfileFIDO21Pre Profile = "FIDO_2_1_PRE"
	ProfileFIDO21    Profile = "FIDO_2_1"
	ProfileFIDO23    Profile = "FIDO_2_3"
	ProfileU2FV2     Profile = "U2F_V2"
)

type SpecificationID string

const (
	SpecificationCTAP20 SpecificationID = "ctap-2.0-ps-20190130"
	SpecificationCTAP21 SpecificationID = "ctap-2.1-ps-20210615"
	SpecificationCTAP23 SpecificationID = "ctap-2.3-ps-20260226"
)

type Target struct {
	Specification SpecificationID `json:"specification"`
	Profile       Profile         `json:"profile"`
}

type RuleID string

const (
	RuleVersionsRequired                      RuleID = "ctap.get_info.versions.required"
	RulePinUVAuthProtocolsNonEmpty            RuleID = "ctap.get_info.pin_uv_auth_protocols.nonempty"
	RulePinUVAuthProtocolsUnique              RuleID = "ctap.get_info.pin_uv_auth_protocols.unique"
	RuleTransportsNonEmpty                    RuleID = "ctap.get_info.transports.nonempty"
	RuleTransportsUnique                      RuleID = "ctap.get_info.transports.unique"
	RuleAlgorithmsNonEmpty                    RuleID = "ctap.get_info.algorithms.nonempty"
	RuleAlgorithmsUnique                      RuleID = "ctap.get_info.algorithms.unique"
	RuleTransportsForResetNonEmpty            RuleID = "ctap.get_info.transports_for_reset.nonempty"
	RuleTransportsForResetUnique              RuleID = "ctap.get_info.transports_for_reset.unique"
	RuleAttestationFormatsNonEmpty            RuleID = "ctap.get_info.attestation_formats.nonempty"
	RuleAttestationFormatsUnique              RuleID = "ctap.get_info.attestation_formats.unique"
	RuleAttestationFormatsNoneOmitted         RuleID = "ctap.get_info.attestation_formats.none_omitted"
	RuleCertificationLevelRange               RuleID = "ctap.get_info.certifications.level_range"
	RuleProfileHMACSecretRequired             RuleID = "ctap.profile.hmac_secret.required"
	RuleProfileRKUVCapabilityRequired         RuleID = "ctap.profile.rk.user_verification_capability_required"
	RuleProfileRKCredentialManagementRequired RuleID = "ctap.profile.rk.credential_management_required"
	RuleProfileCredentialProtectionRequired   RuleID = "ctap.profile.user_verification.cred_protect_required"
	RuleProfilePinUVAuthTokenRequired         RuleID = "ctap.profile.pin_uv_auth_token.required"
	RuleProfilePinUVProtocolTwoRequired       RuleID = "ctap.profile.pin_uv_protocol_2.required"
	RuleCredBlobRequiresCredProtect           RuleID = "ctap.get_info.cred_blob.cred_protect_required"
	RuleCredBlobRequiresMaxLength             RuleID = "ctap.get_info.cred_blob.max_length_required"
	RuleCredBlobMaxLengthMinimum              RuleID = "ctap.get_info.cred_blob.max_length_minimum"
	RuleCredBlobMaxLengthRequiresExtension    RuleID = "ctap.get_info.cred_blob.max_length_requires_extension"
	RuleLargeBlobModesMutuallyExclusive       RuleID = "ctap.get_info.large_blob.modes_mutually_exclusive"
	RuleLargeBlobExtensionsMutuallyExclusive  RuleID = "ctap.get_info.large_blob.extensions_mutually_exclusive"
	RuleLargeBlobKeyRequiresCommand           RuleID = "ctap.get_info.large_blob_key.command_required"
	RuleLargeBlobsRequiresCapacity            RuleID = "ctap.get_info.large_blobs.capacity_required"
	RuleLargeBlobsCapacityMinimum             RuleID = "ctap.get_info.large_blobs.capacity_minimum"
	RuleLargeBlobsCapacityRequiresCommand     RuleID = "ctap.get_info.large_blobs.capacity_requires_command"
	RuleSetMinPINRequiresPINCapability        RuleID = "ctap.get_info.set_min_pin_length.pin_capability_required"
	RuleSetMinPINSupportConsistency           RuleID = "ctap.get_info.set_min_pin_length.support_consistency"
	RuleAuthenticatorConfigSupportConsistency RuleID = "ctap.get_info.authenticator_config.support_consistency"
	RuleConfigCommandRequired                 RuleID = "ctap.get_info.authenticator_config.command_required"
	RuleConfigCommandPrerequisite             RuleID = "ctap.get_info.authenticator_config.command_prerequisite"
	RuleMinPINLengthMinimum                   RuleID = "ctap.get_info.min_pin_length.minimum"
	RuleMinPINLengthRequiresClientPIN         RuleID = "ctap.get_info.min_pin_length.requires_client_pin"
	RuleClientPINRequiresMinPINLength         RuleID = "ctap.get_info.client_pin.min_pin_length_required"
	RuleMaxPINLengthMinimum                   RuleID = "ctap.get_info.max_pin_length.minimum"
	RuleMaxPINLengthRequiresClientPIN         RuleID = "ctap.get_info.max_pin_length.requires_client_pin"
	RulePinComplexityRequiresClientPIN        RuleID = "ctap.get_info.pin_complexity.requires_client_pin"
	RuleNoMCGARequiresClientPIN               RuleID = "ctap.get_info.no_mc_ga_permissions.requires_client_pin"
	RuleUVBioEnrollRequiresBioEnroll          RuleID = "ctap.get_info.uv_bio_enroll.requires_bio_enroll"
	RuleUVAcfgRequiresAuthnrCfg               RuleID = "ctap.get_info.uv_acfg.requires_authnr_cfg"
	RuleAlwaysUVConflictsWithMakeCredUVNotRqd RuleID = "ctap.get_info.always_uv.conflicts_with_make_cred_uv_not_required"
	RuleAlwaysUVU2FRequiresBuiltInUV          RuleID = "ctap.get_info.always_uv.u2f_requires_built_in_uv"
)

type FieldPath string

type ExpectationKind string

const (
	ExpectationRequired ExpectationKind = "required"
	ExpectationAbsent   ExpectationKind = "absent"
	ExpectationNonEmpty ExpectationKind = "non_empty"
	ExpectationUnique   ExpectationKind = "unique"
	ExpectationMinimum  ExpectationKind = "minimum"
	ExpectationRange    ExpectationKind = "range"
	ExpectationContains ExpectationKind = "contains"
	ExpectationExcludes ExpectationKind = "excludes"
	ExpectationTrue     ExpectationKind = "true"
	ExpectationNotBoth  ExpectationKind = "not_both"
)

type ExpectationQuantifier string

const (
	ExpectationAll ExpectationQuantifier = "all"
	ExpectationAny ExpectationQuantifier = "any"
)

type EvidenceState string

const (
	EvidenceAbsent       EvidenceState = "absent"
	EvidencePresentEmpty EvidenceState = "present_empty"
	EvidencePresent      EvidenceState = "present"
	EvidenceFalse        EvidenceState = "false"
	EvidenceTrue         EvidenceState = "true"
	EvidenceValue        EvidenceState = "value"
)

type EvidenceGapID string

const (
	EvidenceGapAuthenticatorUIUnknown     EvidenceGapID = "authenticator_ui_unknown"
	EvidenceGapImplicitCredProtectUnknown EvidenceGapID = "implicit_cred_protect_unknown"
	EvidenceGapBuiltInPINEntryUnknown     EvidenceGapID = "built_in_pin_entry_unknown"
)

type RequirementID string

type RequirementLevel string

const (
	RequirementConstraint RequirementLevel = "CONSTRAINT"
	RequirementMust       RequirementLevel = "MUST"
	RequirementMustNot    RequirementLevel = "MUST_NOT"
	RequirementShould     RequirementLevel = "SHOULD"
)

type Expectation struct {
	Subjects   []FieldPath           `json:"subjects"`
	Quantifier ExpectationQuantifier `json:"quantifier"`
	Kind       ExpectationKind       `json:"kind"`
	Values     []string              `json:"values"`
}

type Evidence struct {
	Path   FieldPath     `json:"path"`
	State  EvidenceState `json:"state"`
	Values []string      `json:"values"`
}

type RequirementRef struct {
	ID            RequirementID    `json:"id"`
	Specification SpecificationID  `json:"specification"`
	Section       string           `json:"section"`
	Clause        string           `json:"clause"`
	URL           string           `json:"url"`
	Level         RequirementLevel `json:"level"`
}

type Finding struct {
	RuleID       RuleID           `json:"ruleId"`
	Profile      Profile          `json:"profile"`
	Expectations []Expectation    `json:"expectations"`
	Evidence     []Evidence       `json:"evidence"`
	References   []RequirementRef `json:"references"`
}

type Inconclusive struct {
	RuleID       RuleID           `json:"ruleId"`
	Profile      Profile          `json:"profile"`
	Reason       EvidenceGapID    `json:"reason"`
	Expectations []Expectation    `json:"expectations"`
	Evidence     []Evidence       `json:"evidence"`
	References   []RequirementRef `json:"references"`
}

// Assessment is a static assessment of the information observable in one
// authenticatorGetInfo response. Target is nil and no normative rules are run
// when the response does not advertise a stable supported FIDO2 profile. It is
// not a replacement for protocol-level certification testing.
type Assessment struct {
	Target             *Target        `json:"target"`
	AdvertisedProfiles []Profile      `json:"advertisedProfiles"`
	Findings           []Finding      `json:"findings"`
	Inconclusive       []Inconclusive `json:"inconclusive"`
}
