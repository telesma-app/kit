// Package getinfo resolves authenticatorGetInfo wire values into stable domain
// facts shared by inspection and configuration workflows.
package getinfo

import (
	"encoding/base64"
	"slices"
	"sort"
	"strconv"

	"github.com/telesma-app/ctap/protocol"
	model "github.com/telesma-app/kit/model/inspect"
)

// Resolve returns every supported fact in a fixed order. Display order remains
// the responsibility of consuming applications.
func Resolve(info protocol.AuthenticatorGetInfoResponse) model.Assessment {
	facts := make([]model.Fact, 0, 64)
	add := func(fact model.Fact) { facts = append(facts, fact) }

	add(textFact(model.FactIDAAGUID, "aaguid", model.FactStateObserved, model.FactOriginReported, info.AAGUID.String()))
	add(optionalListFact(model.FactIDTransports, "transports", stringsFrom(info.Transports), info.Transports != nil))
	add(optionFact(info.Options, model.FactIDPlatformAttachment, "options.plat", protocol.OptionPlatformDevice, optionEnabled))
	add(optionalBytesFact(model.FactIDEncryptedDeviceIdentifier, "encIdentifier", info.EncIdentifier))
	add(optionalListFact(model.FactIDVersions, "versions", stringsFrom(info.Versions), info.Versions != nil))
	add(versionFact(info.Versions, protocol.U2F_V2, model.FactIDVersionU2FV2))
	add(versionFact(info.Versions, protocol.FIDO_2_0, model.FactIDVersionFIDO20))
	add(versionFact(info.Versions, protocol.FIDO_2_1_PRE, model.FactIDVersionFIDO21Preview))
	add(versionFact(info.Versions, protocol.FIDO_2_1, model.FactIDVersionFIDO21))
	add(versionFact(info.Versions, protocol.FIDO_2_3, model.FactIDVersionFIDO23))
	add(optionalListFact(model.FactIDAlgorithms, "algorithms", algorithmValues(info), info.Algorithms != nil))

	add(optionFact(info.Options, model.FactIDUserPresence, "options.up", protocol.OptionUserPresence, optionUserPresence))
	add(optionFact(info.Options, model.FactIDResidentCredentials, "options.rk", protocol.OptionResidentKeys, optionCapability))
	add(optionFact(info.Options, model.FactIDClientPIN, "options.clientPin", protocol.OptionClientPIN, optionConfigured))
	add(optionFact(info.Options, model.FactIDUserVerification, "options.uv", protocol.OptionUserVerification, optionConfigured))
	add(optionFact(info.Options, model.FactIDPinUvAuthToken, "options.pinUvAuthToken", protocol.OptionPinUvAuthToken, optionCapability))
	add(invertedOptionFact(info.Options, model.FactIDClientPINMCGAPermissions, "options.noMcGaPermissionsWithClientPin", protocol.OptionNoMcGaPermissionsWithClientPin, model.FactStateEnabled, model.FactStateDisabled))
	add(optionalListFact(model.FactIDPinUvAuthProtocols, "pinUvAuthProtocols", decimalValues(info.PinUvAuthProtocols), info.PinUvAuthProtocols != nil))
	add(optionFact(info.Options, model.FactIDBioEnrollment, "options.bioEnroll", protocol.OptionBioEnroll, optionConfigured))
	add(optionFact(info.Options, model.FactIDBioEnrollmentPreview, "options.userVerificationMgmtPreview", protocol.OptionUserVerificationMgmtPreview, optionConfigured))
	add(optionFact(info.Options, model.FactIDUvBioEnroll, "options.uvBioEnroll", protocol.OptionUvBioEnroll, optionCapability))
	add(optionalUintPointerFact(model.FactIDUvModality, "uvModality", userVerifyPointer(info.UvModality), ""))
	add(optionalUintFact(model.FactIDPreferredPlatformUVAttempts, "preferredPlatformUvAttempts", info.PreferredPlatformUvAttempts, ""))
	add(optionalUintPointerFact(model.FactIDUVCountSinceLastPINEntry, "uvCountSinceLastPinEntry", info.UvCountSinceLastPinEntry, ""))

	add(optionFact(info.Options, model.FactIDLargeBlobs, "options.largeBlobs", protocol.OptionLargeBlobs, optionCapability))
	add(extensionFact(info.Extensions, "largeBlobKey", model.FactIDLargeBlobKey))
	add(optionalUintFact(model.FactIDMaxSerializedLargeBlobArray, "maxSerializedLargeBlobArray", info.MaxSerializedLargeBlobArray, model.FactUnitBytes))
	add(optionalUintFact(model.FactIDMaxCredBlobLength, "maxCredBlobLength", info.MaxCredBlobLength, model.FactUnitBytes))
	add(optionalBytesFact(model.FactIDEncryptedCredentialStoreState, "encCredStoreState", info.EncCredStoreState))

	add(optionFact(info.Options, model.FactIDCredentialManagement, "options.credMgmt", protocol.OptionCredentialManagement, optionCapability))
	add(optionFact(info.Options, model.FactIDCredentialManagementPreview, "options.credentialMgmtPreview", protocol.OptionCredentialManagementPreview, optionCapability))
	add(optionFact(info.Options, model.FactIDCredentialManagementReadOnly, "options.perCredMgmtRO", protocol.OptionPersistentCredentialManagementReadOnly, optionCapability))
	add(optionFact(info.Options, model.FactIDAuthenticatorConfig, "options.authnrCfg", protocol.OptionAuthenticatorConfig, optionCapability))
	add(optionFact(info.Options, model.FactIDUvAuthenticatorConfig, "options.uvAcfg", protocol.OptionUvAcfg, optionCapability))
	add(optionalListFact(model.FactIDAuthenticatorConfigCommands, "authenticatorConfigCommands", decimalValues(info.AuthenticatorConfigCommands), info.AuthenticatorConfigCommands != nil))
	add(optionalListFact(model.FactIDVendorPrototypeConfigCommands, "vendorPrototypeConfigCommands", decimalValues(info.VendorPrototypeConfigCommands), info.VendorPrototypeConfigCommands != nil))
	add(longTouchFact(info))
	add(optionalListFact(model.FactIDTransportsForReset, "transportsForReset", stringsFrom(info.TransportsForReset), info.TransportsForReset != nil))

	add(optionFact(info.Options, model.FactIDEnterpriseAttestation, "options.ep", protocol.OptionEnterpriseAttestation, optionEnabled))
	add(optionFact(info.Options, model.FactIDAlwaysUV, "options.alwaysUv", protocol.OptionAlwaysUv, optionEnabled))
	add(optionFact(info.Options, model.FactIDSetMinPINLength, "options.setMinPINLength", protocol.OptionSetMinPINLength, optionCapability))
	add(invertedOptionFact(info.Options, model.FactIDMakeCredentialUVRequirement, "options.makeCredUvNotRqd", protocol.OptionMakeCredentialUvNotRequired, model.FactStateRequired, model.FactStateNotRequired))
	add(forcePINChangeFact(info.ForcePINChange))
	add(optionalBoolFact(model.FactIDPINComplexityPolicy, "pinComplexityPolicy", info.PinComplexityPolicy, model.FactStateEnabled, model.FactStateDisabled))
	add(optionalTextFact(model.FactIDPINComplexityPolicyURL, "pinComplexityPolicyURL", info.PinComplexityPolicyURLString(), info.PinComplexityPolicyURL != nil))
	add(optionalUintPointerFact(model.FactIDMaxRPIDsForSetMinPINLength, "maxRPIDsForSetMinPINLength", info.MaxRPIDsForSetMinPINLength, ""))

	for _, extension := range extensionFacts {
		add(extensionFact(info.Extensions, extension.name, extension.id))
	}

	add(effectiveUintFact(model.FactIDEffectiveMaxMessageSize, "maxMsgSize", info.EffectiveMaxMsgSize(), info.MaxMsgSize != 0, model.FactUnitBytes))
	add(optionalUintFact(model.FactIDMaxCredentialCountInList, "maxCredentialCountInList", info.MaxCredentialCountInList, ""))
	add(optionalUintFact(model.FactIDMaxCredentialIDLength, "maxCredentialIdLength", info.MaxCredentialIdLength, model.FactUnitBytes))
	add(effectiveUintFact(model.FactIDEffectiveMinPINLength, "minPINLength", info.EffectiveMinPINLength(), info.MinPINLength != 0, model.FactUnitCodePoints))
	add(effectiveUintFact(model.FactIDEffectiveMaxPINLength, "maxPINLength", info.EffectiveMaxPINLength(), info.MaxPINLength != 0, model.FactUnitCodePoints))
	add(optionalUintPointerFact(model.FactIDRemainingDiscoverableCredentials, "remainingDiscoverableCredentials", info.RemainingDiscoverableCredentials, ""))
	add(attestationFormatsFact(info))
	add(certificationsFact(info.Certifications))
	add(optionalUintPointerFact(model.FactIDFirmwareVersion, "firmwareVersion", info.FirmwareVersion, ""))

	return model.Assessment{Facts: facts}
}

// Find returns a resolved fact by its stable identifier.
func Find(assessment model.Assessment, id model.FactID) (model.Fact, bool) {
	for _, fact := range assessment.Facts {
		if fact.ID == id {
			return fact, true
		}
	}

	return model.Fact{}, false
}

type optionSemantics struct {
	trueState    model.FactState
	falseState   model.FactState
	defaultValue bool
}

var (
	optionCapability   = optionSemantics{trueState: model.FactStateSupported, falseState: model.FactStateUnsupported}
	optionConfigured   = optionSemantics{trueState: model.FactStateConfigured, falseState: model.FactStateNotConfigured}
	optionEnabled      = optionSemantics{trueState: model.FactStateEnabled, falseState: model.FactStateDisabled}
	optionUserPresence = optionSemantics{trueState: model.FactStateSupported, falseState: model.FactStateUnsupported, defaultValue: true}
)

func optionFact(options map[protocol.Option]bool, id model.FactID, source string, option protocol.Option, semantics optionSemantics) model.Fact {
	if options == nil {
		return unknownFact(id, source, model.FactValueBoolean)
	}

	value, present := options[option]
	if !present {
		return boolFact(
			id,
			source,
			stateFor(semantics.defaultValue, semantics.trueState, model.FactStateUnsupported),
			model.FactOriginSpecDefault,
			semantics.defaultValue,
		)
	}

	return boolFact(id, source, stateFor(value, semantics.trueState, semantics.falseState), model.FactOriginReported, value)
}

func invertedOptionFact(options map[protocol.Option]bool, id model.FactID, source string, option protocol.Option, trueState, falseState model.FactState) model.Fact {
	if options == nil {
		return unknownFact(id, source, model.FactValueBoolean)
	}

	raw, present := options[option]
	if !present {
		return boolFact(id, source, trueState, model.FactOriginSpecDefault, true)
	}

	value := !raw
	return boolFact(id, source, stateFor(value, trueState, falseState), model.FactOriginDerived, value)
}

func versionFact(versions protocol.Versions, version protocol.Version, id model.FactID) model.Fact {
	source := "versions." + string(version)
	if versions == nil {
		return unknownFact(id, source, model.FactValueBoolean)
	}

	supported := slices.Contains(versions, version)
	return boolFact(id, source, stateFor(supported, model.FactStateSupported, model.FactStateUnsupported), model.FactOriginDerived, supported)
}

func extensionFact[T ~string](extensions []T, extension string, id model.FactID) model.Fact {
	source := "extensions." + extension
	if extensions == nil {
		return unknownFact(id, source, model.FactValueBoolean)
	}

	supported := false
	for _, value := range extensions {
		if string(value) == extension {
			supported = true
			break
		}
	}

	return boolFact(id, source, stateFor(supported, model.FactStateSupported, model.FactStateUnsupported), model.FactOriginDerived, supported)
}

func longTouchFact(info protocol.AuthenticatorGetInfoResponse) model.Fact {
	const source = "longTouchForReset"
	if info.LongTouchForReset == nil {
		return newFact(model.FactIDLongTouchForReset, source, model.FactStateUnsupported, model.FactOriginAbsent, model.FactValue{Kind: model.FactValueBoolean})
	}

	if !slices.Contains(info.AuthenticatorConfigCommands, protocol.ConfigSubCommandEnableLongTouchForReset) {
		return boolFact(model.FactIDLongTouchForReset, source, model.FactStateUnsupported, model.FactOriginDerived, *info.LongTouchForReset)
	}

	return boolFact(model.FactIDLongTouchForReset, source, stateFor(*info.LongTouchForReset, model.FactStateEnabled, model.FactStateDisabled), model.FactOriginReported, *info.LongTouchForReset)
}

func forcePINChangeFact(force bool) model.Fact {
	state := model.FactStateNotRequired
	origin := model.FactOriginSpecDefault
	if force {
		state = model.FactStateWarning
		origin = model.FactOriginReported
	}

	return boolFact(model.FactIDForcePINChange, "forcePINChange", state, origin, force)
}

func attestationFormatsFact(info protocol.AuthenticatorGetInfoResponse) model.Fact {
	if info.AttestationFormats == nil {
		return listFact(model.FactIDAttestationFormats, "attestationFormats", model.FactStateObserved, model.FactOriginSpecDefault, []string{})
	}

	return listFact(model.FactIDAttestationFormats, "attestationFormats", model.FactStateObserved, model.FactOriginReported, stringsFrom(info.AttestationFormats))
}

func certificationsFact(certifications map[string]uint64) model.Fact {
	if certifications == nil {
		return unknownFact(model.FactIDCertifications, "certifications", model.FactValueList)
	}

	keys := make([]string, 0, len(certifications))
	for key := range certifications {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+strconv.FormatUint(certifications[key], 10))
	}

	state := model.FactStateObserved
	if len(values) == 0 {
		state = model.FactStateUnsupported
	}

	return listFact(model.FactIDCertifications, "certifications", state, model.FactOriginReported, values)
}

func unknownFact(id model.FactID, source string, kind model.FactValueKind) model.Fact {
	return newFact(id, source, model.FactStateUnknown, model.FactOriginAbsent, model.FactValue{Kind: kind})
}

func boolFact(id model.FactID, source string, state model.FactState, origin model.FactOrigin, value bool) model.Fact {
	return newFact(id, source, state, origin, model.FactValue{Kind: model.FactValueBoolean, Boolean: new(value)})
}

func integerFact(id model.FactID, source string, state model.FactState, origin model.FactOrigin, value uint64, unit model.FactUnit) model.Fact {
	return newFact(id, source, state, origin, model.FactValue{Kind: model.FactValueInteger, Integer: new(value), Unit: unit})
}

func textFact(id model.FactID, source string, state model.FactState, origin model.FactOrigin, value string) model.Fact {
	return newFact(id, source, state, origin, model.FactValue{Kind: model.FactValueText, Text: new(value)})
}

func listFact(id model.FactID, source string, state model.FactState, origin model.FactOrigin, value []string) model.Fact {
	if value == nil {
		value = []string{}
	}

	return newFact(id, source, state, origin, model.FactValue{Kind: model.FactValueList, List: &value})
}

func newFact(id model.FactID, source string, state model.FactState, origin model.FactOrigin, value model.FactValue) model.Fact {
	return model.Fact{
		ID:     id,
		Source: model.FactSource(source),
		State:  state,
		Origin: origin,
		Value:  value,
	}
}

func stateFor(value bool, trueState, falseState model.FactState) model.FactState {
	if value {
		return trueState
	}
	return falseState
}

func optionalBoolFact(id model.FactID, source string, value *bool, trueState, falseState model.FactState) model.Fact {
	if value == nil {
		return unknownFact(id, source, model.FactValueBoolean)
	}

	return boolFact(id, source, stateFor(*value, trueState, falseState), model.FactOriginReported, *value)
}

func optionalUintFact(id model.FactID, source string, value uint, unit model.FactUnit) model.Fact {
	if value == 0 {
		return unknownFact(id, source, model.FactValueInteger)
	}

	return integerFact(id, source, model.FactStateObserved, model.FactOriginReported, uint64(value), unit)
}

func optionalUintPointerFact(id model.FactID, source string, value *uint, unit model.FactUnit) model.Fact {
	if value == nil {
		return unknownFact(id, source, model.FactValueInteger)
	}

	return integerFact(id, source, model.FactStateObserved, model.FactOriginReported, uint64(*value), unit)
}

func effectiveUintFact(id model.FactID, source string, value uint, reported bool, unit model.FactUnit) model.Fact {
	origin := model.FactOriginSpecDefault
	if reported {
		origin = model.FactOriginReported
	}

	return integerFact(id, source, model.FactStateObserved, origin, uint64(value), unit)
}

func optionalTextFact(id model.FactID, source, value string, reported bool) model.Fact {
	if !reported {
		return unknownFact(id, source, model.FactValueText)
	}

	return textFact(id, source, model.FactStateObserved, model.FactOriginReported, value)
}

func optionalBytesFact(id model.FactID, source string, value []byte) model.Fact {
	if value == nil {
		return unknownFact(id, source, model.FactValueText)
	}

	return textFact(id, source, model.FactStateObserved, model.FactOriginReported, base64.StdEncoding.EncodeToString(value))
}

func optionalListFact(id model.FactID, source string, value []string, reported bool) model.Fact {
	if !reported {
		return unknownFact(id, source, model.FactValueList)
	}

	return listFact(id, source, model.FactStateObserved, model.FactOriginReported, value)
}

func algorithmValues(info protocol.AuthenticatorGetInfoResponse) []string {
	values := make([]string, 0, len(info.Algorithms))
	for _, algorithm := range info.Algorithms {
		values = append(values, string(algorithm.Type)+":"+strconv.FormatInt(int64(algorithm.Algorithm), 10))
	}

	return values
}

type unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

func decimalValues[S ~[]E, E unsigned](input S) []string {
	values := make([]string, len(input))
	for index, value := range input {
		values[index] = strconv.FormatUint(uint64(value), 10)
	}

	return values
}

func stringsFrom[E ~string](values []E) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}

	return result
}

func userVerifyPointer(value *protocol.UserVerify) *uint {
	if value == nil {
		return nil
	}

	return new(uint(*value))
}

var extensionFacts = [...]struct {
	id   model.FactID
	name string
}{
	{model.FactIDExtensionCredProtect, "credProtect"},
	{model.FactIDExtensionCredBlob, "credBlob"},
	{model.FactIDExtensionLargeBlobKey, "largeBlobKey"},
	{model.FactIDExtensionLargeBlob, "largeBlob"},
	{model.FactIDExtensionMinPINLength, "minPinLength"},
	{model.FactIDExtensionPINComplexityPolicy, "pinComplexityPolicy"},
	{model.FactIDExtensionHMACSecret, "hmac-secret"},
	{model.FactIDExtensionHMACSecretMC, "hmac-secret-mc"},
	{model.FactIDExtensionThirdPartyPayment, "thirdPartyPayment"},
}
