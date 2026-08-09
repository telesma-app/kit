package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
)

const (
	TestIDMetadataStmt1P32 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-32"
	TestIDMetadataStmt1P33 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-33"
	TestIDMetadataStmt1P34 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-34"
	TestIDMetadataStmt1P35 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-35"
	TestIDMetadataStmt1P36 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-36"

	metadataSampleDescription = "FIDO Alliance Sample FIDO2 Authenticator"
	metadataSampleAAGUID      = "0132d110-bf4e-4208-a403-ab4f5f12efe5"
	metadataSampleIconSHA256  = "356e5a259fc0a6d5532bdb63ff51a1f9a4dbdf76b2c964138faadf450c0df3c7"
	metadataSampleRootSHA256  = "630c818a826a7dbdc2bbd143c1397f6c904ebe8c22ccf29472794d37c2a26a89"
)

var metadataGetInfoFieldNumbers = map[string]uint64{
	"versions":                         1,
	"extensions":                       2,
	"aaguid":                           3,
	"options":                          4,
	"maxMsgSize":                       5,
	"pinUvAuthProtocols":               6,
	"maxCredentialCountInList":         7,
	"maxCredentialIdLength":            8,
	"transports":                       9,
	"algorithms":                       10,
	"maxSerializedLargeBlobArray":      11,
	"forcePINChange":                   12,
	"minPINLength":                     13,
	"firmwareVersion":                  14,
	"maxCredBlobLength":                15,
	"maxRPIDsForSetMinPINLength":       16,
	"preferredPlatformUvAttempts":      17,
	"uvModality":                       18,
	"certifications":                   19,
	"remainingDiscoverableCredentials": 20,
	"vendorPrototypeConfigCommands":    21,
	"attestationFormats":               22,
	"uvCountSinceLastPinEntry":         23,
	"longTouchForReset":                24,
	"encIdentifier":                    25,
	"transportsForReset":               26,
	"pinComplexityPolicy":              27,
	"pinComplexityPolicyURL":           28,
	"maxPINLength":                     29,
	"encCredStoreState":                30,
	"authenticatorConfigCommands":      31,
}

var metadataStatementFields = map[string]bool{
	"legalHeader":                          true,
	"aaid":                                 true,
	"aaguid":                               true,
	"attestationCertificateKeyIdentifiers": true,
	"friendlyNames":                        true,
	"description":                          true,
	"alternativeDescriptions":              true,
	"authenticatorVersion":                 true,
	"protocolFamily":                       true,
	"schema":                               true,
	"upv":                                  true,
	"authenticationAlgorithms":             true,
	"publicKeyAlgAndEncodings":             true,
	"attestationTypes":                     true,
	"userVerificationDetails":              true,
	"keyProtection":                        true,
	"isKeyRestricted":                      true,
	"isFreshUserVerificationRequired":      true,
	"matcherProtection":                    true,
	"cryptoStrength":                       true,
	"attachmentHint":                       true,
	"tcDisplay":                            true,
	"tcDisplayContentType":                 true,
	"tcDisplayPNGCharacteristics":          true,
	"attestationRootCertificates":          true,
	"ecdaaTrustAnchors":                    true,
	"icon":                                 true,
	"iconDark":                             true,
	"providerLogoLight":                    true,
	"providerLogoDark":                     true,
	"supportedExtensions":                  true,
	"multiDeviceCredentialSupport":         true,
	"authenticatorGetInfo":                 true,
	// Metadata Statement 3.1.1 renamed the pinned source's cxpConfigURL.
	"cxConfigURL": true,
}

func metadataStatementTestsP32ThroughP36(metadata Metadata) []conformance.Test {
	cases := []metadataStatementCase{
		{
			id:     TestIDMetadataStmt1P32,
			marker: "P-32",
			name:   "Metadata authenticator GetInfo declaration",
			references: slices.Concat(
				metadataP15ThroughP24References("3.13", "authenticator-get-info-members", "sctn-type-agid", conformance.RequirementConstraint),
				metadataP15ThroughP24References("4", "authenticatorGetInfo", "sctn-md-keys", conformance.RequirementMust),
				[]conformance.RequirementRef{getInfoReference(), fidoRegistryReference("3.1", "user-verification-methods"), fidoRegistryReference("3.6.1", "authentication-algorithms")},
			),
			validate: validateMetadataAuthenticatorGetInfo,
		},
		{
			id:         TestIDMetadataStmt1P33,
			marker:     "P-33",
			name:       "Deprecated metadata fields",
			references: metadataP15ThroughP24References("4", "metadata-statement-members", "sctn-md-keys", conformance.RequirementMustNot),
			validate:   validateMetadataDeprecatedFields,
		},
		{
			id:         TestIDMetadataStmt1P34,
			marker:     "P-34",
			name:       "Metadata statement member set",
			references: metadataP15ThroughP24References("4", "metadata-statement-members", "sctn-md-keys", conformance.RequirementConstraint),
			validate:   validateMetadataStatementFields,
		},
		{
			id:         TestIDMetadataStmt1P35,
			marker:     "P-35",
			name:       "FIDO2 example metadata reuse",
			references: metadataP15ThroughP24References("5.3", "fido2-example", "sctn-fido2-example", conformance.RequirementConstraint),
			// Section 5.3 is non-normative. P-35 is retained as the pinned
			// certification safeguard against copying the published fixture.
			validate: validateMetadataExampleReuse,
		},
		{
			id:     TestIDMetadataStmt1P36,
			marker: "P-36",
			name:   "Metadata legal agreement indication",
			references: slices.Concat(
				metadataP15ThroughP24References("1", "webidl-dictionary-members-not-null", "sctn-notation", conformance.RequirementMust),
				metadataP15ThroughP24References("4", "legalHeader", "sctn-md-keys", conformance.RequirementMust),
			),
			validate: validateMetadataLegalAgreement,
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		definition := definition
		tests = append(tests, conformance.Test{
			ID:         definition.id,
			Name:       definition.name,
			Source:     conformance.SourceLocation{Path: metadataStatementSourcePath, Case: definition.marker},
			References: definition.references,
			Run: func(test *conformance.TestContext) {
				test.Step(conformance.Step{
					ID:         conformance.StepID("metadata-statement." + strings.ToLower(definition.marker)),
					Name:       "Validate " + definition.name,
					References: definition.references,
					Run: func(context.Context) error {
						statement, err := parseMetadataStatement(metadata.StatementJSON)
						if err != nil {
							return err
						}

						return definition.validate(statement)
					},
				})
			},
		})
	}

	return tests
}

func validateMetadataAuthenticatorGetInfo(statement metadataStatement) error {
	rawInfo, present := statement.fields["authenticatorGetInfo"]
	if !present {
		return conformance.Fail("authenticatorGetInfo is required for a native FIDO2 authenticator")
	}
	fields, err := metadataP15ThroughP24Object(rawInfo, "authenticatorGetInfo")
	if err != nil {
		return err
	}
	for name, raw := range fields.fields {
		if _, supported := metadataGetInfoFieldNumbers[name]; !supported {
			return conformance.Failf("authenticatorGetInfo contains unsupported member %q", name)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return conformance.Failf("authenticatorGetInfo.%s must not be null", name)
		}
	}

	if err := validateMetadataGetInfoJSONMembers(fields); err != nil {
		return err
	}

	var info protocol.AuthenticatorGetInfoResponse
	if err := json.Unmarshal(rawInfo, &info); err != nil {
		return conformance.Failf("authenticatorGetInfo has an invalid field type: %v", err)
	}

	wireFields, err := metadataGetInfoWireFields(fields, info)
	if err != nil {
		return err
	}
	if err := validateRequiredGetInfoFields(wireFields, info); err != nil {
		return err
	}

	// Metadata carries empty placeholders for these two per-device encrypted
	// values. The wire validator correctly requires 32-byte iv || ciphertext,
	// so exclude only those fields from the shared static-value checks.
	staticFields := make(map[uint64]cbor.RawMessage, len(wireFields))
	for key, raw := range wireFields {
		staticFields[key] = raw
	}
	delete(staticFields, 25)
	delete(staticFields, 30)
	// The shared validators consume the raw field set, so false and zero are
	// never mistaken for absence as they are by several pinned JS truthiness
	// branches. Current CTAP also explicitly allows zero for
	// maxRPIDsForSetMinPINLength and remainingDiscoverableCredentials.
	if err := validateDeclaredGetInfoFields(staticFields, info); err != nil {
		return err
	}
	if err := validateGetInfoAssessment(info); err != nil {
		return err
	}
	// Use the current CTAP rules rather than the pinned extension and transport
	// whitelists, which cannot represent later registered identifiers.

	if err := validateMetadataGetInfoIdentity(statement, fields, info); err != nil {
		return err
	}
	if err := validateMetadataGetInfoVersions(statement, info.Versions); err != nil {
		return err
	}
	if fields.has("algorithms") {
		if err := validateMetadataGetInfoAlgorithms(statement, info.Algorithms); err != nil {
			return err
		}
	}
	if err := validateMetadataGetInfoFirmware(statement, info); err != nil {
		return err
	}
	if err := validateMetadataGetInfoUVModality(statement, info); err != nil {
		return err
	}

	return validateMetadataEncryptedGetInfoPlaceholders(fields)
}

func validateMetadataGetInfoJSONMembers(fields metadataStatement) error {
	for _, name := range []string{"versions", "extensions", "transports", "attestationFormats", "transportsForReset"} {
		if err := validateMetadataGetInfoList[string](fields, name); err != nil {
			return err
		}
	}
	for _, name := range []string{"pinUvAuthProtocols", "vendorPrototypeConfigCommands", "authenticatorConfigCommands"} {
		if err := validateMetadataGetInfoList[uint64](fields, name); err != nil {
			return err
		}
	}
	for _, name := range []string{"options", "certifications"} {
		raw, present := fields.fields[name]
		if !present {
			continue
		}
		object, err := metadataP15ThroughP24Object(raw, "authenticatorGetInfo."+name)
		if err != nil {
			return err
		}
		for key, value := range object.fields {
			if name == "options" {
				if err := validateMetadataGetInfoJSONValue[bool](value, name+"."+key); err != nil {
					return err
				}
			} else if err := validateMetadataGetInfoJSONValue[uint64](value, name+"."+key); err != nil {
				return err
			}
		}
	}

	return validateMetadataGetInfoAlgorithmObjects(fields)
}

func validateMetadataGetInfoList[T any](fields metadataStatement, name string) error {
	raw, present := fields.fields[name]
	if !present {
		return nil
	}

	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return conformance.Failf("authenticatorGetInfo.%s must be an array: %v", name, err)
	}
	for index, element := range elements {
		if err := validateMetadataGetInfoJSONValue[T](element, fmt.Sprintf("%s[%d]", name, index)); err != nil {
			return err
		}
	}

	return nil
}

func validateMetadataGetInfoJSONValue[T any](raw json.RawMessage, path string) error {
	var value *T
	if err := json.Unmarshal(raw, &value); err != nil {
		return conformance.Failf("authenticatorGetInfo.%s has an invalid type: %v", path, err)
	}
	if value == nil {
		return conformance.Failf("authenticatorGetInfo.%s must not be null", path)
	}

	return nil
}

func validateMetadataGetInfoAlgorithmObjects(fields metadataStatement) error {
	rawAlgorithms, present := fields.fields["algorithms"]
	if !present {
		return nil
	}
	var algorithms []json.RawMessage
	if err := json.Unmarshal(rawAlgorithms, &algorithms); err != nil {
		return conformance.Failf("authenticatorGetInfo.algorithms must be an array: %v", err)
	}
	for index, rawAlgorithm := range algorithms {
		algorithm, err := metadataP15ThroughP24Object(rawAlgorithm, fmt.Sprintf("authenticatorGetInfo.algorithms[%d]", index))
		if err != nil {
			return err
		}
		if len(algorithm.fields) != 2 || !algorithm.has("type") || !algorithm.has("alg") {
			return conformance.Failf("authenticatorGetInfo.algorithms[%d] must contain exactly type and alg", index)
		}
		typ, err := requiredMetadataValue[string](algorithm, "type")
		if err != nil {
			return err
		}
		if typ != string(credential.PublicKeyCredentialTypePublicKey) {
			return conformance.Failf("authenticatorGetInfo.algorithms[%d].type must be public-key", index)
		}
		if _, err := requiredMetadataValue[int64](algorithm, "alg"); err != nil {
			return err
		}
	}

	return nil
}

func metadataGetInfoWireFields(
	fields metadataStatement,
	info protocol.AuthenticatorGetInfoResponse,
) (map[uint64]cbor.RawMessage, error) {
	wire := make(map[uint64]cbor.RawMessage, len(fields.fields))
	for name := range fields.fields {
		wire[metadataGetInfoFieldNumbers[name]] = cbor.RawMessage{0xf6}
	}
	if fields.has("aaguid") {
		rawAAGUID, err := cbor.Marshal(info.AAGUID[:])
		if err != nil {
			return nil, fmt.Errorf("ctap23: encode metadata AAGUID: %w", err)
		}
		wire[3] = rawAAGUID
	}
	if fields.has("algorithms") {
		rawAlgorithms, err := cbor.Marshal(info.Algorithms)
		if err != nil {
			return nil, fmt.Errorf("ctap23: encode metadata algorithms: %w", err)
		}
		wire[10] = rawAlgorithms
	}

	return wire, nil
}

func validateMetadataGetInfoIdentity(
	statement metadataStatement,
	fields metadataStatement,
	info protocol.AuthenticatorGetInfoResponse,
) error {
	getInfoAAGUID, err := requiredMetadataValue[string](fields, "aaguid")
	if err != nil {
		return err
	}
	if len(getInfoAAGUID) != 32 || strings.ToLower(getInfoAAGUID) != getInfoAAGUID {
		return conformance.Fail("authenticatorGetInfo.aaguid must be 32 lower-case hexadecimal characters")
	}
	if _, err := hex.DecodeString(getInfoAAGUID); err != nil {
		return conformance.Fail("authenticatorGetInfo.aaguid must be 32 lower-case hexadecimal characters")
	}

	metadataAAGUID, err := requiredMetadataValue[string](statement, "aaguid")
	if err != nil {
		return err
	}
	if strings.ReplaceAll(strings.ToLower(metadataAAGUID), "-", "") != getInfoAAGUID {
		return conformance.Fail("authenticatorGetInfo.aaguid differs from metadata aaguid")
	}
	if strings.ReplaceAll(info.AAGUID.String(), "-", "") != getInfoAAGUID {
		return conformance.Fail("authenticatorGetInfo.aaguid has an invalid UUID encoding")
	}

	return nil
}

func validateMetadataGetInfoVersions(statement metadataStatement, versions protocol.Versions) error {
	if err := validateMetadataProtocolVersions(statement); err != nil {
		return err
	}
	seen := make(map[protocol.Version]bool, len(versions))
	for _, version := range versions {
		if seen[version] {
			return conformance.Failf("authenticatorGetInfo.versions contains duplicate %q", version)
		}
		seen[version] = true
		switch version {
		case protocol.FIDO_2_0, protocol.FIDO_2_1_PRE, protocol.FIDO_2_1, protocol.FIDO_2_3, protocol.U2F_V2:
		default:
			return conformance.Failf("authenticatorGetInfo.versions contains unsupported value %q", version)
		}
	}

	upv, err := requiredMetadataValue[[]*metadataProtocolVersion](statement, "upv")
	if err != nil {
		return err
	}
	for _, version := range versions {
		var minor uint16
		switch version {
		case protocol.FIDO_2_0:
			minor = 0
		case protocol.FIDO_2_1_PRE, protocol.FIDO_2_1:
			minor = 1
		case protocol.FIDO_2_3:
			minor = 3
		default:
			continue
		}

		if !slices.ContainsFunc(upv, func(candidate *metadataProtocolVersion) bool {
			return candidate != nil && candidate.Major != nil && candidate.Minor != nil &&
				*candidate.Major == 1 && *candidate.Minor == minor
		}) {
			return conformance.Failf("upv does not declare authenticatorGetInfo version %q", version)
		}
	}

	return nil
}

func validateMetadataGetInfoAlgorithms(
	statement metadataStatement,
	algorithms []credential.PublicKeyCredentialParameters,
) error {
	names, err := requiredMetadataNames(statement, "authenticationAlgorithms", registry.ParseAuthenticationAlgorithm)
	if err != nil {
		return err
	}
	if len(algorithms) != len(names) {
		return conformance.Fail("authenticatorGetInfo.algorithms does not match authenticationAlgorithms")
	}
	remaining := slices.Clone(names)
	for _, algorithm := range algorithms {
		index := slices.IndexFunc(remaining, func(name string) bool {
			registered, ok := registry.ParseAuthenticationAlgorithm(name)
			if !ok {
				return false
			}
			profile, ok := registered.COSEProfile()

			return ok && profile.Algorithm == int64(algorithm.Algorithm)
		})
		if index < 0 {
			return conformance.Failf("authenticatorGetInfo algorithm %d is absent from authenticationAlgorithms", algorithm.Algorithm)
		}
		remaining = slices.Delete(remaining, index, index+1)
	}

	return nil
}

func validateMetadataGetInfoFirmware(statement metadataStatement, info protocol.AuthenticatorGetInfoResponse) error {
	if info.FirmwareVersion == nil {
		return nil
	}
	version, err := requiredMetadataValue[uint32](statement, "authenticatorVersion")
	if err != nil {
		return err
	}
	if uint64(*info.FirmwareVersion) != uint64(version) {
		return conformance.Fail("authenticatorGetInfo.firmwareVersion differs from authenticatorVersion")
	}

	return nil
}

func validateMetadataGetInfoUVModality(statement metadataStatement, info protocol.AuthenticatorGetInfoResponse) error {
	if info.UvModality == nil {
		return nil
	}
	if uint64(*info.UvModality) > uint64(^uint32(0)) {
		return conformance.Fail("authenticatorGetInfo.uvModality contains bits outside the FIDO Registry mask")
	}
	modality := registry.UserVerificationMethod(*info.UvModality)
	if !modality.Registered() || modality == 0 {
		return conformance.Fail("authenticatorGetInfo.uvModality contains an unregistered user verification method")
	}

	groups, present, err := optionalMetadataValue[[]json.RawMessage](statement, "userVerificationDetails")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Fail("uvModality requires matching userVerificationDetails")
	}
	declared := registry.UserVerificationMethod(0)
	for groupIndex, rawGroup := range groups {
		var descriptors []json.RawMessage
		if err := json.Unmarshal(rawGroup, &descriptors); err != nil {
			return conformance.Failf("userVerificationDetails group %d must be an array", groupIndex)
		}
		for descriptorIndex, rawDescriptor := range descriptors {
			descriptor, err := metadataP15ThroughP24Object(rawDescriptor, "userVerificationDetails descriptor")
			if err != nil {
				return err
			}
			name, err := requiredMetadataValue[string](descriptor, "userVerificationMethod")
			if err != nil {
				return err
			}
			method, ok := registry.ParseUserVerificationMethod(name)
			if !ok {
				return conformance.Failf("userVerificationDetails descriptor %d/%d has unregistered method %q", groupIndex, descriptorIndex, name)
			}
			declared |= method
		}
	}
	if modality&^declared != 0 {
		return conformance.Fail("authenticatorGetInfo.uvModality contains a method absent from userVerificationDetails")
	}

	return nil
}

func validateMetadataEncryptedGetInfoPlaceholders(fields metadataStatement) error {
	for _, name := range []string{"encIdentifier", "encCredStoreState"} {
		value, present, err := optionalMetadataValue[string](fields, name)
		if err != nil {
			return err
		}
		if present && value != "" {
			return conformance.Failf("authenticatorGetInfo.%s must be an empty metadata placeholder", name)
		}
	}

	return nil
}

func validateMetadataDeprecatedFields(statement metadataStatement) error {
	for _, name := range []string{
		"assertionScheme",
		"authenticationAlgorithm",
		"publicKeyAlgAndEncoding",
		"operatingEnv",
		"isSecondFactorOnly",
	} {
		if statement.has(name) {
			return conformance.Failf("deprecated metadata field %s must be absent", name)
		}
	}

	return nil
}

func validateMetadataStatementFields(statement metadataStatement) error {
	for _, name := range statement.fieldNames() {
		if !metadataStatementFields[name] {
			return conformance.Failf("metadata field %q is not defined by Metadata Statement 3.1.1", name)
		}
	}

	return nil
}

func validateMetadataExampleReuse(statement metadataStatement) error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "aaguid", value: metadataSampleAAGUID},
		{name: "description", value: metadataSampleDescription},
	} {
		value, present, err := optionalMetadataValue[string](statement, field.name)
		if err != nil {
			return err
		}
		if present && value == field.value {
			return conformance.Failf("%s reuses the FIDO2 example value", field.name)
		}
	}

	icon, present, err := optionalMetadataValue[string](statement, "icon")
	if err != nil {
		return err
	}
	if present && metadataValueSHA256(icon) == metadataSampleIconSHA256 {
		return conformance.Fail("icon reuses the FIDO2 example value")
	}

	certificates, present, err := optionalMetadataValue[[]string](statement, "attestationRootCertificates")
	if err != nil {
		return err
	}
	if present {
		for index, certificate := range certificates {
			if metadataValueSHA256(certificate) == metadataSampleRootSHA256 {
				return conformance.Failf("attestationRootCertificates[%d] reuses the FIDO2 example value", index)
			}
		}
	}

	return nil
}

func metadataValueSHA256(value string) string {
	digest := sha256.Sum256([]byte(value))

	return hex.EncodeToString(digest[:])
}

func validateMetadataLegalAgreement(statement metadataStatement) error {
	legalHeader, err := requiredMetadataValue[string](statement, "legalHeader")
	if err != nil {
		return err
	}
	if legalHeader == "" {
		return conformance.Fail("legalHeader must not be empty")
	}

	// The pinned test requires one historical MDS3 sentence. Metadata Statement
	// 3.1.1 instead gives a different example and does not normatively prescribe
	// an exact string, so any nonempty agreement indication is accepted.
	return nil
}
