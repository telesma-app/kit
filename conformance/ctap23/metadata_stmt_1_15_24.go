package ctap23

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
	mdsmodel "github.com/telesma-app/mds/model"
)

const (
	TestIDMetadataStmt1P15 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-15"
	TestIDMetadataStmt1P16 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-16"
	TestIDMetadataStmt1P17 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-17"
	TestIDMetadataStmt1P18 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-18"
	TestIDMetadataStmt1P19 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-19"
	TestIDMetadataStmt1P20 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-20"
	TestIDMetadataStmt1P22 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-22"
	TestIDMetadataStmt1P24 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-24"
)

func metadataStatementTestsP15ThroughP24(metadata Metadata) []conformance.Test {
	cases := []metadataStatementCase{
		{
			id:     TestIDMetadataStmt1P15,
			marker: "P-15",
			name:   "Metadata user verification details",
			references: slices.Concat(
				metadataP15ThroughP24References("3.2", "code-accuracy-descriptor", "sctn-type-cad", conformance.RequirementConstraint),
				metadataP15ThroughP24References("3.3", "biometric-accuracy-descriptor", "sctn-type-bad", conformance.RequirementConstraint),
				metadataP15ThroughP24References("3.4", "pattern-accuracy-descriptor", "sctn-type-pad", conformance.RequirementConstraint),
				metadataP15ThroughP24References("3.5", "verification-method-descriptor", "sctn-type-vmd", conformance.RequirementConstraint),
				metadataP15ThroughP24References("3.6", "verification-method-and-combinations", "sctn-type-vmac", conformance.RequirementConstraint),
				metadataReferences("4", "userVerificationDetails", conformance.RequirementConstraint),
				[]conformance.RequirementRef{fidoRegistryReference("3.1", "user-verification-methods")},
			),
			validate: validateMetadataUserVerificationDetails,
		},
		{
			id:     TestIDMetadataStmt1P16,
			marker: "P-16",
			name:   "Metadata key protection",
			references: slices.Concat(
				metadataReferences("4", "keyProtection", conformance.RequirementMust),
				metadataReferences("4", "multiDeviceCredentialSupport", conformance.RequirementConstraint),
				[]conformance.RequirementRef{fidoRegistryReference("3.2", "key-protection-types")},
			),
			validate: validateMetadataKeyProtection,
		},
		{
			id:         TestIDMetadataStmt1P17,
			marker:     "P-17",
			name:       "Metadata key restriction",
			references: metadataReferences("4", "isKeyRestricted", conformance.RequirementConstraint),
			validate: func(statement metadataStatement) error {
				return validateOptionalMetadataBoolean(statement, "isKeyRestricted")
			},
		},
		{
			id:         TestIDMetadataStmt1P18,
			marker:     "P-18",
			name:       "Metadata fresh user verification requirement",
			references: metadataReferences("4", "isFreshUserVerificationRequired", conformance.RequirementConstraint),
			validate: func(statement metadataStatement) error {
				return validateOptionalMetadataBoolean(statement, "isFreshUserVerificationRequired")
			},
		},
		{
			id:     TestIDMetadataStmt1P19,
			marker: "P-19",
			name:   "Metadata matcher protection",
			references: slices.Concat(
				metadataReferences("4", "matcherProtection", conformance.RequirementMust),
				[]conformance.RequirementRef{fidoRegistryReference("3.3", "matcher-protection-types")},
			),
			validate: validateMetadataMatcherProtection,
		},
		{
			id:         TestIDMetadataStmt1P20,
			marker:     "P-20",
			name:       "Metadata cryptographic strength",
			references: metadataReferences("4", "cryptoStrength", conformance.RequirementConstraint),
			validate:   validateMetadataCryptoStrength,
		},
		{
			id:     TestIDMetadataStmt1P22,
			marker: "P-22",
			name:   "Metadata attachment hints",
			references: slices.Concat(
				metadataReferences("4", "attachmentHint", conformance.RequirementMust),
				[]conformance.RequirementRef{fidoRegistryReference("3.4", "authenticator-attachment-hints")},
			),
			validate: validateMetadataAttachmentHints,
		},
		{
			id:     TestIDMetadataStmt1P24,
			marker: "P-24",
			name:   "Metadata transaction confirmation display",
			references: slices.Concat(
				metadataReferences("4", "tcDisplay", conformance.RequirementMust),
				metadataP15ThroughP24References("1", "webidl-dictionary-members-not-null", "notation", conformance.RequirementMust),
				[]conformance.RequirementRef{fidoRegistryReference("3.5", "transaction-confirmation-display-types")},
			),
			validate: validateMetadataTransactionConfirmationDisplay,
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

func validateMetadataUserVerificationDetails(statement metadataStatement) error {
	groups, present, err := optionalMetadataValue[[]json.RawMessage](statement, "userVerificationDetails")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip("userVerificationDetails is absent")
	}
	if len(groups) == 0 {
		return conformance.Fail("userVerificationDetails must not be empty")
	}

	for groupIndex, rawGroup := range groups {
		var descriptors []json.RawMessage
		if err := json.Unmarshal(rawGroup, &descriptors); err != nil {
			return conformance.Failf("userVerificationDetails group %d must be an array", groupIndex)
		}
		if len(descriptors) == 0 {
			return conformance.Failf("userVerificationDetails group %d must not be empty", groupIndex)
		}

		for descriptorIndex, rawDescriptor := range descriptors {
			if err := validateMetadataVerificationMethodDescriptor(rawDescriptor, groupIndex, descriptorIndex); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateMetadataVerificationMethodDescriptor(raw json.RawMessage, groupIndex, descriptorIndex int) error {
	path := "userVerificationDetails descriptor"
	fields, err := metadataP15ThroughP24Object(raw, path)
	if err != nil {
		return err
	}

	var descriptor mdsmodel.VerificationMethodDescriptor
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		return conformance.Failf("userVerificationDetails descriptor %d/%d has an invalid field type: %v", groupIndex, descriptorIndex, err)
	}

	_, err = requiredMetadataValue[string](fields, "userVerificationMethod")
	if err != nil {
		return err
	}
	methodName := *descriptor.UserVerificationMethod
	if methodName == "" {
		return conformance.Fail("userVerificationMethod must not be empty")
	}
	method, ok := registry.ParseUserVerificationMethod(methodName)
	if !ok {
		return conformance.Failf("userVerificationMethod contains unregistered value %q", methodName)
	}
	if !method.ValidMetadata() {
		return conformance.Fail("userVerificationMethod must not be all")
	}

	if fields.has("caDesc") {
		if method != registry.UserVerificationPasscodeInternal && method != registry.UserVerificationPasscodeExternal {
			return conformance.Fail("caDesc is incompatible with userVerificationMethod")
		}

		accuracyFields, err := metadataP15ThroughP24Object(fields.fields["caDesc"], "caDesc")
		if err != nil {
			return err
		}
		if err := validateMetadataCodeAccuracyDescriptor(descriptor.CADesc, accuracyFields); err != nil {
			return err
		}
	}

	if fields.has("baDesc") {
		switch method {
		case registry.UserVerificationFingerprintInternal,
			registry.UserVerificationVoiceprintInternal,
			registry.UserVerificationFaceprintInternal,
			registry.UserVerificationEyeprintInternal,
			registry.UserVerificationHandprintInternal:
		default:
			return conformance.Fail("baDesc is incompatible with userVerificationMethod")
		}

		accuracyFields, err := metadataP15ThroughP24Object(fields.fields["baDesc"], "baDesc")
		if err != nil {
			return err
		}
		if err := validateMetadataBiometricAccuracyDescriptor(descriptor.BADesc, accuracyFields); err != nil {
			return err
		}
	}

	if fields.has("paDesc") {
		if method != registry.UserVerificationPatternInternal && method != registry.UserVerificationPatternExternal {
			return conformance.Fail("paDesc is incompatible with userVerificationMethod")
		}

		accuracyFields, err := metadataP15ThroughP24Object(fields.fields["paDesc"], "paDesc")
		if err != nil {
			return err
		}
		if err := validateMetadataPatternAccuracyDescriptor(descriptor.PADesc, accuracyFields); err != nil {
			return err
		}
	}

	return nil
}

func validateMetadataCodeAccuracyDescriptor(descriptor *mdsmodel.CodeAccuracyDescriptor, fields metadataStatement) error {
	_, err := requiredMetadataValue[uint16](fields, "base")
	if err != nil {
		return err
	}
	if descriptor.Base == 0 {
		return conformance.Fail("caDesc.base must be greater than zero")
	}

	_, err = requiredMetadataValue[uint16](fields, "minLength")
	if err != nil {
		return err
	}
	if descriptor.MinLength == 0 {
		return conformance.Fail("caDesc.minLength must be greater than zero")
	}

	if err := validateMetadataOptionalUint16(fields, "maxRetries"); err != nil {
		return err
	}

	return validateMetadataOptionalUint16(fields, "blockSlowdown")
}

func validateMetadataBiometricAccuracyDescriptor(descriptor *mdsmodel.BiometricAccuracyDescriptor, fields metadataStatement) error {
	names := []string{
		"selfAttestedFRR",
		"selfAttestedFAR",
		"iAPARThreshold",
		"maxTemplates",
		"maxRetries",
		"blockSlowdown",
	}
	if !slices.ContainsFunc(names, fields.has) {
		return conformance.Fail("baDesc must contain at least one accuracy value")
	}

	if err := validateMetadataBiometricRate(fields, "selfAttestedFRR", descriptor.SelfAttestedFRR); err != nil {
		return err
	}
	if err := validateMetadataBiometricRate(fields, "selfAttestedFAR", descriptor.SelfAttestedFAR); err != nil {
		return err
	}
	if err := validateMetadataBiometricRate(fields, "iAPARThreshold", descriptor.IAPARThreshold); err != nil {
		return err
	}

	_, maxTemplatesPresent, err := optionalMetadataValue[uint16](fields, "maxTemplates")
	if err != nil {
		return err
	}
	if maxTemplatesPresent && *descriptor.MaxTemplates == 0 {
		return conformance.Fail("baDesc.maxTemplates must be greater than zero")
	}

	if err := validateMetadataOptionalUint16(fields, "maxRetries"); err != nil {
		return err
	}

	return validateMetadataOptionalUint16(fields, "blockSlowdown")
}

func validateMetadataBiometricRate(fields metadataStatement, name string, value *float64) error {
	_, present, err := optionalMetadataValue[float64](fields, name)
	if err != nil {
		return err
	}
	if present && (*value <= 0 || *value > 1) {
		return conformance.Failf("baDesc.%s must be greater than zero and at most one", name)
	}

	return nil
}

func validateMetadataPatternAccuracyDescriptor(descriptor *mdsmodel.PatternAccuracyDescriptor, fields metadataStatement) error {
	_, err := requiredMetadataValue[uint32](fields, "minComplexity")
	if err != nil {
		return err
	}
	if descriptor.MinComplexity == 0 {
		return conformance.Fail("paDesc.minComplexity must be greater than zero")
	}

	if err := validateMetadataOptionalUint16(fields, "maxRetries"); err != nil {
		return err
	}

	return validateMetadataOptionalUint16(fields, "blockSlowdown")
}

func validateMetadataOptionalUint16(fields metadataStatement, name string) error {
	_, _, err := optionalMetadataValue[uint16](fields, name)

	return err
}

func validateMetadataKeyProtection(statement metadataStatement) error {
	names, err := requiredMetadataValue[[]string](statement, "keyProtection")
	if err != nil {
		return err
	}
	protection, ok := registry.ParseKeyProtections(names)
	if !ok || !protection.ValidMetadata() {
		return conformance.Fail("keyProtection is not a valid registered combination")
	}
	if protection&registry.KeyProtectionSyncFabric != 0 {
		support, present, err := optionalMetadataValue[string](statement, "multiDeviceCredentialSupport")
		if err != nil {
			return err
		}
		if !present || (support != "explicit" && support != "implicit") {
			return conformance.Fail("sync_fabric requires explicit or implicit multiDeviceCredentialSupport")
		}
	}

	return nil
}

func validateOptionalMetadataBoolean(statement metadataStatement, name string) error {
	_, present, err := optionalMetadataValue[bool](statement, name)
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skipf("%s is absent", name)
	}

	return nil
}

func validateMetadataMatcherProtection(statement metadataStatement) error {
	names, err := requiredMetadataValue[[]string](statement, "matcherProtection")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return conformance.Fail("matcherProtection must not be empty")
	}
	if len(names) == 1 {
		protection, ok := registry.ParseMatcherProtection(names[0])
		if !ok || !protection.ValidMetadata() {
			return conformance.Fail("matcherProtection contains an invalid registered value")
		}
	} else {
		for _, name := range names {
			protection, ok := registry.ParseMatcherProtection(name)
			if !ok || !protection.ValidMetadata() {
				return conformance.Failf("matcherProtection contains unregistered value %q", name)
			}
		}
	}

	groups, present, err := optionalMetadataValue[[]json.RawMessage](statement, "userVerificationDetails")
	if err != nil {
		return err
	}
	if !present {
		if len(names) != 1 {
			return conformance.Fail("matcherProtection must contain one minimum security level when userVerificationDetails is absent")
		}

		return nil
	}
	if len(names) == 1 {
		return nil
	}

	methodCount := 0
	for groupIndex, rawGroup := range groups {
		var descriptors []json.RawMessage
		if err := json.Unmarshal(rawGroup, &descriptors); err != nil {
			return conformance.Failf("userVerificationDetails group %d must be an array", groupIndex)
		}
		methodCount += len(descriptors)
	}
	if len(names) != methodCount {
		return conformance.Fail("matcherProtection must contain one value or one value per user verification method")
	}

	return nil
}

func validateMetadataCryptoStrength(statement metadataStatement) error {
	strength, present, err := optionalMetadataValue[uint16](statement, "cryptoStrength")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip("cryptoStrength is absent")
	}
	if strength == 0 {
		return conformance.Fail("cryptoStrength must be greater than zero")
	}

	return nil
}

func validateMetadataAttachmentHints(statement metadataStatement) error {
	// Metadata Statement 3.1.1 conditionally requires attachmentHint for
	// authenticators supporting CTAP 2.2 or newer, which includes CTAP 2.3.
	// Registry 2.3 registers ready, and smart-card's wired pairing is a SHOULD.
	names, err := requiredMetadataValue[[]string](statement, "attachmentHint")
	if err != nil {
		return err
	}
	hints, ok := registry.ParseAttachmentHints(names)
	if !ok || !hints.ValidMetadata() {
		return conformance.Fail("attachmentHint is not a valid registered combination")
	}

	return nil
}

func validateMetadataTransactionConfirmationDisplay(statement metadataStatement) error {
	names, err := requiredMetadataValue[[]string](statement, "tcDisplay")
	if err != nil {
		return err
	}
	display, ok := registry.ParseTransactionConfirmationDisplays(names)
	if !ok || !display.ValidMetadata() {
		return conformance.Fail("tcDisplay is not a valid registered combination")
	}

	supported, err := metadataSupportsTransactionConfirmation(statement)
	if err != nil {
		return err
	}
	if !supported {
		if display != 0 {
			return conformance.Fail("tcDisplay must be empty when transaction confirmation is unsupported")
		}

		return nil
	}
	if display == 0 {
		return conformance.Fail("tcDisplay must not be empty when transaction confirmation is supported")
	}

	return nil
}

func metadataSupportsTransactionConfirmation(statement metadataStatement) (bool, error) {
	rawInfo, present := statement.fields["authenticatorGetInfo"]
	if !present {
		return false, nil
	}

	info, err := metadataP15ThroughP24Object(rawInfo, "authenticatorGetInfo")
	if err != nil {
		return false, err
	}
	extensions, present, err := optionalMetadataValue[[]string](info, "extensions")
	if err != nil {
		return false, err
	}
	if !present {
		return false, nil
	}

	return slices.Contains(extensions, "txAuthSimple") || slices.Contains(extensions, "txAuthGeneric"), nil
}

func metadataP15ThroughP24Object(raw json.RawMessage, name string) (metadataStatement, error) {
	if string(raw) == "null" {
		return metadataStatement{}, conformance.Failf("%s must not be null", name)
	}
	fields, err := mdsmodel.ParseMetadataStatementDocument(raw)
	if err != nil {
		return metadataStatement{}, conformance.Failf("%s must be an object", name)
	}

	return metadataStatement{fields: fields}, nil
}

func metadataP15ThroughP24References(
	section string,
	clause string,
	anchor string,
	level conformance.RequirementLevel,
) []conformance.RequirementRef {
	return []conformance.RequirementRef{
		{
			ID:            conformance.RequirementID("fido-metadata-statement-3.1.1:" + section + ":" + clause),
			Specification: metadataStatementSpecification,
			Section:       section,
			Clause:        clause,
			URL:           metadataStatementURL + "#" + anchor,
			Level:         level,
		},
	}
}
