package ctap23

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
	"golang.org/x/text/language"
)

const (
	TestIDMetadataStmt1P1  conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-1"
	TestIDMetadataStmt1P2  conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-2"
	TestIDMetadataStmt1P3  conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-3"
	TestIDMetadataStmt1P4  conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-4"
	TestIDMetadataStmt1P5  conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-5"
	TestIDMetadataStmt1P6  conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-6"
	TestIDMetadataStmt1P7  conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-7"
	TestIDMetadataStmt1P8  conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-8"
	TestIDMetadataStmt1P11 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-11"
	TestIDMetadataStmt1P13 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-13"
	TestIDMetadataStmt1P14 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-14"

	metadataStatementSourcePath = "tests/CTAP2/Metadata/Metadata-Stmt-1.js"

	metadataStatementSpecification conformance.SpecificationID = "fido-metadata-statement-3.1.1-ps-20260105"
	fidoRegistrySpecification      conformance.SpecificationID = "fido-registry-2.3-ps-20260105"
	rfc4122Specification           conformance.SpecificationID = "rfc-4122"
	rfc5646Specification           conformance.SpecificationID = "rfc-5646"

	metadataStatementURL = "https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html"
	fidoRegistryURL      = "https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps-20260105.html"
	metadataCTAP23URL    = "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html"
)

var canonicalUUIDPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

type metadataStatementCase struct {
	id         conformance.TestID
	marker     string
	name       string
	references []conformance.RequirementRef
	validate   func(metadataStatement) error
}

type metadataProtocolVersion struct {
	Major *uint16 `json:"major"`
	Minor *uint16 `json:"minor"`
}

func metadataStatementTests(metadata Metadata) []conformance.Test {
	cases := []metadataStatementCase{
		{
			id:         TestIDMetadataStmt1P1,
			marker:     "P-1",
			name:       "Metadata legal header",
			references: metadataReferences("4", "legalHeader", conformance.RequirementConstraint),
			validate:   validateMetadataLegalHeader,
		},
		{
			id:     TestIDMetadataStmt1P2,
			marker: "P-2",
			name:   "Metadata authenticator identifier",
			references: slices.Concat(
				metadataReferences("3.1", "aaguid-string-representation", conformance.RequirementConstraint),
				metadataReferences("4", "aaguid-required-for-fido2", conformance.RequirementMust),
				[]conformance.RequirementRef{rfc4122UUIDReference()},
			),
			validate: validateMetadataAAGUID,
		},
		{
			id:         TestIDMetadataStmt1P3,
			marker:     "P-3",
			name:       "FIDO2-only metadata fields",
			references: metadataReferences("4", "fido2-inapplicable-fields", conformance.RequirementMustNot),
			validate:   validateMetadataFIDO2Fields,
		},
		{
			id:         TestIDMetadataStmt1P4,
			marker:     "P-4",
			name:       "Metadata description",
			references: metadataReferences("4", "description", conformance.RequirementMust),
			validate:   validateMetadataDescription,
		},
		{
			id:     TestIDMetadataStmt1P5,
			marker: "P-5",
			name:   "Alternative metadata descriptions",
			references: slices.Concat(
				metadataReferences("3.12", "alternative-descriptions", conformance.RequirementConstraint),
				[]conformance.RequirementRef{rfc5646LanguageTagReference()},
			),
			validate: validateMetadataAlternativeDescriptions,
		},
		{
			id:         TestIDMetadataStmt1P6,
			marker:     "P-6",
			name:       "Metadata authenticator version",
			references: metadataReferences("4", "authenticatorVersion", conformance.RequirementConstraint),
			validate:   validateMetadataAuthenticatorVersion,
		},
		{
			id:         TestIDMetadataStmt1P7,
			marker:     "P-7",
			name:       "Metadata protocol family",
			references: metadataReferences("4", "protocolFamily-fido2", conformance.RequirementMust),
			validate:   validateMetadataProtocolFamily,
		},
		{
			id:         TestIDMetadataStmt1P8,
			marker:     "P-8",
			name:       "Metadata protocol versions",
			references: metadataReferences("4", "upv-ctap-2.3", conformance.RequirementConstraint),
			validate:   validateMetadataProtocolVersions,
		},
		{
			id:     TestIDMetadataStmt1P11,
			marker: "P-11",
			name:   "Metadata authentication algorithms",
			references: slices.Concat(
				metadataReferences("4", "authenticationAlgorithms", conformance.RequirementMust),
				[]conformance.RequirementRef{fidoRegistryReference("3.6.1", "authentication-algorithms")},
			),
			validate: validateMetadataAuthenticationAlgorithms,
		},
		{
			id:     TestIDMetadataStmt1P13,
			marker: "P-13",
			name:   "Metadata public key encodings",
			references: slices.Concat(
				metadataReferences("4", "publicKeyAlgAndEncodings", conformance.RequirementMust),
				[]conformance.RequirementRef{
					fidoRegistryReference("3.6.2", "public-key-representation-formats"),
					ctap23CredentialPublicKeyReference(),
				},
			),
			validate: validateMetadataPublicKeyEncodings,
		},
		{
			id:     TestIDMetadataStmt1P14,
			marker: "P-14",
			name:   "Metadata attestation types",
			references: slices.Concat(
				metadataReferences("4", "attestationTypes", conformance.RequirementMust),
				[]conformance.RequirementRef{fidoRegistryReference("3.7", "authenticator-attestation-types")},
			),
			validate: validateMetadataAttestationTypes,
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

func validateMetadataLegalHeader(statement metadataStatement) error {
	legalHeader, present, err := optionalMetadataValue[string](statement, "legalHeader")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip("legalHeader is absent")
	}
	if legalHeader == "" {
		return conformance.Fail("legalHeader must not be empty")
	}

	return nil
}

func validateMetadataAAGUID(statement metadataStatement) error {
	aaguid, err := requiredMetadataValue[string](statement, "aaguid")
	if err != nil {
		return err
	}
	if !canonicalUUIDPattern.MatchString(aaguid) {
		return conformance.Fail("aaguid is not an RFC 4122 UUID string")
	}

	return nil
}

func validateMetadataFIDO2Fields(statement metadataStatement) error {
	for _, name := range []string{"aaid", "attestationCertificateKeyIdentifiers", "supportedExtensions"} {
		if statement.has(name) {
			return conformance.Failf("%s does not apply to FIDO2 metadata", name)
		}
	}

	return nil
}

func validateMetadataDescription(statement metadataStatement) error {
	description, err := requiredMetadataValue[string](statement, "description")
	if err != nil {
		return err
	}
	if description == "" {
		return conformance.Fail("description must not be empty")
	}
	if !asciiString(description) {
		return conformance.Fail("description must contain only ASCII characters")
	}
	if utf8.RuneCountInString(description) > 200 {
		return conformance.Fail("description exceeds 200 characters")
	}

	return nil
}

func validateMetadataAlternativeDescriptions(statement metadataStatement) error {
	descriptions, present, err := optionalMetadataValue[map[string]string](statement, "alternativeDescriptions")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip("alternativeDescriptions is absent")
	}

	languages := make([]string, 0, len(descriptions))
	for language := range descriptions {
		languages = append(languages, language)
	}
	slices.Sort(languages)

	for _, language := range languages {
		if !validAlternativeDescriptionLanguageTag(language) {
			return conformance.Failf("alternativeDescriptions key %q is not a valid language tag", language)
		}

		description := descriptions[language]
		if description == "" {
			return conformance.Failf("alternativeDescriptions value for %q must not be empty", language)
		}
		if utf8.RuneCountInString(description) > 200 {
			return conformance.Failf("alternativeDescriptions value for %q exceeds 200 characters", language)
		}
	}

	return nil
}

func validateMetadataAuthenticatorVersion(statement metadataStatement) error {
	_, err := requiredMetadataValue[uint32](statement, "authenticatorVersion")

	return err
}

func validateMetadataProtocolFamily(statement metadataStatement) error {
	family, err := requiredMetadataValue[string](statement, "protocolFamily")
	if err != nil {
		return err
	}
	if family != "fido2" {
		return conformance.Fail("protocolFamily must be fido2")
	}

	return nil
}

func validateMetadataProtocolVersions(statement metadataStatement) error {
	versions, err := requiredMetadataValue[[]*metadataProtocolVersion](statement, "upv")
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return conformance.Fail("upv must not be empty")
	}

	foundCTAP23 := false
	for _, version := range versions {
		if version == nil || version.Major == nil || version.Minor == nil {
			return conformance.Fail("upv contains an invalid Version value")
		}
		if *version.Major == 1 && *version.Minor == 3 {
			foundCTAP23 = true
		}
	}
	if !foundCTAP23 {
		return conformance.Fail("upv does not contain CTAP 2.3")
	}

	return nil
}

func validateMetadataAuthenticationAlgorithms(statement metadataStatement) error {
	return validateRequiredMetadataNames(statement, "authenticationAlgorithms", registry.ParseAuthenticationAlgorithm)
}

func validateMetadataPublicKeyEncodings(statement metadataStatement) error {
	encodings, err := requiredMetadataNames(statement, "publicKeyAlgAndEncodings", registry.ParsePublicKeyEncoding)
	if err != nil {
		return err
	}
	if !slices.Contains(encodings, "cose") {
		return conformance.Fail("publicKeyAlgAndEncodings does not contain cose")
	}

	return nil
}

func validateMetadataAttestationTypes(statement metadataStatement) error {
	return validateRequiredMetadataNames(statement, "attestationTypes", registry.ParseAttestationType)
}

func validateRequiredMetadataNames[T any](statement metadataStatement, field string, parse func(string) (T, bool)) error {
	_, err := requiredMetadataNames(statement, field, parse)

	return err
}

func requiredMetadataNames[T any](
	statement metadataStatement,
	field string,
	parse func(string) (T, bool),
) ([]string, error) {
	names, err := requiredMetadataValue[[]string](statement, field)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, conformance.Failf("%s must not be empty", field)
	}
	for _, name := range names {
		if _, ok := parse(name); !ok {
			return nil, conformance.Failf("%s contains unregistered value %q", field, name)
		}
	}

	return names, nil
}

func requiredMetadataValue[T any](statement metadataStatement, name string) (T, error) {
	value, present, err := optionalMetadataValue[T](statement, name)
	if err != nil {
		return value, err
	}
	if !present {
		return value, conformance.Failf("%s is required", name)
	}

	return value, nil
}

func optionalMetadataValue[T any](statement metadataStatement, name string) (T, bool, error) {
	var zero T

	var value *T
	present, err := statement.field(name, &value)
	if err != nil {
		return zero, true, conformance.Failf("%s has an invalid type: %v", name, err)
	}
	if !present {
		return zero, false, nil
	}
	if value == nil {
		return zero, true, conformance.Failf("%s must not be null", name)
	}

	return *value, true, nil
}

func validAlternativeDescriptionLanguageTag(tag string) bool {
	// language.Parse also accepts CLDR-style underscores and the non-BCP-47
	// root locale. Keep the accepted input restricted to RFC 5646 syntax.
	if strings.EqualFold(tag, "root") {
		return false
	}
	for _, char := range []byte(tag) {
		if char != '-' &&
			!(char >= 'A' && char <= 'Z') &&
			!(char >= 'a' && char <= 'z') &&
			!(char >= '0' && char <= '9') {
			return false
		}
	}
	if hasRepeatedLanguageTagSubtag(tag) {
		return false
	}

	_, err := language.Parse(tag)

	return err == nil
}

// language.Parse removes duplicate variants and does not reject repeated
// extension singletons, both of which RFC 5646 prohibits.
func hasRepeatedLanguageTagSubtag(tag string) bool {
	parts := strings.Split(tag, "-")
	if strings.EqualFold(parts[0], "x") {
		return false
	}

	variants := make(map[string]struct{})
	singletons := make(map[string]struct{})
	inExtensions := false
	for _, part := range parts[1:] {
		if len(part) == 1 {
			if strings.EqualFold(part, "x") {
				break
			}

			singleton := strings.ToLower(part)
			if _, exists := singletons[singleton]; exists {
				return true
			}
			singletons[singleton] = struct{}{}
			inExtensions = true

			continue
		}
		if inExtensions || !languageTagVariantSubtag(part) {
			continue
		}

		variant := strings.ToLower(part)
		if _, exists := variants[variant]; exists {
			return true
		}
		variants[variant] = struct{}{}
	}

	return false
}

func languageTagVariantSubtag(subtag string) bool {
	return len(subtag) >= 5 && len(subtag) <= 8 ||
		len(subtag) == 4 && subtag[0] >= '0' && subtag[0] <= '9'
}

func asciiString(value string) bool {
	for _, char := range value {
		if char > 0x7f {
			return false
		}
	}

	return true
}

func metadataReferences(
	section string,
	clause string,
	level conformance.RequirementLevel,
) []conformance.RequirementRef {
	anchor := "metadata-keys"
	switch section {
	case "3.1":
		anchor = "authenticator-attestation-guid-aaguid-typedef"
	case "3.12":
		anchor = "alternativedescriptions-dictionary"
	}

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

func fidoRegistryReference(section, clause string) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID("fido-registry-2.3:" + section + ":" + clause),
		Specification: fidoRegistrySpecification,
		Section:       section,
		Clause:        clause,
		URL:           fidoRegistryURL + "#" + clause,
		Level:         conformance.RequirementConstraint,
	}
}

func rfc4122UUIDReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "rfc-4122:3:uuid-string-representation",
		Specification: rfc4122Specification,
		Section:       "3",
		Clause:        "uuid-string-representation",
		URL:           "https://www.rfc-editor.org/rfc/rfc4122.html#section-3",
		Level:         conformance.RequirementConstraint,
	}
}

func rfc5646LanguageTagReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "rfc-5646:2.1:language-tag-syntax",
		Specification: rfc5646Specification,
		Section:       "2.1",
		Clause:        "language-tag-syntax",
		URL:           "https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1",
		Level:         conformance.RequirementConstraint,
	}
}

func ctap23CredentialPublicKeyReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.1:credential-public-key-cose-key",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.1",
		Clause:        "credential-public-key-cose-key",
		URL:           metadataCTAP23URL + "#authenticatorMakeCredential",
		Level:         conformance.RequirementConstraint,
	}
}
