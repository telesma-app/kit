package ctap23

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/telesma-app/kit/conformance"
)

const (
	TestIDMetadataStmt1P37 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-37"
	TestIDMetadataStmt1P38 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-38"
	TestIDMetadataStmt1P39 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-39"
	TestIDMetadataStmt1P40 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-40"
	TestIDMetadataStmt1P41 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-41"
	TestIDMetadataStmt1P42 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-42"
	TestIDMetadataStmt1P43 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-43"
)

var metadataSVGLengthPattern = regexp.MustCompile(`^([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)([A-Za-z%]*)$`)

func metadataStatementTestsP37ThroughP43(metadata Metadata) []conformance.Test {
	cases := []metadataStatementCase{
		{
			id:     TestIDMetadataStmt1P37,
			marker: "P-37",
			name:   "Metadata friendly names",
			references: slices.Concat(
				metadataP15ThroughP24References("3.11", "friendly-names", "sctn-type-fn", conformance.RequirementConstraint),
				metadataReferences("4", "friendlyNames", conformance.RequirementMust),
				[]conformance.RequirementRef{rfc5646LanguageTagReference()},
			),
			validate: validateMetadataFriendlyNames,
		},
		{
			id:     TestIDMetadataStmt1P38,
			marker: "P-38",
			name:   "Metadata dark authenticator icon",
			references: slices.Concat(
				metadataReferences("4", "iconDark", conformance.RequirementConstraint),
				[]conformance.RequirementRef{rfc2397DataURLReference(), svg11ImageReference()},
			),
			validate: func(statement metadataStatement) error {
				return validateMetadataSVGIcon(statement, "iconDark")
			},
		},
		{
			id:         TestIDMetadataStmt1P39,
			marker:     "P-39",
			name:       "Metadata light provider logo",
			references: metadataProviderLogoReferences("providerLogoLight"),
			validate: func(statement metadataStatement) error {
				return validateMetadataProviderLogo(statement, "providerLogoLight")
			},
		},
		{
			id:         TestIDMetadataStmt1P40,
			marker:     "P-40",
			name:       "Metadata dark provider logo",
			references: metadataProviderLogoReferences("providerLogoDark"),
			validate: func(statement metadataStatement) error {
				return validateMetadataProviderLogo(statement, "providerLogoDark")
			},
		},
		{
			id:         TestIDMetadataStmt1P41,
			marker:     "P-41",
			name:       "Metadata legacy key scope",
			references: metadataReferences("4", "metadata-keys", conformance.RequirementConstraint),
			validate:   validateMetadataLegacyKeyScope,
		},
		{
			id:         TestIDMetadataStmt1P42,
			marker:     "P-42",
			name:       "Metadata multi-device credential support",
			references: metadataReferences("4", "multiDeviceCredentialSupport", conformance.RequirementConstraint),
			validate:   validateMetadataMultiDeviceCredentialSupport,
		},
		{
			id:         TestIDMetadataStmt1P43,
			marker:     "P-43",
			name:       "Metadata credential exchange configuration URL",
			references: metadataReferences("4", "cxConfigURL", conformance.RequirementConstraint),
			validate:   validateMetadataCredentialExchangeConfigurationURL,
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

func validateMetadataFriendlyNames(statement metadataStatement) error {
	names, present, err := optionalMetadataValue[map[string]string](statement, "friendlyNames")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip("friendlyNames is absent")
	}

	languages := make([]string, 0, len(names))
	for language := range names {
		languages = append(languages, language)
	}
	slices.Sort(languages)

	for _, language := range languages {
		if !validAlternativeDescriptionLanguageTag(language) {
			return conformance.Failf("friendlyNames key %q is not a valid RFC 5646 language tag", language)
		}

		name := names[language]
		if name == "" {
			return conformance.Failf("friendlyNames value for %q must not be empty", language)
		}
		if utf8.RuneCountInString(name) > 63 {
			return conformance.Failf("friendlyNames value for %q exceeds 63 characters", language)
		}
	}

	if names["en-US"] == "" {
		return conformance.Fail("friendlyNames must contain a nonempty en-US entry")
	}

	// Pinned P-37 rejects a 63-character value despite describing 63 as the
	// maximum. Metadata Statement 3.1.1 says values SHOULD NOT exceed 63, so
	// exactly 63 characters is accepted.
	return nil
}

func validateMetadataSVGIcon(statement metadataStatement, field string) error {
	value, present, err := optionalMetadataValue[string](statement, field)
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip(field + " is absent")
	}
	if err := validateMetadataIconDataURL(value, true); err != nil {
		return err
	}

	// The pinned shared helper applies the provider-logo Tiny-P/S profile to
	// iconDark. Metadata Statement 3.1.1 section 4.1 scopes that profile to
	// provider icons; iconDark itself requires an RFC 2397 encoded SVG11 icon.
	return nil
}

func validateMetadataProviderLogo(statement metadataStatement, field string) error {
	value, present, err := optionalMetadataValue[string](statement, field)
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip(field + " is absent")
	}
	if err := validateMetadataIconDataURL(value, true); err != nil {
		return err
	}

	friendlyNames, err := requiredMetadataValue[map[string]string](statement, "friendlyNames")
	if err != nil {
		return err
	}
	englishName := friendlyNames["en-US"]
	if englishName == "" {
		return conformance.Fail(field + " requires a nonempty friendlyNames en-US entry")
	}

	encoded := strings.TrimPrefix(value, "data:image/svg+xml;base64,")
	data, err := decodeMetadataBase64(encoded)
	if err != nil {
		return conformance.Failf("%s has an invalid SVG data URL payload: %v", field, err)
	}
	profile, err := inspectMetadataProviderSVG(data)
	if err != nil {
		return conformance.Failf("%s does not satisfy the provider SVG profile: %v", field, err)
	}
	if profile.version != "1.2" {
		return conformance.Failf("%s SVG version is %q, want 1.2", field, profile.version)
	}
	if profile.baseProfile != "tiny-ps" {
		return conformance.Failf("%s SVG baseProfile is %q, want tiny-ps", field, profile.baseProfile)
	}
	if err := validateMetadataSVGSquareDimensions(profile); err != nil {
		return conformance.Failf("%s SVG dimensions are not square: %v", field, err)
	}
	if strings.TrimSpace(profile.title) != englishName {
		return conformance.Failf("%s SVG title must equal friendlyNames en-US", field)
	}

	// The pinned helper only checks that title is nonempty. Section 4.1
	// requires the English provider friendly name, so this validator compares
	// the title with friendlyNames["en-US"]. This case covers the additional
	// section 4.1 checks represented by the assigned upstream helper; complete
	// SVG-P/S RNC validation is a separate shared primitive.
	return nil
}

type metadataProviderSVGProfile struct {
	version     string
	baseProfile string
	viewBox     string
	width       string
	height      string
	title       string
}

func inspectMetadataProviderSVG(data []byte) (metadataProviderSVGProfile, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var profile metadataProviderSVGProfile
	var title strings.Builder
	depth := 0
	titleDepth := 0
	titleSeen := false
	rootSeen := false

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return metadataProviderSVGProfile{}, err
		}

		switch token := token.(type) {
		case xml.StartElement:
			if titleDepth != 0 {
				return metadataProviderSVGProfile{}, errors.New("title must contain text only")
			}
			if depth == 0 {
				if rootSeen {
					return metadataProviderSVGProfile{}, errors.New("multiple root elements")
				}
				rootSeen = true
				profile.version = metadataSVGAttribute(token.Attr, "version")
				profile.baseProfile = metadataSVGAttribute(token.Attr, "baseProfile")
				profile.viewBox = metadataSVGAttribute(token.Attr, "viewBox")
				profile.width = metadataSVGAttribute(token.Attr, "width")
				profile.height = metadataSVGAttribute(token.Attr, "height")
			}
			switch token.Name.Local {
			case "image", "feImage", "foreignObject":
				return metadataProviderSVGProfile{}, errors.New("raster or foreign-content element is prohibited")
			}
			if depth == 1 && token.Name.Space == "http://www.w3.org/2000/svg" && token.Name.Local == "title" {
				if titleSeen {
					return metadataProviderSVGProfile{}, errors.New("multiple title elements")
				}
				titleSeen = true
				titleDepth = depth + 1
			}
			depth++
		case xml.EndElement:
			if titleDepth == depth && token.Name.Space == "http://www.w3.org/2000/svg" && token.Name.Local == "title" {
				titleDepth = 0
			}
			depth--
		case xml.CharData:
			if titleDepth != 0 {
				title.Write(token)
			} else if strings.TrimSpace(string(token)) != "" {
				return metadataProviderSVGProfile{}, errors.New("extra text is prohibited")
			}
		case xml.Comment:
			return metadataProviderSVGProfile{}, errors.New("comments are prohibited")
		case xml.Directive:
			return metadataProviderSVGProfile{}, errors.New("directives are prohibited")
		case xml.ProcInst:
			if token.Target != "xml" || rootSeen {
				return metadataProviderSVGProfile{}, errors.New("processing instructions are prohibited")
			}
		}
	}

	if !rootSeen {
		return metadataProviderSVGProfile{}, errors.New("SVG root is missing")
	}
	if !titleSeen {
		return metadataProviderSVGProfile{}, errors.New("title is missing")
	}
	profile.title = title.String()

	return profile, nil
}

func metadataSVGAttribute(attributes []xml.Attr, name string) string {
	for _, attribute := range attributes {
		if attribute.Name.Space == "" && attribute.Name.Local == name {
			return attribute.Value
		}
	}

	return ""
}

func validateMetadataSVGSquareDimensions(profile metadataProviderSVGProfile) error {
	if profile.viewBox != "" {
		parts := strings.FieldsFunc(profile.viewBox, func(char rune) bool {
			return char == ',' || unicode.IsSpace(char)
		})
		if len(parts) != 4 {
			return errors.New("viewBox must contain four numbers")
		}

		width, err := parseMetadataSVGNumber(parts[2])
		if err != nil {
			return err
		}
		height, err := parseMetadataSVGNumber(parts[3])
		if err != nil {
			return err
		}
		if width <= 0 || height <= 0 || !metadataSVGDimensionsEqual(width, height) {
			return errors.New("viewBox width and height differ")
		}
		if profile.width != "" || profile.height != "" {
			return validateMetadataSVGViewportDimensions(profile.width, profile.height)
		}

		return nil
	}

	return validateMetadataSVGViewportDimensions(profile.width, profile.height)
}

func validateMetadataSVGViewportDimensions(widthValue, heightValue string) error {
	if widthValue == "" || heightValue == "" {
		return errors.New("viewBox or width and height are required")
	}

	width, widthUnit, err := parseMetadataSVGLength(widthValue)
	if err != nil {
		return err
	}
	height, heightUnit, err := parseMetadataSVGLength(heightValue)
	if err != nil {
		return err
	}
	width, widthUnit = normalizeMetadataSVGLength(width, widthUnit)
	height, heightUnit = normalizeMetadataSVGLength(height, heightUnit)
	if width <= 0 || height <= 0 || widthUnit != heightUnit || !metadataSVGDimensionsEqual(width, height) {
		return errors.New("width and height differ")
	}

	return nil
}

func parseMetadataSVGNumber(value string) (float64, error) {
	number, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, errors.New("invalid SVG number")
	}

	return number, nil
}

func parseMetadataSVGLength(value string) (float64, string, error) {
	matches := metadataSVGLengthPattern.FindStringSubmatch(strings.TrimSpace(value))
	if matches == nil {
		return 0, "", errors.New("invalid SVG length")
	}

	number, err := parseMetadataSVGNumber(matches[1])
	if err != nil {
		return 0, "", err
	}
	unit := matches[2]
	if !slices.Contains([]string{"", "px", "em", "ex", "in", "cm", "mm", "pt", "pc", "%"}, unit) {
		return 0, "", errors.New("unsupported SVG length unit")
	}

	return number, unit, nil
}

func normalizeMetadataSVGLength(value float64, unit string) (float64, string) {
	switch unit {
	case "", "px":
		return value, "px"
	case "in":
		return value * 96, "px"
	case "cm":
		return value * 96 / 2.54, "px"
	case "mm":
		return value * 96 / 25.4, "px"
	case "pt":
		return value * 96 / 72, "px"
	case "pc":
		return value * 16, "px"
	default:
		return value, unit
	}
}

func metadataSVGDimensionsEqual(first, second float64) bool {
	scale := math.Max(math.Abs(first), math.Abs(second))

	return math.Abs(first-second) <= scale*1e-12
}

func validateMetadataLegacyKeyScope(metadataStatement) error {
	// Pinned P-41 is disabled unconditionally. keyScope is also absent from
	// the Metadata Statement 3.1.1 dictionary, so preserving Skip avoids
	// inventing a non-normative field contract.
	return conformance.Skip("keyScope is not a Metadata Statement 3.1.1 member")
}

func validateMetadataMultiDeviceCredentialSupport(statement metadataStatement) error {
	support, present, err := optionalMetadataValue[string](statement, "multiDeviceCredentialSupport")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip("multiDeviceCredentialSupport is absent and implicitly unsupported")
	}
	if !slices.Contains([]string{"unsupported", "explicit", "implicit"}, support) {
		return conformance.Failf("multiDeviceCredentialSupport has invalid value %q", support)
	}

	return nil
}

func validateMetadataCredentialExchangeConfigurationURL(statement metadataStatement) error {
	configurationURL, present, err := optionalMetadataValue[string](statement, "cxConfigURL")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip("cxConfigURL is absent")
	}
	if configurationURL == "" {
		return conformance.Fail("cxConfigURL must not be empty")
	}

	parsed, err := url.ParseRequestURI(configurationURL)
	if err != nil || !parsed.IsAbs() {
		return conformance.Fail("cxConfigURL must be an absolute URL")
	}

	// Pinned P-43 uses the obsolete spelling cxpConfigURL and only checks a
	// nonempty string. Metadata Statement 3.1.1 defines cxConfigURL as a URL;
	// this port uses that current member name and validates URL syntax.
	return nil
}

func metadataProviderLogoReferences(field string) []conformance.RequirementRef {
	return slices.Concat(
		metadataReferences("4", field, conformance.RequirementConstraint),
		metadataP15ThroughP24References("4.1", "svg-provider-icons", "sctn-svg-requirements", conformance.RequirementMust),
		[]conformance.RequirementRef{rfc2397DataURLReference(), svg11ImageReference()},
	)
}
