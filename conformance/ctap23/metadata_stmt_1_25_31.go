package ctap23

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"image/png"
	"mime"
	"slices"
	"strings"

	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
	mdsmodel "github.com/telesma-app/mds/model"
)

const (
	TestIDMetadataStmt1P25 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-25"
	TestIDMetadataStmt1P26 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-26"
	TestIDMetadataStmt1P27 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-27"
	TestIDMetadataStmt1P28 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-28"
	TestIDMetadataStmt1P29 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-29"
	TestIDMetadataStmt1P31 conformance.TestID = "fido.ctap2.3.metadata-stmt-1.p-31"

	maxPNGDimension = uint32(1<<31 - 1)
)

func metadataStatementTestsP25ThroughP31(metadata Metadata) []conformance.Test {
	cases := []metadataStatementCase{
		{
			id:     TestIDMetadataStmt1P25,
			marker: "P-25",
			name:   "Metadata transaction confirmation content type",
			references: slices.Concat(
				metadataReferences("4", "tcDisplayContentType", conformance.RequirementMust),
				metadataReferences("4", "tcDisplay", conformance.RequirementConstraint),
			),
			validate: validateMetadataTransactionConfirmationContentType,
		},
		{
			id:     TestIDMetadataStmt1P26,
			marker: "P-26",
			name:   "Metadata PNG display characteristics",
			references: slices.Concat(
				metadataP15ThroughP24References("1", "webidl-list-members-not-empty", "notation", conformance.RequirementMust),
				metadataP15ThroughP24References("3.7", "rgb-palette-entry", "sctn-type-rgbpe", conformance.RequirementMust),
				metadataP15ThroughP24References("3.8", "display-png-characteristics", "sctn-type-dpngcd", conformance.RequirementMust),
				metadataReferences("4", "tcDisplayPNGCharacteristics", conformance.RequirementMust),
				[]conformance.RequirementRef{pngIHDRReference(), pngPLTEReference()},
			),
			validate: validateMetadataPNGDisplayCharacteristics,
		},
		{
			id:     TestIDMetadataStmt1P27,
			marker: "P-27",
			name:   "Metadata attestation root certificates",
			references: slices.Concat(
				metadataReferences("4", "attestationRootCertificates", conformance.RequirementMust),
				[]conformance.RequirementRef{
					fidoRegistryReference("3.7", "authenticator-attestation-types"),
					rfc4648Reference("4", "base64"),
					rfc5280CertificateReference(),
				},
			),
			validate: validateMetadataAttestationRootCertificates,
		},
		{
			id:     TestIDMetadataStmt1P28,
			marker: "P-28",
			name:   "Metadata ECDAA trust anchors",
			references: slices.Concat(
				metadataP15ThroughP24References("3.9", "ecdaa-trust-anchor", "sctn-type-ecdaata", conformance.RequirementMust),
				metadataReferences("4", "ecdaaTrustAnchors", conformance.RequirementMust),
				[]conformance.RequirementRef{
					fidoRegistryReference("3.7", "authenticator-attestation-types"),
					rfc4648Reference("5", "base64url"),
				},
			),
			validate: validateMetadataECDAATrustAnchors,
		},
		{
			id:     TestIDMetadataStmt1P29,
			marker: "P-29",
			name:   "Metadata authenticator icon",
			references: slices.Concat(
				metadataReferences("4", "icon", conformance.RequirementConstraint),
				[]conformance.RequirementRef{
					rfc2397DataURLReference(),
					pngImageReference(),
					svg11ImageReference(),
				},
			),
			validate: validateMetadataIcon,
		},
		{
			id:         TestIDMetadataStmt1P31,
			marker:     "P-31",
			name:       "Metadata schema version",
			references: metadataReferences("4", "schema", conformance.RequirementMust),
			validate:   validateMetadataSchema,
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

func validateMetadataTransactionConfirmationContentType(statement metadataStatement) error {
	display, err := requiredMetadataValue[[]string](statement, "tcDisplay")
	if err != nil {
		return err
	}
	contentType, present, err := optionalMetadataValue[string](statement, "tcDisplayContentType")
	if err != nil {
		return err
	}
	if len(display) != 0 && !present {
		return conformance.Fail("tcDisplayContentType is required when transaction confirmation is supported")
	}
	if !present {
		return nil
	}
	if contentType == "" {
		return conformance.Fail("tcDisplayContentType must not be empty")
	}
	if _, _, err := mime.ParseMediaType(contentType); err != nil {
		return conformance.Failf("tcDisplayContentType is not a valid MIME media type: %v", err)
	}

	// Pinned P-25 binds MIME values to legacy extension IDs and forbids the
	// optional member when tcDisplay is empty. Metadata Statement 3.1.1 only
	// requires a MIME type when tcDisplay is nonempty, so those constraints are
	// intentionally not applied.
	return nil
}

func validateMetadataPNGDisplayCharacteristics(statement metadataStatement) error {
	display, err := requiredMetadataValue[[]string](statement, "tcDisplay")
	if err != nil {
		return err
	}
	contentType, contentTypePresent, err := optionalMetadataValue[string](statement, "tcDisplayContentType")
	if err != nil {
		return err
	}
	descriptors, present, err := optionalMetadataValue[[]json.RawMessage](statement, "tcDisplayPNGCharacteristics")
	if err != nil {
		return err
	}

	required := len(display) != 0 && contentTypePresent && contentType == "image/png"
	if required && !present {
		return conformance.Fail("tcDisplayPNGCharacteristics is required for PNG transaction confirmation")
	}
	if !present {
		return nil
	}
	if len(descriptors) == 0 {
		return conformance.Fail("tcDisplayPNGCharacteristics must not be empty")
	}

	for index, raw := range descriptors {
		if err := validateMetadataPNGDisplayDescriptor(raw, index); err != nil {
			return err
		}
	}

	// Metadata Statement 3.1.1 does not prohibit this optional member outside
	// the condition that makes it required, unlike the pinned P-26 body.
	return nil
}

func validateMetadataPNGDisplayDescriptor(raw json.RawMessage, index int) error {
	fields, err := metadataP15ThroughP24Object(raw, "tcDisplayPNGCharacteristics descriptor")
	if err != nil {
		return err
	}

	var descriptor mdsmodel.DisplayPNGCharacteristicsDescriptor
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		return conformance.Failf("tcDisplayPNGCharacteristics descriptor %d has an invalid field type: %v", index, err)
	}
	for _, name := range []string{"width", "height", "bitDepth", "colorType", "compression", "filter", "interlace"} {
		if _, err := requiredMetadataValue[json.RawMessage](fields, name); err != nil {
			return err
		}
	}
	if descriptor.Width == 0 || descriptor.Width > maxPNGDimension {
		return conformance.Failf("tcDisplayPNGCharacteristics descriptor %d width is not a valid PNG dimension", index)
	}
	if descriptor.Height == 0 || descriptor.Height > maxPNGDimension {
		return conformance.Failf("tcDisplayPNGCharacteristics descriptor %d height is not a valid PNG dimension", index)
	}
	if !validPNGBitDepth(descriptor.ColorType, descriptor.BitDepth) {
		return conformance.Failf(
			"tcDisplayPNGCharacteristics descriptor %d has invalid PNG color type %d and bit depth %d",
			index,
			descriptor.ColorType,
			descriptor.BitDepth,
		)
	}
	if descriptor.Compression != 0 {
		return conformance.Failf("tcDisplayPNGCharacteristics descriptor %d has unsupported PNG compression method %d", index, descriptor.Compression)
	}
	if descriptor.Filter != 0 {
		return conformance.Failf("tcDisplayPNGCharacteristics descriptor %d has unsupported PNG filter method %d", index, descriptor.Filter)
	}
	if descriptor.Interlace > 1 {
		return conformance.Failf("tcDisplayPNGCharacteristics descriptor %d has invalid PNG interlace method %d", index, descriptor.Interlace)
	}

	palette, present, err := optionalMetadataValue[[]json.RawMessage](fields, "plte")
	if err != nil {
		return err
	}
	if !present {
		if descriptor.ColorType == 3 {
			return conformance.Fail("tcDisplayPNGCharacteristics.plte is required for indexed-color PNG")
		}

		return nil
	}
	if descriptor.ColorType == 0 || descriptor.ColorType == 4 {
		return conformance.Failf("tcDisplayPNGCharacteristics.plte is forbidden for PNG color type %d", descriptor.ColorType)
	}
	if len(palette) == 0 || len(palette) > 256 {
		return conformance.Fail("tcDisplayPNGCharacteristics.plte must contain 1 to 256 entries")
	}
	if descriptor.ColorType == 3 && len(palette) > 1<<descriptor.BitDepth {
		return conformance.Fail("tcDisplayPNGCharacteristics.plte has more entries than the indexed-color bit depth permits")
	}

	for paletteIndex, rawEntry := range palette {
		entryFields, err := metadataP15ThroughP24Object(rawEntry, "tcDisplayPNGCharacteristics.plte entry")
		if err != nil {
			return err
		}

		var entry mdsmodel.RGBPaletteEntry
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			return conformance.Failf("tcDisplayPNGCharacteristics.plte entry %d has an invalid field type: %v", paletteIndex, err)
		}
		for _, name := range []string{"r", "g", "b"} {
			if _, err := requiredMetadataValue[json.RawMessage](entryFields, name); err != nil {
				return err
			}
		}
	}

	return nil
}

func validPNGBitDepth(colorType, bitDepth byte) bool {
	switch colorType {
	case 0:
		return bitDepth == 1 || bitDepth == 2 || bitDepth == 4 || bitDepth == 8 || bitDepth == 16
	case 2, 4, 6:
		return bitDepth == 8 || bitDepth == 16
	case 3:
		return bitDepth == 1 || bitDepth == 2 || bitDepth == 4 || bitDepth == 8
	default:
		return false
	}
}

func validateMetadataAttestationRootCertificates(statement metadataStatement) error {
	attestationTypes, err := requiredMetadataValue[[]string](statement, "attestationTypes")
	if err != nil {
		return err
	}
	registeredTypes := make([]registry.AttestationType, 0, len(attestationTypes))
	for _, name := range attestationTypes {
		attestationType, ok := registry.ParseAttestationType(name)
		if !ok {
			return conformance.Failf("attestationTypes contains unregistered value %q", name)
		}
		registeredTypes = append(registeredTypes, attestationType)
	}

	certificates, err := requiredMetadataValue[[]string](statement, "attestationRootCertificates")
	if err != nil {
		return err
	}

	certificateBacked := slices.ContainsFunc(registeredTypes, func(attestationType registry.AttestationType) bool {
		return attestationType == registry.AttestationTypeBasicFull ||
			attestationType == registry.AttestationTypeAttCA ||
			attestationType == registry.AttestationTypeAnonCA
	})
	if certificateBacked && len(certificates) == 0 {
		return conformance.Fail("attestationRootCertificates must not be empty for certificate-backed attestation")
	}
	if len(registeredTypes) == 1 && registeredTypes[0] == registry.AttestationTypeBasicSurrogate && len(certificates) != 0 {
		return conformance.Fail("attestationRootCertificates must be empty for surrogate basic attestation only")
	}

	// Pinned P-27 checks nonempty only for basic_full despite broader prose.
	// Registry 2.3 identifies ECDAA and none as non-certificate attestation;
	// current Metadata Statement text separately makes roots irrelevant to
	// ECDAA, so only certificate-backed types require a nonempty list here.
	for index, certificate := range certificates {
		if certificate == "" {
			return conformance.Failf("attestationRootCertificates entry %d must not be empty", index)
		}

		der, err := decodeMetadataBase64(certificate)
		if err != nil {
			return conformance.Failf("attestationRootCertificates entry %d is not canonical base64: %v", index, err)
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			return conformance.Failf("attestationRootCertificates entry %d is not a DER PKIX certificate: %v", index, err)
		}
	}

	return nil
}

func validateMetadataECDAATrustAnchors(statement metadataStatement) error {
	attestationTypes, err := requiredMetadataValue[[]string](statement, "attestationTypes")
	if err != nil {
		return err
	}
	hasECDAA := slices.Contains(attestationTypes, "ecdaa")

	anchors, present, err := optionalMetadataValue[[]json.RawMessage](statement, "ecdaaTrustAnchors")
	if err != nil {
		return err
	}
	if !present {
		if hasECDAA {
			return conformance.Fail("ecdaaTrustAnchors is required for ECDAA attestation")
		}

		return conformance.Skip("ecdaaTrustAnchors is absent and ECDAA attestation is not declared")
	}
	if !hasECDAA {
		return conformance.Fail("ecdaaTrustAnchors is present without ECDAA attestation")
	}
	if len(anchors) == 0 {
		return conformance.Fail("ecdaaTrustAnchors must not be empty")
	}

	// Pinned P-28 treats the field as independently optional. Metadata
	// Statement 3.1.1 requires it if and only if attestationTypes includes
	// ECDAA, so the cross-field condition above is intentional adjudication.
	for index, raw := range anchors {
		if err := validateMetadataECDAATrustAnchor(raw, index); err != nil {
			return err
		}
	}

	return nil
}

func validateMetadataECDAATrustAnchor(raw json.RawMessage, index int) error {
	fields, err := metadataP15ThroughP24Object(raw, "ecdaaTrustAnchors entry")
	if err != nil {
		return err
	}

	for _, name := range []string{"X", "Y", "c", "sx", "sy"} {
		value, err := requiredMetadataValue[string](fields, name)
		if err != nil {
			return err
		}
		if value == "" {
			return conformance.Failf("ecdaaTrustAnchors entry %d field %s must not be empty", index, name)
		}
		if err := decodeMetadataBase64URL(value); err != nil {
			return conformance.Failf("ecdaaTrustAnchors entry %d field %s is not base64url: %v", index, name, err)
		}
	}

	curve, err := requiredMetadataValue[string](fields, "G1Curve")
	if err != nil {
		return err
	}
	if !slices.Contains([]string{"BN_P256", "BN_P638", "BN_ISOP256", "BN_ISOP512"}, curve) {
		return conformance.Failf("ecdaaTrustAnchors entry %d has unsupported G1Curve %q", index, curve)
	}

	return nil
}

func decodeMetadataBase64URL(value string) error {
	if strings.Contains(value, "=") {
		decoded, err := base64.URLEncoding.Strict().DecodeString(value)
		if err != nil {
			return err
		}
		if base64.URLEncoding.EncodeToString(decoded) != value {
			return errors.New("non-canonical encoding")
		}

		return nil
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return err
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return errors.New("non-canonical encoding")
	}

	return nil
}

func validateMetadataIcon(statement metadataStatement) error {
	icon, present, err := optionalMetadataValue[string](statement, "icon")
	if err != nil {
		return err
	}
	if !present {
		return conformance.Skip("icon is absent")
	}
	if icon == "" {
		return conformance.Fail("icon must not be empty")
	}

	requireSVG := statement.has("iconDark") || statement.has("providerLogoLight") || statement.has("providerLogoDark")

	return validateMetadataIconDataURL(icon, requireSVG)
}

func validateMetadataIconDataURL(icon string, requireSVG bool) error {
	var mediaType string
	var encoded string
	switch {
	case strings.HasPrefix(icon, "data:image/png;base64,"):
		mediaType = "image/png"
		encoded = strings.TrimPrefix(icon, "data:image/png;base64,")
	case strings.HasPrefix(icon, "data:image/svg+xml;base64,"):
		mediaType = "image/svg+xml"
		encoded = strings.TrimPrefix(icon, "data:image/svg+xml;base64,")
	default:
		return conformance.Fail("icon must be a base64 PNG or SVG data URL")
	}
	if encoded == "" {
		return conformance.Fail("icon data URL payload must not be empty")
	}

	data, err := decodeMetadataBase64(encoded)
	if err != nil {
		return conformance.Failf("icon data URL payload is not canonical base64: %v", err)
	}
	if requireSVG && mediaType != "image/svg+xml" {
		return conformance.Fail("icon must use SVG when a dark icon or provider logo is present")
	}

	switch mediaType {
	case "image/png":
		if err := validateMetadataPNGIcon(data); err != nil {
			return err
		}
	case "image/svg+xml":
		var document struct {
			XMLName xml.Name
		}
		if err := xml.Unmarshal(data, &document); err != nil {
			return conformance.Failf("icon payload is not a well-formed SVG document: %v", err)
		}
		if document.XMLName.Local != "svg" || document.XMLName.Space != "http://www.w3.org/2000/svg" {
			return conformance.Fail("icon SVG payload has no SVG-namespace svg root element")
		}
	}

	// The pinned helper applies Metadata Statement section 4.1's provider-icon
	// Tiny-P/S profile to this authenticator icon. Section 4.1 now scopes that
	// profile to provider icons, while the icon member only requires SVG format
	// when a sibling dark icon or provider logo is used.
	return nil
}

const metadataPNGIconDecodeBudget = 32 << 20

func validateMetadataPNGIcon(data []byte) error {
	if err := validateMetadataPNGIconDecodeBudget(data); err != nil {
		return err
	}
	if _, err := png.DecodeConfig(bytes.NewReader(data)); err != nil {
		return conformance.Failf("icon payload is not a PNG image: %v", err)
	}

	reader := bytes.NewReader(data)
	if _, err := png.Decode(reader); err != nil {
		return conformance.Failf("icon payload is not a PNG image: %v", err)
	}
	if reader.Len() != 0 {
		return conformance.Fail("icon PNG payload has trailing data after IEND")
	}

	return nil
}

func validateMetadataPNGIconDecodeBudget(data []byte) error {
	const (
		pngHeaderLength = 33
		pngSignature    = "\x89PNG\r\n\x1a\n"
	)

	// Only trust dimensions from a complete, checksummed, semantically valid
	// IHDR. Malformed headers remain conformance failures in png.DecodeConfig.
	if len(data) < pngHeaderLength ||
		string(data[:8]) != pngSignature ||
		binary.BigEndian.Uint32(data[8:12]) != 13 ||
		string(data[12:16]) != "IHDR" ||
		binary.BigEndian.Uint32(data[29:33]) != crc32.ChecksumIEEE(data[12:29]) {
		return nil
	}

	width := binary.BigEndian.Uint32(data[16:20])
	height := binary.BigEndian.Uint32(data[20:24])
	bitDepth := data[24]
	colorType := data[25]
	if width == 0 || width > maxPNGDimension || height == 0 || height > maxPNGDimension ||
		!validPNGBitDepth(colorType, bitDepth) || data[26] != 0 || data[27] != 0 || data[28] > 1 {
		return nil
	}

	// The standard decoder can expand transparency and 16-bit channels. Use
	// its worst-case storage for the IHDR form, and compare by division so even
	// maximum legal PNG dimensions cannot overflow the calculation.
	bytesPerPixel := uint64(4)
	if colorType == 3 {
		bytesPerPixel = 1
	} else if bitDepth == 16 {
		bytesPerPixel = 8
	}
	if uint64(width) > uint64(metadataPNGIconDecodeBudget)/bytesPerPixel/uint64(height) {
		return fmt.Errorf(
			"ctap23: icon PNG dimensions %dx%d exceed the %d-byte validation limit",
			width,
			height,
			metadataPNGIconDecodeBudget,
		)
	}

	return nil
}

func decodeMetadataBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical encoding")
	}

	return decoded, nil
}

func validateMetadataSchema(statement metadataStatement) error {
	schema, err := requiredMetadataValue[uint16](statement, "schema")
	if err != nil {
		return err
	}
	if schema != 3 {
		return conformance.Failf("schema is %d, want 3", schema)
	}

	return nil
}

func rfc4648Reference(section, clause string) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID("rfc-4648:" + section + ":" + clause),
		Specification: "rfc-4648",
		Section:       section,
		Clause:        clause,
		URL:           "https://www.rfc-editor.org/rfc/rfc4648.html#section-" + section,
		Level:         conformance.RequirementConstraint,
	}
}

func rfc5280CertificateReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "rfc-5280:4.1:certificate-profile",
		Specification: "rfc-5280",
		Section:       "4.1",
		Clause:        "certificate-profile",
		URL:           "https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1",
		Level:         conformance.RequirementConstraint,
	}
}

func rfc2397DataURLReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "rfc-2397:2:data-url-syntax",
		Specification: "rfc-2397",
		Section:       "2",
		Clause:        "data-url-syntax",
		URL:           "https://www.rfc-editor.org/rfc/rfc2397.html#section-2",
		Level:         conformance.RequirementConstraint,
	}
}

func pngImageReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "png-3:5:png-datastream",
		Specification: "png-3",
		Section:       "5",
		Clause:        "png-datastream",
		URL:           "https://www.w3.org/TR/png-3/#5PNG-file-signature",
		Level:         conformance.RequirementConstraint,
	}
}

func pngIHDRReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "png-3:11.2.1:ihdr-image-header",
		Specification: "png-3",
		Section:       "11.2.1",
		Clause:        "ihdr-image-header",
		URL:           "https://www.w3.org/TR/png-3/#11IHDR",
		Level:         conformance.RequirementConstraint,
	}
}

func pngPLTEReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "png-3:11.2.2:plte-palette",
		Specification: "png-3",
		Section:       "11.2.2",
		Clause:        "plte-palette",
		URL:           "https://www.w3.org/TR/png-3/#11PLTE",
		Level:         conformance.RequirementConstraint,
	}
}

func svg11ImageReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "svg-1.1:5.1.2:svg-element",
		Specification: "svg-1.1",
		Section:       "5.1.2",
		Clause:        "svg-element",
		URL:           "https://www.w3.org/TR/SVG11/struct.html#SVGElement",
		Level:         conformance.RequirementConstraint,
	}
}
