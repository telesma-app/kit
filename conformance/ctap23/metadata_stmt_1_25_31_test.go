package ctap23

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/telesma-app/kit/conformance"
)

func TestMetadataStmt1P25ThroughP31SourceMapping(t *testing.T) {
	tests := metadataStatementTestsP25ThroughP31(Metadata{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{id: TestIDMetadataStmt1P25, marker: "P-25"},
		{id: TestIDMetadataStmt1P26, marker: "P-26"},
		{id: TestIDMetadataStmt1P27, marker: "P-27"},
		{id: TestIDMetadataStmt1P28, marker: "P-28"},
		{id: TestIDMetadataStmt1P29, marker: "P-29"},
		{id: TestIDMetadataStmt1P31, marker: "P-31"},
	}

	if len(tests) != len(want) {
		t.Fatalf("metadata tests = %d, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != metadataStatementSourcePath || test.Source.Case != expected.marker {
			t.Errorf("test %d mapping = (%q, %q, %q), want (%q, %q, %q)",
				index,
				test.ID,
				test.Source.Path,
				test.Source.Case,
				expected.id,
				metadataStatementSourcePath,
				expected.marker,
			)
		}
		assertCompleteMetadataReferences(t, test.References)
	}
}

func TestMetadataStmt1P25ThroughP31NormativeReferenceTargets(t *testing.T) {
	want := map[conformance.TestID][]string{
		TestIDMetadataStmt1P25: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|tcDisplayContentType|" + metadataStatementURL + "#metadata-keys",
			"fido-metadata-statement-3.1.1-ps-20260105|4|tcDisplay|" + metadataStatementURL + "#metadata-keys",
		},
		TestIDMetadataStmt1P26: {
			"fido-metadata-statement-3.1.1-ps-20260105|1|webidl-list-members-not-empty|" + metadataStatementURL + "#notation",
			"fido-metadata-statement-3.1.1-ps-20260105|3.7|rgb-palette-entry|" + metadataStatementURL + "#sctn-type-rgbpe",
			"fido-metadata-statement-3.1.1-ps-20260105|3.8|display-png-characteristics|" + metadataStatementURL + "#sctn-type-dpngcd",
			"fido-metadata-statement-3.1.1-ps-20260105|4|tcDisplayPNGCharacteristics|" + metadataStatementURL + "#metadata-keys",
			"png-3|11.2.1|ihdr-image-header|https://www.w3.org/TR/png-3/#11IHDR",
			"png-3|11.2.2|plte-palette|https://www.w3.org/TR/png-3/#11PLTE",
		},
		TestIDMetadataStmt1P27: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|attestationRootCertificates|" + metadataStatementURL + "#metadata-keys",
			"fido-registry-2.3-ps-20260105|3.7|authenticator-attestation-types|" + fidoRegistryURL + "#authenticator-attestation-types",
			"rfc-4648|4|base64|https://www.rfc-editor.org/rfc/rfc4648.html#section-4",
			"rfc-5280|4.1|certificate-profile|https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1",
		},
		TestIDMetadataStmt1P28: {
			"fido-metadata-statement-3.1.1-ps-20260105|3.9|ecdaa-trust-anchor|" + metadataStatementURL + "#sctn-type-ecdaata",
			"fido-metadata-statement-3.1.1-ps-20260105|4|ecdaaTrustAnchors|" + metadataStatementURL + "#metadata-keys",
			"fido-registry-2.3-ps-20260105|3.7|authenticator-attestation-types|" + fidoRegistryURL + "#authenticator-attestation-types",
			"rfc-4648|5|base64url|https://www.rfc-editor.org/rfc/rfc4648.html#section-5",
		},
		TestIDMetadataStmt1P29: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|icon|" + metadataStatementURL + "#metadata-keys",
			"rfc-2397|2|data-url-syntax|https://www.rfc-editor.org/rfc/rfc2397.html#section-2",
			"png-3|5|png-datastream|https://www.w3.org/TR/png-3/#5PNG-file-signature",
			"svg-1.1|5.1.2|svg-element|https://www.w3.org/TR/SVG11/struct.html#SVGElement",
		},
		TestIDMetadataStmt1P31: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|schema|" + metadataStatementURL + "#metadata-keys",
		},
	}

	for _, test := range metadataStatementTestsP25ThroughP31(Metadata{}) {
		got := make([]string, 0, len(test.References))
		for _, reference := range test.References {
			got = append(got, string(reference.Specification)+"|"+reference.Section+"|"+reference.Clause+"|"+reference.URL)
		}
		if !slices.Equal(got, want[test.ID]) {
			t.Errorf("test %q reference targets = %v, want %v", test.ID, got, want[test.ID])
		}
	}
}

func TestMetadataStmt1P25ContentTypePresenceAndType(t *testing.T) {
	tests := []struct {
		name        string
		display     any
		contentType any
		setContent  bool
		want        conformance.Status
	}{
		{name: "unsupported absent", display: []string{}, want: conformance.StatusPassed},
		{name: "supported text", display: []string{"any"}, contentType: "text/plain", setContent: true, want: conformance.StatusPassed},
		{name: "supported PNG", display: []string{"any"}, contentType: "image/png", setContent: true, want: conformance.StatusPassed},
		{name: "supported other MIME", display: []string{"any"}, contentType: "application/json", setContent: true, want: conformance.StatusPassed},
		{name: "unsupported present", display: []string{}, contentType: "text/plain", setContent: true, want: conformance.StatusPassed},
		{name: "supported missing", display: []string{"any"}, want: conformance.StatusFailed},
		{name: "empty", display: []string{"any"}, contentType: "", setContent: true, want: conformance.StatusFailed},
		{name: "null", display: []string{"any"}, contentType: nil, setContent: true, want: conformance.StatusFailed},
		{name: "wrong type", display: []string{"any"}, contentType: true, setContent: true, want: conformance.StatusFailed},
		{name: "malformed MIME", display: []string{"any"}, contentType: "not a media type", setContent: true, want: conformance.StatusFailed},
		{name: "null display", display: nil, want: conformance.StatusFailed},
		{name: "wrong display type", display: "any", want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP25ThroughP31Statement()
			statement["tcDisplay"] = test.display
			if test.setContent {
				statement["tcDisplayContentType"] = test.contentType
			} else {
				delete(statement, "tcDisplayContentType")
			}

			assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P25, test.want)
		})
	}

	statement := validMetadataP25ThroughP31Statement()
	delete(statement, "tcDisplay")
	assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P25, conformance.StatusFailed)
}

func TestMetadataStmt1P25UsesCurrentMDSContentTypeRule(t *testing.T) {
	statement := validMetadataP25ThroughP31Statement()
	statement["tcDisplay"] = []string{"any"}
	statement["tcDisplayContentType"] = "application/json"
	statement["authenticatorGetInfo"] = map[string]any{"extensions": []string{"txAuthSimple"}}
	assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P25, conformance.StatusPassed)

	statement["tcDisplay"] = []string{}
	statement["tcDisplayContentType"] = "image/png"
	assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P25, conformance.StatusPassed)
}

func TestMetadataStmt1P26PNGCharacteristicsCondition(t *testing.T) {
	tests := []struct {
		name           string
		display        []string
		contentType    any
		characteristic any
		setContent     bool
		setDescriptors bool
		want           conformance.Status
	}{
		{name: "non PNG absent", display: []string{"any"}, contentType: "text/plain", setContent: true, want: conformance.StatusPassed},
		{name: "PNG display descriptor", display: []string{"any"}, contentType: "image/png", characteristic: []any{validMetadataPNGDisplayDescriptor()}, setContent: true, setDescriptors: true, want: conformance.StatusPassed},
		{name: "PNG type without display", display: []string{}, contentType: "image/png", setContent: true, want: conformance.StatusPassed},
		{name: "optional outside condition", display: []string{}, characteristic: []any{validMetadataPNGDisplayDescriptor()}, setDescriptors: true, want: conformance.StatusPassed},
		{name: "optional empty outside condition", display: []string{}, characteristic: []any{}, setDescriptors: true, want: conformance.StatusFailed},
		{name: "required missing", display: []string{"any"}, contentType: "image/png", setContent: true, want: conformance.StatusFailed},
		{name: "required empty", display: []string{"any"}, contentType: "image/png", characteristic: []any{}, setContent: true, setDescriptors: true, want: conformance.StatusFailed},
		{name: "null", display: []string{"any"}, contentType: "image/png", characteristic: nil, setContent: true, setDescriptors: true, want: conformance.StatusFailed},
		{name: "wrong type", display: []string{"any"}, contentType: "image/png", characteristic: "descriptor", setContent: true, setDescriptors: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP25ThroughP31Statement()
			statement["tcDisplay"] = test.display
			if test.setContent {
				statement["tcDisplayContentType"] = test.contentType
			}
			if test.setDescriptors {
				statement["tcDisplayPNGCharacteristics"] = test.characteristic
			}

			assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P26, test.want)
		})
	}
}

func TestMetadataStmt1P26PNGDescriptorSemantics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   conformance.Status
	}{
		{name: "minimum dimension", mutate: func(descriptor map[string]any) { descriptor["width"] = 1; descriptor["height"] = 1 }, want: conformance.StatusPassed},
		{name: "maximum dimension", mutate: func(descriptor map[string]any) {
			descriptor["width"] = uint32(1<<31 - 1)
			descriptor["height"] = uint32(1<<31 - 1)
		}, want: conformance.StatusPassed},
		{name: "zero width", mutate: func(descriptor map[string]any) { descriptor["width"] = 0 }, want: conformance.StatusFailed},
		{name: "zero height", mutate: func(descriptor map[string]any) { descriptor["height"] = 0 }, want: conformance.StatusFailed},
		{name: "PNG dimension overflow", mutate: func(descriptor map[string]any) { descriptor["width"] = uint32(1 << 31) }, want: conformance.StatusFailed},
		{name: "invalid color type", mutate: func(descriptor map[string]any) { descriptor["colorType"] = 1 }, want: conformance.StatusFailed},
		{name: "invalid greyscale bit depth", mutate: func(descriptor map[string]any) { descriptor["colorType"] = 0; descriptor["bitDepth"] = 3 }, want: conformance.StatusFailed},
		{name: "invalid truecolor bit depth", mutate: func(descriptor map[string]any) { descriptor["colorType"] = 2; descriptor["bitDepth"] = 4 }, want: conformance.StatusFailed},
		{name: "invalid indexed bit depth", mutate: func(descriptor map[string]any) {
			descriptor["colorType"] = 3
			descriptor["bitDepth"] = 16
			descriptor["plte"] = []any{map[string]any{"r": 0, "g": 0, "b": 0}}
		}, want: conformance.StatusFailed},
		{name: "invalid alpha bit depth", mutate: func(descriptor map[string]any) { descriptor["colorType"] = 6; descriptor["bitDepth"] = 4 }, want: conformance.StatusFailed},
		{name: "compression method", mutate: func(descriptor map[string]any) { descriptor["compression"] = 1 }, want: conformance.StatusFailed},
		{name: "filter method", mutate: func(descriptor map[string]any) { descriptor["filter"] = 1 }, want: conformance.StatusFailed},
		{name: "interlace method", mutate: func(descriptor map[string]any) { descriptor["interlace"] = 2 }, want: conformance.StatusFailed},
		{name: "indexed palette", mutate: func(descriptor map[string]any) {
			descriptor["colorType"] = 3
			descriptor["bitDepth"] = 1
			descriptor["plte"] = []any{map[string]any{"r": 0, "g": 0, "b": 0}, map[string]any{"r": 1, "g": 1, "b": 1}}
		}, want: conformance.StatusPassed},
		{name: "indexed palette missing", mutate: func(descriptor map[string]any) { descriptor["colorType"] = 3; descriptor["bitDepth"] = 1 }, want: conformance.StatusFailed},
		{name: "indexed palette beyond bit depth", mutate: func(descriptor map[string]any) {
			descriptor["colorType"] = 3
			descriptor["bitDepth"] = 1
			descriptor["plte"] = []any{map[string]any{"r": 0, "g": 0, "b": 0}, map[string]any{"r": 1, "g": 1, "b": 1}, map[string]any{"r": 2, "g": 2, "b": 2}}
		}, want: conformance.StatusFailed},
		{name: "greyscale palette forbidden", mutate: func(descriptor map[string]any) {
			descriptor["colorType"] = 0
			descriptor["plte"] = []any{map[string]any{"r": 0, "g": 0, "b": 0}}
		}, want: conformance.StatusFailed},
		{name: "greyscale alpha palette forbidden", mutate: func(descriptor map[string]any) {
			descriptor["colorType"] = 4
			descriptor["plte"] = []any{map[string]any{"r": 0, "g": 0, "b": 0}}
		}, want: conformance.StatusFailed},
		{name: "truecolor suggested palette", mutate: func(descriptor map[string]any) { descriptor["plte"] = []any{map[string]any{"r": 0, "g": 0, "b": 0}} }, want: conformance.StatusPassed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := validMetadataPNGDisplayDescriptor()
			test.mutate(descriptor)

			assertMetadataP26DescriptorStatus(t, descriptor, test.want)
		})
	}
}

func TestMetadataStmt1P26RequiresEveryPNGDescriptorField(t *testing.T) {
	for _, field := range []string{"width", "height", "bitDepth", "colorType", "compression", "filter", "interlace"} {
		t.Run("missing "+field, func(t *testing.T) {
			descriptor := validMetadataPNGDisplayDescriptor()
			delete(descriptor, field)

			assertMetadataP26DescriptorStatus(t, descriptor, conformance.StatusFailed)
		})
		t.Run("null "+field, func(t *testing.T) {
			descriptor := validMetadataPNGDisplayDescriptor()
			descriptor[field] = nil

			assertMetadataP26DescriptorStatus(t, descriptor, conformance.StatusFailed)
		})
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "width string", mutate: func(descriptor map[string]any) { descriptor["width"] = "1" }},
		{name: "width negative", mutate: func(descriptor map[string]any) { descriptor["width"] = -1 }},
		{name: "width overflow", mutate: func(descriptor map[string]any) { descriptor["width"] = uint64(1) << 32 }},
		{name: "width fractional", mutate: func(descriptor map[string]any) { descriptor["width"] = 1.5 }},
		{name: "bit depth string", mutate: func(descriptor map[string]any) { descriptor["bitDepth"] = "8" }},
		{name: "bit depth negative", mutate: func(descriptor map[string]any) { descriptor["bitDepth"] = -1 }},
		{name: "bit depth overflow", mutate: func(descriptor map[string]any) { descriptor["bitDepth"] = 256 }},
		{name: "descriptor null", mutate: func(descriptor map[string]any) { descriptor["__replace"] = nil }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := validMetadataPNGDisplayDescriptor()
			test.mutate(descriptor)
			if replacement, replace := descriptor["__replace"]; replace {
				assertMetadataP26DescriptorStatus(t, replacement, conformance.StatusFailed)

				return
			}

			assertMetadataP26DescriptorStatus(t, descriptor, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P26PalettePresenceTypesAndBounds(t *testing.T) {
	tests := []struct {
		name    string
		palette any
		set     bool
		want    conformance.Status
	}{
		{name: "absent", want: conformance.StatusPassed},
		{name: "one", palette: []any{map[string]any{"r": 0, "g": 255, "b": 65535}}, set: true, want: conformance.StatusPassed},
		{name: "null", palette: nil, set: true, want: conformance.StatusFailed},
		{name: "wrong type", palette: "palette", set: true, want: conformance.StatusFailed},
		{name: "empty", palette: []any{}, set: true, want: conformance.StatusFailed},
		{name: "too many", palette: make([]any, 257), set: true, want: conformance.StatusFailed},
		{name: "null entry", palette: []any{nil}, set: true, want: conformance.StatusFailed},
		{name: "wrong entry type", palette: []any{"rgb"}, set: true, want: conformance.StatusFailed},
		{name: "missing channel", palette: []any{map[string]any{"r": 0, "g": 0}}, set: true, want: conformance.StatusFailed},
		{name: "null channel", palette: []any{map[string]any{"r": 0, "g": 0, "b": nil}}, set: true, want: conformance.StatusFailed},
		{name: "wrong channel type", palette: []any{map[string]any{"r": 0, "g": 0, "b": "0"}}, set: true, want: conformance.StatusFailed},
		{name: "negative channel", palette: []any{map[string]any{"r": -1, "g": 0, "b": 0}}, set: true, want: conformance.StatusFailed},
		{name: "overflow channel", palette: []any{map[string]any{"r": 65536, "g": 0, "b": 0}}, set: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := validMetadataPNGDisplayDescriptor()
			if test.set {
				descriptor["plte"] = test.palette
			}

			assertMetadataP26DescriptorStatus(t, descriptor, test.want)
		})
	}
}

func TestMetadataStmt1P27AttestationRootCardinality(t *testing.T) {
	certificate := validMetadataRootCertificate(t)
	tests := []struct {
		name         string
		attestations any
		certificates any
		setRoots     bool
		want         conformance.Status
	}{
		{name: "basic full", attestations: []string{"basic_full"}, certificates: []string{certificate}, setRoots: true, want: conformance.StatusPassed},
		{name: "attestation CA", attestations: []string{"attca"}, certificates: []string{certificate}, setRoots: true, want: conformance.StatusPassed},
		{name: "anonymization CA", attestations: []string{"anonca"}, certificates: []string{certificate}, setRoots: true, want: conformance.StatusPassed},
		{name: "surrogate empty", attestations: []string{"basic_surrogate"}, certificates: []string{}, setRoots: true, want: conformance.StatusPassed},
		{name: "none empty", attestations: []string{"none"}, certificates: []string{}, setRoots: true, want: conformance.StatusPassed},
		{name: "ECDAA empty", attestations: []string{"ecdaa"}, certificates: []string{}, setRoots: true, want: conformance.StatusPassed},
		{name: "basic full empty", attestations: []string{"basic_full"}, certificates: []string{}, setRoots: true, want: conformance.StatusFailed},
		{name: "attestation CA empty", attestations: []string{"attca"}, certificates: []string{}, setRoots: true, want: conformance.StatusFailed},
		{name: "anonymization CA empty", attestations: []string{"anonca"}, certificates: []string{}, setRoots: true, want: conformance.StatusFailed},
		{name: "surrogate nonempty", attestations: []string{"basic_surrogate"}, certificates: []string{certificate}, setRoots: true, want: conformance.StatusFailed},
		{name: "roots missing", attestations: []string{"none"}, want: conformance.StatusFailed},
		{name: "roots null", attestations: []string{"none"}, certificates: nil, setRoots: true, want: conformance.StatusFailed},
		{name: "roots wrong type", attestations: []string{"none"}, certificates: certificate, setRoots: true, want: conformance.StatusFailed},
		{name: "attestations null", attestations: nil, certificates: []string{}, setRoots: true, want: conformance.StatusFailed},
		{name: "attestations wrong type", attestations: "none", certificates: []string{}, setRoots: true, want: conformance.StatusFailed},
		{name: "attestation unregistered", attestations: []string{"reserved"}, certificates: []string{}, setRoots: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP25ThroughP31Statement()
			statement["attestationTypes"] = test.attestations
			if test.setRoots {
				statement["attestationRootCertificates"] = test.certificates
			} else {
				delete(statement, "attestationRootCertificates")
			}

			assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P27, test.want)
		})
	}
}

func TestMetadataStmt1P27ValidatesCanonicalBase64DERPKIX(t *testing.T) {
	validCertificate := validMetadataRootCertificate(t)
	tests := []struct {
		name        string
		certificate string
	}{
		{name: "empty"},
		{name: "invalid base64", certificate: "***"},
		{name: "unpadded base64", certificate: "AQ"},
		{name: "base64 with newline", certificate: validCertificate[:20] + "\n" + validCertificate[20:]},
		{name: "valid base64 not certificate", certificate: base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP25ThroughP31Statement()
			statement["attestationTypes"] = []string{"basic_full"}
			statement["attestationRootCertificates"] = []string{test.certificate}

			assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P27, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P28ECDAACrossFieldCondition(t *testing.T) {
	tests := []struct {
		name         string
		attestations []string
		anchors      any
		setAnchors   bool
		want         conformance.Status
	}{
		{name: "not declared and absent", attestations: []string{"none"}, want: conformance.StatusSkipped},
		{name: "declared and valid", attestations: []string{"ecdaa"}, anchors: []any{validMetadataECDAATrustAnchor()}, setAnchors: true, want: conformance.StatusPassed},
		{name: "declared and missing", attestations: []string{"ecdaa"}, want: conformance.StatusFailed},
		{name: "not declared and present", attestations: []string{"none"}, anchors: []any{validMetadataECDAATrustAnchor()}, setAnchors: true, want: conformance.StatusFailed},
		{name: "declared and empty", attestations: []string{"ecdaa"}, anchors: []any{}, setAnchors: true, want: conformance.StatusFailed},
		{name: "declared and null", attestations: []string{"ecdaa"}, anchors: nil, setAnchors: true, want: conformance.StatusFailed},
		{name: "declared and wrong type", attestations: []string{"ecdaa"}, anchors: "anchor", setAnchors: true, want: conformance.StatusFailed},
		{name: "null entry", attestations: []string{"ecdaa"}, anchors: []any{nil}, setAnchors: true, want: conformance.StatusFailed},
		{name: "wrong entry type", attestations: []string{"ecdaa"}, anchors: []any{"anchor"}, setAnchors: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP25ThroughP31Statement()
			statement["attestationTypes"] = test.attestations
			if test.setAnchors {
				statement["ecdaaTrustAnchors"] = test.anchors
			}

			assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P28, test.want)
		})
	}
}

func TestMetadataStmt1P28ECDAAAnchorFields(t *testing.T) {
	for _, field := range []string{"X", "Y", "c", "sx", "sy", "G1Curve"} {
		t.Run("missing "+field, func(t *testing.T) {
			anchor := validMetadataECDAATrustAnchor()
			delete(anchor, field)

			assertMetadataP28AnchorStatus(t, anchor, conformance.StatusFailed)
		})
		t.Run("null "+field, func(t *testing.T) {
			anchor := validMetadataECDAATrustAnchor()
			anchor[field] = nil

			assertMetadataP28AnchorStatus(t, anchor, conformance.StatusFailed)
		})
		t.Run("wrong type "+field, func(t *testing.T) {
			anchor := validMetadataECDAATrustAnchor()
			anchor[field] = true

			assertMetadataP28AnchorStatus(t, anchor, conformance.StatusFailed)
		})
		t.Run("empty "+field, func(t *testing.T) {
			anchor := validMetadataECDAATrustAnchor()
			anchor[field] = ""

			assertMetadataP28AnchorStatus(t, anchor, conformance.StatusFailed)
		})
	}

	for _, field := range []string{"X", "Y", "c", "sx", "sy"} {
		t.Run("malformed base64url "+field, func(t *testing.T) {
			anchor := validMetadataECDAATrustAnchor()
			anchor[field] = "+/8="

			assertMetadataP28AnchorStatus(t, anchor, conformance.StatusFailed)
		})
	}

	anchor := validMetadataECDAATrustAnchor()
	anchor["X"] = "A\nQ"
	assertMetadataP28AnchorStatus(t, anchor, conformance.StatusFailed)

	for _, curve := range []string{"BN_P256", "BN_P638", "BN_ISOP256", "BN_ISOP512"} {
		t.Run(curve, func(t *testing.T) {
			anchor := validMetadataECDAATrustAnchor()
			anchor["G1Curve"] = curve

			assertMetadataP28AnchorStatus(t, anchor, conformance.StatusPassed)
		})
	}
}

func TestMetadataStmt1P29IconPresenceAndDataURL(t *testing.T) {
	pngURL := validMetadataPNGIcon(t)
	pngWithTrailingData := metadataPNGIconWithTrailingData(t, pngURL)
	oversizedPNG := metadataPNGIconWithDimensions(t, pngURL, 100_000, 100_000)
	maximumDimensionPNG := metadataPNGIconWithDimensions(t, pngURL, maxPNGDimension, maxPNGDimension)
	svgURL := validMetadataSVGIcon()
	tests := []struct {
		name    string
		icon    any
		setIcon bool
		mutate  func(map[string]any)
		want    conformance.Status
	}{
		{name: "absent", want: conformance.StatusSkipped},
		{name: "PNG", icon: pngURL, setIcon: true, want: conformance.StatusPassed},
		{name: "SVG", icon: svgURL, setIcon: true, want: conformance.StatusPassed},
		{name: "SVG with dark icon", icon: svgURL, setIcon: true, mutate: func(statement map[string]any) { statement["iconDark"] = nil }, want: conformance.StatusPassed},
		{name: "PNG with dark icon", icon: pngURL, setIcon: true, mutate: func(statement map[string]any) { statement["iconDark"] = nil }, want: conformance.StatusFailed},
		{name: "PNG with light provider logo", icon: pngURL, setIcon: true, mutate: func(statement map[string]any) { statement["providerLogoLight"] = "" }, want: conformance.StatusFailed},
		{name: "empty", icon: "", setIcon: true, want: conformance.StatusFailed},
		{name: "null", icon: nil, setIcon: true, want: conformance.StatusFailed},
		{name: "wrong type", icon: true, setIcon: true, want: conformance.StatusFailed},
		{name: "wrong media type", icon: "data:image/jpeg;base64,AQ==", setIcon: true, want: conformance.StatusFailed},
		{name: "empty payload", icon: "data:image/png;base64,", setIcon: true, want: conformance.StatusFailed},
		{name: "malformed base64", icon: "data:image/png;base64,***", setIcon: true, want: conformance.StatusFailed},
		{name: "base64 with newline", icon: strings.Replace(pngURL, "base64,", "base64,\n", 1), setIcon: true, want: conformance.StatusFailed},
		{name: "not PNG", icon: "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("not png")), setIcon: true, want: conformance.StatusFailed},
		{name: "PNG trailing data", icon: pngWithTrailingData, setIcon: true, want: conformance.StatusFailed},
		{name: "PNG decode resource limit", icon: oversizedPNG, setIcon: true, want: conformance.StatusError},
		{name: "PNG maximum dimensions resource limit", icon: maximumDimensionPNG, setIcon: true, want: conformance.StatusError},
		{name: "malformed SVG", icon: "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<svg>")), setIcon: true, want: conformance.StatusFailed},
		{name: "non SVG root", icon: "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<html/>")), setIcon: true, want: conformance.StatusFailed},
		{name: "wrong SVG namespace", icon: "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<svg xmlns=\"urn:not-svg\"/>")), setIcon: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP25ThroughP31Statement()
			if test.setIcon {
				statement["icon"] = test.icon
			}
			if test.mutate != nil {
				test.mutate(statement)
			}

			assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P29, test.want)
		})
	}
}

func TestMetadataStmt1P29DoesNotApplyProviderIconProfile(t *testing.T) {
	statement := validMetadataP25ThroughP31Statement()
	statement["icon"] = validMetadataSVGIcon()
	statement["providerLogoLight"] = "present"

	assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P29, conformance.StatusPassed)
}

func TestMetadataStmt1P31SchemaPresenceTypeAndValue(t *testing.T) {
	tests := []struct {
		name   string
		schema any
		set    bool
		want   conformance.Status
	}{
		{name: "three", schema: 3, set: true, want: conformance.StatusPassed},
		{name: "missing", want: conformance.StatusFailed},
		{name: "null", schema: nil, set: true, want: conformance.StatusFailed},
		{name: "string", schema: "3", set: true, want: conformance.StatusFailed},
		{name: "boolean", schema: true, set: true, want: conformance.StatusFailed},
		{name: "zero", schema: 0, set: true, want: conformance.StatusFailed},
		{name: "two", schema: 2, set: true, want: conformance.StatusFailed},
		{name: "four", schema: 4, set: true, want: conformance.StatusFailed},
		{name: "negative", schema: -1, set: true, want: conformance.StatusFailed},
		{name: "overflow", schema: 65536, set: true, want: conformance.StatusFailed},
		{name: "fractional", schema: 3.5, set: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP25ThroughP31Statement()
			if test.set {
				statement["schema"] = test.schema
			} else {
				delete(statement, "schema")
			}

			assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P31, test.want)
		})
	}
}

func TestMetadataStmt1P25ThroughP31MalformedDocumentIsError(t *testing.T) {
	result := runMetadataStatementP25ThroughP31Tests(t, `{"schema":3} trailing`, TestIDMetadataStmt1P31)
	if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
		t.Fatalf("result = %#v, want error", result)
	}
}

func runMetadataStatementP25ThroughP31Tests(
	t *testing.T,
	statementJSON string,
	selected ...conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	tests := metadataStatementTestsP25ThroughP31(Metadata{StatementJSON: statementJSON})
	if len(selected) != 0 {
		tests = slices.DeleteFunc(tests, func(test conformance.Test) bool {
			return !slices.Contains(selected, test.ID)
		})
	}
	if len(tests) == 0 {
		t.Fatalf("no metadata tests selected for %v", selected)
	}

	runner, err := conformance.NewRunner(metadataStatementTestDevice{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), conformance.Suite{
		ID:    "test.metadata-statement-p25-p31",
		Name:  "Metadata statement P-25 through P-31 tests",
		Tests: tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertMetadataP25ThroughP31Status(
	t *testing.T,
	statement map[string]any,
	id conformance.TestID,
	want conformance.Status,
) {
	t.Helper()

	result := runMetadataStatementP25ThroughP31Tests(t, metadataStatementJSON(t, statement), id)
	if result.Status != want || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %q", result, want)
	}
}

func assertMetadataP26DescriptorStatus(t *testing.T, descriptor any, want conformance.Status) {
	t.Helper()

	statement := validMetadataP25ThroughP31Statement()
	statement["tcDisplay"] = []string{"any"}
	statement["tcDisplayContentType"] = "image/png"
	statement["tcDisplayPNGCharacteristics"] = []any{descriptor}
	assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P26, want)
}

func assertMetadataP28AnchorStatus(t *testing.T, anchor any, want conformance.Status) {
	t.Helper()

	statement := validMetadataP25ThroughP31Statement()
	statement["attestationTypes"] = []string{"ecdaa"}
	statement["ecdaaTrustAnchors"] = []any{anchor}
	assertMetadataP25ThroughP31Status(t, statement, TestIDMetadataStmt1P28, want)
}

func validMetadataP25ThroughP31Statement() map[string]any {
	statement := validMetadataP15ThroughP24Statement()
	statement["schema"] = 3
	statement["attestationTypes"] = []string{"basic_surrogate"}
	statement["attestationRootCertificates"] = []string{}

	return statement
}

func validMetadataPNGDisplayDescriptor() map[string]any {
	return map[string]any{
		"width":       32,
		"height":      32,
		"bitDepth":    8,
		"colorType":   2,
		"compression": 0,
		"filter":      0,
		"interlace":   0,
	}
}

func validMetadataECDAATrustAnchor() map[string]any {
	return map[string]any{
		"X":       "AQ",
		"Y":       "Ag==",
		"c":       "Aw",
		"sx":      "BA==",
		"sy":      "BQ",
		"G1Curve": "BN_P256",
	}
}

func validMetadataRootCertificate(t *testing.T) string {
	t.Helper()

	seed := [ed25519.SeedSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic metadata root"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(86400, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 64)), template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(der)
}

func validMetadataPNGIcon(t *testing.T) string {
	t.Helper()

	imageData := image.NewNRGBA(image.Rect(0, 0, 1, 1))
	imageData.Set(0, 0, color.NRGBA{R: 1, G: 2, B: 3, A: 255})

	var data bytes.Buffer
	if err := png.Encode(&data, imageData); err != nil {
		t.Fatal(err)
	}

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data.Bytes())
}

func metadataPNGIconWithTrailingData(t *testing.T, icon string) string {
	t.Helper()

	data := decodeMetadataPNGIconFixture(t, icon)
	data = append(data, 0)

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
}

func metadataPNGIconWithDimensions(t *testing.T, icon string, width, height uint32) string {
	t.Helper()

	data := decodeMetadataPNGIconFixture(t, icon)
	binary.BigEndian.PutUint32(data[16:20], width)
	binary.BigEndian.PutUint32(data[20:24], height)
	binary.BigEndian.PutUint32(data[29:33], crc32.ChecksumIEEE(data[12:29]))

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
}

func decodeMetadataPNGIconFixture(t *testing.T, icon string) []byte {
	t.Helper()

	encoded := strings.TrimPrefix(icon, "data:image/png;base64,")
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func validMetadataSVGIcon() string {
	data := []byte(`<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 1 1"><title>Authenticator</title></svg>`)

	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(data)
}

func TestMetadataStmt1P25ThroughP31TestIDsAreStable(t *testing.T) {
	ids := []string{
		string(TestIDMetadataStmt1P25),
		string(TestIDMetadataStmt1P26),
		string(TestIDMetadataStmt1P27),
		string(TestIDMetadataStmt1P28),
		string(TestIDMetadataStmt1P29),
		string(TestIDMetadataStmt1P31),
	}
	if strings.Join(ids, ",") != "fido.ctap2.3.metadata-stmt-1.p-25,fido.ctap2.3.metadata-stmt-1.p-26,fido.ctap2.3.metadata-stmt-1.p-27,fido.ctap2.3.metadata-stmt-1.p-28,fido.ctap2.3.metadata-stmt-1.p-29,fido.ctap2.3.metadata-stmt-1.p-31" {
		t.Fatalf("IDs = %v", ids)
	}
}

func TestMetadataStmt1P25ThroughP31FixturesAreJSON(t *testing.T) {
	for name, value := range map[string]any{
		"statement":  validMetadataP25ThroughP31Statement(),
		"descriptor": validMetadataPNGDisplayDescriptor(),
		"anchor":     validMetadataECDAATrustAnchor(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := json.Marshal(value); err != nil {
				t.Fatal(err)
			}
		})
	}
}
