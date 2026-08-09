package ctap23

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/kit/conformance"
)

func TestMetadataStmt1P37ThroughP43SourceMapping(t *testing.T) {
	tests := metadataStatementTestsP37ThroughP43(Metadata{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{id: TestIDMetadataStmt1P37, marker: "P-37"},
		{id: TestIDMetadataStmt1P38, marker: "P-38"},
		{id: TestIDMetadataStmt1P39, marker: "P-39"},
		{id: TestIDMetadataStmt1P40, marker: "P-40"},
		{id: TestIDMetadataStmt1P41, marker: "P-41"},
		{id: TestIDMetadataStmt1P42, marker: "P-42"},
		{id: TestIDMetadataStmt1P43, marker: "P-43"},
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

func TestMetadataStmt1P37ThroughP43NormativeReferenceTargets(t *testing.T) {
	want := map[conformance.TestID][]string{
		TestIDMetadataStmt1P37: {
			"fido-metadata-statement-3.1.1-ps-20260105|3.11|friendly-names|" + metadataStatementURL + "#sctn-type-fn",
			"fido-metadata-statement-3.1.1-ps-20260105|4|friendlyNames|" + metadataStatementURL + "#metadata-keys",
			"rfc-5646|2.1|language-tag-syntax|https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1",
		},
		TestIDMetadataStmt1P38: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|iconDark|" + metadataStatementURL + "#metadata-keys",
			"rfc-2397|2|data-url-syntax|https://www.rfc-editor.org/rfc/rfc2397.html#section-2",
			"svg-1.1|5.1.2|svg-element|https://www.w3.org/TR/SVG11/struct.html#SVGElement",
		},
		TestIDMetadataStmt1P39: metadataProviderLogoReferenceTargets("providerLogoLight"),
		TestIDMetadataStmt1P40: metadataProviderLogoReferenceTargets("providerLogoDark"),
		TestIDMetadataStmt1P41: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|metadata-keys|" + metadataStatementURL + "#metadata-keys",
		},
		TestIDMetadataStmt1P42: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|multiDeviceCredentialSupport|" + metadataStatementURL + "#metadata-keys",
		},
		TestIDMetadataStmt1P43: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|cxConfigURL|" + metadataStatementURL + "#metadata-keys",
		},
	}

	for _, test := range metadataStatementTestsP37ThroughP43(Metadata{}) {
		got := make([]string, 0, len(test.References))
		for _, reference := range test.References {
			got = append(got, string(reference.Specification)+"|"+reference.Section+"|"+reference.Clause+"|"+reference.URL)
		}
		if !slices.Equal(got, want[test.ID]) {
			t.Errorf("test %q reference targets = %v, want %v", test.ID, got, want[test.ID])
		}
	}
}

func TestMetadataStmt1P37FriendlyNamesPresenceTypesAndValues(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		setValue bool
		want     conformance.Status
	}{
		{name: "absent", want: conformance.StatusSkipped},
		{name: "English", value: map[string]any{"en-US": "Example Authenticator"}, setValue: true, want: conformance.StatusPassed},
		{name: "RFC 5646 variants", value: map[string]any{"en-US": "Example", "de": "Beispiel", "zh-Hant-TW": "範例"}, setValue: true, want: conformance.StatusPassed},
		{name: "63 characters", value: map[string]any{"en-US": strings.Repeat("界", 63)}, setValue: true, want: conformance.StatusPassed},
		{name: "64 characters", value: map[string]any{"en-US": strings.Repeat("a", 64)}, setValue: true, want: conformance.StatusFailed},
		{name: "null", value: nil, setValue: true, want: conformance.StatusFailed},
		{name: "wrong dictionary type", value: []string{"Example"}, setValue: true, want: conformance.StatusFailed},
		{name: "empty dictionary", value: map[string]any{}, setValue: true, want: conformance.StatusFailed},
		{name: "missing English", value: map[string]any{"de": "Beispiel"}, setValue: true, want: conformance.StatusFailed},
		{name: "empty English", value: map[string]any{"en-US": ""}, setValue: true, want: conformance.StatusFailed},
		{name: "invalid language tag", value: map[string]any{"en-US": "Example", "en_US": "Invalid"}, setValue: true, want: conformance.StatusFailed},
		{name: "null name", value: map[string]any{"en-US": nil}, setValue: true, want: conformance.StatusFailed},
		{name: "wrong name type", value: map[string]any{"en-US": true}, setValue: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP37ThroughP43Statement()
			if test.setValue {
				statement["friendlyNames"] = test.value
			}

			assertMetadataP37ThroughP43Status(t, statement, TestIDMetadataStmt1P37, test.want)
		})
	}
}

func TestMetadataStmt1P38DarkAuthenticatorIcon(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		setValue bool
		want     conformance.Status
	}{
		{name: "absent", want: conformance.StatusSkipped},
		{name: "SVG 1.1 without provider profile", value: validMetadataSVGIcon(), setValue: true, want: conformance.StatusPassed},
		{name: "null", value: nil, setValue: true, want: conformance.StatusFailed},
		{name: "wrong type", value: true, setValue: true, want: conformance.StatusFailed},
		{name: "empty", value: "", setValue: true, want: conformance.StatusFailed},
		{name: "PNG", value: validMetadataPNGIcon(t), setValue: true, want: conformance.StatusFailed},
		{name: "invalid base64", value: "data:image/svg+xml;base64,***", setValue: true, want: conformance.StatusFailed},
		{name: "malformed XML", value: metadataSVGDataURL(`<svg xmlns="http://www.w3.org/2000/svg">`), setValue: true, want: conformance.StatusFailed},
		{name: "wrong namespace", value: metadataSVGDataURL(`<svg xmlns="urn:not-svg"/>`), setValue: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP37ThroughP43Statement()
			if test.setValue {
				statement["iconDark"] = test.value
			}

			assertMetadataP37ThroughP43Status(t, statement, TestIDMetadataStmt1P38, test.want)
		})
	}
}

func TestMetadataStmt1P39LightProviderLogoProfile(t *testing.T) {
	valid := validMetadataProviderLogoSVG()
	tests := []struct {
		name     string
		logo     any
		setLogo  bool
		friendly any
		setNames bool
		want     conformance.Status
	}{
		{name: "absent", want: conformance.StatusSkipped},
		{name: "valid viewBox", logo: metadataSVGDataURL(valid), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusPassed},
		{name: "valid width height", logo: metadataSVGDataURL(strings.Replace(valid, `viewBox="0 0 32 32"`, `width="1in" height="96px"`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusPassed},
		{name: "null", logo: nil, setLogo: true, want: conformance.StatusFailed},
		{name: "wrong type", logo: true, setLogo: true, want: conformance.StatusFailed},
		{name: "empty", logo: "", setLogo: true, want: conformance.StatusFailed},
		{name: "friendly names absent", logo: metadataSVGDataURL(valid), setLogo: true, want: conformance.StatusFailed},
		{name: "English name absent", logo: metadataSVGDataURL(valid), setLogo: true, friendly: map[string]any{"de": "Beispiel"}, setNames: true, want: conformance.StatusFailed},
		{name: "wrong version", logo: metadataSVGDataURL(strings.Replace(valid, `version="1.2"`, `version="1.1"`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "missing profile", logo: metadataSVGDataURL(strings.Replace(valid, ` baseProfile="tiny-ps"`, "", 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "raster image", logo: metadataSVGDataURL(strings.Replace(valid, `</svg>`, `<image href="data:image/png;base64,AQ=="/></svg>`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "filter raster image", logo: metadataSVGDataURL(strings.Replace(valid, `</svg>`, `<feImage href="data:image/png;base64,AQ=="/></svg>`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "foreign raster content", logo: metadataSVGDataURL(strings.Replace(valid, `</svg>`, `<foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><img src="image.png"/></div></foreignObject></svg>`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "non-square", logo: metadataSVGDataURL(strings.Replace(valid, `viewBox="0 0 32 32"`, `viewBox="0 0 32 16"`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "square viewBox conflicting viewport", logo: metadataSVGDataURL(strings.Replace(valid, `viewBox="0 0 32 32"`, `viewBox="0 0 32 32" width="32" height="16"`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "dimensions absent", logo: metadataSVGDataURL(strings.Replace(valid, ` viewBox="0 0 32 32"`, "", 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "title absent", logo: metadataSVGDataURL(strings.Replace(valid, `<title>Example Provider</title>`, "", 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "title mismatch", logo: metadataSVGDataURL(strings.Replace(valid, `Example Provider`, `Other Provider`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "comment", logo: metadataSVGDataURL(strings.Replace(valid, `</svg>`, `<!--comment--></svg>`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
		{name: "extra text", logo: metadataSVGDataURL(strings.Replace(valid, `</svg>`, `<text>extra</text></svg>`, 1)), setLogo: true, friendly: map[string]any{"en-US": "Example Provider"}, setNames: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP37ThroughP43Statement()
			if test.setLogo {
				statement["providerLogoLight"] = test.logo
			}
			if test.setNames {
				statement["friendlyNames"] = test.friendly
			}

			assertMetadataP37ThroughP43Status(t, statement, TestIDMetadataStmt1P39, test.want)
		})
	}
}

func TestMetadataStmt1P40DarkProviderLogoProfile(t *testing.T) {
	valid := metadataSVGDataURL(validMetadataProviderLogoSVG())
	tests := []struct {
		name     string
		value    any
		setValue bool
		want     conformance.Status
	}{
		{name: "absent", want: conformance.StatusSkipped},
		{name: "valid", value: valid, setValue: true, want: conformance.StatusPassed},
		{name: "null", value: nil, setValue: true, want: conformance.StatusFailed},
		{name: "wrong type", value: 1, setValue: true, want: conformance.StatusFailed},
		{name: "invalid profile", value: metadataSVGDataURL(strings.Replace(validMetadataProviderLogoSVG(), `tiny-ps`, `full`, 1)), setValue: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP37ThroughP43Statement()
			statement["friendlyNames"] = map[string]any{"en-US": "Example Provider"}
			if test.setValue {
				statement["providerLogoDark"] = test.value
			}

			assertMetadataP37ThroughP43Status(t, statement, TestIDMetadataStmt1P40, test.want)
		})
	}
}

func TestMetadataStmt1P41LegacyKeyScopeAlwaysSkips(t *testing.T) {
	for _, statement := range []map[string]any{
		validMetadataP37ThroughP43Statement(),
		func() map[string]any {
			statement := validMetadataP37ThroughP43Statement()
			statement["keyScope"] = "public-key-credential-source"

			return statement
		}(),
	} {
		assertMetadataP37ThroughP43Status(t, statement, TestIDMetadataStmt1P41, conformance.StatusSkipped)
	}
}

func TestMetadataStmt1P42MultiDeviceCredentialSupport(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		setValue bool
		want     conformance.Status
	}{
		{name: "absent implicit unsupported", want: conformance.StatusSkipped},
		{name: "unsupported", value: "unsupported", setValue: true, want: conformance.StatusPassed},
		{name: "explicit", value: "explicit", setValue: true, want: conformance.StatusPassed},
		{name: "implicit", value: "implicit", setValue: true, want: conformance.StatusPassed},
		{name: "null", value: nil, setValue: true, want: conformance.StatusFailed},
		{name: "wrong type", value: false, setValue: true, want: conformance.StatusFailed},
		{name: "empty", value: "", setValue: true, want: conformance.StatusFailed},
		{name: "unknown", value: "synced", setValue: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP37ThroughP43Statement()
			if test.setValue {
				statement["multiDeviceCredentialSupport"] = test.value
			}

			assertMetadataP37ThroughP43Status(t, statement, TestIDMetadataStmt1P42, test.want)
		})
	}
}

func TestMetadataStmt1P43CredentialExchangeConfigurationURL(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    any
		setValue bool
		want     conformance.Status
	}{
		{name: "absent", want: conformance.StatusSkipped},
		{name: "current field", field: "cxConfigURL", value: "https://example.test/credential-exchange/config.json", setValue: true, want: conformance.StatusPassed},
		{name: "legacy upstream spelling", field: "cxpConfigURL", value: "https://example.test/config", setValue: true, want: conformance.StatusSkipped},
		{name: "null", field: "cxConfigURL", value: nil, setValue: true, want: conformance.StatusFailed},
		{name: "wrong type", field: "cxConfigURL", value: true, setValue: true, want: conformance.StatusFailed},
		{name: "empty", field: "cxConfigURL", value: "", setValue: true, want: conformance.StatusFailed},
		{name: "relative", field: "cxConfigURL", value: "/config.json", setValue: true, want: conformance.StatusFailed},
		{name: "malformed", field: "cxConfigURL", value: "https://example.test/%zz", setValue: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP37ThroughP43Statement()
			if test.setValue {
				statement[test.field] = test.value
			}

			assertMetadataP37ThroughP43Status(t, statement, TestIDMetadataStmt1P43, test.want)
		})
	}
}

func TestMetadataStmt1P37ThroughP43MalformedDocumentIsError(t *testing.T) {
	result := runMetadataStatementP37ThroughP43Tests(t, `{"friendlyNames":{}} trailing`, TestIDMetadataStmt1P37)
	if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
		t.Fatalf("result = %#v, want error", result)
	}
}

func runMetadataStatementP37ThroughP43Tests(
	t *testing.T,
	statementJSON string,
	selected ...conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	tests := metadataStatementTestsP37ThroughP43(Metadata{StatementJSON: statementJSON})
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
		ID:    "test.metadata-statement-p37-p43",
		Name:  "Metadata statement P-37 through P-43 tests",
		Tests: tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertMetadataP37ThroughP43Status(
	t *testing.T,
	statement map[string]any,
	id conformance.TestID,
	want conformance.Status,
) {
	t.Helper()

	result := runMetadataStatementP37ThroughP43Tests(t, metadataStatementJSON(t, statement), id)
	if result.Status != want || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %q", result, want)
	}
}

func validMetadataP37ThroughP43Statement() map[string]any {
	return validMetadataP25ThroughP31Statement()
}

func validMetadataProviderLogoSVG() string {
	return `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 32 32"><title>Example Provider</title><path d="M0 0h32v32H0z"/></svg>`
}

func metadataSVGDataURL(document string) string {
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(document))
}

func metadataProviderLogoReferenceTargets(field string) []string {
	return []string{
		"fido-metadata-statement-3.1.1-ps-20260105|4|" + field + "|" + metadataStatementURL + "#metadata-keys",
		"fido-metadata-statement-3.1.1-ps-20260105|4.1|svg-provider-icons|" + metadataStatementURL + "#sctn-svg-requirements",
		"rfc-2397|2|data-url-syntax|https://www.rfc-editor.org/rfc/rfc2397.html#section-2",
		"svg-1.1|5.1.2|svg-element|https://www.w3.org/TR/SVG11/struct.html#SVGElement",
	}
}

func TestMetadataStmt1P37ThroughP43FixturesAreJSON(t *testing.T) {
	if _, err := json.Marshal(validMetadataP37ThroughP43Statement()); err != nil {
		t.Fatal(err)
	}
}
