package ctap23

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

type metadataStatementTestDevice struct{}

func (metadataStatementTestDevice) CBOR(context.Context, []byte) (ctaptransport.CBORResponse, error) {
	panic("metadata statement validation must not issue a CTAP command")
}

func TestMetadataStmt1P1ThroughP14SourceMapping(t *testing.T) {
	tests := metadataStatementTests(Metadata{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{id: TestIDMetadataStmt1P1, marker: "P-1"},
		{id: TestIDMetadataStmt1P2, marker: "P-2"},
		{id: TestIDMetadataStmt1P3, marker: "P-3"},
		{id: TestIDMetadataStmt1P4, marker: "P-4"},
		{id: TestIDMetadataStmt1P5, marker: "P-5"},
		{id: TestIDMetadataStmt1P6, marker: "P-6"},
		{id: TestIDMetadataStmt1P7, marker: "P-7"},
		{id: TestIDMetadataStmt1P8, marker: "P-8"},
		{id: TestIDMetadataStmt1P11, marker: "P-11"},
		{id: TestIDMetadataStmt1P13, marker: "P-13"},
		{id: TestIDMetadataStmt1P14, marker: "P-14"},
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

func TestMetadataStmt1P1ThroughP14PassValidStatement(t *testing.T) {
	result := runMetadataStatementTests(t, metadataStatementJSON(t, validMetadataStatement()))

	if result.Status != conformance.StatusPassed {
		t.Fatalf("suite status = %q, want passed: %#v", result.Status, result.Tests)
	}
	if len(result.Tests) != 11 {
		t.Fatalf("tests = %d, want 11", len(result.Tests))
	}
	for _, test := range result.Tests {
		if test.Status != conformance.StatusPassed {
			t.Errorf("test %q status = %q, want passed: %#v", test.ID, test.Status, test.Steps)
		}
		if len(test.Steps) != 1 || test.Steps[0].Status != conformance.StatusPassed {
			t.Errorf("test %q steps = %#v, want one passed step", test.ID, test.Steps)
			continue
		}
		assertCompleteMetadataReferences(t, test.Steps[0].References)
	}
}

func TestMetadataStmt1P13ReferencesCTAPCOSEKeyEncoding(t *testing.T) {
	var test conformance.Test
	for _, candidate := range metadataStatementTests(Metadata{}) {
		if candidate.ID == TestIDMetadataStmt1P13 {
			test = candidate
			break
		}
	}

	if !slices.ContainsFunc(test.References, func(reference conformance.RequirementRef) bool {
		return reference.ID == "ctap-2.3-ps-20260226:6.1:credential-public-key-cose-key" &&
			reference.Specification == conformance.SpecificationCTAP23 &&
			reference.Section == "6.1" &&
			reference.Clause == "credential-public-key-cose-key" &&
			reference.URL == metadataCTAP23URL+"#authenticatorMakeCredential" &&
			reference.Level == conformance.RequirementConstraint
	}) {
		t.Fatalf("P-13 references = %#v, want CTAP credential public key COSE_Key requirement", test.References)
	}
}

func TestMetadataStmt1P1ThroughP14ReportNormativeFailures(t *testing.T) {
	tests := []struct {
		name   string
		id     conformance.TestID
		mutate func(map[string]any)
	}{
		{
			name: "P-1 present non-string legal header",
			id:   TestIDMetadataStmt1P1,
			mutate: func(statement map[string]any) {
				statement["legalHeader"] = false
			},
		},
		{
			name: "P-2 malformed AAGUID",
			id:   TestIDMetadataStmt1P2,
			mutate: func(statement map[string]any) {
				statement["aaguid"] = "00112233445566778899AABBCCDDEEFF"
			},
		},
		{
			name: "P-3 inapplicable field present as null",
			id:   TestIDMetadataStmt1P3,
			mutate: func(statement map[string]any) {
				statement["aaid"] = nil
			},
		},
		{
			name: "P-4 non-ASCII description",
			id:   TestIDMetadataStmt1P4,
			mutate: func(statement map[string]any) {
				statement["description"] = "Authenticatör"
			},
		},
		{
			name: "P-5 malformed language tag",
			id:   TestIDMetadataStmt1P5,
			mutate: func(statement map[string]any) {
				statement["alternativeDescriptions"] = map[string]string{"en_US": "Alternate name"}
			},
		},
		{
			name: "P-6 negative authenticator version",
			id:   TestIDMetadataStmt1P6,
			mutate: func(statement map[string]any) {
				statement["authenticatorVersion"] = -1
			},
		},
		{
			name: "P-7 non-FIDO2 protocol family",
			id:   TestIDMetadataStmt1P7,
			mutate: func(statement map[string]any) {
				statement["protocolFamily"] = "uaf"
			},
		},
		{
			name: "P-8 missing CTAP 2.3 version",
			id:   TestIDMetadataStmt1P8,
			mutate: func(statement map[string]any) {
				statement["upv"] = []any{map[string]any{"major": 1, "minor": 1}}
			},
		},
		{
			name: "P-11 unregistered authentication algorithm",
			id:   TestIDMetadataStmt1P11,
			mutate: func(statement map[string]any) {
				statement["authenticationAlgorithms"] = []string{"vendor_algorithm"}
			},
		},
		{
			name: "P-13 missing COSE encoding",
			id:   TestIDMetadataStmt1P13,
			mutate: func(statement map[string]any) {
				statement["publicKeyAlgAndEncodings"] = []string{"ecc_x962_raw"}
			},
		},
		{
			name: "P-14 unregistered attestation type",
			id:   TestIDMetadataStmt1P14,
			mutate: func(statement map[string]any) {
				statement["attestationTypes"] = []string{"vendor_attestation"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataStatement()
			test.mutate(statement)

			result := runMetadataStatementTests(t, metadataStatementJSON(t, statement), test.id)
			if result.Status != conformance.StatusFailed || len(result.Tests) != 1 || result.Tests[0].Status != conformance.StatusFailed {
				t.Fatalf("result = %#v, want one failed test", result)
			}
			if len(result.Tests[0].Steps) != 1 || result.Tests[0].Steps[0].Status != conformance.StatusFailed {
				t.Fatalf("steps = %#v, want one failed step", result.Tests[0].Steps)
			}
		})
	}
}

func TestMetadataStmt1OptionalFieldsSkipOnlyWhenAbsent(t *testing.T) {
	tests := []struct {
		name  string
		id    conformance.TestID
		field string
	}{
		{name: "P-1", id: TestIDMetadataStmt1P1, field: "legalHeader"},
		{name: "P-5", id: TestIDMetadataStmt1P5, field: "alternativeDescriptions"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataStatement()
			delete(statement, test.field)

			result := runMetadataStatementTests(t, metadataStatementJSON(t, statement), test.id)
			if result.Status != conformance.StatusSkipped || result.Tests[0].Status != conformance.StatusSkipped {
				t.Fatalf("result = %#v, want skipped", result)
			}
		})
	}

	statement := validMetadataStatement()
	statement["alternativeDescriptions"] = map[string]string{}
	result := runMetadataStatementTests(t, metadataStatementJSON(t, statement), TestIDMetadataStmt1P5)
	if result.Status != conformance.StatusPassed {
		t.Fatalf("present empty dictionary status = %q, want passed: %#v", result.Status, result.Tests)
	}

	statement = validMetadataStatement()
	statement["alternativeDescriptions"] = nil
	result = runMetadataStatementTests(t, metadataStatementJSON(t, statement), TestIDMetadataStmt1P5)
	if result.Status != conformance.StatusFailed {
		t.Fatalf("present null dictionary status = %q, want failed: %#v", result.Status, result.Tests)
	}
}

func TestMetadataStmt1MalformedOrMissingInputIsExecutionError(t *testing.T) {
	for _, statement := range []string{"", "{"} {
		result := runMetadataStatementTests(t, statement, TestIDMetadataStmt1P2)
		if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
			t.Fatalf("statement %q result = %#v, want execution error", statement, result)
		}
	}
}

func TestMetadataStmt1NormativeBoundaryCases(t *testing.T) {
	t.Run("P-4 permits exactly 200 ASCII characters", func(t *testing.T) {
		statement := validMetadataStatement()
		statement["description"] = strings.Repeat("d", 200)

		assertMetadataTestStatus(t, statement, TestIDMetadataStmt1P4, conformance.StatusPassed)

		statement["description"] = strings.Repeat("d", 201)
		assertMetadataTestStatus(t, statement, TestIDMetadataStmt1P4, conformance.StatusFailed)
	})

	t.Run("P-5 applies RFC 5646 case-insensitively and counts characters", func(t *testing.T) {
		statement := validMetadataStatement()
		statement["alternativeDescriptions"] = map[string]string{"EN-us": strings.Repeat("界", 200)}

		assertMetadataTestStatus(t, statement, TestIDMetadataStmt1P5, conformance.StatusPassed)

		statement["alternativeDescriptions"] = map[string]string{"EN-us": strings.Repeat("界", 201)}
		assertMetadataTestStatus(t, statement, TestIDMetadataStmt1P5, conformance.StatusFailed)
	})

	t.Run("P-5 accepts complete BCP 47 language tags", func(t *testing.T) {
		for _, tag := range []string{
			"zh-Hant",
			"es-419",
			"zh-Hant-TW",
			"de-CH-1901",
			"sl-rozaj-biske-1994",
			"en-US-u-ca-gregory",
			"en-a-aaa-b-bbb",
			"en-a-bbb-x-a-ccc",
			"x-abcde-abcde",
			"i-klingon",
		} {
			t.Run(tag, func(t *testing.T) {
				statement := validMetadataStatement()
				statement["alternativeDescriptions"] = map[string]string{tag: "Localized name"}

				assertMetadataTestStatus(t, statement, TestIDMetadataStmt1P5, conformance.StatusPassed)
			})
		}
	})

	t.Run("P-5 rejects malformed and non-BCP-47 locale identifiers", func(t *testing.T) {
		for _, tag := range []string{
			"en_US",
			"en--US",
			"root",
			"xy",
			"nl-fonupa-fonupa",
			"nl-fonupa-FONUPA",
			"en-a-bbb-a-ccc",
			"en-a-bbb-A-ccc",
		} {
			t.Run(tag, func(t *testing.T) {
				statement := validMetadataStatement()
				statement["alternativeDescriptions"] = map[string]string{tag: "Localized name"}

				assertMetadataTestStatus(t, statement, TestIDMetadataStmt1P5, conformance.StatusFailed)
			})
		}
	})

	t.Run("P-6 accepts zero unsigned long", func(t *testing.T) {
		statement := validMetadataStatement()
		statement["authenticatorVersion"] = uint32(0)

		assertMetadataTestStatus(t, statement, TestIDMetadataStmt1P6, conformance.StatusPassed)
	})

	t.Run("P-8 rejects null Version members", func(t *testing.T) {
		statement := validMetadataStatement()
		statement["upv"] = []any{nil, map[string]any{"major": 1, "minor": 3}}

		assertMetadataTestStatus(t, statement, TestIDMetadataStmt1P8, conformance.StatusFailed)
	})
}

func runMetadataStatementTests(
	t *testing.T,
	statementJSON string,
	selected ...conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	tests := metadataStatementTests(Metadata{StatementJSON: statementJSON})
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
		ID:    "test.metadata-statement",
		Name:  "Metadata statement tests",
		Tests: tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertMetadataTestStatus(
	t *testing.T,
	statement map[string]any,
	id conformance.TestID,
	want conformance.Status,
) {
	t.Helper()

	result := runMetadataStatementTests(t, metadataStatementJSON(t, statement), id)
	if result.Status != want || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %q", result, want)
	}
}

func validMetadataStatement() map[string]any {
	return map[string]any{
		"legalHeader":              "Legal terms accepted",
		"aaguid":                   "00112233-4455-6677-8899-AABBCCDDEEFF",
		"description":              "Synthetic authenticator",
		"alternativeDescriptions":  map[string]string{"de-at": "Alternativer Name"},
		"authenticatorVersion":     uint32(0),
		"protocolFamily":           "fido2",
		"upv":                      []any{map[string]any{"major": 1, "minor": 3}},
		"authenticationAlgorithms": []string{"secp256r1_ecdsa_sha256_raw"},
		"publicKeyAlgAndEncodings": []string{"cose", "ecc_x962_raw"},
		"attestationTypes":         []string{"none"},
	}
}

func metadataStatementJSON(t *testing.T, statement map[string]any) string {
	t.Helper()

	data, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func assertCompleteMetadataReferences(t *testing.T, references []conformance.RequirementRef) {
	t.Helper()

	if len(references) == 0 {
		t.Fatal("normative references are empty")
	}
	for _, reference := range references {
		if reference.ID == "" || reference.Specification == "" || reference.Section == "" ||
			reference.Clause == "" || reference.URL == "" || reference.Level == "" {
			t.Errorf("incomplete normative reference: %#v", reference)
		}
	}
}
