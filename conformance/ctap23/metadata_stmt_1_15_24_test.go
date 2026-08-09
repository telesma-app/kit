package ctap23

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/kit/conformance"
)

func TestMetadataStmt1P15ThroughP24SourceMapping(t *testing.T) {
	tests := metadataStatementTestsP15ThroughP24(Metadata{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{id: TestIDMetadataStmt1P15, marker: "P-15"},
		{id: TestIDMetadataStmt1P16, marker: "P-16"},
		{id: TestIDMetadataStmt1P17, marker: "P-17"},
		{id: TestIDMetadataStmt1P18, marker: "P-18"},
		{id: TestIDMetadataStmt1P19, marker: "P-19"},
		{id: TestIDMetadataStmt1P20, marker: "P-20"},
		{id: TestIDMetadataStmt1P22, marker: "P-22"},
		{id: TestIDMetadataStmt1P24, marker: "P-24"},
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

func TestMetadataStmt1P15ThroughP24NormativeReferenceTargets(t *testing.T) {
	want := map[conformance.TestID][]string{
		TestIDMetadataStmt1P15: {
			"fido-metadata-statement-3.1.1-ps-20260105|3.2|code-accuracy-descriptor|" + metadataStatementURL + "#sctn-type-cad",
			"fido-metadata-statement-3.1.1-ps-20260105|3.3|biometric-accuracy-descriptor|" + metadataStatementURL + "#sctn-type-bad",
			"fido-metadata-statement-3.1.1-ps-20260105|3.4|pattern-accuracy-descriptor|" + metadataStatementURL + "#sctn-type-pad",
			"fido-metadata-statement-3.1.1-ps-20260105|3.5|verification-method-descriptor|" + metadataStatementURL + "#sctn-type-vmd",
			"fido-metadata-statement-3.1.1-ps-20260105|3.6|verification-method-and-combinations|" + metadataStatementURL + "#sctn-type-vmac",
			"fido-metadata-statement-3.1.1-ps-20260105|4|userVerificationDetails|" + metadataStatementURL + "#metadata-keys",
			"fido-registry-2.3-ps-20260105|3.1|user-verification-methods|" + fidoRegistryURL + "#user-verification-methods",
		},
		TestIDMetadataStmt1P16: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|keyProtection|" + metadataStatementURL + "#metadata-keys",
			"fido-metadata-statement-3.1.1-ps-20260105|4|multiDeviceCredentialSupport|" + metadataStatementURL + "#metadata-keys",
			"fido-registry-2.3-ps-20260105|3.2|key-protection-types|" + fidoRegistryURL + "#key-protection-types",
		},
		TestIDMetadataStmt1P17: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|isKeyRestricted|" + metadataStatementURL + "#metadata-keys",
		},
		TestIDMetadataStmt1P18: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|isFreshUserVerificationRequired|" + metadataStatementURL + "#metadata-keys",
		},
		TestIDMetadataStmt1P19: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|matcherProtection|" + metadataStatementURL + "#metadata-keys",
			"fido-registry-2.3-ps-20260105|3.3|matcher-protection-types|" + fidoRegistryURL + "#matcher-protection-types",
		},
		TestIDMetadataStmt1P20: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|cryptoStrength|" + metadataStatementURL + "#metadata-keys",
		},
		TestIDMetadataStmt1P22: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|attachmentHint|" + metadataStatementURL + "#metadata-keys",
			"fido-registry-2.3-ps-20260105|3.4|authenticator-attachment-hints|" + fidoRegistryURL + "#authenticator-attachment-hints",
		},
		TestIDMetadataStmt1P24: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|tcDisplay|" + metadataStatementURL + "#metadata-keys",
			"fido-metadata-statement-3.1.1-ps-20260105|1|webidl-dictionary-members-not-null|" + metadataStatementURL + "#notation",
			"fido-registry-2.3-ps-20260105|3.5|transaction-confirmation-display-types|" + fidoRegistryURL + "#transaction-confirmation-display-types",
		},
	}

	for _, test := range metadataStatementTestsP15ThroughP24(Metadata{}) {
		got := make([]string, 0, len(test.References))
		for _, reference := range test.References {
			got = append(got, string(reference.Specification)+"|"+reference.Section+"|"+reference.Clause+"|"+reference.URL)
		}
		if !slices.Equal(got, want[test.ID]) {
			t.Errorf("test %q reference targets = %v, want %v", test.ID, got, want[test.ID])
		}
		if test.ID == TestIDMetadataStmt1P22 && test.References[0].Level != conformance.RequirementMust {
			t.Errorf("P-22 attachmentHint reference level = %q, want MUST", test.References[0].Level)
		}
		if test.ID == TestIDMetadataStmt1P24 && test.References[1].Level != conformance.RequirementMust {
			t.Errorf("P-24 dictionary nullability reference level = %q, want MUST", test.References[1].Level)
		}
	}
}

func TestMetadataStmt1P15ThroughP24PassValidStatement(t *testing.T) {
	result := runMetadataStatementP15ThroughP24Tests(t, metadataStatementJSON(t, validMetadataP15ThroughP24Statement()))

	if result.Status != conformance.StatusPassed {
		t.Fatalf("suite status = %q, want passed: %#v", result.Status, result.Tests)
	}
	if len(result.Tests) != 8 {
		t.Fatalf("tests = %d, want 8", len(result.Tests))
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

func TestMetadataStmt1P15ThroughP24ClassifyNormativeFailures(t *testing.T) {
	tests := []struct {
		name   string
		id     conformance.TestID
		mutate func(map[string]any)
	}{
		{
			name: "P-15 forbids all as a base method",
			id:   TestIDMetadataStmt1P15,
			mutate: func(statement map[string]any) {
				statement["userVerificationDetails"] = []any{[]any{map[string]any{"userVerificationMethod": "all"}}}
			},
		},
		{
			name: "P-16 forbids software and hardware",
			id:   TestIDMetadataStmt1P16,
			mutate: func(statement map[string]any) {
				statement["keyProtection"] = []string{"software", "hardware"}
			},
		},
		{
			name: "P-17 rejects a string boolean",
			id:   TestIDMetadataStmt1P17,
			mutate: func(statement map[string]any) {
				statement["isKeyRestricted"] = "false"
			},
		},
		{
			name: "P-18 rejects null",
			id:   TestIDMetadataStmt1P18,
			mutate: func(statement map[string]any) {
				statement["isFreshUserVerificationRequired"] = nil
			},
		},
		{
			name: "P-19 requires one matcher value or one per method",
			id:   TestIDMetadataStmt1P19,
			mutate: func(statement map[string]any) {
				statement["matcherProtection"] = []string{"software", "tee"}
			},
		},
		{
			name: "P-20 rejects zero strength",
			id:   TestIDMetadataStmt1P20,
			mutate: func(statement map[string]any) {
				statement["cryptoStrength"] = 0
			},
		},
		{
			name: "P-22 forbids combining internal with another hint",
			id:   TestIDMetadataStmt1P22,
			mutate: func(statement map[string]any) {
				statement["attachmentHint"] = []string{"internal", "wired"}
			},
		},
		{
			name: "P-24 requires a display for transaction confirmation",
			id:   TestIDMetadataStmt1P24,
			mutate: func(statement map[string]any) {
				statement["authenticatorGetInfo"] = map[string]any{"extensions": []string{"txAuthSimple"}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			test.mutate(statement)

			assertMetadataP15ThroughP24Status(t, statement, test.id, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P15ThroughP24OptionalFieldsSkipOnlyWhenAbsent(t *testing.T) {
	tests := []struct {
		name  string
		id    conformance.TestID
		field string
	}{
		{name: "P-15", id: TestIDMetadataStmt1P15, field: "userVerificationDetails"},
		{name: "P-17", id: TestIDMetadataStmt1P17, field: "isKeyRestricted"},
		{name: "P-18", id: TestIDMetadataStmt1P18, field: "isFreshUserVerificationRequired"},
		{name: "P-20", id: TestIDMetadataStmt1P20, field: "cryptoStrength"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			delete(statement, test.field)

			assertMetadataP15ThroughP24Status(t, statement, test.id, conformance.StatusSkipped)
		})
	}

	for _, test := range []struct {
		name  string
		id    conformance.TestID
		field string
	}{
		{name: "P-17 false", id: TestIDMetadataStmt1P17, field: "isKeyRestricted"},
		{name: "P-18 false", id: TestIDMetadataStmt1P18, field: "isFreshUserVerificationRequired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement[test.field] = false

			assertMetadataP15ThroughP24Status(t, statement, test.id, conformance.StatusPassed)
		})
	}
}

func TestMetadataStmt1P15ThroughP24MalformedInputIsExecutionError(t *testing.T) {
	for _, input := range []string{"", "{"} {
		result := runMetadataStatementP15ThroughP24Tests(t, input, TestIDMetadataStmt1P15)
		if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
			t.Fatalf("input %q result = %#v, want execution error", input, result)
		}
	}
}

func TestMetadataStmt1P15ValidatesNestedStructureAndMethods(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "null outer list", value: nil},
		{name: "wrong outer type", value: map[string]any{}},
		{name: "empty outer list", value: []any{}},
		{name: "null AND group", value: []any{nil}},
		{name: "wrong AND group type", value: []any{map[string]any{}}},
		{name: "empty AND group", value: []any{[]any{}}},
		{name: "null descriptor", value: []any{[]any{nil}}},
		{name: "wrong descriptor type", value: []any{[]any{"passcode_internal"}}},
		{name: "missing method", value: []any{[]any{map[string]any{}}}},
		{name: "null method", value: []any{[]any{map[string]any{"userVerificationMethod": nil}}}},
		{name: "wrong method type", value: []any{[]any{map[string]any{"userVerificationMethod": 4}}}},
		{name: "empty method", value: []any{[]any{map[string]any{"userVerificationMethod": ""}}}},
		{name: "unregistered method", value: []any{[]any{map[string]any{"userVerificationMethod": "vendor_method"}}}},
		{name: "all method", value: []any{[]any{map[string]any{"userVerificationMethod": "all"}}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement["userVerificationDetails"] = test.value

			assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P15, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P15ValidatesDescriptorCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		descriptor map[string]any
	}{
		{
			name: "presence with code accuracy",
			descriptor: map[string]any{
				"userVerificationMethod": "presence_internal",
				"caDesc":                 map[string]any{"base": 10, "minLength": 4},
			},
		},
		{
			name: "passcode with biometric accuracy",
			descriptor: map[string]any{
				"userVerificationMethod": "passcode_internal",
				"baDesc":                 map[string]any{"selfAttestedFAR": 0.01},
			},
		},
		{
			name: "passcode with pattern accuracy",
			descriptor: map[string]any{
				"userVerificationMethod": "passcode_external",
				"paDesc":                 map[string]any{"minComplexity": 16},
			},
		},
		{
			name: "biometric with pattern accuracy",
			descriptor: map[string]any{
				"userVerificationMethod": "fingerprint_internal",
				"paDesc":                 map[string]any{"minComplexity": 16},
			},
		},
		{
			name: "pattern with code accuracy",
			descriptor: map[string]any{
				"userVerificationMethod": "pattern_internal",
				"caDesc":                 map[string]any{"base": 10, "minLength": 4},
			},
		},
		{
			name: "pattern with biometric accuracy",
			descriptor: map[string]any{
				"userVerificationMethod": "pattern_external",
				"baDesc":                 map[string]any{"selfAttestedFAR": 0.01},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement["userVerificationDetails"] = []any{[]any{test.descriptor}}

			assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P15, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P15AcceptsCompatibleAccuracyDescriptors(t *testing.T) {
	tests := []struct {
		method     string
		descriptor string
		accuracy   map[string]any
	}{
		{method: "passcode_internal", descriptor: "caDesc", accuracy: map[string]any{"base": 10, "minLength": 4}},
		{method: "passcode_external", descriptor: "caDesc", accuracy: map[string]any{"base": 10, "minLength": 4}},
		{method: "fingerprint_internal", descriptor: "baDesc", accuracy: map[string]any{"selfAttestedFAR": 0.01}},
		{method: "voiceprint_internal", descriptor: "baDesc", accuracy: map[string]any{"selfAttestedFAR": 0.01}},
		{method: "faceprint_internal", descriptor: "baDesc", accuracy: map[string]any{"selfAttestedFAR": 0.01}},
		{method: "eyeprint_internal", descriptor: "baDesc", accuracy: map[string]any{"selfAttestedFAR": 0.01}},
		{method: "handprint_internal", descriptor: "baDesc", accuracy: map[string]any{"selfAttestedFAR": 0.01}},
		{method: "pattern_internal", descriptor: "paDesc", accuracy: map[string]any{"minComplexity": 16}},
		{method: "pattern_external", descriptor: "paDesc", accuracy: map[string]any{"minComplexity": 16}},
	}

	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement["userVerificationDetails"] = []any{[]any{map[string]any{
				"userVerificationMethod": test.method,
				test.descriptor:          test.accuracy,
			}}}

			assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P15, conformance.StatusPassed)
		})
	}
}

func TestMetadataStmt1P15AcceptsDescriptorNumericBoundaries(t *testing.T) {
	descriptors := []map[string]any{
		{
			"userVerificationMethod": "passcode_external",
			"caDesc": map[string]any{
				"base":          65535,
				"minLength":     65535,
				"maxRetries":    0,
				"blockSlowdown": 65535,
			},
		},
		{
			"userVerificationMethod": "faceprint_internal",
			"baDesc": map[string]any{
				"selfAttestedFRR": 1,
				"selfAttestedFAR": 0.00001,
				"iAPARThreshold":  1,
				"maxTemplates":    65535,
				"maxRetries":      0,
				"blockSlowdown":   65535,
			},
		},
		{
			"userVerificationMethod": "pattern_external",
			"paDesc": map[string]any{
				"minComplexity": 4294967295,
				"maxRetries":    0,
				"blockSlowdown": 65535,
			},
		},
	}

	statement := validMetadataP15ThroughP24Statement()
	statement["userVerificationDetails"] = []any{[]any{descriptors[0]}, []any{descriptors[1]}, []any{descriptors[2]}}

	assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P15, conformance.StatusPassed)
}

func TestMetadataStmt1P15RejectsInvalidAccuracyDescriptors(t *testing.T) {
	tests := []struct {
		name       string
		descriptor map[string]any
	}{
		{name: "null caDesc", descriptor: map[string]any{"userVerificationMethod": "passcode_internal", "caDesc": nil}},
		{name: "wrong caDesc type", descriptor: map[string]any{"userVerificationMethod": "passcode_internal", "caDesc": []any{}}},
		{name: "missing code base", descriptor: map[string]any{"userVerificationMethod": "passcode_internal", "caDesc": map[string]any{"minLength": 4}}},
		{name: "zero code base", descriptor: map[string]any{"userVerificationMethod": "passcode_internal", "caDesc": map[string]any{"base": 0, "minLength": 4}}},
		{name: "code base overflow", descriptor: map[string]any{"userVerificationMethod": "passcode_internal", "caDesc": map[string]any{"base": 65536, "minLength": 4}}},
		{name: "fractional code base", descriptor: map[string]any{"userVerificationMethod": "passcode_internal", "caDesc": map[string]any{"base": 10.5, "minLength": 4}}},
		{name: "missing code length", descriptor: map[string]any{"userVerificationMethod": "passcode_external", "caDesc": map[string]any{"base": 10}}},
		{name: "zero code length", descriptor: map[string]any{"userVerificationMethod": "passcode_external", "caDesc": map[string]any{"base": 10, "minLength": 0}}},
		{name: "negative code retries", descriptor: map[string]any{"userVerificationMethod": "passcode_external", "caDesc": map[string]any{"base": 10, "minLength": 4, "maxRetries": -1}}},
		{name: "null code slowdown", descriptor: map[string]any{"userVerificationMethod": "passcode_external", "caDesc": map[string]any{"base": 10, "minLength": 4, "blockSlowdown": nil}}},
		{name: "empty biometric descriptor", descriptor: map[string]any{"userVerificationMethod": "fingerprint_internal", "baDesc": map[string]any{}}},
		{name: "zero biometric FRR", descriptor: map[string]any{"userVerificationMethod": "fingerprint_internal", "baDesc": map[string]any{"selfAttestedFRR": 0}}},
		{name: "biometric FAR above one", descriptor: map[string]any{"userVerificationMethod": "voiceprint_internal", "baDesc": map[string]any{"selfAttestedFAR": 1.01}}},
		{name: "negative biometric threshold", descriptor: map[string]any{"userVerificationMethod": "faceprint_internal", "baDesc": map[string]any{"iAPARThreshold": -0.1}}},
		{name: "zero biometric templates", descriptor: map[string]any{"userVerificationMethod": "eyeprint_internal", "baDesc": map[string]any{"maxTemplates": 0}}},
		{name: "biometric retry overflow", descriptor: map[string]any{"userVerificationMethod": "handprint_internal", "baDesc": map[string]any{"maxRetries": 65536}}},
		{name: "missing pattern complexity", descriptor: map[string]any{"userVerificationMethod": "pattern_internal", "paDesc": map[string]any{}}},
		{name: "zero pattern complexity", descriptor: map[string]any{"userVerificationMethod": "pattern_internal", "paDesc": map[string]any{"minComplexity": 0}}},
		{name: "pattern complexity overflow", descriptor: map[string]any{"userVerificationMethod": "pattern_external", "paDesc": map[string]any{"minComplexity": 4294967296}}},
		{name: "fractional pattern slowdown", descriptor: map[string]any{"userVerificationMethod": "pattern_external", "paDesc": map[string]any{"minComplexity": 16, "blockSlowdown": 0.5}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement["userVerificationDetails"] = []any{[]any{test.descriptor}}

			assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P15, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P16KeyProtectionCombinations(t *testing.T) {
	pass := []struct {
		protection []string
		support    string
	}{
		{protection: []string{"software"}},
		{protection: []string{"tee"}},
		{protection: []string{"hardware", "tee", "remote_handle"}},
		{protection: []string{"hardware", "secure_element"}},
		{protection: []string{"sync_fabric"}, support: "explicit"},
		{protection: []string{"sync_fabric", "secure_element"}, support: "implicit"},
	}
	for _, test := range pass {
		statement := validMetadataP15ThroughP24Statement()
		statement["keyProtection"] = test.protection
		if test.support != "" {
			statement["multiDeviceCredentialSupport"] = test.support
		}

		assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P16, conformance.StatusPassed)
	}

	fail := []any{
		nil,
		"hardware",
		[]string{},
		[]string{"reserved"},
		[]string{"software", "software"},
		[]string{"software", "hardware"},
		[]string{"software", "tee"},
		[]string{"software", "secure_element"},
		[]string{"tee", "secure_element"},
		[]string{"remote_handle"},
		[]string{"remote_handle", "sync_fabric"},
	}
	for _, protection := range fail {
		statement := validMetadataP15ThroughP24Statement()
		statement["keyProtection"] = protection

		assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P16, conformance.StatusFailed)
	}

	statement := validMetadataP15ThroughP24Statement()
	delete(statement, "keyProtection")
	assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P16, conformance.StatusFailed)
}

func TestMetadataStmt1P16SyncFabricRequiresDeclaredMultiDeviceSupport(t *testing.T) {
	tests := []struct {
		name       string
		support    any
		setSupport bool
	}{
		{name: "absent"},
		{name: "unsupported", support: "unsupported", setSupport: true},
		{name: "empty", support: "", setSupport: true},
		{name: "null", support: nil, setSupport: true},
		{name: "wrong type", support: true, setSupport: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement["keyProtection"] = []string{"sync_fabric"}
			if test.setSupport {
				statement["multiDeviceCredentialSupport"] = test.support
			}

			assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P16, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P19MatcherProtectionCardinality(t *testing.T) {
	tests := []struct {
		name       string
		protection any
		details    any
		setDetails bool
		want       conformance.Status
	}{
		{name: "minimum level", protection: []string{"on_chip"}, details: validMetadataUserVerificationDetails(), setDetails: true, want: conformance.StatusPassed},
		{name: "one per method", protection: []string{"software", "tee", "on_chip", "on_chip"}, details: validMetadataUserVerificationDetails(), setDetails: true, want: conformance.StatusPassed},
		{name: "same level per method", protection: []string{"tee", "tee", "tee", "tee"}, details: validMetadataUserVerificationDetails(), setDetails: true, want: conformance.StatusPassed},
		{name: "minimum without details", protection: []string{"tee"}, want: conformance.StatusPassed},
		{name: "empty", protection: []string{}, details: validMetadataUserVerificationDetails(), setDetails: true, want: conformance.StatusFailed},
		{name: "null", protection: nil, details: validMetadataUserVerificationDetails(), setDetails: true, want: conformance.StatusFailed},
		{name: "wrong type", protection: "tee", details: validMetadataUserVerificationDetails(), setDetails: true, want: conformance.StatusFailed},
		{name: "unregistered", protection: []string{"reserved"}, details: validMetadataUserVerificationDetails(), setDetails: true, want: conformance.StatusFailed},
		{name: "cardinality mismatch", protection: []string{"software", "tee"}, details: validMetadataUserVerificationDetails(), setDetails: true, want: conformance.StatusFailed},
		{name: "multiple without details", protection: []string{"software", "tee"}, want: conformance.StatusFailed},
		{name: "null details", protection: []string{"tee"}, details: nil, setDetails: true, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement["matcherProtection"] = test.protection
			if test.setDetails {
				statement["userVerificationDetails"] = test.details
			} else {
				delete(statement, "userVerificationDetails")
			}

			assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P19, test.want)
		})
	}
}

func TestMetadataStmt1P19CountsMethodsInsideANDGroups(t *testing.T) {
	details := []any{
		[]any{
			map[string]any{"userVerificationMethod": "fingerprint_internal"},
			map[string]any{"userVerificationMethod": "voiceprint_internal"},
		},
		[]any{map[string]any{"userVerificationMethod": "passcode_internal"}},
	}

	statement := validMetadataP15ThroughP24Statement()
	statement["userVerificationDetails"] = details
	statement["matcherProtection"] = []string{"on_chip", "tee", "software"}
	assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P19, conformance.StatusPassed)

	statement["matcherProtection"] = []string{"on_chip", "tee"}
	assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P19, conformance.StatusFailed)
}

func TestMetadataStmt1P20CryptoStrengthRanges(t *testing.T) {
	tests := []struct {
		name     string
		strength any
		want     conformance.Status
	}{
		{name: "one", strength: 1, want: conformance.StatusPassed},
		{name: "maximum", strength: 65535, want: conformance.StatusPassed},
		{name: "zero", strength: 0, want: conformance.StatusFailed},
		{name: "negative", strength: -1, want: conformance.StatusFailed},
		{name: "overflow", strength: 65536, want: conformance.StatusFailed},
		{name: "fractional", strength: 1.5, want: conformance.StatusFailed},
		{name: "string", strength: "128", want: conformance.StatusFailed},
		{name: "null", strength: nil, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement["cryptoStrength"] = test.strength

			assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P20, test.want)
		})
	}
}

func TestMetadataStmt1P22AttachmentHintCombinations(t *testing.T) {
	pass := [][]string{
		{"internal"},
		{"wired"},
		{"nfc"},
		{"ready"},
		{"external", "ready"},
		{"smart-card"},
		{"external", "wired"},
		{"external", "wired", "smart-card"},
	}
	for _, hints := range pass {
		statement := validMetadataP15ThroughP24Statement()
		statement["attachmentHint"] = hints

		assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P22, conformance.StatusPassed)
	}

	fail := []any{
		nil,
		"external",
		[]string{},
		[]string{"reserved"},
		[]string{"wired", "wired"},
		[]string{"internal", "wired"},
		[]string{"external"},
	}
	for _, hints := range fail {
		statement := validMetadataP15ThroughP24Statement()
		statement["attachmentHint"] = hints

		assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P22, conformance.StatusFailed)
	}

	statement := validMetadataP15ThroughP24Statement()
	delete(statement, "attachmentHint")
	assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P22, conformance.StatusFailed)
}

func TestMetadataStmt1P24TransactionConfirmationDisplay(t *testing.T) {
	tests := []struct {
		name       string
		extensions any
		display    any
		want       conformance.Status
	}{
		{name: "unsupported empty", extensions: []string{}, display: []string{}, want: conformance.StatusPassed},
		{name: "unrelated extension empty", extensions: []string{"hmac-secret"}, display: []string{}, want: conformance.StatusPassed},
		{name: "simple display without P-25 content type", extensions: []string{"txAuthSimple"}, display: []string{"any", "hardware", "remote"}, want: conformance.StatusPassed},
		{name: "generic display without P-25 content type", extensions: []string{"txAuthGeneric"}, display: []string{"any", "tee"}, want: conformance.StatusPassed},
		{name: "supported empty", extensions: []string{"txAuthSimple"}, display: []string{}, want: conformance.StatusFailed},
		{name: "unsupported nonempty", extensions: []string{}, display: []string{"any"}, want: conformance.StatusFailed},
		{name: "missing any", extensions: []string{"txAuthSimple"}, display: []string{"hardware"}, want: conformance.StatusFailed},
		{name: "exclusive implementations", extensions: []string{"txAuthSimple"}, display: []string{"any", "tee", "hardware"}, want: conformance.StatusFailed},
		{name: "duplicate", extensions: []string{"txAuthSimple"}, display: []string{"any", "any"}, want: conformance.StatusFailed},
		{name: "unregistered", extensions: []string{"txAuthSimple"}, display: []string{"any", "vendor_display"}, want: conformance.StatusFailed},
		{name: "null display", extensions: []string{"txAuthSimple"}, display: nil, want: conformance.StatusFailed},
		{name: "wrong display type", extensions: []string{"txAuthSimple"}, display: "any", want: conformance.StatusFailed},
		{name: "null extensions", extensions: nil, display: []string{}, want: conformance.StatusFailed},
		{name: "wrong extensions type", extensions: "txAuthSimple", display: []string{}, want: conformance.StatusFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP15ThroughP24Statement()
			statement["authenticatorGetInfo"] = map[string]any{"extensions": test.extensions}
			statement["tcDisplay"] = test.display

			assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P24, test.want)
		})
	}

	statement := validMetadataP15ThroughP24Statement()
	delete(statement, "tcDisplay")
	assertMetadataP15ThroughP24Status(t, statement, TestIDMetadataStmt1P24, conformance.StatusFailed)
}

func TestMetadataStmt1P24RejectsNullAuthenticatorGetInfo(t *testing.T) {
	statement := validMetadataP15ThroughP24Statement()
	statement["authenticatorGetInfo"] = nil

	result := runMetadataStatementP15ThroughP24Tests(
		t,
		metadataStatementJSON(t, statement),
		TestIDMetadataStmt1P24,
	)
	step := result.Tests[0].Steps[0]
	if result.Status != conformance.StatusFailed || step.Status != conformance.StatusFailed ||
		!strings.Contains(step.Message, "authenticatorGetInfo must not be null") {
		t.Fatalf("result = %#v, want null authenticatorGetInfo failure", result)
	}
}

func runMetadataStatementP15ThroughP24Tests(
	t *testing.T,
	statementJSON string,
	selected ...conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	tests := metadataStatementTestsP15ThroughP24(Metadata{StatementJSON: statementJSON})
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
		ID:    "test.metadata-statement-p15-p24",
		Name:  "Metadata statement P-15 through P-24 tests",
		Tests: tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertMetadataP15ThroughP24Status(
	t *testing.T,
	statement map[string]any,
	id conformance.TestID,
	want conformance.Status,
) {
	t.Helper()

	result := runMetadataStatementP15ThroughP24Tests(t, metadataStatementJSON(t, statement), id)
	if result.Status != want || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %q", result, want)
	}
}

func validMetadataP15ThroughP24Statement() map[string]any {
	statement := validMetadataStatement()
	statement["userVerificationDetails"] = validMetadataUserVerificationDetails()
	statement["keyProtection"] = []string{"hardware", "tee"}
	statement["isKeyRestricted"] = false
	statement["isFreshUserVerificationRequired"] = false
	statement["matcherProtection"] = []string{"tee"}
	statement["cryptoStrength"] = 128
	statement["attachmentHint"] = []string{"external", "wired"}
	statement["tcDisplay"] = []string{}

	return statement
}

func validMetadataUserVerificationDetails() []any {
	return []any{
		[]any{
			map[string]any{
				"userVerificationMethod": "passcode_external",
				"caDesc": map[string]any{
					"base":          10,
					"minLength":     4,
					"maxRetries":    0,
					"blockSlowdown": 0,
				},
			},
		},
		[]any{
			map[string]any{
				"userVerificationMethod": "fingerprint_internal",
				"baDesc": map[string]any{
					"selfAttestedFRR": 0.01,
					"selfAttestedFAR": 0.001,
					"iAPARThreshold":  0.07,
					"maxTemplates":    5,
					"maxRetries":      0,
					"blockSlowdown":   0,
				},
			},
		},
		[]any{
			map[string]any{
				"userVerificationMethod": "pattern_internal",
				"paDesc": map[string]any{
					"minComplexity": 1624,
					"maxRetries":    0,
					"blockSlowdown": 0,
				},
			},
		},
		[]any{map[string]any{"userVerificationMethod": "presence_internal"}},
	}
}
