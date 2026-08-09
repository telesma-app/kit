package ctap23

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/kit/conformance"
)

func TestMetadataStmt1P32ThroughP36SourceMapping(t *testing.T) {
	tests := metadataStatementTestsP32ThroughP36(Metadata{})
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{id: TestIDMetadataStmt1P32, marker: "P-32"},
		{id: TestIDMetadataStmt1P33, marker: "P-33"},
		{id: TestIDMetadataStmt1P34, marker: "P-34"},
		{id: TestIDMetadataStmt1P35, marker: "P-35"},
		{id: TestIDMetadataStmt1P36, marker: "P-36"},
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

func TestMetadataStmt1P32ThroughP36NormativeReferenceTargets(t *testing.T) {
	want := map[conformance.TestID][]string{
		TestIDMetadataStmt1P32: {
			"fido-metadata-statement-3.1.1-ps-20260105|3.13|authenticator-get-info-members|" + metadataStatementURL + "#sctn-type-agid",
			"fido-metadata-statement-3.1.1-ps-20260105|4|authenticatorGetInfo|" + metadataStatementURL + "#sctn-md-keys",
			"ctap-2.3-ps-20260226|6.4|authenticator-get-info|" + metadataCTAP23URL + "#authenticatorGetInfo",
			"fido-registry-2.3-ps-20260105|3.1|user-verification-methods|" + fidoRegistryURL + "#user-verification-methods",
			"fido-registry-2.3-ps-20260105|3.6.1|authentication-algorithms|" + fidoRegistryURL + "#authentication-algorithms",
		},
		TestIDMetadataStmt1P33: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|metadata-statement-members|" + metadataStatementURL + "#sctn-md-keys",
		},
		TestIDMetadataStmt1P34: {
			"fido-metadata-statement-3.1.1-ps-20260105|4|metadata-statement-members|" + metadataStatementURL + "#sctn-md-keys",
		},
		TestIDMetadataStmt1P35: {
			"fido-metadata-statement-3.1.1-ps-20260105|5.3|fido2-example|" + metadataStatementURL + "#sctn-fido2-example",
		},
		TestIDMetadataStmt1P36: {
			"fido-metadata-statement-3.1.1-ps-20260105|1|webidl-dictionary-members-not-null|" + metadataStatementURL + "#sctn-notation",
			"fido-metadata-statement-3.1.1-ps-20260105|4|legalHeader|" + metadataStatementURL + "#sctn-md-keys",
		},
	}

	for _, test := range metadataStatementTestsP32ThroughP36(Metadata{}) {
		got := make([]string, 0, len(test.References))
		for _, reference := range test.References {
			got = append(got, string(reference.Specification)+"|"+reference.Section+"|"+reference.Clause+"|"+reference.URL)
		}
		if !slices.Equal(got, want[test.ID]) {
			t.Errorf("test %q reference targets = %v, want %v", test.ID, got, want[test.ID])
		}
	}
}

func TestMetadataStmt1P32ThroughP36ExecutionShapeUsesNoHardware(t *testing.T) {
	result := runMetadataStatementP32ThroughP36Tests(
		t,
		metadataStatementJSON(t, validMetadataP32ThroughP36Statement()),
	)
	if result.Status != conformance.StatusPassed || len(result.Tests) != 5 {
		t.Fatalf("result = %#v, want five passed tests", result)
	}
	for _, test := range result.Tests {
		if test.Status != conformance.StatusPassed || len(test.Steps) != 1 {
			t.Fatalf("test = %#v, want one passed step", test)
		}
		step := test.Steps[0]
		if step.ID != conformance.StepID("metadata-statement."+strings.ToLower(test.Source.Case)) ||
			!slices.Equal(step.References, test.References) {
			t.Errorf("test %q step = %#v, want matching marker and references", test.ID, step)
		}
	}
}

func TestMetadataStmt1P32ValidatesPresenceAndCurrentGetInfoRules(t *testing.T) {
	assertMetadataP32ThroughP36Status(t, validMetadataP32ThroughP36Statement(), TestIDMetadataStmt1P32, conformance.StatusPassed)

	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		want   conformance.Status
	}{
		{
			name: "missing declaration",
			mutate: func(statement, _ map[string]any) {
				delete(statement, "authenticatorGetInfo")
			},
			want: conformance.StatusFailed,
		},
		{
			name: "null declaration",
			mutate: func(statement, _ map[string]any) {
				statement["authenticatorGetInfo"] = nil
			},
			want: conformance.StatusFailed,
		},
		{
			name: "unknown member",
			mutate: func(_, info map[string]any) {
				info["futureField"] = false
			},
			want: conformance.StatusFailed,
		},
		{
			name: "null list element",
			mutate: func(_, info map[string]any) {
				info["versions"] = []any{nil, "FIDO_2_3"}
			},
			want: conformance.StatusFailed,
		},
		{
			name: "present false force PIN change without protocols",
			mutate: func(_, info map[string]any) {
				info["forcePINChange"] = false
			},
			want: conformance.StatusPassed,
		},
		{
			name: "present true force PIN change without protocols",
			mutate: func(_, info map[string]any) {
				info["forcePINChange"] = true
			},
			want: conformance.StatusFailed,
		},
		{
			name: "algorithms absent",
			mutate: func(_, info map[string]any) {
				delete(info, "algorithms")
			},
			want: conformance.StatusPassed,
		},
		{
			name: "registry DER algorithm shares the COSE profile",
			mutate: func(statement, _ map[string]any) {
				statement["authenticationAlgorithms"] = []string{"secp256r1_ecdsa_sha256_der"}
			},
			want: conformance.StatusPassed,
		},
		{
			name: "duplicate GetInfo algorithm does not consume another metadata profile",
			mutate: func(statement, info map[string]any) {
				statement["authenticationAlgorithms"] = []string{
					"secp256r1_ecdsa_sha256_raw",
					"ed25519_eddsa_sha512_raw",
				}
				info["algorithms"] = []any{
					map[string]any{"type": "public-key", "alg": -7},
					map[string]any{"type": "public-key", "alg": -7},
				}
			},
			want: conformance.StatusFailed,
		},
		{
			name: "firmware version zero matches metadata",
			mutate: func(statement, info map[string]any) {
				statement["authenticatorVersion"] = 0
				info["firmwareVersion"] = 0
			},
			want: conformance.StatusPassed,
		},
		{
			name: "present zero maximum message size",
			mutate: func(_, info map[string]any) {
				info["maxMsgSize"] = 0
			},
			want: conformance.StatusFailed,
		},
		{
			name: "remaining credentials zero",
			mutate: func(_, info map[string]any) {
				info["remainingDiscoverableCredentials"] = 0
			},
			want: conformance.StatusPassed,
		},
		{
			name: "additional RP IDs zero",
			mutate: func(_, info map[string]any) {
				info["maxRPIDsForSetMinPINLength"] = 0
				info["pinUvAuthProtocols"] = []any{2}
				info["minPINLength"] = 4
				info["extensions"] = []string{"hmac-secret", "credProtect", "minPinLength"}
				info["options"] = map[string]bool{
					"authnrCfg":       true,
					"clientPin":       false,
					"pinUvAuthToken":  true,
					"setMinPINLength": true,
				}
				info["authenticatorConfigCommands"] = []any{3}
			},
			want: conformance.StatusPassed,
		},
		{
			name: "empty vendor command list",
			mutate: func(_, info map[string]any) {
				info["vendorPrototypeConfigCommands"] = []any{}
				info["options"] = map[string]bool{"authnrCfg": true}
				info["authenticatorConfigCommands"] = []any{255}
			},
			want: conformance.StatusPassed,
		},
		{
			name: "empty encrypted placeholders",
			mutate: func(_, info map[string]any) {
				info["encIdentifier"] = ""
				info["encCredStoreState"] = ""
			},
			want: conformance.StatusPassed,
		},
		{
			name: "nonempty encrypted identifier",
			mutate: func(_, info map[string]any) {
				info["encIdentifier"] = "AA=="
			},
			want: conformance.StatusFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP32ThroughP36Statement()
			info, _ := statement["authenticatorGetInfo"].(map[string]any)
			test.mutate(statement, info)

			assertMetadataP32ThroughP36Status(t, statement, TestIDMetadataStmt1P32, test.want)
		})
	}
}

func TestMetadataStmt1P32CrossFieldBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{
			name: "AAGUID differs",
			mutate: func(_, info map[string]any) {
				info["aaguid"] = "ffeeddccbbaa99887766554433221100"
			},
		},
		{
			name: "version duplicated",
			mutate: func(_, info map[string]any) {
				info["versions"] = []string{"FIDO_2_3", "FIDO_2_3"}
			},
		},
		{
			name: "version missing from UPV",
			mutate: func(_, info map[string]any) {
				info["versions"] = []string{"FIDO_2_1", "FIDO_2_3"}
			},
		},
		{
			name: "algorithm differs",
			mutate: func(_, info map[string]any) {
				info["algorithms"] = []any{map[string]any{"type": "public-key", "alg": -257}}
			},
		},
		{
			name: "algorithm contains unknown member",
			mutate: func(_, info map[string]any) {
				info["algorithms"] = []any{map[string]any{"type": "public-key", "alg": -7, "extra": false}}
			},
		},
		{
			name: "firmware differs",
			mutate: func(_, info map[string]any) {
				info["firmwareVersion"] = 8
			},
		},
		{
			name: "UV modality absent from details",
			mutate: func(_, info map[string]any) {
				info["uvModality"] = 2
			},
		},
		{
			name: "UV modality exceeds registry mask",
			mutate: func(_, info map[string]any) {
				info["uvModality"] = uint64(1)<<32 | 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP32ThroughP36Statement()
			info := statement["authenticatorGetInfo"].(map[string]any)
			test.mutate(statement, info)

			assertMetadataP32ThroughP36Status(t, statement, TestIDMetadataStmt1P32, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P33RejectsEveryDeprecatedFieldByPresence(t *testing.T) {
	for _, name := range []string{
		"assertionScheme",
		"authenticationAlgorithm",
		"publicKeyAlgAndEncoding",
		"operatingEnv",
		"isSecondFactorOnly",
	} {
		t.Run(name, func(t *testing.T) {
			statement := validMetadataP32ThroughP36Statement()
			statement[name] = nil

			assertMetadataP32ThroughP36Status(t, statement, TestIDMetadataStmt1P33, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P34UsesCurrentMetadataStatementMembers(t *testing.T) {
	statement := validMetadataP32ThroughP36Statement()
	statement["cxConfigURL"] = "https://example.com/cx"
	assertMetadataP32ThroughP36Status(t, statement, TestIDMetadataStmt1P34, conformance.StatusPassed)

	for _, name := range []string{"cxpConfigURL", "unknownMember"} {
		t.Run(name, func(t *testing.T) {
			statement := validMetadataP32ThroughP36Statement()
			statement[name] = false

			assertMetadataP32ThroughP36Status(t, statement, TestIDMetadataStmt1P34, conformance.StatusFailed)
		})
	}
}

func TestMetadataStmt1P35RejectsFIDO2ExampleValues(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "AAGUID",
			mutate: func(statement map[string]any) {
				statement["aaguid"] = metadataSampleAAGUID
			},
		},
		{
			name: "description",
			mutate: func(statement map[string]any) {
				statement["description"] = metadataSampleDescription
			},
		},
		{
			name: "icon",
			mutate: func(statement map[string]any) {
				statement["icon"] = metadataFIDO2ExampleIcon
			},
		},
		{
			name: "root certificate",
			mutate: func(statement map[string]any) {
				statement["attestationRootCertificates"] = []string{metadataFIDO2ExampleRootCertificate}
			},
		},
	}

	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP32ThroughP36Statement()
			test.mutate(statement)

			assertMetadataP32ThroughP36Status(t, statement, TestIDMetadataStmt1P35, conformance.StatusFailed)
		})
	}

	statement := validMetadataP32ThroughP36Statement()
	delete(statement, "icon")
	statement["attestationRootCertificates"] = []string{}
	assertMetadataP32ThroughP36Status(t, statement, TestIDMetadataStmt1P35, conformance.StatusPassed)
}

func TestMetadataStmt1P36UsesCurrentLegalHeaderRule(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		set   bool
		want  conformance.Status
	}{
		{
			name:  "historical MDS3 sentence",
			value: "Submission of this statement and retrieval and use of this statement indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/.",
			set:   true,
			want:  conformance.StatusPassed,
		},
		{name: "current specification example", value: "https://fidoalliance.org/metadata/metadata-statement-legal-header/", set: true, want: conformance.StatusPassed},
		{name: "other agreement indication", value: "Vendor accepts the applicable MDS agreement", set: true, want: conformance.StatusPassed},
		{name: "missing", want: conformance.StatusFailed},
		{name: "null", value: nil, set: true, want: conformance.StatusFailed},
		{name: "empty", value: "", set: true, want: conformance.StatusFailed},
		{name: "wrong type", value: false, set: true, want: conformance.StatusFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			statement := validMetadataP32ThroughP36Statement()
			if test.set {
				statement["legalHeader"] = test.value
			} else {
				delete(statement, "legalHeader")
			}

			assertMetadataP32ThroughP36Status(t, statement, TestIDMetadataStmt1P36, test.want)
		})
	}
}

func TestMetadataStmt1P32ThroughP36MalformedDocumentIsError(t *testing.T) {
	result := runMetadataStatementP32ThroughP36Tests(t, `{"authenticatorGetInfo":{}} trailing`, TestIDMetadataStmt1P32)
	if result.Status != conformance.StatusError || result.Tests[0].Status != conformance.StatusError {
		t.Fatalf("result = %#v, want error", result)
	}
}

func runMetadataStatementP32ThroughP36Tests(
	t *testing.T,
	statementJSON string,
	selected ...conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	tests := metadataStatementTestsP32ThroughP36(Metadata{StatementJSON: statementJSON})
	if len(selected) != 0 {
		tests = slices.DeleteFunc(tests, func(test conformance.Test) bool {
			return !slices.Contains(selected, test.ID)
		})
	}
	if len(tests) == 0 {
		t.Fatalf("no metadata tests selected for %v", selected)
	}

	transport := newScriptedCBORTransport(t)
	runner, err := conformance.NewRunner(transport)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), conformance.Suite{
		ID:    "test.metadata-statement-p32-p36",
		Name:  "Metadata statement P-32 through P-36 tests",
		Tests: tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertMetadataP32ThroughP36Status(
	t *testing.T,
	statement map[string]any,
	id conformance.TestID,
	want conformance.Status,
) {
	t.Helper()

	result := runMetadataStatementP32ThroughP36Tests(t, metadataStatementJSON(t, statement), id)
	if result.Status != want || result.Tests[0].Status != want {
		step := result.Tests[0].Steps[0]
		t.Fatalf("result = (%q, %q, %q), want %q", result.Status, result.Tests[0].Status, step.Message, want)
	}
}

func validMetadataP32ThroughP36Statement() map[string]any {
	statement := validMetadataP25ThroughP31Statement()
	statement["legalHeader"] = "Vendor accepts the applicable MDS agreement"
	statement["aaguid"] = "00112233-4455-6677-8899-aabbccddeeff"
	statement["authenticatorVersion"] = 7
	statement["authenticationAlgorithms"] = []string{"secp256r1_ecdsa_sha256_raw"}
	statement["userVerificationDetails"] = []any{
		[]any{map[string]any{"userVerificationMethod": "presence_internal"}},
	}
	statement["authenticatorGetInfo"] = map[string]any{
		"versions":   []string{"FIDO_2_3"},
		"extensions": []string{"hmac-secret"},
		"aaguid":     "00112233445566778899aabbccddeeff",
		"algorithms": []any{
			map[string]any{"type": "public-key", "alg": -7},
		},
		"firmwareVersion": 7,
	}

	return statement
}

const metadataFIDO2ExampleIcon = "data:image/png;base64,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" +
	"HSD7RkTyihogAAAABJRU5ErkJggg=="

const metadataFIDO2ExampleRootCertificate = "MIICPTCCAeOgAwIBAgIJAOuexvU3Oy2wMAoGCCqGSM49BAMCMHsxIDAeBgNVBAMMF1NhbXBsZSBBdHRlc3RhdGlvbiBSb290MRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMREwDwYDVQQLDAhVQUYgVFdHLDESMBAGA1UEBwwJUGFsbyBBbHRvMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwHhcNMTQwNjE4MTMzMzMyWhcNNDExMTAzMTMzMzMyWjB7MSAwHgYDVQQDDBdTYW1wbGUgQXR0ZXN0YXRpb24gUm9vdDEWMBQGA1UECgwNRklETyBBbGxpYW5jZTERMA8GA1UECwwIVUFGIFRXRywxEjAQBgNVBAcMCVBhbG8gQWx0bzELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH8hv2D0HXa59/BmpQ7RZehL/FMGzFd1QBg9vAUpOZ3ajnuQ94PR7aMzH33nUSBr8fHYDrqOBb58pxGqHJRyX/6NQME4wHQYDVR0OBBYEFPoHA3CLhxFbC0It7zE4w8hk5EJ/MB8GA1UdIwQYMBaAFPoHA3CLhxFbC0It7zE4w8hk5EJ/MAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ06QSXt9ihIbEKYKIjsPkriVdLIgtfsbDSu7ErJfzr4AiBqoYCZf0+zI55aQeAHjIzA9Xm63rruAxBZ9ps9z2XNlQ=="
