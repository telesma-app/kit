package ctap23

import (
	"bytes"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
)

func TestUVMDefinitionMatchesPinnedSource(t *testing.T) {
	tests := uvmTests(Config{})
	if len(tests) != 1 {
		t.Fatalf("tests = %d, want 1", len(tests))
	}
	test := tests[0]
	if test.ID != TestIDUVMP1 || test.Source.Path != uvmSourcePath ||
		test.Source.Case != "P-1" || !test.Destructive || test.Run == nil ||
		len(test.References) != 6 || test.References[0].Section != "10.8" {
		t.Fatalf("test = %#v", test)
	}
}

func TestUVMCaseExecutesExactRawWireAndMetadataSubset(t *testing.T) {
	device := newCredentialExtensionTestDevice(t)
	config := device.config()
	config.Metadata.StatementJSON = `{
  "schema": 3,
  "userVerificationDetails": [[{"userVerificationMethod":"fingerprint_internal"}]],
  "keyProtection": ["hardware", "tee"],
  "matcherProtection": ["tee"]
}`
	device.uvmOutput = []any{
		[]any{
			uint64(registry.UserVerificationFingerprintInternal),
			uint64(registry.KeyProtectionTEE),
			uint64(registry.MatcherProtectionTEE),
		},
	}
	result := runCredentialExtensionTest(t, device, uvmTests(config)[0])
	requireCredentialExtensionPassed(t, result)

	if len(device.makeRecords) != 1 || len(device.getRecords) != 0 || len(device.tokenRequests) != 1 {
		t.Fatalf("Make/Get/tokens = %d/%d/%d, want 1/0/1", len(device.makeRecords), len(device.getRecords), len(device.tokenRequests))
	}
	record := device.makeRecords[0]
	if len(record.options) != 0 || !bytes.Equal(
		record.extensions[string(extension.ExtensionIdentifierUserVerificationMethod)],
		[]byte{0xf5},
	) {
		t.Fatalf("MakeCredential wire = %#v", record)
	}
	if device.tokenRequests[0].Permission != protocol.PermissionMakeCredential ||
		device.tokenRequests[0].RPID == "" {
		t.Fatalf("token scope = %#v", device.tokenRequests[0])
	}
	device.assertOwnedBuffersWiped(t)
}

func TestUVMRejectsInvalidOutputsAndMetadata(t *testing.T) {
	validEntry := func() []any {
		return []any{
			uint64(registry.UserVerificationFingerprintInternal),
			uint64(registry.KeyProtectionTEE),
			uint64(registry.MatcherProtectionTEE),
		}
	}
	for _, testCase := range []struct {
		name     string
		output   any
		metadata string
		omit     bool
	}{
		{name: "empty entries", output: []any{}},
		{name: "four entries", output: []any{validEntry(), validEntry(), validEntry(), validEntry()}},
		{name: "wrong tuple arity", output: []any{[]any{uint64(2), uint64(4)}}},
		{name: "negative method", output: []any{[]any{int64(-1), uint64(4), uint64(2)}}},
		{name: "method exceeds uint32", output: []any{[]any{uint64(1) << 32, uint64(4), uint64(2)}}},
		{name: "unknown method", output: []any{[]any{uint64(0x80000000), uint64(4), uint64(2)}}},
		{name: "key flag absent from metadata", output: []any{[]any{uint64(2), uint64(2), uint64(2)}}},
		{name: "unknown key flag", output: []any{[]any{uint64(2), uint64(0x8000), uint64(2)}}},
		{name: "matcher absent from metadata", output: []any{[]any{uint64(2), uint64(4), uint64(4)}}},
		{name: "unknown matcher", output: []any{[]any{uint64(2), uint64(4), uint64(8)}}},
		{name: "missing output", output: []any{validEntry()}, omit: true},
		{name: "missing metadata", output: []any{validEntry()}, metadata: `{"schema":3}`},
		{name: "invalid metadata method", output: []any{validEntry()}, metadata: `{
  "schema":3,
  "userVerificationDetails":[[{"userVerificationMethod":"unknown"}]],
  "keyProtection":["tee"],
  "matcherProtection":["tee"]
}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newCredentialExtensionTestDevice(t)
			device.uvmOutput = testCase.output
			if testCase.omit {
				device.omitCreateOutput = string(extension.ExtensionIdentifierUserVerificationMethod)
			}
			config := device.config()
			if testCase.metadata != "" {
				config.Metadata.StatementJSON = testCase.metadata
			}
			result := runCredentialExtensionTest(t, device, uvmTests(config)[0])
			if result.Status != conformance.StatusFailed && result.Status != conformance.StatusError {
				t.Fatalf("status = %s, want failed or environment error: %#v", result.Status, result.Tests)
			}
		})
	}
}

func TestUVMApplicabilityStopsBeforeMutation(t *testing.T) {
	device := newCredentialExtensionTestDevice(t)
	device.info.Extensions = []extension.ExtensionIdentifier{
		extension.ExtensionIdentifierCredentialProtection,
	}
	config := device.config()
	config.Featureful = false
	result := runCredentialExtensionTest(t, device, uvmTests(config)[0])
	if result.Status != conformance.StatusSkipped || device.resetCalls != 0 ||
		len(device.tokenRequests) != 0 {
		t.Fatalf("result/reset/tokens = %s/%d/%d, want skip/0/0", result.Status, device.resetCalls, len(device.tokenRequests))
	}
}
