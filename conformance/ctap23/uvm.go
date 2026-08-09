package ctap23

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
	mdsmodel "github.com/telesma-app/mds/model"
)

const uvmSourcePath = "tests/CTAP2/Protocol/Extensions/uvm.js"

const TestIDUVMP1 conformance.TestID = "fido.ctap2.3.uvm.p-1"

type uvmMetadata struct {
	methods           map[registry.UserVerificationMethod]struct{}
	keyProtection     registry.KeyProtection
	matcherProtection registry.MatcherProtection
}

type uvmEntry struct {
	method            registry.UserVerificationMethod
	keyProtection     registry.KeyProtection
	matcherProtection registry.MatcherProtection
}

func uvmTests(config Config) []conformance.Test {
	references := slices.Concat(
		[]conformance.RequirementRef{uvmExtensionReference()},
		metadataReferences("3.11", "user-verification-details", conformance.RequirementConstraint),
		metadataReferences("3.11", "key-and-matcher-protection", conformance.RequirementConstraint),
		[]conformance.RequirementRef{
			fidoRegistryReference("3.1", "user-verification-methods"),
			fidoRegistryReference("3.2", "key-protection-types"),
			fidoRegistryReference("3.3", "matcher-protection-types"),
		},
	)

	return []conformance.Test{credentialExtensionTest(credentialExtensionCase{
		id:          TestIDUVMP1,
		marker:      "P-1",
		sourcePath:  uvmSourcePath,
		name:        "Return metadata-consistent user-verification methods",
		description: "Sends the raw canonical uvm:true input without options and requires one through three exact unsigned triples whose registry values agree with metadata",
		references:  references,
		destructive: true,
		applicability: func(_ map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
			if err := requireCredentialExtension(info, string(extension.ExtensionIdentifierUserVerificationMethod), config.Featureful); err != nil {
				return err
			}
			_, err := parseUVMMetadata(config.Metadata.StatementJSON)

			return err
		},
		run: func(ctx context.Context, test *conformance.TestContext) error {
			metadata, err := parseUVMMetadata(config.Metadata.StatementJSON)
			if err != nil {
				return err
			}
			fixture, err := prepareCredentialExtensionFixture(
				ctx,
				test,
				config,
				"uvm-p-1.ctap23-conformance.example",
			)
			if err != nil {
				return err
			}
			defer fixture.clear()

			fields := fixture.make.rawFields()
			if _, present := fields[7]; present {
				clearCTAP2WireValue(fields)

				return conformance.Fail("baseline UVM MakeCredential request unexpectedly contains options")
			}
			fields[6] = map[string]any{string(extension.ExtensionIdentifierUserVerificationMethod): true}
			response, err := fixture.makeCredentialRaw(ctx, fields)
			if err != nil {
				return err
			}
			defer clearMakeCredentialResponse(&response)

			entries, err := requireUVMOutput(response.AuthDataRaw)
			if err != nil {
				return err
			}

			return validateUVMMetadata(entries, metadata)
		},
	})}
}

func parseUVMMetadata(statementJSON string) (uvmMetadata, error) {
	statement, err := parseMetadataStatement(statementJSON)
	if err != nil {
		return uvmMetadata{}, err
	}

	var rawAlternatives []json.RawMessage
	present, err := statement.field("userVerificationDetails", &rawAlternatives)
	if err != nil {
		return uvmMetadata{}, err
	}
	if !present || len(rawAlternatives) == 0 {
		return uvmMetadata{}, fmt.Errorf(
			"ctap23: metadata userVerificationDetails is required and must not be empty for UVM",
		)
	}
	methods := make(map[registry.UserVerificationMethod]struct{})
	for alternativeIndex, rawAlternative := range rawAlternatives {
		var rawDescriptors []json.RawMessage
		if err := json.Unmarshal(rawAlternative, &rawDescriptors); err != nil || len(rawDescriptors) == 0 {
			return uvmMetadata{}, fmt.Errorf(
				"ctap23: metadata userVerificationDetails alternative %d must be a nonempty array",
				alternativeIndex,
			)
		}
		for descriptorIndex, rawDescriptor := range rawDescriptors {
			document, err := mdsmodel.ParseMetadataStatementDocument(rawDescriptor)
			if err != nil {
				return uvmMetadata{}, fmt.Errorf(
					"ctap23: metadata userVerificationDetails descriptor %d/%d must be an object: %w",
					alternativeIndex,
					descriptorIndex,
					err,
				)
			}
			var name string
			present, err := document.DecodeField("userVerificationMethod", &name)
			if err != nil || !present || name == "" {
				return uvmMetadata{}, fmt.Errorf(
					"ctap23: metadata userVerificationDetails descriptor %d/%d requires a string userVerificationMethod",
					alternativeIndex,
					descriptorIndex,
				)
			}
			method, ok := registry.ParseUserVerificationMethod(name)
			if !ok || !method.ValidMetadata() {
				return uvmMetadata{}, fmt.Errorf(
					"ctap23: metadata userVerificationMethod %q is not one registered base method",
					name,
				)
			}
			methods[method] = struct{}{}
		}
	}

	var keyProtectionNames []string
	present, err = statement.field("keyProtection", &keyProtectionNames)
	if err != nil {
		return uvmMetadata{}, err
	}
	keyProtection, ok := registry.ParseKeyProtections(keyProtectionNames)
	if !present || !ok || !keyProtection.ValidMetadata() {
		return uvmMetadata{}, fmt.Errorf(
			"ctap23: metadata keyProtection must be a nonempty valid Registry 2.3 mask",
		)
	}

	var matcherProtectionNames []string
	present, err = statement.field("matcherProtection", &matcherProtectionNames)
	if err != nil {
		return uvmMetadata{}, err
	}
	matcherProtection, ok := registry.ParseMatcherProtections(matcherProtectionNames)
	if !present || !ok || !matcherProtection.ValidMetadata() {
		return uvmMetadata{}, fmt.Errorf(
			"ctap23: metadata matcherProtection must contain registered single-value protections",
		)
	}

	return uvmMetadata{
		methods:           methods,
		keyProtection:     keyProtection,
		matcherProtection: matcherProtection,
	}, nil
}

func requireUVMOutput(authData []byte) ([]uvmEntry, error) {
	view, err := observeMakeCredentialAuthDataExtensions(authData)
	if err != nil {
		return nil, err
	}
	defer view.clearValues()
	if !view.Included {
		return nil, conformance.Fail("authenticatorMakeCredential authData omits extension data")
	}
	raw, present := view.Values[string(extension.ExtensionIdentifierUserVerificationMethod)]
	if !present {
		return nil, conformance.Fail("authenticatorMakeCredential extension output omits uvm")
	}
	if !hasCBORMajorType(raw, 4) {
		return nil, conformance.Fail("uvm extension output is not a CBOR array")
	}
	var rawEntries []cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &rawEntries); err != nil {
		clearUVMRawMessages(rawEntries)

		return nil, conformance.Failf("invalid uvm extension output: %v", err)
	}
	defer clearUVMRawMessages(rawEntries)
	if len(rawEntries) < 1 || len(rawEntries) > 3 {
		return nil, conformance.Failf("uvm extension contains %d entries, want 1 through 3", len(rawEntries))
	}

	entries := make([]uvmEntry, len(rawEntries))
	for index, rawEntry := range rawEntries {
		if !hasCBORMajorType(rawEntry, 4) {
			return nil, conformance.Failf("uvm entry %d is not a CBOR array", index)
		}
		var values []cbor.RawMessage
		if err := getInfoDecMode.Unmarshal(rawEntry, &values); err != nil {
			clearUVMRawMessages(values)

			return nil, conformance.Failf("invalid uvm entry %d: %v", index, err)
		}
		if len(values) != 3 {
			clearUVMRawMessages(values)

			return nil, conformance.Failf("uvm entry %d contains %d values, want exactly 3", index, len(values))
		}
		method, err := decodeUVMUnsigned(values[0], math.MaxUint32, "userVerificationMethod")
		if err != nil {
			clearUVMRawMessages(values)

			return nil, err
		}
		keyProtection, err := decodeUVMUnsigned(values[1], math.MaxUint16, "keyProtectionType")
		if err != nil {
			clearUVMRawMessages(values)

			return nil, err
		}
		matcherProtection, err := decodeUVMUnsigned(values[2], math.MaxUint16, "matcherProtectionType")
		clearUVMRawMessages(values)
		if err != nil {
			return nil, err
		}
		entries[index] = uvmEntry{
			method:            registry.UserVerificationMethod(method),
			keyProtection:     registry.KeyProtection(keyProtection),
			matcherProtection: registry.MatcherProtection(matcherProtection),
		}
	}

	return entries, nil
}

func decodeUVMUnsigned(raw cbor.RawMessage, maximum uint64, name string) (uint64, error) {
	if !hasCBORMajorType(raw, 0) {
		return 0, conformance.Failf("uvm %s is not a CBOR unsigned integer", name)
	}
	var value uint64
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		return 0, conformance.Failf("invalid uvm %s: %v", name, err)
	}
	if value > maximum {
		return 0, conformance.Failf("uvm %s = 0x%x exceeds its %d-bit range", name, value, maximum)
	}

	return value, nil
}

func clearUVMRawMessages(values []cbor.RawMessage) {
	for index := range values {
		clear(values[index])
		values[index] = nil
	}
}

func validateUVMMetadata(entries []uvmEntry, metadata uvmMetadata) error {
	weakest := make(map[registry.UserVerificationMethod]registry.MatcherProtection)
	for index, entry := range entries {
		if !entry.method.ValidMetadata() {
			return conformance.Failf("uvm entry %d userVerificationMethod 0x%x is not a registered base method", index, entry.method)
		}
		if _, present := metadata.methods[entry.method]; !present {
			return conformance.Failf("uvm entry %d userVerificationMethod 0x%x is absent from metadata", index, entry.method)
		}
		if entry.keyProtection == 0 || !entry.keyProtection.Registered() {
			return conformance.Failf("uvm entry %d keyProtectionType 0x%x is not a registered mask", index, entry.keyProtection)
		}
		if entry.keyProtection&metadata.keyProtection != entry.keyProtection {
			return conformance.Failf("uvm entry %d keyProtectionType 0x%x contains a flag absent from metadata mask 0x%x", index, entry.keyProtection, metadata.keyProtection)
		}
		if !entry.matcherProtection.ValidMetadata() {
			return conformance.Failf("uvm entry %d matcherProtectionType 0x%x is not one registered value", index, entry.matcherProtection)
		}
		current, present := weakest[entry.method]
		if !present || entry.matcherProtection < current {
			weakest[entry.method] = entry.matcherProtection
		}
	}
	for method, protection := range weakest {
		if protection&metadata.matcherProtection == 0 {
			return conformance.Failf(
				"weakest matcherProtectionType 0x%x for userVerificationMethod 0x%x is absent from metadata",
				protection,
				method,
			)
		}
	}

	return nil
}

func uvmExtensionReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "webauthn-1:10.8:user-verification-method-extension",
		Specification: "webauthn-level-1",
		Section:       "10.8",
		Clause:        "user-verification-method-extension",
		URL:           "https://www.w3.org/TR/webauthn-1/#sctn-uvm-extension",
		Level:         conformance.RequirementMust,
	}
}
