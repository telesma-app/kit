package ctap23

import (
	"bytes"
	"context"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const (
	credBlobSourcePath = "tests/CTAP2/Protocol/Extensions/credBlob.js"
	credBlobP2RPID     = "cred-blob-p-2.ctap23-conformance.example"
	credBlobP3RPID     = "cred-blob-p-3.ctap23-conformance.example"

	TestIDCredBlobP1 conformance.TestID = "fido.ctap2.3.cred-blob.p-1"
	TestIDCredBlobP2 conformance.TestID = "fido.ctap2.3.cred-blob.p-2"
	TestIDCredBlobP3 conformance.TestID = "fido.ctap2.3.cred-blob.p-3"
)

func credBlobTests(config Config) []conformance.Test {
	featureReference := credBlobFeatureReference()
	behaviorReference := credBlobBehaviorReference()

	return []conformance.Test{
		credentialExtensionTest(credentialExtensionCase{
			id:          TestIDCredBlobP1,
			marker:      "P-1",
			sourcePath:  credBlobSourcePath,
			name:        "GetInfo reports a usable credential-blob capacity",
			description: "Requires raw maxCredBlobLength to be a present canonical unsigned integer of at least 32 bytes and validates the credProtect dependency",
			references:  []conformance.RequirementRef{featureReference},
			applicability: func(_ map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
				return requireCredentialExtension(info, string(extension.ExtensionIdentifierCredentialBlob), config.Featureful)
			},
			run: func(ctx context.Context, test *conformance.TestContext) error {
				fields, info, err := readGetInfo(ctx, test.CBOR())
				if err != nil {
					return err
				}

				_, err = requireCredBlobCapacity(fields, info, config)

				return err
			},
		}),
		credentialExtensionTest(credentialExtensionCase{
			id:          TestIDCredBlobP2,
			marker:      "P-2",
			sourcePath:  credBlobSourcePath,
			name:        "Store and retrieve an exact credential blob",
			description: "Creates a discoverable credential with a deterministic in-range blob, requires the exact true creation output, and retrieves the exact byte string",
			references:  []conformance.RequirementRef{featureReference, behaviorReference},
			destructive: true,
			applicability: func(fields map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
				_, err := requireCredBlobCapacity(fields, info, config)
				if err != nil {
					return err
				}

				return requireCredBlobResidentKeys(fields)
			},
			run: func(ctx context.Context, test *conformance.TestContext) error {
				return runCredBlobP2(ctx, test, config)
			},
		}),
		credentialExtensionTest(credentialExtensionCase{
			id:          TestIDCredBlobP3,
			marker:      "P-3",
			sourcePath:  credBlobSourcePath,
			name:        "An omitted credential blob is returned as an empty byte string",
			description: "Requires the creation output target to be absent, then distinguishes the required zero-length byte-string authentication output from absence",
			references:  []conformance.RequirementRef{featureReference, behaviorReference},
			destructive: true,
			applicability: func(fields map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
				_, err := requireCredBlobCapacity(fields, info, config)
				if err != nil {
					return err
				}

				return requireCredBlobResidentKeys(fields)
			},
			run: func(ctx context.Context, test *conformance.TestContext) error {
				return runCredBlobP3(ctx, test, config)
			},
		}),
	}
}

func requireCredBlobCapacity(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
) (uint, error) {
	if err := requireCredentialExtension(info, string(extension.ExtensionIdentifierCredentialBlob), config.Featureful); err != nil {
		return 0, err
	}
	if !slices.Contains(info.Extensions, extension.ExtensionIdentifierCredentialProtection) {
		return 0, conformance.Fail("credBlob is advertised without its required credProtect dependency")
	}
	raw, present := fields[15]
	if !present {
		return 0, conformance.Fail("GetInfo omits maxCredBlobLength while advertising credBlob")
	}
	if !hasCBORMajorType(raw, 0) {
		return 0, conformance.Fail("GetInfo maxCredBlobLength is not a CBOR unsigned integer")
	}
	var maximum uint
	if err := getInfoDecMode.Unmarshal(raw, &maximum); err != nil {
		return 0, conformance.Failf("invalid GetInfo maxCredBlobLength: %v", err)
	}
	if maximum < 32 {
		return 0, conformance.Failf("GetInfo maxCredBlobLength = %d, want at least 32", maximum)
	}

	return maximum, nil
}

func requireCredBlobResidentKeys(fields map[uint64]cbor.RawMessage) error {
	residentKeys, present, err := rawGetInfoOption(fields, protocol.OptionResidentKeys)
	if err != nil {
		return err
	}
	if !present || !residentKeys {
		return conformance.Skip("credBlob discoverable-credential cases require rk=true")
	}

	return nil
}

func runCredBlobP2(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) error {
	fixture, err := prepareCredentialExtensionFixture(ctx, test, config, credBlobP2RPID)
	if err != nil {
		return err
	}
	defer fixture.clear()

	blob := bytes.Repeat([]byte{0x42}, 32)
	defer clear(blob)
	request := fixture.make.Request
	request.Extensions.CreateCredBlobInput.CredBlob = blob
	request.Options = map[protocol.Option]bool{protocol.OptionResidentKeys: true}
	created, err := fixture.make.makeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return err
	}
	defer clearMakeCredentialResponse(&created)
	if err := requireCredBlobCreateOutput(created.AuthDataRaw, true); err != nil {
		return err
	}
	if err := fixture.rememberCredential(created); err != nil {
		return err
	}
	fixture.make.clear()

	asserted, err := fixture.getAssertion(
		ctx,
		protocol.GetExtensionInputs{GetCredBlobInput: protocol.GetCredBlobInput{CredBlob: true}},
		nil,
		true,
		true,
	)
	if err != nil {
		return err
	}
	defer asserted.clear()

	return requireCredBlobGetOutput(asserted.Response.AuthDataRaw, blob)
}

func runCredBlobP3(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) error {
	fixture, err := prepareCredentialExtensionFixture(ctx, test, config, credBlobP3RPID)
	if err != nil {
		return err
	}
	defer fixture.clear()

	request := fixture.make.Request
	request.Options = map[protocol.Option]bool{protocol.OptionResidentKeys: true}
	created, err := fixture.make.makeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return err
	}
	defer clearMakeCredentialResponse(&created)
	if err := requireCredBlobCreateOutput(created.AuthDataRaw, false); err != nil {
		return err
	}
	if err := fixture.rememberCredential(created); err != nil {
		return err
	}
	fixture.make.clear()

	asserted, err := fixture.getAssertion(
		ctx,
		protocol.GetExtensionInputs{GetCredBlobInput: protocol.GetCredBlobInput{CredBlob: true}},
		nil,
		true,
		true,
	)
	if err != nil {
		return err
	}
	defer asserted.clear()

	return requireCredBlobGetOutput(asserted.Response.AuthDataRaw, []byte{})
}

func requireCredBlobCreateOutput(authData []byte, expected bool) error {
	view, err := observeMakeCredentialAuthDataExtensions(authData)
	if err != nil {
		return err
	}
	defer view.clearValues()
	raw, present := view.Values[string(extension.ExtensionIdentifierCredentialBlob)]
	if !expected {
		if present {
			return conformance.Fail("authenticatorMakeCredential returned unsolicited credBlob output")
		}

		return nil
	}
	if !view.Included || !present {
		return conformance.Fail("authenticatorMakeCredential extension output omits credBlob")
	}
	if !bytes.Equal(raw, []byte{0xf5}) {
		return conformance.Fail("authenticatorMakeCredential credBlob output is not canonical true")
	}

	return nil
}

func requireCredBlobGetOutput(authData []byte, expected []byte) error {
	view, err := observeGetAssertionAuthDataExtensions(authData)
	if err != nil {
		return err
	}
	defer view.clearValues()
	if !view.Included {
		return conformance.Fail("authenticatorGetAssertion authData omits extension data")
	}
	raw, present := view.Values[string(extension.ExtensionIdentifierCredentialBlob)]
	if !present {
		return conformance.Fail("authenticatorGetAssertion extension output omits credBlob")
	}
	if !hasCBORMajorType(raw, 2) {
		return conformance.Fail("authenticatorGetAssertion credBlob output is not a CBOR byte string")
	}
	var actual []byte
	if err := getInfoDecMode.Unmarshal(raw, &actual); err != nil {
		clear(actual)

		return conformance.Failf("invalid authenticatorGetAssertion credBlob output: %v", err)
	}
	defer clear(actual)
	if !bytes.Equal(actual, expected) {
		return conformance.Fail("authenticatorGetAssertion credBlob output differs from the stored value")
	}

	return nil
}

func credBlobFeatureReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:12.2.1:credential-blob-feature-detection",
		Specification: conformance.SpecificationCTAP23,
		Section:       "12.2.1",
		Clause:        "credential-blob-feature-detection",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credBlob-extension",
		Level:         conformance.RequirementMust,
	}
}

func credBlobBehaviorReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:12.2:credential-blob-processing",
		Specification: conformance.SpecificationCTAP23,
		Section:       "12.2",
		Clause:        "credential-blob-processing",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credBlob-extension",
		Level:         conformance.RequirementMust,
	}
}
