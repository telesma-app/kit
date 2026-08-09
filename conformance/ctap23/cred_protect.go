package ctap23

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const (
	credProtectSourcePath = "tests/CTAP2/Protocol/Extensions/credProtect.js"

	TestIDCredProtectP1 conformance.TestID = "fido.ctap2.3.cred-protect.p-1"
	TestIDCredProtectP2 conformance.TestID = "fido.ctap2.3.cred-protect.p-2"
	TestIDCredProtectP3 conformance.TestID = "fido.ctap2.3.cred-protect.p-3"
	TestIDCredProtectP4 conformance.TestID = "fido.ctap2.3.cred-protect.p-4"
)

func credProtectTests(config Config) []conformance.Test {
	policyReference := credProtectPolicyReference()
	discoveryReference := credProtectDiscoveryReference()
	managementReference := credProtectManagementReference()

	definitions := []struct {
		id        conformance.TestID
		marker    string
		requested int
		name      string
	}{
		{TestIDCredProtectP1, "P-1", 1, "Credential protection level 1 permits silent use"},
		{TestIDCredProtectP2, "P-2", 2, "Credential protection level 2 requires an allowList for silent use"},
		{TestIDCredProtectP3, "P-3", 3, "Credential protection level 3 requires user verification"},
	}
	tests := make([]conformance.Test, 0, 4)
	for _, definition := range definitions {
		definition := definition
		tests = append(tests, credentialExtensionTest(credentialExtensionCase{
			id:          definition.id,
			marker:      definition.marker,
			sourcePath:  credProtectSourcePath,
			name:        definition.name,
			description: "Creates one credential with the requested credProtect policy, uses the returned effective policy, and checks exact allowList and discoverable silent-authentication behavior",
			references:  []conformance.RequirementRef{policyReference, discoveryReference},
			destructive: true,
			applicability: func(fields map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
				return credProtectApplicability(fields, info, config, false, true)
			},
			run: func(ctx context.Context, test *conformance.TestContext) error {
				return runCredProtectPolicy(ctx, test, config, definition.marker, definition.requested)
			},
		}))
	}

	tests = append(tests, credentialExtensionTest(credentialExtensionCase{
		id:          TestIDCredProtectP4,
		marker:      "P-4",
		sourcePath:  credProtectSourcePath,
		name:        "Credential management returns each effective credProtect policy",
		description: "Deterministically creates requested policies 1, 2, and 3 in independent lifecycles, then matches the exact credential ID and effective policy in credential enumeration",
		references:  []conformance.RequirementRef{policyReference, managementReference},
		destructive: true,
		applicability: func(fields map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
			return credProtectApplicability(fields, info, config, true, false)
		},
		run: func(ctx context.Context, test *conformance.TestContext) error {
			for requested := 1; requested <= 3; requested++ {
				if err := runCredProtectManagement(ctx, test, config, requested); err != nil {
					return err
				}
			}

			return nil
		},
	}))

	return tests
}

func credProtectApplicability(
	fields map[uint64]cbor.RawMessage,
	info protocol.AuthenticatorGetInfoResponse,
	config Config,
	requireManagement bool,
	requireSilent bool,
) error {
	if err := requireCredentialExtension(info, string(extension.ExtensionIdentifierCredentialProtection), config.Featureful); err != nil {
		return err
	}
	_, clientPINPresent, err := rawGetInfoOption(fields, protocol.OptionClientPIN)
	if err != nil {
		return err
	}
	_, uvPresent, err := rawGetInfoOption(fields, protocol.OptionUserVerification)
	if err != nil {
		return err
	}
	if !clientPINPresent && !uvPresent {
		return conformance.Fail("credProtect is advertised without any form of user verification")
	}
	if requireSilent {
		alwaysUV, _, err := rawGetInfoOption(fields, protocol.OptionAlwaysUv)
		if err != nil {
			return err
		}
		if alwaysUV {
			return conformance.Skip("silent credProtect behavior is not observable while alwaysUv is enabled")
		}
	}
	if !requireManagement {
		return nil
	}
	residentKeys, present, err := rawGetInfoOption(fields, protocol.OptionResidentKeys)
	if err != nil {
		return err
	}
	if !present || !residentKeys {
		return conformance.Skip("credProtect P-4 requires rk=true")
	}
	management, present, err := rawGetInfoOption(fields, protocol.OptionCredentialManagement)
	if err != nil {
		return err
	}
	if !present || !management {
		return conformance.Skip("credProtect P-4 requires credMgmt=true")
	}
	if !slices.Contains(info.PinUvAuthProtocols, protocol.PinUvAuthProtocolTwo) {
		return conformance.Skip("credProtect P-4 requires PIN/UV protocol 2 credential management")
	}

	return nil
}

func runCredProtectPolicy(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	marker string,
	requested int,
) error {
	rpID := fmt.Sprintf("cred-protect-%s.ctap23-conformance.example", marker)
	fixture, err := prepareCredentialExtensionFixture(ctx, test, config, rpID)
	if err != nil {
		return err
	}
	defer fixture.clear()

	discoverable := fixture.make.Info.Options[protocol.OptionResidentKeys]
	request := fixture.make.Request
	request.Extensions.CreateCredProtectInput.CredProtect = requested
	request.Options = map[protocol.Option]bool{protocol.OptionResidentKeys: discoverable}
	created, err := fixture.make.makeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return err
	}
	defer clearMakeCredentialResponse(&created)

	effective, err := requireCredProtectOutput(created.AuthDataRaw, requested)
	if err != nil {
		return err
	}
	if err := fixture.rememberCredential(created); err != nil {
		return err
	}
	fixture.make.clear()

	noPresence := map[protocol.Option]bool{protocol.OptionUserPresence: false}
	if effective == 3 {
		if err := fixture.expectGetAssertionError(ctx, noPresence, true); err != nil {
			return err
		}
	} else {
		asserted, err := fixture.getAssertion(ctx, protocol.GetExtensionInputs{}, noPresence, true, false)
		if err != nil {
			return err
		}
		defer asserted.clear()
		if !bytes.Equal(asserted.Response.Credential.ID, fixture.credentialID) {
			return conformance.Fail("allowList GetAssertion returned a different credential ID")
		}
	}

	if !discoverable {
		return nil
	}
	if effective == 1 {
		asserted, err := fixture.getAssertion(ctx, protocol.GetExtensionInputs{}, noPresence, false, false)
		if err != nil {
			return err
		}
		defer asserted.clear()
		if !bytes.Equal(asserted.Response.Credential.ID, fixture.credentialID) {
			return conformance.Fail("discoverable GetAssertion returned a different credential ID")
		}

		return nil
	}

	return fixture.expectGetAssertionError(ctx, noPresence, false)
}

func runCredProtectManagement(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	requested int,
) error {
	rpID := fmt.Sprintf("cred-protect-p-4-%d.ctap23-conformance.example", requested)
	fixture, err := prepareCredentialExtensionFixture(ctx, test, config, rpID)
	if err != nil {
		return err
	}
	defer fixture.clear()

	request := fixture.make.Request
	request.Extensions.CreateCredProtectInput.CredProtect = requested
	request.Options = map[protocol.Option]bool{protocol.OptionResidentKeys: true}
	created, err := fixture.make.makeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return err
	}
	defer clearMakeCredentialResponse(&created)

	effective, err := requireCredProtectOutput(created.AuthDataRaw, requested)
	if err != nil {
		return err
	}
	if err := fixture.rememberCredential(created); err != nil {
		return err
	}
	fixture.make.clear()

	result, err := fixture.enumerateCredential(ctx)
	if err != nil {
		return err
	}
	defer clearCredentialExtensionManagementResponse(&result)
	for field := range result.Fields {
		switch field {
		case 6, 7, 8, 9, 10, 11, 12:
		default:
			return conformance.Failf("credential enumeration response contains unexpected field 0x%02x", field)
		}
	}
	for _, field := range []uint64{6, 7, 8, 9, 10} {
		if _, present := result.Fields[field]; !present {
			return conformance.Failf("credential enumeration response omits field 0x%02x", field)
		}
	}
	if !hasCBORMajorType(result.Fields[10], 0) {
		return conformance.Fail("credential enumeration credProtect is not a CBOR unsigned integer")
	}
	if result.Response.TotalCredentials != 1 {
		return conformance.Failf("credential enumeration totalCredentials = %d, want 1", result.Response.TotalCredentials)
	}
	if !bytes.Equal(result.Response.CredentialID.ID, fixture.credentialID) {
		return conformance.Fail("credential enumeration returned a different credential ID")
	}
	if result.Response.CredProtect != uint(effective) {
		return conformance.Failf(
			"credential enumeration credProtect = %d, want effective value %d",
			result.Response.CredProtect,
			effective,
		)
	}

	return nil
}

func requireCredProtectOutput(authData []byte, requested int) (int, error) {
	view, err := observeMakeCredentialAuthDataExtensions(authData)
	if err != nil {
		return 0, err
	}
	defer view.clearValues()
	if !view.Included {
		return 0, conformance.Fail("authenticatorMakeCredential authData omits extension data")
	}
	raw, present := view.Values[string(extension.ExtensionIdentifierCredentialProtection)]
	if !present {
		return 0, conformance.Fail("authenticatorMakeCredential extension output omits credProtect")
	}
	if !hasCBORMajorType(raw, 0) {
		return 0, conformance.Fail("credProtect extension output is not a CBOR unsigned integer")
	}
	var effective uint
	if err := getInfoDecMode.Unmarshal(raw, &effective); err != nil {
		return 0, conformance.Failf("invalid credProtect extension output: %v", err)
	}
	if effective < uint(requested) || effective > 3 {
		return 0, conformance.Failf(
			"effective credProtect = %d, want a value from requested %d through 3",
			effective,
			requested,
		)
	}

	return int(effective), nil
}

func credProtectPolicyReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:12.1:credential-protection-policy",
		Specification: conformance.SpecificationCTAP23,
		Section:       "12.1",
		Clause:        "credential-protection-policy",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension",
		Level:         conformance.RequirementMust,
	}
}

func credProtectDiscoveryReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.2.2:credential-protection-discovery",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.2.2",
		Clause:        "credential-protection-discovery",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getAssertion-authnr-alg",
		Level:         conformance.RequirementMust,
	}
}

func credProtectManagementReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.8.4:enumerated-cred-protect",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.8.4",
		Clause:        "enumerated-cred-protect",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#enumeratingCredentials",
		Level:         conformance.RequirementMust,
	}
}
