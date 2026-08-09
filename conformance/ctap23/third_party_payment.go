package ctap23

import (
	"bytes"
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

const thirdPartyPaymentSourcePath = "tests/CTAP2/Protocol/Extensions/thirdPartyPayment.js"

const (
	TestIDThirdPartyPaymentP1 conformance.TestID = "fido.ctap2.3.third-party-payment.p-1"
	TestIDThirdPartyPaymentP2 conformance.TestID = "fido.ctap2.3.third-party-payment.p-2"
	TestIDThirdPartyPaymentF1 conformance.TestID = "fido.ctap2.3.third-party-payment.f-1"
)

func thirdPartyPaymentTests(config Config) []conformance.Test {
	reference := thirdPartyPaymentReference()
	definitions := []struct {
		id            conformance.TestID
		marker        string
		discoverable  bool
		createEnabled bool
		name          string
	}{
		{TestIDThirdPartyPaymentP1, "P-1", true, true, "Return true for a discoverable third-party-payment credential"},
		{TestIDThirdPartyPaymentP2, "P-2", false, true, "Return true for a non-discoverable third-party-payment credential"},
		{TestIDThirdPartyPaymentF1, "F-1", false, false, "Return false when third-party payment was not enabled"},
	}

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		definition := definition
		tests = append(tests, credentialExtensionTest(credentialExtensionCase{
			id:          definition.id,
			marker:      definition.marker,
			sourcePath:  thirdPartyPaymentSourcePath,
			name:        definition.name,
			description: "Requires exact boolean extension input/output semantics, no MakeCredential output, a fresh RP-scoped GetAssertion authorization, and an allowListed credential",
			references:  []conformance.RequirementRef{reference},
			destructive: true,
			applicability: func(fields map[uint64]cbor.RawMessage, info protocol.AuthenticatorGetInfoResponse) error {
				if err := requireCredentialExtension(info, string(extension.ExtensionIdentifierThirdPartyPayment), config.Featureful); err != nil {
					return err
				}
				if !definition.discoverable {
					return nil
				}
				residentKeys, present, err := rawGetInfoOption(fields, protocol.OptionResidentKeys)
				if err != nil {
					return err
				}
				if !present || !residentKeys {
					return conformance.Skip("thirdPartyPayment P-1 requires rk=true")
				}

				return nil
			},
			run: func(ctx context.Context, test *conformance.TestContext) error {
				return runThirdPartyPayment(ctx, test, config, definition)
			},
		}))
	}

	return tests
}

func runThirdPartyPayment(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	definition struct {
		id            conformance.TestID
		marker        string
		discoverable  bool
		createEnabled bool
		name          string
	},
) error {
	rpID := fmt.Sprintf("third-party-payment-%s.ctap23-conformance.example", definition.marker)
	fixture, err := prepareCredentialExtensionFixture(ctx, test, config, rpID)
	if err != nil {
		return err
	}
	defer fixture.clear()

	request := fixture.make.Request
	request.Options = map[protocol.Option]bool{protocol.OptionResidentKeys: definition.discoverable}
	if definition.createEnabled {
		request.Extensions.CreateThirdPartyPaymentInput.ThirdPartyPayment = true
	}
	created, err := fixture.make.makeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return err
	}
	defer clearMakeCredentialResponse(&created)
	if err := rejectThirdPartyPaymentCreateOutput(created.AuthDataRaw); err != nil {
		return err
	}
	if err := fixture.rememberCredential(created); err != nil {
		return err
	}
	fixture.make.clear()

	asserted, err := fixture.getAssertion(
		ctx,
		protocol.GetExtensionInputs{
			GetThirdPartyPaymentInput: protocol.GetThirdPartyPaymentInput{ThirdPartyPayment: true},
		},
		nil,
		true,
		true,
	)
	if err != nil {
		return err
	}
	defer asserted.clear()

	return requireThirdPartyPaymentGetOutput(
		asserted.Response.AuthDataRaw,
		definition.createEnabled,
	)
}

func rejectThirdPartyPaymentCreateOutput(authData []byte) error {
	view, err := observeMakeCredentialAuthDataExtensions(authData)
	if err != nil {
		return err
	}
	defer view.clearValues()
	if _, present := view.Values[string(extension.ExtensionIdentifierThirdPartyPayment)]; present {
		return conformance.Fail("authenticatorMakeCredential returned an unsolicited thirdPartyPayment output")
	}

	return nil
}

func requireThirdPartyPaymentGetOutput(authData []byte, expected bool) error {
	view, err := observeGetAssertionAuthDataExtensions(authData)
	if err != nil {
		return err
	}
	defer view.clearValues()
	if !view.Included {
		return conformance.Fail("authenticatorGetAssertion authData omits extension data")
	}
	raw, present := view.Values[string(extension.ExtensionIdentifierThirdPartyPayment)]
	if !present {
		return conformance.Fail("authenticatorGetAssertion extension output omits thirdPartyPayment")
	}
	want := []byte{0xf4}
	if expected {
		want = []byte{0xf5}
	}
	if !bytes.Equal(raw, want) {
		return conformance.Failf("thirdPartyPayment output is not canonical %t", expected)
	}

	return nil
}

func thirdPartyPaymentReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:12.9:third-party-payment-processing",
		Specification: conformance.SpecificationCTAP23,
		Section:       "12.9",
		Clause:        "third-party-payment-processing",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-thirdPartyPayment-extension",
		Level:         conformance.RequirementMust,
	}
}
