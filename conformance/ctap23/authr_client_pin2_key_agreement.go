package ctap23

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN2KeyAgreementSourcePath                    = "tests/CTAP2/Protocol/ClientPin/ClientPin2/Authr-ClientPin2-KeyAgreement.js"
	TestIDAuthrClientPIN2KeyAgreementP1   conformance.TestID = "fido.ctap2.3.authr-client-pin2-key-agreement.p-1"
)

var clientPIN2GetKeyAgreementRequest = []byte{
	byte(protocol.AuthenticatorClientPIN),
	0xa2,
	0x01, byte(protocol.PinUvAuthProtocolTwo),
	0x02, byte(protocol.ClientPINSubCommandGetKeyAgreement),
}

func authrClientPIN2KeyAgreementTest(config Config) conformance.Test {
	getInfoRequirement := getInfoReference()
	algorithmRequirement := clientPIN2KeyAgreementAlgorithmReference()
	optionalParametersRequirement := clientPIN2KeyAgreementOptionalParametersReference()
	sharedSecretRequirement := clientPIN2KeyAgreementSharedSecretReference()
	protocolOneRequirement := clientPIN2KeyAgreementProtocolOneReference()
	protocolTwoRequirement := clientPIN2KeyAgreementProtocolTwoReference()
	resetRequirement := resetReference()
	encodingRequirement := ctapMessageEncodingReference()
	featurefulRequirement := clientPIN2KeyAgreementFeaturefulReference()

	return conformance.Test{
		ID:          TestIDAuthrClientPIN2KeyAgreementP1,
		Name:        "PIN/UV protocol 2 key agreement",
		Description: "Resets the authenticator, requests its protocol 2 key-agreement public key, and validates the response at the CBOR boundary",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN2KeyAgreementSourcePath,
			Case: "P-1",
		},
		References: []conformance.RequirementRef{
			getInfoRequirement,
			algorithmRequirement,
			optionalParametersRequirement,
			sharedSecretRequirement,
			protocolOneRequirement,
			protocolTwoRequirement,
			resetRequirement,
			encodingRequirement,
			featurefulRequirement,
		},
		Run: func(test *conformance.TestContext) {
			if !test.Step(conformance.Step{
				ID:         "client-pin2.support",
				Name:       "Confirm PIN/UV protocol 2 support",
				References: []conformance.RequirementRef{getInfoRequirement, protocolTwoRequirement, featurefulRequirement},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}

					return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolTwo)
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "client-pin2.reset",
				Name:       "Reset the authenticator before key agreement",
				References: []conformance.RequirementRef{resetRequirement},
				Run: func(ctx context.Context) error {
					return resetAuthenticatorForTest(ctx, test.Client(), config.Resetter)
				},
			}) {
				return
			}

			var responseData []byte
			if !test.Step(conformance.Step{
				ID:   "client-pin2.get-key-agreement",
				Name: "Request the protocol 2 key-agreement key",
				References: []conformance.RequirementRef{
					sharedSecretRequirement,
					protocolOneRequirement,
					protocolTwoRequirement,
					encodingRequirement,
				},
				Run: func(ctx context.Context) error {
					response, err := test.CBOR().CBOR(ctx, clientPIN2GetKeyAgreementRequest)
					if err == nil {
						response, err = ctaptransport.ValidateCBORResponse(protocol.AuthenticatorClientPIN, response)
					}
					if err != nil {
						return unexpectedCTAPStatus("authenticatorClientPIN getKeyAgreement", err)
					}
					responseData = response.Data

					return nil
				},
			}) {
				return
			}

			test.Step(conformance.Step{
				ID:   "client-pin2.key-agreement",
				Name: "Validate the protocol 2 key-agreement COSE key",
				References: []conformance.RequirementRef{
					algorithmRequirement,
					optionalParametersRequirement,
					sharedSecretRequirement,
					protocolOneRequirement,
					protocolTwoRequirement,
					encodingRequirement,
				},
				Run: func(context.Context) error {
					return validateClientPINKeyAgreementResponse(responseData)
				},
			})
		},
	}
}

func clientPIN2KeyAgreementAlgorithmReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5:key-agreement-algorithm-required",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5",
		Clause:        "key-agreement-algorithm-required",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN",
		Level:         conformance.RequirementMust,
	}
}

func clientPIN2KeyAgreementOptionalParametersReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5:key-agreement-no-other-optional-parameters",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5",
		Clause:        "key-agreement-no-other-optional-parameters",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN",
		Level:         conformance.RequirementMustNot,
	}
}

func clientPIN2KeyAgreementSharedSecretReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.4:obtaining-shared-secret",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.4",
		Clause:        "obtaining-shared-secret",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getKeyAgreement",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPIN2KeyAgreementProtocolOneReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.6:key-agreement-public-key",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.6",
		Clause:        "key-agreement-public-key",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinProto1",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPIN2KeyAgreementProtocolTwoReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.7:pin-uv-auth-protocol-two",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.7",
		Clause:        "pin-uv-auth-protocol-two",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinProto2",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPIN2KeyAgreementFeaturefulReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:9:item-6-pin-uv-auth-protocol-two-required",
		Specification: conformance.SpecificationCTAP23,
		Section:       "9",
		Clause:        "item-6-pin-uv-auth-protocol-two-required",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#mandatory-features",
		Level:         conformance.RequirementMust,
	}
}
