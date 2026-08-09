package ctap23

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrClientPIN1KeyAgreementSourcePath = "tests/CTAP2/Protocol/ClientPin/ClientPin1/Authr-ClientPin1-KeyAgreement.js"
	clientPIN1CertificationPolicy         = "fido-authenticator-certification-policy"
	TestIDAuthrClientPIN1KeyAgreementP1   = "fido.ctap2.3.authr-client-pin1-key-agreement.p-1"
)

var clientPIN1GetKeyAgreementRequest = []byte{
	byte(protocol.AuthenticatorClientPIN),
	0xa2,
	0x01, byte(protocol.PinUvAuthProtocolOne),
	0x02, byte(protocol.ClientPINSubCommandGetKeyAgreement),
}

func authrClientPIN1KeyAgreementTest(config Config) conformance.Test {
	getInfoRequirement := getInfoReference()
	clientPINRequirement := clientPIN1KeyAgreementCommandReference()
	algRequirement := clientPIN1KeyAgreementAlgReference()
	parametersRequirement := clientPIN1KeyAgreementParametersReference()
	sharedSecretRequirement := clientPIN1KeyAgreementSharedSecretReference()
	protocolOneRequirement := clientPIN1KeyAgreementProtocolOneReference()
	encodingRequirement := ctapMessageEncodingReference()
	resetRequirement := resetReference()
	profileRequirement := clientPIN1KeyAgreementProfileReference()

	return conformance.Test{
		ID:          TestIDAuthrClientPIN1KeyAgreementP1,
		Name:        "PIN/UV protocol 1 key agreement",
		Description: "Resets the authenticator, requests its protocol 1 key-agreement public key, and validates the response at the CBOR boundary",
		Destructive: true,
		Source: conformance.SourceLocation{
			Path: authrClientPIN1KeyAgreementSourcePath,
			Case: "P-1",
		},
		References: []conformance.RequirementRef{
			getInfoRequirement,
			clientPINRequirement,
			algRequirement,
			parametersRequirement,
			sharedSecretRequirement,
			protocolOneRequirement,
			encodingRequirement,
			resetRequirement,
			profileRequirement,
		},
		Run: func(test *conformance.TestContext) {
			if !test.Step(conformance.Step{
				ID:         "client-pin1.support",
				Name:       "Confirm PIN/UV protocol 1 support",
				References: []conformance.RequirementRef{getInfoRequirement, protocolOneRequirement, profileRequirement},
				Run: func(ctx context.Context) error {
					fields, info, err := readGetInfo(ctx, test.CBOR())
					if err != nil {
						return err
					}

					return validateClientPINProtocolSupport(fields, info, config, protocol.PinUvAuthProtocolOne)
				},
			}) {
				return
			}

			if !test.Step(conformance.Step{
				ID:         "client-pin1.reset",
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
				ID:   "client-pin1.get-key-agreement",
				Name: "Request the protocol 1 key-agreement key",
				References: []conformance.RequirementRef{
					clientPINRequirement,
					algRequirement,
					parametersRequirement,
					sharedSecretRequirement,
					protocolOneRequirement,
					encodingRequirement,
				},
				Run: func(ctx context.Context) error {
					response, err := test.CBOR().CBOR(ctx, clientPIN1GetKeyAgreementRequest)
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
				ID:   "client-pin1.key-agreement",
				Name: "Validate the protocol 1 key-agreement COSE key",
				References: []conformance.RequirementRef{
					clientPINRequirement,
					algRequirement,
					parametersRequirement,
					sharedSecretRequirement,
					protocolOneRequirement,
					encodingRequirement,
				},
				Run: func(context.Context) error {
					return validateClientPINKeyAgreementResponse(responseData)
				},
			})
		},
	}
}

func clientPIN1KeyAgreementCommandReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5:authenticator-client-pin",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5",
		Clause:        "authenticator-client-pin",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPIN1KeyAgreementAlgReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5:key-agreement-alg-parameter",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5",
		Clause:        "key-agreement-alg-parameter",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN",
		Level:         conformance.RequirementMust,
	}
}

func clientPIN1KeyAgreementParametersReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5:key-agreement-no-other-optional-parameters",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5",
		Clause:        "key-agreement-no-other-optional-parameters",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN",
		Level:         conformance.RequirementMustNot,
	}
}

func clientPIN1KeyAgreementSharedSecretReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.5.4:obtaining-shared-secret",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.5.4",
		Clause:        "obtaining-shared-secret",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getKeyAgreement",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPIN1KeyAgreementProtocolOneReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "ctap-2.3-ps-20260226:6.5.6:key-agreement-public-key",
		Specification: conformance.SpecificationCTAP23,
		Section:       "6.5.6",
		Clause:        "key-agreement-public-key",
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinProto1",
		Level:         conformance.RequirementConstraint,
	}
}

func clientPIN1KeyAgreementProfileReference() conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            "fido-authenticator-certification-policy:ctap2.3-featureful:pin-uv-protocol-one-nfc-exception",
		Specification: conformance.SpecificationID(clientPIN1CertificationPolicy),
		Section:       "CTAP 2.3 featureful profile",
		Clause:        "pin-uv-protocol-one-nfc-exception",
		URL:           "https://github.com/fido-alliance/certification/issues/38",
		Level:         conformance.RequirementConstraint,
	}
}
