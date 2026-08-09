package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

const (
	enterpriseAttestationSourcePath = "tests/CTAP2/Protocol/Options/EntepriseAttestation.js"
	enterpriseAttestationRPID       = "enterprisetest.certinfra.fidoalliance.org"
	enterpriseAttestationWrongRPID  = "not-enterprise.ctap23-conformance.example"

	TestIDEnterpriseAttestationP1 conformance.TestID = "fido.ctap2.3.enteprise-attestation.p-1"
	TestIDEnterpriseAttestationP2 conformance.TestID = "fido.ctap2.3.enteprise-attestation.p-2"
	TestIDEnterpriseAttestationP3 conformance.TestID = "fido.ctap2.3.enteprise-attestation.p-3"
	TestIDEnterpriseAttestationF1 conformance.TestID = "fido.ctap2.3.enteprise-attestation.f-1"
	TestIDEnterpriseAttestationF2 conformance.TestID = "fido.ctap2.3.enteprise-attestation.f-2"
	TestIDEnterpriseAttestationF3 conformance.TestID = "fido.ctap2.3.enteprise-attestation.f-3"
	TestIDEnterpriseAttestationF4 conformance.TestID = "fido.ctap2.3.enteprise-attestation.f-4"
	TestIDEnterpriseAttestationF5 conformance.TestID = "fido.ctap2.3.enteprise-attestation.f-5"
	TestIDEnterpriseAttestationF6 conformance.TestID = "fido.ctap2.3.enteprise-attestation.f-6"
)

var enterpriseAttestationLeafDigest = [sha256.Size]byte{
	0x1c, 0x0b, 0x94, 0x92, 0x87, 0xeb, 0x9a, 0x3b,
	0xbb, 0xac, 0xa3, 0x13, 0xcb, 0xd5, 0x63, 0x31,
	0xb2, 0xff, 0x20, 0x2f, 0xe3, 0xca, 0x01, 0x37,
	0x9a, 0x66, 0x12, 0xf6, 0x36, 0xf9, 0x20, 0x8b,
}

type enterpriseAttestationCase struct {
	id         conformance.TestID
	marker     string
	profile    SecurityProfile
	name       string
	references []conformance.RequirementRef
	run        func(context.Context, *conformance.TestContext, Config, [sha256.Size]byte) error
}

func enterpriseAttestationTests(config Config) []conformance.Test {
	return enterpriseAttestationTestsWithDigest(config, enterpriseAttestationLeafDigest)
}

func enterpriseAttestationTestsWithDigest(
	config Config,
	expectedLeafDigest [sha256.Size]byte,
) []conformance.Test {
	featureReference := enterpriseAttestationReference("7.1", "enterprise-attestation", "sctn-enterpriseAttestation", conformance.RequirementMust)
	configReference := enterpriseAttestationReference("6.11.1", "enable-enterprise-attestation", "enableEnterpriseAttestation", conformance.RequirementMust)
	makeReference := authrMakeCredReq1CommandReference()
	definitions := []enterpriseAttestationCase{
		{TestIDEnterpriseAttestationP1, "P-1", SecurityProfileEnterprise, "Enable enterprise attestation", []conformance.RequirementRef{featureReference, configReference}, runEnterpriseAttestationP1},
		{TestIDEnterpriseAttestationP2, "P-2", SecurityProfileEnterprise, "Return vendor-facilitated enterprise attestation", []conformance.RequirementRef{featureReference, makeReference}, runEnterpriseAttestationP2},
		{TestIDEnterpriseAttestationP3, "P-3", SecurityProfileEnterprise, "Return platform-managed enterprise attestation", []conformance.RequirementRef{featureReference, makeReference}, runEnterpriseAttestationP3},
		{TestIDEnterpriseAttestationF1, "F-1", SecurityProfileConsumer, "Omit the enterprise option for a consumer authenticator", []conformance.RequirementRef{featureReference}, runEnterpriseAttestationF1},
		{TestIDEnterpriseAttestationF2, "F-2", SecurityProfileConsumer, "Reject enterprise attestation mode 1 for a consumer authenticator", []conformance.RequirementRef{featureReference, makeReference}, runEnterpriseAttestationF2},
		{TestIDEnterpriseAttestationF3, "F-3", SecurityProfileConsumer, "Reject enterprise attestation mode 2 for a consumer authenticator", []conformance.RequirementRef{featureReference, makeReference}, runEnterpriseAttestationF3},
		{TestIDEnterpriseAttestationF4, "F-4", SecurityProfileEnterprise, "Reject a non-integer enterprise attestation input", []conformance.RequirementRef{featureReference, makeReference, ctapMessageEncodingReference()}, runEnterpriseAttestationF4},
		{TestIDEnterpriseAttestationF5, "F-5", SecurityProfileEnterprise, "Reject an unsupported enterprise attestation mode", []conformance.RequirementRef{featureReference, makeReference}, runEnterpriseAttestationF5},
		{TestIDEnterpriseAttestationF6, "F-6", SecurityProfileEnterprise, "Protect enterprise identity for an unrelated RP", []conformance.RequirementRef{featureReference, makeReference}, runEnterpriseAttestationF6},
	}

	tests := make([]conformance.Test, 0, len(definitions))
	for _, definition := range definitions {
		definition := definition
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: definition.name,
			Source: conformance.SourceLocation{
				Path: enterpriseAttestationSourcePath,
				Case: definition.marker,
			},
			References:  definition.references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				if !test.Step(enterpriseAttestationApplicabilityStep(test, config, definition)) {
					return
				}
				if config.PowerCycler == nil {
					test.Step(conformance.Step{
						ID:   "enterprise-attestation.environment",
						Name: "Require authenticator lifecycle control",
						Run: func(context.Context) error {
							return errors.New("ctap23: authenticator power cycler is required for enterprise-attestation tests")
						},
					})
					return
				}

				test.Cleanup(residentKeyCleanupStep(test, config))
				if !test.Step(conformance.Step{
					ID:         "enterprise-attestation.prepare",
					Name:       "Reset, rebind, and configure the selected security profile",
					References: []conformance.RequirementRef{resetReference(), clientPINPowerCycleReference(), configReference},
					Run: func(ctx context.Context) error {
						if err := residentKeyResetAndRebind(ctx, test, config); err != nil {
							return err
						}
						if definition.profile == SecurityProfileEnterprise {
							return enableEnterpriseAttestationForCase(ctx, test, config)
						}
						return nil
					},
				}) {
					return
				}

				test.Step(conformance.Step{
					ID:         conformance.StepID("enterprise-attestation." + strings.ToLower(definition.marker) + ".execute"),
					Name:       definition.name,
					References: definition.references,
					Run: func(ctx context.Context) error {
						return definition.run(ctx, test, config, expectedLeafDigest)
					},
				})
			},
		})
	}

	return tests
}

func enterpriseAttestationApplicabilityStep(
	test *conformance.TestContext,
	config Config,
	definition enterpriseAttestationCase,
) conformance.Step {
	return conformance.Step{
		ID:         conformance.StepID("enterprise-attestation." + definition.marker + ".applicability"),
		Name:       "Confirm the declared security profile and case applicability",
		References: definition.references,
		Run: func(ctx context.Context) error {
			if config.SecurityProfile == SecurityProfileUnspecified {
				return conformance.Skip("security profile is not declared")
			}
			if config.SecurityProfile != definition.profile {
				return conformance.Skipf("case requires securityProfile=%s", definition.profile)
			}
			fields, _, err := readGetInfo(ctx, test.CBOR())
			if err != nil {
				return err
			}
			if definition.profile == SecurityProfileEnterprise {
				if _, present, err := rawGetInfoOption(fields, protocol.OptionEnterpriseAttestation); err != nil {
					return err
				} else if !present {
					return conformance.Fail("enterprise profile omits GetInfo options.ep")
				}
			}
			if definition.id == TestIDEnterpriseAttestationF6 {
				if _, present, err := rawGetInfoOption(fields, protocol.OptionClientPIN); err != nil {
					return err
				} else if !present {
					return conformance.Skip("F-6 requires the clientPin option")
				}
			}
			return nil
		},
	}
}

func enableEnterpriseAttestationForCase(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) error {
	fields, info, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	enabled, present, err := rawGetInfoOption(fields, protocol.OptionEnterpriseAttestation)
	if err != nil {
		return err
	}
	if !present || enabled {
		return conformance.Fail("fresh enterprise profile must report ep=false")
	}
	if !slices.Contains(info.AuthenticatorConfigCommands, protocol.ConfigSubCommandEnableEnterpriseAttestation) {
		return conformance.Fail("authenticatorConfigCommands omits enableEnterpriseAttestation")
	}
	if config.TokenProvider == nil {
		return errors.New("ctap23: PIN/UV token provider is required to enable enterprise attestation")
	}
	authorization, err := config.TokenProvider(ctx, test.Client(), PinUvAuthTokenRequest{
		Permission: protocol.PermissionAuthenticatorConfiguration,
	})
	if err != nil {
		clear(authorization.Value)
		return err
	}
	defer clear(authorization.Value)
	if err := validatePinUvAuthorization(info, authorization); err != nil {
		return err
	}
	if err := test.Client().EnableEnterpriseAttestation(ctx, authorization.Protocol, authorization.Value); err != nil {
		return unexpectedCTAPStatus("authenticatorConfig enableEnterpriseAttestation", err)
	}

	refreshedFields, _, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	enabled, present, err = rawGetInfoOption(refreshedFields, protocol.OptionEnterpriseAttestation)
	if err != nil {
		return err
	}
	if !present || !enabled {
		return conformance.Fail("ep is not true after enableEnterpriseAttestation")
	}
	return nil
}

func runEnterpriseAttestationP1(
	ctx context.Context,
	test *conformance.TestContext,
	_ Config,
	_ [sha256.Size]byte,
) error {
	fields, _, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	enabled, present, err := rawGetInfoOption(fields, protocol.OptionEnterpriseAttestation)
	if err != nil {
		return err
	}
	if !present || !enabled {
		return conformance.Fail("enterprise profile does not report ep=true after configuration")
	}
	return nil
}

func runEnterpriseAttestationP2(ctx context.Context, test *conformance.TestContext, config Config, digest [sha256.Size]byte) error {
	return runEnterpriseAttestationPositive(ctx, test, config, 1, digest)
}

func runEnterpriseAttestationP3(ctx context.Context, test *conformance.TestContext, config Config, digest [sha256.Size]byte) error {
	return runEnterpriseAttestationPositive(ctx, test, config, 2, digest)
}

func runEnterpriseAttestationPositive(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	mode uint,
	digest [sha256.Size]byte,
) error {
	request, err := prepareAuthorizedMakeCredentialRequest(ctx, test, config, enterpriseAttestationRPID)
	if err != nil {
		return err
	}
	defer clearAuthorizedMakeCredentialRequest(&request)
	request.EnterpriseAttestation = mode
	result, err := exchangeEnterpriseMakeCredential(ctx, test, request)
	if err != nil {
		return err
	}
	defer result.clear()
	return validateEnterpriseAttestation(result, request.ClientDataHash, digest, true)
}

func runEnterpriseAttestationF1(ctx context.Context, test *conformance.TestContext, _ Config, _ [sha256.Size]byte) error {
	fields, _, err := readGetInfo(ctx, test.CBOR())
	if err != nil {
		return err
	}
	if _, present, err := rawGetInfoOption(fields, protocol.OptionEnterpriseAttestation); err != nil {
		return err
	} else if present {
		return conformance.Fail("consumer profile exposes GetInfo options.ep")
	}
	return nil
}

func runEnterpriseAttestationF2(ctx context.Context, test *conformance.TestContext, config Config, _ [sha256.Size]byte) error {
	return expectEnterpriseMakeCredentialStatus(ctx, test, config, enterpriseAttestationRPID, 1, ctaptransport.CTAP1_ERR_INVALID_PARAMETER)
}

func runEnterpriseAttestationF3(ctx context.Context, test *conformance.TestContext, config Config, _ [sha256.Size]byte) error {
	return expectEnterpriseMakeCredentialStatus(ctx, test, config, enterpriseAttestationRPID, 2, ctaptransport.CTAP1_ERR_INVALID_PARAMETER)
}

func runEnterpriseAttestationF4(ctx context.Context, test *conformance.TestContext, config Config, _ [sha256.Size]byte) error {
	request, err := prepareAuthorizedMakeCredentialRequest(ctx, test, config, enterpriseAttestationRPID)
	if err != nil {
		return err
	}
	defer clearAuthorizedMakeCredentialRequest(&request)
	fields := ctap2WireFields("enterprise-attestation malformed MakeCredential", request)
	defer clearCTAP2WireValue(fields)
	fields[10] = "not-an-unsigned-integer"
	response, err := exchangeRawMakeCredential(ctx, test.CBOR(), fields)
	defer clearCTAP2ResponseData(response)
	return expectAnyCTAPError(err)
}

func runEnterpriseAttestationF5(ctx context.Context, test *conformance.TestContext, config Config, _ [sha256.Size]byte) error {
	return expectEnterpriseMakeCredentialStatus(ctx, test, config, enterpriseAttestationRPID, 3, ctaptransport.CTAP2_ERR_INVALID_OPTION)
}

func runEnterpriseAttestationF6(ctx context.Context, test *conformance.TestContext, config Config, digest [sha256.Size]byte) error {
	request, err := prepareAuthorizedMakeCredentialRequest(ctx, test, config, enterpriseAttestationWrongRPID)
	if err != nil {
		return err
	}
	defer clearAuthorizedMakeCredentialRequest(&request)
	request.EnterpriseAttestation = 1
	result, err := exchangeEnterpriseMakeCredential(ctx, test, request)
	if err != nil {
		return err
	}
	defer result.clear()
	return validateEnterpriseAttestation(result, request.ClientDataHash, digest, false)
}

func expectEnterpriseMakeCredentialStatus(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	rpID string,
	mode uint,
	status ctaptransport.StatusCode,
) error {
	request, err := prepareAuthorizedMakeCredentialRequest(ctx, test, config, rpID)
	if err != nil {
		return err
	}
	defer clearAuthorizedMakeCredentialRequest(&request)
	request.EnterpriseAttestation = mode
	response, err := exchangeMakeCredential(ctx, test.CBOR(), request)
	defer clearCTAP2ResponseData(response)
	return expectCTAPStatus(err, status)
}

type enterpriseMakeCredentialResult struct {
	fields   map[uint64]cbor.RawMessage
	response protocol.AuthenticatorMakeCredentialResponse
}

func (result *enterpriseMakeCredentialResult) clear() {
	clearCTAP2RawFields(result.fields)
	result.fields = nil
	clearMakeCredentialResponse(&result.response)
}

func exchangeEnterpriseMakeCredential(
	ctx context.Context,
	test *conformance.TestContext,
	request protocol.AuthenticatorMakeCredentialRequest,
) (enterpriseMakeCredentialResult, error) {
	wireResponse, err := exchangeMakeCredential(ctx, test.CBOR(), request)
	if err != nil {
		return enterpriseMakeCredentialResult{}, unexpectedCTAPStatus("authenticatorMakeCredential", err)
	}
	defer clearCTAP2ResponseData(wireResponse)
	if err := validateCanonicalMakeCredentialResponse(wireResponse.Data); err != nil {
		return enterpriseMakeCredentialResult{}, err
	}
	var result enterpriseMakeCredentialResult
	if err := getInfoDecMode.Unmarshal(wireResponse.Data, &result.fields); err != nil {
		clearCTAP2RawFields(result.fields)
		return enterpriseMakeCredentialResult{}, conformance.Failf("invalid authenticatorMakeCredential response CBOR: %v", err)
	}
	result.response, err = decodeMakeCredentialResponse(wireResponse.Data)
	if err != nil {
		result.clear()
		return enterpriseMakeCredentialResult{}, err
	}
	return result, nil
}

func validateEnterpriseAttestation(
	result enterpriseMakeCredentialResult,
	clientDataHash []byte,
	expectedLeafDigest [sha256.Size]byte,
	enterprise bool,
) error {
	if result.response.Format != attestation.AttestationStatementFormatIdentifierPacked {
		return conformance.Failf("attestation format = %q, want packed", result.response.Format)
	}
	statement, ok := attestation.ParsePackedStatement(result.response.AttestationStatement)
	if !ok {
		return conformance.Fail("packed attestation statement is malformed")
	}
	if enterprise && len(statement.X509Chain) != 1 {
		return conformance.Fail("enterprise packed attestation must contain exactly one x5c certificate")
	}
	if !enterprise && len(statement.X509Chain) == 0 {
		return conformance.Fail("regular packed attestation omits its x5c certificate")
	}
	leafDigest := sha256.Sum256(statement.X509Chain[0])
	if enterprise && leafDigest != expectedLeafDigest {
		return conformance.Fail("enterprise attestation leaf certificate digest does not match the pinned fixture")
	}
	if !enterprise && leafDigest == expectedLeafDigest {
		return conformance.Fail("unrelated RP received the pinned enterprise attestation certificate")
	}
	rawEPAtt, present := result.fields[4]
	if enterprise {
		if !present || !bytes.Equal(rawEPAtt, []byte{0xf5}) {
			return conformance.Fail("enterprise MakeCredential response omits canonical epAtt=true")
		}
	} else if present && !bytes.Equal(rawEPAtt, []byte{0xf4}) {
		return conformance.Fail("unrelated RP response epAtt is neither absent nor canonical false")
	}
	signedData := slices.Concat(result.response.AuthDataRaw, clientDataHash)
	defer clear(signedData)
	verification, err := attestation.VerifyPacked(statement, false, nil, 0, signedData)
	if err != nil {
		return conformance.Failf("invalid packed attestation signature: %v", err)
	}
	if verification.Type != attestation.TypeBasic || verification.SignatureValid == nil ||
		!*verification.SignatureValid {
		return conformance.Fail("packed attestation signature is not a valid basic attestation")
	}
	return nil
}

func enterpriseAttestationReference(
	section string,
	clause string,
	anchor string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID(fmt.Sprintf("ctap-2.3-ps-20260226:%s:%s", section, clause)),
		Specification: conformance.SpecificationCTAP23,
		Section:       section,
		Clause:        clause,
		URL: "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/" +
			"fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#" + anchor,
		Level: level,
	}
}
