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
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/kit/conformance"
)

const (
	authrGetAssertionResp1SourcePath = "tests/CTAP2/Protocol/Get/Authr-GetAssertion-Resp-1.js"
	authrGetAssertionResp1RPID       = "get-assertion-resp-1.ctap23-conformance.example"

	TestIDAuthrGetAssertionResp1P1 conformance.TestID = "fido.ctap2.3.authr-get-assertion-resp-1.p-1"
	TestIDAuthrGetAssertionResp1P2 conformance.TestID = "fido.ctap2.3.authr-get-assertion-resp-1.p-2"
	TestIDAuthrGetAssertionResp1P3 conformance.TestID = "fido.ctap2.3.authr-get-assertion-resp-1.p-3"
	TestIDAuthrGetAssertionResp1P4 conformance.TestID = "fido.ctap2.3.authr-get-assertion-resp-1.p-4"
	TestIDAuthrGetAssertionResp1F1 conformance.TestID = "fido.ctap2.3.authr-get-assertion-resp-1.f-1"
)

type authrGetAssertionResp1Case struct {
	id         conformance.TestID
	marker     string
	name       string
	references []conformance.RequirementRef
	run        func(context.Context, *conformance.TestContext, Config, *getAssertionFixture) error
}

type authrGetAssertionResp1Input struct {
	algorithms       []metadataCOSEAlgorithm
	pubKeyCredParams []credential.PublicKeyCredentialParameters
}

func authrGetAssertionResp1Tests(config Config) []conformance.Test {
	commandReference := authrGetAssertionReq1CommandReference()
	responseReference := authrGetAssertionResp1Reference(
		"6.2",
		"get-assertion-response-members",
		"authenticatorGetAssertion",
		conformance.RequirementConstraint,
	)
	cases := []authrGetAssertionResp1Case{
		{
			id:     TestIDAuthrGetAssertionResp1P1,
			marker: "P-1",
			name:   "GetAssertion returns the required response fields",
			references: []conformance.RequirementRef{
				responseReference,
				authrGetAssertionReq3CredentialDescriptorReference(),
			},
			run: runAuthrGetAssertionResp1P1,
		},
		{
			id:     TestIDAuthrGetAssertionResp1P2,
			marker: "P-2",
			name:   "GetAssertion authenticator data identifies the relying party",
			references: []conformance.RequirementRef{
				responseReference,
				authrGetAssertionResp1WebAuthnReference(
					"6.1",
					"assertion-authenticator-data",
					"sctn-authenticator-data",
					conformance.RequirementMust,
				),
			},
			run: runAuthrGetAssertionResp1P2,
		},
		{
			id:     TestIDAuthrGetAssertionResp1P3,
			marker: "P-3",
			name:   "GetAssertion signature counter is supported or increases",
			references: []conformance.RequirementRef{
				responseReference,
				authrGetAssertionResp1WebAuthnReference(
					"6.1.1",
					"signature-counter",
					"sctn-sign-counter",
					conformance.RequirementConstraint,
				),
			},
			run: runAuthrGetAssertionResp1P3,
		},
		{
			id:     TestIDAuthrGetAssertionResp1P4,
			marker: "P-4",
			name:   "GetAssertion signature verifies over the exact signed bytes",
			references: []conformance.RequirementRef{
				responseReference,
				authrGetAssertionResp1WebAuthnReference(
					"7.2",
					"verify-assertion-signature",
					"sctn-verifying-assertion",
					conformance.RequirementMust,
				),
			},
			run: runAuthrGetAssertionResp1P4,
		},
		{
			id:     TestIDAuthrGetAssertionResp1F1,
			marker: "F-1",
			name:   "GetAssertion omits unsolicited unsigned extension outputs",
			references: []conformance.RequirementRef{
				authrGetAssertionResp1Reference(
					"6.2",
					"unsigned-extension-outputs",
					"authenticatorGetAssertion",
					conformance.RequirementShould,
				),
			},
			run: runAuthrGetAssertionResp1F1,
		},
	}

	tests := make([]conformance.Test, 0, len(cases))
	for _, definition := range cases {
		definition := definition
		references := slices.Concat(
			[]conformance.RequirementRef{commandReference},
			definition.references,
		)
		tests = append(tests, conformance.Test{
			ID:          definition.id,
			Name:        definition.name,
			Description: "Validates one authenticatorGetAssertion response requirement",
			Source: conformance.SourceLocation{
				Path: authrGetAssertionResp1SourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var fixture getAssertionFixture
				if !test.Step(conformance.Step{
					ID: conformance.StepID(
						"get-assertion-resp-1." + strings.ToLower(definition.marker) + ".prepare",
					),
					Name:       "Create one isolated credential from the metadata algorithms",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						input, err := parseAuthrGetAssertionResp1Input(config.Metadata.StatementJSON)
						if err != nil {
							return err
						}

						fixture, err = prepareGetAssertionFixture(
							ctx,
							test,
							config,
							getAssertionFixtureSpec{
								RPID:             authrGetAssertionResp1RPID,
								PubKeyCredParams: input.pubKeyCredParams,
							},
						)
						if err != nil {
							return err
						}
						if err := validateAuthrGetAssertionResp1CredentialKey(
							fixture.CredentialPublicKey,
							input.algorithms,
						); err != nil {
							fixture.clear()

							return err
						}

						return nil
					},
				}) {
					return
				}
				defer fixture.clear()

				test.Step(conformance.Step{
					ID: conformance.StepID(
						"get-assertion-resp-1." + strings.ToLower(definition.marker) + ".validate",
					),
					Name:       "Get and validate the created credential assertion",
					References: references,
					Run: func(ctx context.Context) error {
						return definition.run(ctx, test, config, &fixture)
					},
				})
			},
		})
	}

	return tests
}

func parseAuthrGetAssertionResp1Input(statementJSON string) (authrGetAssertionResp1Input, error) {
	statement, err := parseMetadataStatement(statementJSON)
	if err != nil {
		return authrGetAssertionResp1Input{}, conformance.Failf("invalid metadata statement: %v", err)
	}
	algorithmNames, err := requiredMetadataValue[[]string](statement, "authenticationAlgorithms")
	if err != nil {
		return authrGetAssertionResp1Input{}, err
	}
	if len(algorithmNames) == 0 {
		return authrGetAssertionResp1Input{}, conformance.Fail(
			"metadata authenticationAlgorithms must not be empty",
		)
	}

	algorithms, err := resolveMetadataCOSEAlgorithms(algorithmNames)
	if err != nil {
		return authrGetAssertionResp1Input{}, err
	}
	parameters := make([]credential.PublicKeyCredentialParameters, 0, len(algorithms))
	for _, algorithm := range algorithms {
		parameters = append(parameters, credential.PublicKeyCredentialParameters{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.Algorithm(algorithm.profile.Algorithm),
		})
	}

	return authrGetAssertionResp1Input{
		algorithms:       algorithms,
		pubKeyCredParams: parameters,
	}, nil
}

func validateAuthrGetAssertionResp1CredentialKey(
	key cose.Key,
	algorithms []metadataCOSEAlgorithm,
) error {
	matches, err := resolveCredentialPublicKeyMetadataAlgorithms(key, algorithms)
	if err != nil {
		return err
	}
	raw, err := ctap2EncMode.Marshal(key)
	if err != nil {
		return conformance.Failf("invalid credential COSE key: %v", err)
	}
	for _, match := range matches {
		if err := validateCredentialPublicKeyProfile(key, raw, match); err != nil {
			return fmt.Errorf("metadata algorithm %s: %w", match.name, err)
		}
	}

	return nil
}

func runAuthrGetAssertionResp1P1(
	ctx context.Context,
	test *conformance.TestContext,
	_ Config,
	fixture *getAssertionFixture,
) error {
	response, err := fixture.getAssertion(ctx, test.CBOR(), fixture.Request)
	if err != nil {
		return err
	}

	return validateAuthrGetAssertionResp1Credential(response, fixture.Request.AllowList[0].ID)
}

func validateAuthrGetAssertionResp1Credential(
	response getAssertionResponse,
	wantID []byte,
) error {
	var fields map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(response.Fields[1], &fields); err != nil {
		return conformance.Failf("invalid GetAssertion credential descriptor: %v", err)
	}
	typeRaw, present := fields["type"]
	if !present || !hasCBORMajorType(typeRaw, 3) {
		return conformance.Fail("GetAssertion credential type is missing or is not a text string")
	}
	var credentialType string
	if err := getInfoDecMode.Unmarshal(typeRaw, &credentialType); err != nil {
		return conformance.Failf("invalid GetAssertion credential type: %v", err)
	}
	if credentialType != string(credential.PublicKeyCredentialTypePublicKey) {
		return conformance.Failf("GetAssertion credential type is %q, want public-key", credentialType)
	}
	idRaw, present := fields["id"]
	if !present || !hasCBORMajorType(idRaw, 2) {
		return conformance.Fail("GetAssertion credential ID is missing or is not a byte string")
	}
	var credentialID []byte
	if err := getInfoDecMode.Unmarshal(idRaw, &credentialID); err != nil {
		return conformance.Failf("invalid GetAssertion credential ID: %v", err)
	}
	if !bytes.Equal(credentialID, wantID) {
		return conformance.Fail("GetAssertion returned a different credential ID")
	}

	return nil
}

func runAuthrGetAssertionResp1P2(
	ctx context.Context,
	test *conformance.TestContext,
	_ Config,
	fixture *getAssertionFixture,
) error {
	response, err := fixture.getAssertion(ctx, test.CBOR(), fixture.Request)
	if err != nil {
		return err
	}
	authData := response.Response.AuthData
	if len(response.Response.AuthDataRaw) != 37 {
		return conformance.Failf(
			"GetAssertion authData is %d bytes, want exactly 37",
			len(response.Response.AuthDataRaw),
		)
	}
	wantRPIDHash := sha256.Sum256([]byte(fixture.Request.RPID))
	if !bytes.Equal(authData.RPIDHash, wantRPIDHash[:]) {
		return conformance.Fail("GetAssertion authData rpIdHash does not match the request RP ID")
	}
	if authData.Flags.AttestedCredentialDataIncluded() {
		return conformance.Fail("GetAssertion authData has the AT flag set")
	}

	return nil
}

func runAuthrGetAssertionResp1P3(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	fixture *getAssertionFixture,
) error {
	request := fixture.Request
	defer clear(request.PinUvAuthParam)

	counters := make([]uint32, 0, 3)
	for index := 0; index < 3; index++ {
		if index != 0 {
			hash := sha256.Sum256([]byte(fmt.Sprintf(
				"ctap23 Authr-GetAssertion-Resp-1 P-3 request %d",
				index+1,
			)))
			request.ClientDataHash = slices.Clone(hash[:])
			if err := fixture.refreshAuthorization(ctx, test, config, &request); err != nil {
				return err
			}
		}

		response, err := fixture.getAssertion(ctx, test.CBOR(), request)
		if err != nil {
			return err
		}
		if err := validateAuthrGetAssertionResp1Credential(
			response,
			fixture.Request.AllowList[0].ID,
		); err != nil {
			return err
		}
		counters = append(counters, response.Response.AuthData.SignCount)
	}

	if counters[0] == 0 && counters[1] == 0 && counters[2] == 0 {
		return nil
	}
	if counters[0] < counters[1] && counters[1] < counters[2] {
		return nil
	}

	return conformance.Failf(
		"GetAssertion signature counters are %d, %d, %d; want all zero or strictly increasing",
		counters[0],
		counters[1],
		counters[2],
	)
}

func runAuthrGetAssertionResp1P4(
	ctx context.Context,
	test *conformance.TestContext,
	_ Config,
	fixture *getAssertionFixture,
) error {
	response, err := fixture.getAssertion(ctx, test.CBOR(), fixture.Request)
	if err != nil {
		return err
	}
	algorithm, err := fixture.CredentialPublicKey.Algorithm()
	if err != nil {
		return conformance.Failf("invalid credential COSE key algorithm: %v", err)
	}
	publicKey, err := fixture.CredentialPublicKey.PublicKey()
	if err != nil {
		if errors.Is(err, cose.ErrUnsupportedAlgorithm) || errors.Is(err, cose.ErrUnsupportedKey) {
			return fmt.Errorf("ctap23: Registry COSE profile is not implemented by ctap/cose: %w", err)
		}

		return conformance.Failf("invalid credential COSE key: %v", err)
	}
	signed := make([]byte, 0, len(response.Response.AuthDataRaw)+len(fixture.Request.ClientDataHash))
	signed = append(signed, response.Response.AuthDataRaw...)
	signed = append(signed, fixture.Request.ClientDataHash...)
	if err := cose.VerifySignature(publicKey, algorithm, signed, response.Response.Signature); err != nil {
		if errors.Is(err, cose.ErrUnsupportedAlgorithm) {
			return fmt.Errorf("ctap23: Registry COSE profile is not implemented by ctap/cose: %w", err)
		}

		return conformance.Failf("GetAssertion signature verification failed: %v", err)
	}

	return nil
}

func runAuthrGetAssertionResp1F1(
	ctx context.Context,
	test *conformance.TestContext,
	_ Config,
	fixture *getAssertionFixture,
) error {
	response, err := fixture.getAssertion(ctx, test.CBOR(), fixture.Request)
	if err != nil {
		return err
	}
	if _, present := response.Fields[8]; present {
		return conformance.Fail("GetAssertion response contains unsolicited unsigned extension outputs")
	}

	return nil
}

func authrGetAssertionResp1Reference(
	section string,
	clause string,
	anchor string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID("ctap-2.3-ps-20260226:" + section + ":" + clause),
		Specification: conformance.SpecificationCTAP23,
		Section:       section,
		Clause:        clause,
		URL:           "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#" + anchor,
		Level:         level,
	}
}

func authrGetAssertionResp1WebAuthnReference(
	section string,
	clause string,
	anchor string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            conformance.RequirementID("webauthn-3:" + section + ":" + clause),
		Specification: "webauthn-level-3",
		Section:       section,
		Clause:        clause,
		URL:           "https://www.w3.org/TR/webauthn-3/#" + anchor,
		Level:         level,
	}
}
