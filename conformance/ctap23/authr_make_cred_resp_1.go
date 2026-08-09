package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	registry "github.com/telesma-app/fido-registry"
	"github.com/telesma-app/kit/conformance"
	"golang.org/x/text/language"
)

const (
	authrMakeCredResp1SourcePath = "tests/CTAP2/Protocol/Make/Authr-MakeCred-Resp-1.js"
	authrMakeCredResp1RPID       = "make-cred-resp-1.ctap23-conformance.example"

	TestIDAuthrMakeCredResp1P01 conformance.TestID = "fido.ctap2.3.authr-make-cred-resp-1.p-01"
	TestIDAuthrMakeCredResp1P02 conformance.TestID = "fido.ctap2.3.authr-make-cred-resp-1.p-02"
	TestIDAuthrMakeCredResp1P03 conformance.TestID = "fido.ctap2.3.authr-make-cred-resp-1.p-03"
	TestIDAuthrMakeCredResp1P04 conformance.TestID = "fido.ctap2.3.authr-make-cred-resp-1.p-04"
	TestIDAuthrMakeCredResp1P06 conformance.TestID = "fido.ctap2.3.authr-make-cred-resp-1.p-06"
	TestIDAuthrMakeCredResp1F01 conformance.TestID = "fido.ctap2.3.authr-make-cred-resp-1.f-01"
)

var (
	oidCountryName            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganizationName       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnitName = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName             = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidFIDOAAGUID             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
)

type authrMakeCredResp1Case struct {
	id         conformance.TestID
	marker     string
	name       string
	references []conformance.RequirementRef
	validate   func(makeCredResp1Input, makeCredResp1Response) (bool, error)
}

type makeCredResp1Input struct {
	statement  metadataStatement
	aaguid     uuid.UUID
	algorithms []metadataCOSEAlgorithm
	info       protocol.AuthenticatorGetInfoResponse
}

type makeCredResp1Response struct {
	algorithm metadataCOSEAlgorithm
	request   protocol.AuthenticatorMakeCredentialRequest
	fields    map[uint64]cbor.RawMessage
	response  protocol.AuthenticatorMakeCredentialResponse
}

func authrMakeCredResp1Tests(config Config) []conformance.Test {
	commandReference := authrMakeCredReq1CommandReference()
	cases := []authrMakeCredResp1Case{
		{
			id:     TestIDAuthrMakeCredResp1P01,
			marker: "P-01",
			name:   "MakeCredential returns packed format",
			references: []conformance.RequirementRef{
				authrMakeCredResp1PackedSelectionReference(),
			},
			validate: validateMakeCredResp1P01,
		},
		{
			id:     TestIDAuthrMakeCredResp1P02,
			marker: "P-02",
			name:   "MakeCredential authData and credential key match metadata",
			references: []conformance.RequirementRef{
				authrMakeCredResp1AuthDataReference(),
				authrMakeCredResp1AttestedCredentialReference(),
				authrMakeCredResp1MetadataReference(),
				authrMakeCredResp1RegistryReference(),
			},
			validate: validateMakeCredResp1P02,
		},
		{
			id:     TestIDAuthrMakeCredResp1P03,
			marker: "P-03",
			name:   "Packed attestation statement has the exact wire shape",
			references: []conformance.RequirementRef{
				authrMakeCredResp1PackedReference(),
			},
			validate: validateMakeCredResp1P03,
		},
		{
			id:     TestIDAuthrMakeCredResp1P04,
			marker: "P-04",
			name:   "Packed basic attestation certificate chain is valid",
			references: []conformance.RequirementRef{
				authrMakeCredResp1PackedCertificateReference(),
				authrMakeCredResp1MetadataReference(),
			},
			validate: validateMakeCredResp1P04,
		},
		{
			id:     TestIDAuthrMakeCredResp1P06,
			marker: "P-06",
			name:   "Packed self attestation is valid",
			references: []conformance.RequirementRef{
				authrMakeCredResp1PackedReference(),
				authrMakeCredResp1MetadataReference(),
			},
			validate: validateMakeCredResp1P06,
		},
		{
			id:     TestIDAuthrMakeCredResp1F01,
			marker: "F-01",
			name:   "MakeCredential omits unsolicited unsigned extension outputs",
			references: []conformance.RequirementRef{
				authrMakeCredResp1UnsolicitedExtensionsReference(),
			},
			validate: validateMakeCredResp1F01,
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
			Description: "Validates packed MakeCredential response behavior for every metadata algorithm",
			Source: conformance.SourceLocation{
				Path: authrMakeCredResp1SourcePath,
				Case: definition.marker,
			},
			References:  references,
			Destructive: true,
			Run: func(test *conformance.TestContext) {
				var input makeCredResp1Input
				var responses []makeCredResp1Response
				var fixture makeCredentialFixture
				if !test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-resp-1." + strings.ToLower(definition.marker) + ".prepare"),
					Name:       "Create one isolated credential for every metadata algorithm",
					References: []conformance.RequirementRef{commandReference},
					Run: func(ctx context.Context) error {
						var err error
						input, responses, fixture, err = prepareMakeCredResp1Responses(
							ctx,
							test,
							config,
						)

						return err
					},
				}) {
					return
				}
				defer fixture.clear()

				test.Step(conformance.Step{
					ID:         conformance.StepID("make-cred-resp-1." + strings.ToLower(definition.marker) + ".validate"),
					Name:       "Validate every applicable response",
					References: references,
					Run: func(context.Context) error {
						return aggregateMakeCredResp1Responses(input, responses, definition.validate)
					},
				})
			},
		})
	}

	return tests
}

func prepareMakeCredResp1Responses(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
) (makeCredResp1Input, []makeCredResp1Response, makeCredentialFixture, error) {
	input, err := parseMakeCredResp1Input(config.Metadata.StatementJSON)
	if err != nil {
		return makeCredResp1Input{}, nil, makeCredentialFixture{}, err
	}

	fixture, err := prepareMakeCredentialFixture(ctx, test, config, authrMakeCredResp1RPID)
	if err != nil {
		return makeCredResp1Input{}, nil, makeCredentialFixture{}, err
	}
	input.info = fixture.Info

	responses := make([]makeCredResp1Response, 0, len(input.algorithms))
	for index, algorithm := range input.algorithms {
		request := fixture.Request
		request.PubKeyCredParams = []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.Algorithm(algorithm.profile.Algorithm),
		}}
		request.AttestationFormatsPreference = []attestation.AttestationStatementFormatIdentifier{
			attestation.AttestationStatementFormatIdentifierPacked,
		}
		if index != 0 {
			if err := refreshMakeCredResp1Authorization(
				ctx,
				test,
				config,
				&fixture,
				&request,
			); err != nil {
				fixture.clear()

				return makeCredResp1Input{}, nil, makeCredentialFixture{}, err
			}
		}

		wireResponse, err := exchangeMakeCredential(ctx, test.CBOR(), request)
		if err != nil {
			fixture.clear()

			return makeCredResp1Input{}, nil, makeCredentialFixture{}, unexpectedCTAPStatus(
				"authenticatorMakeCredential",
				err,
			)
		}
		response, err := decodeMakeCredentialResponse(wireResponse.Data)
		if err != nil {
			fixture.clear()

			return makeCredResp1Input{}, nil, makeCredentialFixture{}, err
		}
		var fields map[uint64]cbor.RawMessage
		if err := getInfoDecMode.Unmarshal(wireResponse.Data, &fields); err != nil {
			fixture.clear()

			return makeCredResp1Input{}, nil, makeCredentialFixture{}, conformance.Failf(
				"invalid authenticatorMakeCredential response CBOR: %v",
				err,
			)
		}
		responses = append(responses, makeCredResp1Response{
			algorithm: algorithm,
			request:   request,
			fields:    fields,
			response:  response,
		})
	}

	return input, responses, fixture, nil
}

func parseMakeCredResp1Input(statementJSON string) (makeCredResp1Input, error) {
	statement, err := parseMetadataStatement(statementJSON)
	if err != nil {
		return makeCredResp1Input{}, conformance.Failf("invalid metadata statement: %v", err)
	}
	aaguidText, err := requiredMetadataValue[string](statement, "aaguid")
	if err != nil {
		return makeCredResp1Input{}, err
	}
	aaguid, err := uuid.Parse(aaguidText)
	if err != nil {
		return makeCredResp1Input{}, conformance.Failf("metadata aaguid is invalid: %v", err)
	}
	algorithmNames, err := requiredMetadataValue[[]string](statement, "authenticationAlgorithms")
	if err != nil {
		return makeCredResp1Input{}, err
	}
	if len(algorithmNames) == 0 {
		return makeCredResp1Input{}, conformance.Fail("metadata authenticationAlgorithms must not be empty")
	}

	algorithms, err := resolveMetadataCOSEAlgorithms(algorithmNames)
	if err != nil {
		return makeCredResp1Input{}, err
	}

	return makeCredResp1Input{
		statement:  statement,
		aaguid:     aaguid,
		algorithms: algorithms,
	}, nil
}

func refreshMakeCredResp1Authorization(
	ctx context.Context,
	test *conformance.TestContext,
	config Config,
	fixture *makeCredentialFixture,
	request *protocol.AuthenticatorMakeCredentialRequest,
) error {
	fixture.clear()
	request.PinUvAuthParam = nil
	request.PinUvAuthProtocol = 0
	if !fixtureNeedsAuthorization(fixture.Info) {
		return nil
	}
	if config.TokenProvider == nil {
		return fmt.Errorf("ctap23: PIN/UV token provider is required for MakeCredential response tests")
	}

	authorization, err := config.TokenProvider(ctx, test.Client(), PinUvAuthTokenRequest{
		Permission: protocol.PermissionMakeCredential,
		RPID:       request.RP.ID,
	})
	if err != nil {
		clear(authorization.Value)

		return err
	}
	if err := validatePinUvAuthorization(fixture.Info, authorization); err != nil {
		clear(authorization.Value)

		return err
	}

	fixture.Authorization = authorization
	request.PinUvAuthParam = ctapcrypto.Authenticate(
		authorization.Protocol,
		authorization.Value,
		request.ClientDataHash,
	)
	request.PinUvAuthProtocol = authorization.Protocol

	return nil
}

func aggregateMakeCredResp1Responses(
	input makeCredResp1Input,
	responses []makeCredResp1Response,
	validate func(makeCredResp1Input, makeCredResp1Response) (bool, error),
) error {
	applicable := 0
	for _, response := range responses {
		applies, err := validate(input, response)
		if err != nil {
			return fmt.Errorf("metadata algorithm %s: %w", response.algorithm.name, err)
		}
		if applies {
			applicable++
		}
	}
	if applicable == 0 {
		return conformance.Skip("no metadata algorithm produced applicable packed attestation evidence")
	}

	return nil
}

func validateMakeCredResp1P01(
	input makeCredResp1Input,
	response makeCredResp1Response,
) (bool, error) {
	if !hasCBORMajorType(response.fields[1], 3) {
		return true, conformance.Fail("MakeCredential response fmt is not a CBOR text string")
	}
	if response.response.Format == attestation.AttestationStatementFormatIdentifierPacked {
		return true, nil
	}
	if slices.Contains(
		input.info.AttestationFormats,
		attestation.AttestationStatementFormatIdentifierPacked,
	) {
		return true, conformance.Failf(
			"MakeCredential returned format %q despite advertising packed",
			response.response.Format,
		)
	}

	return false, nil
}

func validateMakeCredResp1P02(
	input makeCredResp1Input,
	response makeCredResp1Response,
) (bool, error) {
	if !hasCBORMajorType(response.fields[2], 2) {
		return true, conformance.Fail("MakeCredential response authData is not a CBOR byte string")
	}
	authData := response.response.AuthData
	if authData == nil || authData.AttestedCredentialData == nil {
		return true, conformance.Fail("MakeCredential authData has no attested credential data")
	}
	if !bytes.Equal(authData.RPIDHash, sha256Bytes(response.request.RP.ID)) {
		return true, conformance.Fail("MakeCredential authData RP ID hash does not match the request")
	}
	if authData.AttestedCredentialData.AAGUID != input.aaguid {
		return true, conformance.Fail("MakeCredential authData AAGUID does not match metadata")
	}
	if !authData.Flags.UserPresent() {
		return true, conformance.Fail("MakeCredential authData UP flag is not set")
	}
	if !authData.Flags.AttestedCredentialDataIncluded() {
		return true, conformance.Fail("MakeCredential authData AT flag is not set")
	}
	if authData.Flags.ExtensionDataIncluded() {
		return true, conformance.Fail("MakeCredential authData ED flag is set without requested extensions")
	}
	credentialID := authData.AttestedCredentialData.CredentialID
	if len(credentialID) > 1023 {
		return true, conformance.Failf("MakeCredential credential ID is %d bytes, want at most 1023", len(credentialID))
	}

	keyRaw, err := makeCredResp1CredentialKeyRaw(response.response.AuthDataRaw)
	if err != nil {
		return true, err
	}
	if err := validateCanonicalCTAP2Response("credential public key", keyRaw); err != nil {
		return true, err
	}
	if err := validateCredentialPublicKeyProfile(
		authData.AttestedCredentialData.CredentialPublicKey,
		keyRaw,
		response.algorithm,
	); err != nil {
		return true, err
	}

	return true, nil
}

func validateMakeCredResp1P03(
	input makeCredResp1Input,
	response makeCredResp1Response,
) (bool, error) {
	applicable, err := makeCredResp1PackedApplicable(input.info, response.response.Format)
	if err != nil || !applicable {
		return applicable, err
	}

	statement, hasX5C, _, err := parseMakeCredResp1PackedStatement(response)
	if err != nil {
		return true, err
	}
	if !hasX5C {
		if response.response.AuthData == nil || response.response.AuthData.AttestedCredentialData == nil {
			return true, conformance.Fail("MakeCredential authData has no attested credential data")
		}
		credentialAlgorithm, err := response.response.AuthData.AttestedCredentialData.CredentialPublicKey.Algorithm()
		if err != nil {
			return true, conformance.Failf("invalid credential public key algorithm: %v", err)
		}
		if statement.Algorithm != credentialAlgorithm {
			return true, conformance.Failf(
				"self attestation algorithm %d does not match credential algorithm %d",
				statement.Algorithm,
				credentialAlgorithm,
			)
		}
	}

	return true, nil
}

func validateMakeCredResp1P04(
	input makeCredResp1Input,
	response makeCredResp1Response,
) (bool, error) {
	applicable, err := makeCredResp1PackedApplicable(input.info, response.response.Format)
	if err != nil || !applicable {
		return applicable, err
	}
	hasX5C, _, err := makeCredResp1RawX5C(response)
	if err != nil {
		return true, err
	}
	if !hasX5C {
		return false, nil
	}
	statement, _, rawX5C, err := parseMakeCredResp1PackedStatement(response)
	if err != nil {
		return true, err
	}
	if err := validateMakeCredResp1X5CWire(rawX5C, statement.X509Chain); err != nil {
		return true, err
	}
	if err := requireMakeCredResp1AttestationType(
		input.statement,
		registry.AttestationTypeBasicFull,
	); err != nil {
		return true, err
	}

	verification, err := attestation.VerifyPacked(
		statement,
		false,
		nil,
		0,
		slices.Concat(response.response.AuthDataRaw, response.request.ClientDataHash),
	)
	if err != nil {
		return true, classifyMakeCredResp1VerificationError(err)
	}
	if verification.Type != attestation.TypeBasic || verification.SignatureValid == nil ||
		!*verification.SignatureValid {
		return true, conformance.Fail("packed basic attestation signature is not valid")
	}
	chain, err := verifyMakeCredResp1CertificateChain(input.statement, statement.X509Chain)
	if err != nil {
		return true, err
	}
	if response.response.AuthData == nil || response.response.AuthData.AttestedCredentialData == nil {
		return true, conformance.Fail("MakeCredential authData has no attested credential data")
	}
	if err := validateMakeCredResp1LeafCertificate(
		chain[0],
		response.response.AuthData.AttestedCredentialData.AAGUID,
		time.Now(),
	); err != nil {
		return true, err
	}

	return true, nil
}

func validateMakeCredResp1P06(
	input makeCredResp1Input,
	response makeCredResp1Response,
) (bool, error) {
	applicable, err := makeCredResp1PackedApplicable(input.info, response.response.Format)
	if err != nil || !applicable {
		return applicable, err
	}
	hasX5C, rawX5C, err := makeCredResp1RawX5C(response)
	if err != nil {
		return true, err
	}
	if hasX5C {
		var chain []cbor.RawMessage
		if !hasCBORMajorType(rawX5C, 4) || getInfoDecMode.Unmarshal(rawX5C, &chain) != nil {
			return true, conformance.Fail("packed x5c is not a CBOR array")
		}
		if len(chain) == 0 {
			return true, conformance.Fail("packed x5c is present but empty")
		}

		return false, nil
	}
	statement, _, _, err := parseMakeCredResp1PackedStatement(response)
	if err != nil {
		return true, err
	}
	attestationTypes, err := makeCredResp1AttestationTypes(input.statement)
	if err != nil {
		return true, err
	}
	if !slices.Contains(attestationTypes, registry.AttestationTypeBasicSurrogate) {
		return true, conformance.Failf(
			"metadata attestationTypes does not contain one of %v",
			[]registry.AttestationType{registry.AttestationTypeBasicSurrogate},
		)
	}
	rootCertificates, err := requiredMetadataValue[[]string](
		input.statement,
		"attestationRootCertificates",
	)
	if err != nil {
		return true, err
	}
	if !slices.Contains(attestationTypes, registry.AttestationTypeBasicFull) &&
		len(rootCertificates) != 0 {
		return true, conformance.Fail(
			"metadata attestationRootCertificates must be empty for surrogate-only attestation",
		)
	}
	if response.response.AuthData == nil || response.response.AuthData.AttestedCredentialData == nil {
		return true, conformance.Fail("MakeCredential authData has no attested credential data")
	}

	credentialKey := response.response.AuthData.AttestedCredentialData.CredentialPublicKey
	publicKey, err := credentialKey.PublicKey()
	if err != nil {
		return true, conformance.Failf("invalid credential public key: %v", err)
	}
	credentialAlgorithm, err := credentialKey.Algorithm()
	if err != nil {
		return true, conformance.Failf("invalid credential public key algorithm: %v", err)
	}
	verification, err := attestation.VerifyPacked(
		statement,
		false,
		publicKey,
		credentialAlgorithm,
		slices.Concat(response.response.AuthDataRaw, response.request.ClientDataHash),
	)
	if err != nil {
		return true, classifyMakeCredResp1VerificationError(err)
	}
	if verification.Type != attestation.TypeSelf || verification.SignatureValid == nil ||
		!*verification.SignatureValid {
		return true, conformance.Fail("packed self-attestation signature is not valid")
	}

	return true, nil
}

func validateMakeCredResp1F01(
	_ makeCredResp1Input,
	response makeCredResp1Response,
) (bool, error) {
	if _, present := response.fields[6]; present {
		return true, conformance.Fail("MakeCredential returned unsolicited unsigned extension outputs")
	}

	return true, nil
}

func makeCredResp1PackedApplicable(
	info protocol.AuthenticatorGetInfoResponse,
	format attestation.AttestationStatementFormatIdentifier,
) (bool, error) {
	if format == attestation.AttestationStatementFormatIdentifierPacked {
		return true, nil
	}
	if slices.Contains(info.AttestationFormats, attestation.AttestationStatementFormatIdentifierPacked) {
		return true, conformance.Failf("MakeCredential returned format %q despite advertising packed", format)
	}

	return false, nil
}

func makeCredResp1CredentialKeyRaw(authData []byte) ([]byte, error) {
	if len(authData) < 55 {
		return nil, conformance.Fail("MakeCredential authData is missing attested credential data")
	}
	credentialIDLength := int(authData[53])<<8 | int(authData[54])
	offset := 55 + credentialIDLength
	if offset >= len(authData) {
		return nil, conformance.Fail("MakeCredential authData is missing credential public key")
	}

	return authData[offset:], nil
}

func parseMakeCredResp1PackedStatement(
	response makeCredResp1Response,
) (attestation.PackedAttestationStatementFormat, bool, cbor.RawMessage, error) {
	raw, present := response.fields[3]
	if !present || !hasCBORMajorType(raw, 5) {
		return attestation.PackedAttestationStatementFormat{}, false, nil, conformance.Fail(
			"packed response attStmt is missing or is not a CBOR map",
		)
	}
	var fields map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &fields); err != nil {
		return attestation.PackedAttestationStatementFormat{}, false, nil, conformance.Failf(
			"invalid packed attestation statement: %v",
			err,
		)
	}
	_, hasX5C := fields["x5c"]
	allowed := []string{"alg", "sig"}
	if hasX5C {
		allowed = append(allowed, "x5c")
	}
	if len(fields) != len(allowed) || slices.ContainsFunc(
		allowed,
		func(name string) bool { _, present := fields[name]; return !present },
	) {
		return attestation.PackedAttestationStatementFormat{}, hasX5C, fields["x5c"], conformance.Failf(
			"packed attestation statement fields are %v, want exactly %v",
			mapKeys(fields),
			allowed,
		)
	}
	if rawAlg := fields["alg"]; len(rawAlg) == 0 || rawAlg[0]>>5 > 1 {
		return attestation.PackedAttestationStatementFormat{}, hasX5C, fields["x5c"], conformance.Fail(
			"packed attestation alg is not a CBOR integer",
		)
	}
	if rawSignature := fields["sig"]; !hasCBORMajorType(rawSignature, 2) {
		return attestation.PackedAttestationStatementFormat{}, hasX5C, fields["x5c"], conformance.Fail(
			"packed attestation sig is not a CBOR byte string",
		)
	} else {
		var signature []byte
		if err := getInfoDecMode.Unmarshal(rawSignature, &signature); err != nil || len(signature) == 0 {
			return attestation.PackedAttestationStatementFormat{}, hasX5C, fields["x5c"], conformance.Fail(
				"packed attestation sig is empty",
			)
		}
	}
	if hasX5C && !hasCBORMajorType(fields["x5c"], 4) {
		return attestation.PackedAttestationStatementFormat{}, true, fields["x5c"], conformance.Fail(
			"packed attestation x5c is not a CBOR array",
		)
	}
	statement, ok := attestation.ParsePackedStatement(response.response.AttestationStatement)
	if !ok {
		return attestation.PackedAttestationStatementFormat{}, hasX5C, fields["x5c"], conformance.Fail(
			"packed attestation statement cannot be decoded",
		)
	}

	return statement, hasX5C, fields["x5c"], nil
}

func makeCredResp1RawX5C(response makeCredResp1Response) (bool, cbor.RawMessage, error) {
	raw, present := response.fields[3]
	if !present || !hasCBORMajorType(raw, 5) {
		return false, nil, conformance.Fail("packed response attStmt is missing or is not a CBOR map")
	}
	var fields map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &fields); err != nil {
		return false, nil, conformance.Failf("invalid packed attestation statement: %v", err)
	}
	rawX5C, present := fields["x5c"]

	return present, rawX5C, nil
}

func validateMakeCredResp1X5CWire(raw cbor.RawMessage, chain [][]byte) error {
	if !hasCBORMajorType(raw, 4) {
		return conformance.Fail("packed x5c is not a CBOR array")
	}
	var values []cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &values); err != nil {
		return conformance.Failf("invalid packed x5c: %v", err)
	}
	if len(values) == 0 || len(chain) == 0 {
		return conformance.Fail("packed x5c is present but empty")
	}
	for index, value := range values {
		if !hasCBORMajorType(value, 2) {
			return conformance.Failf("packed x5c certificate %d is not a CBOR byte string", index)
		}
	}

	return nil
}

func requireMakeCredResp1AttestationType(
	statement metadataStatement,
	want ...registry.AttestationType,
) error {
	types, err := makeCredResp1AttestationTypes(statement)
	if err != nil {
		return err
	}
	for _, value := range want {
		if slices.Contains(types, value) {
			return nil
		}
	}

	return conformance.Failf("metadata attestationTypes does not contain one of %v", want)
}

func makeCredResp1AttestationTypes(
	statement metadataStatement,
) ([]registry.AttestationType, error) {
	names, err := requiredMetadataValue[[]string](statement, "attestationTypes")
	if err != nil {
		return nil, err
	}
	types := make([]registry.AttestationType, 0, len(names))
	for _, name := range names {
		value, ok := registry.ParseAttestationType(name)
		if !ok {
			return nil, conformance.Failf(
				"metadata attestationTypes contains unregistered value %q",
				name,
			)
		}
		types = append(types, value)
	}

	return types, nil
}

func verifyMakeCredResp1CertificateChain(
	statement metadataStatement,
	wireChain [][]byte,
) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(wireChain))
	for index, encoded := range wireChain {
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil {
			return nil, conformance.Failf("parse packed x5c certificate %d: %v", index, err)
		}
		chain = append(chain, certificate)
	}
	rootValues, err := requiredMetadataValue[[]string](statement, "attestationRootCertificates")
	if err != nil {
		return nil, err
	}
	if len(rootValues) == 0 {
		return nil, conformance.Fail("metadata attestationRootCertificates must not be empty")
	}
	roots := x509.NewCertPool()
	for index, value := range rootValues {
		encoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, conformance.Failf("decode metadata attestation root %d: %v", index, err)
		}
		root, err := x509.ParseCertificate(encoded)
		if err != nil {
			return nil, conformance.Failf("parse metadata attestation root %d: %v", index, err)
		}
		roots.AddCert(root)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, conformance.Failf("packed x5c does not chain to a metadata root: %v", err)
	}

	return chain, nil
}

func validateMakeCredResp1LeafCertificate(
	certificate *x509.Certificate,
	aaguid uuid.UUID,
	now time.Time,
) error {
	if certificate.Version != 3 {
		return conformance.Failf("packed attestation certificate version is %d, want 3", certificate.Version)
	}
	if !certificate.BasicConstraintsValid || certificate.IsCA {
		return conformance.Fail("packed attestation certificate basicConstraints must set CA=false")
	}
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return conformance.Fail("packed attestation certificate is not currently valid")
	}
	attributes, err := makeCredResp1SubjectAttributes(certificate.RawSubject)
	if err != nil {
		return conformance.Failf("decode packed attestation certificate subject: %v", err)
	}
	country, err := requireMakeCredResp1SubjectAttribute(attributes, oidCountryName, asn1.TagPrintableString, "C")
	if err != nil {
		return err
	}
	if len(country) != 2 {
		return conformance.Fail("packed attestation certificate C is not an ISO 3166-1 alpha-2 code")
	}
	region, err := language.ParseRegion(country)
	if err != nil || region.String() != country || !region.IsCountry() || region.IsPrivateUse() {
		return conformance.Failf("packed attestation certificate C is not an ISO 3166-1 alpha-2 code: %q", country)
	}
	organization, err := requireMakeCredResp1SubjectAttribute(
		attributes,
		oidOrganizationName,
		asn1.TagUTF8String,
		"O",
	)
	if err != nil {
		return err
	}
	if organization == "" {
		return conformance.Fail("packed attestation certificate O must not be empty")
	}
	unit, err := requireMakeCredResp1SubjectAttribute(
		attributes,
		oidOrganizationalUnitName,
		asn1.TagUTF8String,
		"OU",
	)
	if err != nil {
		return err
	}
	if unit != "Authenticator Attestation" {
		return conformance.Fail("packed attestation certificate OU must be Authenticator Attestation")
	}
	commonName, err := requireMakeCredResp1SubjectAttribute(
		attributes,
		oidCommonName,
		asn1.TagUTF8String,
		"CN",
	)
	if err != nil {
		return err
	}
	if commonName == "" {
		return conformance.Fail("packed attestation certificate CN must not be empty")
	}
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidFIDOAAGUID) {
			continue
		}
		if extension.Critical {
			return conformance.Fail("packed attestation certificate AAGUID extension is critical")
		}
		var encoded []byte
		rest, err := asn1.Unmarshal(extension.Value, &encoded)
		if err != nil || len(rest) != 0 || !bytes.Equal(encoded, aaguid[:]) {
			return conformance.Fail("packed attestation certificate AAGUID extension does not match authData")
		}
	}

	return nil
}

type makeCredResp1SubjectAttribute struct {
	oid   asn1.ObjectIdentifier
	value asn1.RawValue
}

func makeCredResp1SubjectAttributes(raw []byte) ([]makeCredResp1SubjectAttribute, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &sequence)
	if err != nil || len(rest) != 0 || sequence.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("invalid subject sequence")
	}

	var attributes []makeCredResp1SubjectAttribute
	sets := sequence.Bytes
	for len(sets) != 0 {
		var set asn1.RawValue
		sets, err = asn1.Unmarshal(sets, &set)
		if err != nil || set.Tag != asn1.TagSet {
			return nil, fmt.Errorf("invalid relative distinguished name")
		}
		values := set.Bytes
		for len(values) != 0 {
			var encoded asn1.RawValue
			values, err = asn1.Unmarshal(values, &encoded)
			if err != nil || encoded.Tag != asn1.TagSequence {
				return nil, fmt.Errorf("invalid subject attribute")
			}
			var attribute struct {
				OID   asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			if trailing, err := asn1.Unmarshal(encoded.FullBytes, &attribute); err != nil || len(trailing) != 0 {
				return nil, fmt.Errorf("invalid subject attribute value")
			}
			attributes = append(attributes, makeCredResp1SubjectAttribute{
				oid:   attribute.OID,
				value: attribute.Value,
			})
		}
	}

	return attributes, nil
}

func requireMakeCredResp1SubjectAttribute(
	attributes []makeCredResp1SubjectAttribute,
	oid asn1.ObjectIdentifier,
	tag int,
	name string,
) (string, error) {
	for _, attribute := range attributes {
		if !attribute.oid.Equal(oid) {
			continue
		}
		if attribute.value.Tag != tag {
			return "", conformance.Failf("packed attestation certificate %s has the wrong ASN.1 string type", name)
		}

		return string(attribute.value.Bytes), nil
	}

	return "", conformance.Failf("packed attestation certificate subject is missing %s", name)
}

func classifyMakeCredResp1VerificationError(err error) error {
	if errors.Is(err, attestation.ErrAlgorithmUnsupported) ||
		errors.Is(err, cose.ErrUnsupportedAlgorithm) ||
		errors.Is(err, cose.ErrUnsupportedKey) {
		return fmt.Errorf("ctap23: packed attestation crypto profile is unsupported: %w", err)
	}

	return conformance.Failf("packed attestation verification failed: %v", err)
}

func sha256Bytes(value string) []byte {
	digest := sha256.Sum256([]byte(value))

	return digest[:]
}

func mapKeys[K comparable, V any](values map[K]V) []K {
	keys := make([]K, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	return keys
}

func authrMakeCredResp1PackedSelectionReference() conformance.RequirementRef {
	return makeCredResp1Reference(
		"ctap-2.3-ps-20260226:6.1.2:packed-format-preference",
		conformance.SpecificationCTAP23,
		"6.1.2",
		"packed-format-preference",
		"https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		conformance.RequirementMust,
	)
}

func authrMakeCredResp1AuthDataReference() conformance.RequirementRef {
	return makeCredResp1Reference(
		"webauthn-3:6.1:authenticator-data",
		conformance.SpecificationID("webauthn-level-3"),
		"6.1",
		"authenticator-data",
		"https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data",
		conformance.RequirementMust,
	)
}

func authrMakeCredResp1AttestedCredentialReference() conformance.RequirementRef {
	return makeCredResp1Reference(
		"webauthn-3:6.5.1:attested-credential-data",
		conformance.SpecificationID("webauthn-level-3"),
		"6.5.1",
		"attested-credential-data",
		"https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data",
		conformance.RequirementMust,
	)
}

func authrMakeCredResp1PackedReference() conformance.RequirementRef {
	return makeCredResp1Reference(
		"webauthn-3:8.2:packed-attestation",
		conformance.SpecificationID("webauthn-level-3"),
		"8.2",
		"packed-attestation",
		"https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation",
		conformance.RequirementMust,
	)
}

func authrMakeCredResp1PackedCertificateReference() conformance.RequirementRef {
	return makeCredResp1Reference(
		"webauthn-3:8.2.1:packed-attestation-certificate",
		conformance.SpecificationID("webauthn-level-3"),
		"8.2.1",
		"packed-attestation-certificate",
		"https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements",
		conformance.RequirementMust,
	)
}

func authrMakeCredResp1MetadataReference() conformance.RequirementRef {
	return makeCredResp1Reference(
		"fido-mds-3.1.1:4:metadata-statement",
		metadataStatementSpecification,
		"4",
		"metadata-statement",
		metadataStatementURL+"#metadata-statement",
		conformance.RequirementConstraint,
	)
}

func authrMakeCredResp1RegistryReference() conformance.RequirementRef {
	return makeCredResp1Reference(
		"fido-registry-2.3:3.6.1:authentication-algorithms",
		fidoRegistrySpecification,
		"3.6.1/3.7",
		"authentication-algorithms-and-cose",
		"https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps.html#authentication-algorithms",
		conformance.RequirementConstraint,
	)
}

func authrMakeCredResp1UnsolicitedExtensionsReference() conformance.RequirementRef {
	return makeCredResp1Reference(
		"ctap-2.3-ps-20260226:6.1:unsolicited-extension-outputs",
		conformance.SpecificationCTAP23,
		"6.1",
		"unsolicited-extension-outputs",
		"https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential",
		conformance.RequirementShould,
	)
}

func makeCredResp1Reference(
	id conformance.RequirementID,
	specification conformance.SpecificationID,
	section string,
	clause string,
	url string,
	level conformance.RequirementLevel,
) conformance.RequirementRef {
	return conformance.RequirementRef{
		ID:            id,
		Specification: specification,
		Section:       section,
		Clause:        clause,
		URL:           url,
		Level:         level,
	}
}
