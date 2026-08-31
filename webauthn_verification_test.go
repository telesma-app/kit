package ctapkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
	"uuid"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func TestVerifyMakeCredentialAttestationFormats(t *testing.T) {
	tests := []struct {
		name          string
		format        attestation.AttestationStatementFormatIdentifier
		basic         bool
		corrupt       bool
		wantStatus    appwebauthn.VerificationStatus
		wantType      appwebauthn.AttestationType
		wantSignature *bool
		wantIssue     appwebauthn.VerificationIssueCode
	}{
		{
			name:       "none",
			format:     attestation.AttestationStatementFormatIdentifierNone,
			wantStatus: appwebauthn.VerificationStatusVerified,
			wantType:   appwebauthn.AttestationTypeNone,
		},
		{
			name:          "packed self",
			format:        attestation.AttestationStatementFormatIdentifierPacked,
			wantStatus:    appwebauthn.VerificationStatusVerified,
			wantType:      appwebauthn.AttestationTypeSelf,
			wantSignature: boolPointer(true),
		},
		{
			name:          "packed basic",
			format:        attestation.AttestationStatementFormatIdentifierPacked,
			basic:         true,
			wantStatus:    appwebauthn.VerificationStatusVerified,
			wantType:      appwebauthn.AttestationTypeBasic,
			wantSignature: boolPointer(true),
		},
		{
			name:          "fido u2f",
			format:        attestation.AttestationStatementFormatIdentifierFIDOU2F,
			wantStatus:    appwebauthn.VerificationStatusVerified,
			wantType:      appwebauthn.AttestationTypeBasic,
			wantSignature: boolPointer(true),
		},
		{
			name:          "invalid packed signature",
			format:        attestation.AttestationStatementFormatIdentifierPacked,
			corrupt:       true,
			wantStatus:    appwebauthn.VerificationStatusFailed,
			wantType:      appwebauthn.AttestationTypeSelf,
			wantSignature: boolPointer(false),
			wantIssue:     appwebauthn.VerificationIssueAttestationSignatureInvalid,
		},
		{
			name:       "unsupported format",
			format:     attestation.AttestationStatementFormatIdentifierTPM,
			wantStatus: appwebauthn.VerificationStatusUnavailable,
			wantType:   appwebauthn.AttestationTypeUnsupported,
			wantIssue:  appwebauthn.VerificationIssueAttestationFormatUnsupported,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, result := makeCredentialVector(t, test.format, test.basic, test.corrupt)
			verification := VerifyMakeCredential(input, result)

			if verification.Status != test.wantStatus {
				t.Fatalf("status = %q, want %q; issues = %v", verification.Status, test.wantStatus, verification.Issues)
			}
			if verification.AttestationType != test.wantType {
				t.Fatalf("attestation type = %q, want %q", verification.AttestationType, test.wantType)
			}
			if !equalOptionalBool(verification.SignatureValid, test.wantSignature) {
				t.Fatalf("signature valid = %v, want %v", verification.SignatureValid, test.wantSignature)
			}
			if test.wantIssue != "" && !containsIssue(verification.Issues, test.wantIssue) {
				t.Fatalf("issues = %v, want %q", verification.Issues, test.wantIssue)
			}
		})
	}
}

func TestVerifyMakeCredentialCorrelatesInputAndResult(t *testing.T) {
	input, result := makeCredentialVector(
		t,
		attestation.AttestationStatementFormatIdentifierNone,
		false,
		false,
	)
	result.RPID = "other.example"
	result.CredentialIDHex = "00"
	input.Options.UserVerification = boolPointer(true)

	verification := VerifyMakeCredential(input, result)
	if verification.Status != appwebauthn.VerificationStatusFailed {
		t.Fatalf("status = %q, want failed", verification.Status)
	}
	for _, issue := range []appwebauthn.VerificationIssueCode{
		appwebauthn.VerificationIssueResultRPIDMismatch,
		appwebauthn.VerificationIssueResultMismatch,
		appwebauthn.VerificationIssueUserVerificationMissing,
	} {
		if !containsIssue(verification.Issues, issue) {
			t.Fatalf("issues = %v, want %q", verification.Issues, issue)
		}
	}
}

func TestVerifyGetAssertionStatusesAndCounter(t *testing.T) {
	previous := uint32(3)
	input, result, material := assertionVector(t, &previous)
	verified := VerifyGetAssertion(input, result, material)
	if verified.Status != appwebauthn.VerificationStatusVerified {
		t.Fatalf("verified status = %q, issues = %v", verified.Status, verified.Issues)
	}
	assertion := verified.Assertions[0]
	if assertion.SignatureValid == nil || !*assertion.SignatureValid {
		t.Fatalf("signature valid = %v, want true", assertion.SignatureValid)
	}
	if assertion.SignCount != appwebauthn.SignCountStatusAdvanced {
		t.Fatalf("sign count = %q, want advanced", assertion.SignCount)
	}

	missing := VerifyGetAssertion(input, result, nil)
	if missing.Status != appwebauthn.VerificationStatusUnavailable ||
		!containsIssue(missing.Assertions[0].Issues, appwebauthn.VerificationIssueVerificationMaterialMissing) {
		t.Fatalf("missing material result = %+v", missing)
	}

	result.Assertions[0].SignatureHex = "00"
	failed := VerifyGetAssertion(input, result, material)
	if failed.Status != appwebauthn.VerificationStatusFailed ||
		failed.Assertions[0].SignatureValid == nil ||
		*failed.Assertions[0].SignatureValid {
		t.Fatalf("invalid signature result = %+v", failed)
	}
}

func TestVerifyGetAssertionCounterWarningDoesNotFailVerification(t *testing.T) {
	previous := uint32(4)
	input, result, material := assertionVector(t, &previous)
	verification := VerifyGetAssertion(input, result, material)

	if verification.Status != appwebauthn.VerificationStatusVerified {
		t.Fatalf("status = %q, want verified", verification.Status)
	}
	assertion := verification.Assertions[0]
	if assertion.SignCount != appwebauthn.SignCountStatusNotAdvanced {
		t.Fatalf("sign count = %q, want not_advanced", assertion.SignCount)
	}
	if !containsIssue(assertion.Warnings, appwebauthn.VerificationWarningSignCountNotAdvanced) {
		t.Fatalf("warnings = %v", assertion.Warnings)
	}
}

func TestVerifyGetAssertionAggregatesFailedBeforeUnavailable(t *testing.T) {
	input, result, material := assertionVector(t, nil)
	second := result.Assertions[0]
	second.Index = 1
	second.Credential.ID = []byte("missing")
	result.Assertions[0].SignatureHex = "00"
	result.Assertions = append(result.Assertions, second)
	result.Assertions[0].NumberOfCredentials = 2

	verification := VerifyGetAssertion(input, result, material)
	if verification.Status != appwebauthn.VerificationStatusFailed {
		t.Fatalf("status = %q, want failed; assertions = %+v", verification.Status, verification.Assertions)
	}
	if verification.Assertions[0].Status != appwebauthn.VerificationStatusFailed ||
		verification.Assertions[1].Status != appwebauthn.VerificationStatusUnavailable {
		t.Fatalf("assertion statuses = %q, %q", verification.Assertions[0].Status, verification.Assertions[1].Status)
	}
}

func makeCredentialVector(
	t *testing.T,
	format attestation.AttestationStatementFormatIdentifier,
	basic bool,
	corrupt bool,
) (appwebauthn.MakeCredentialInput, appwebauthn.MakeCredentialResult) {
	t.Helper()

	const rpID = "example.com"
	clientData := []byte(`{"challenge":"not interpreted"}`)
	credentialKey, coseRaw := p256Credential(t)
	credentialID := []byte("credential-id")
	authData := makeCredentialAuthData(rpID, credentialID, coseRaw)
	clientDataHash := sha256.Sum256(clientData)
	statement := make(map[string]any)

	switch format {
	case attestation.AttestationStatementFormatIdentifierPacked:
		signingKey := credentialKey
		if basic {
			signingKey = generateP256Key(t)
			statement["x5c"] = [][]byte{certificateDER(t, signingKey)}
		}
		message := append(append([]byte(nil), authData...), clientDataHash[:]...)
		statement["alg"] = int64(cose.AlgorithmES256)
		statement["sig"] = signECDSA(t, signingKey, message, corrupt)
	case attestation.AttestationStatementFormatIdentifierFIDOU2F:
		attestationKey := generateP256Key(t)
		encodedKey, err := credentialKey.PublicKey.Bytes()
		if err != nil {
			t.Fatalf("encode credential public key: %v", err)
		}
		rpIDHash := sha256.Sum256([]byte(rpID))
		message := make([]byte, 0, 1+len(rpIDHash)+len(clientDataHash)+len(credentialID)+len(encodedKey))
		message = append(message, 0)
		message = append(message, rpIDHash[:]...)
		message = append(message, clientDataHash[:]...)
		message = append(message, credentialID...)
		message = append(message, encodedKey...)
		statement["x5c"] = [][]byte{certificateDER(t, attestationKey)}
		statement["sig"] = signECDSA(t, attestationKey, message, corrupt)
	}

	objectRaw, err := cbor.Marshal(map[string]any{
		"fmt":      format,
		"authData": authData,
		"attStmt":  statement,
	})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}

	input := appwebauthn.MakeCredentialInput{
		RP:             credential.PublicKeyCredentialRpEntity{ID: rpID},
		ClientDataJSON: clientData,
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
	}
	result := appwebauthn.MakeCredentialResult{
		RPID:                     rpID,
		Format:                   format,
		CredentialIDHex:          hex.EncodeToString(credentialID),
		PublicKeyCOSEHex:         hex.EncodeToString(coseRaw),
		AuthenticatorDataHex:     hex.EncodeToString(authData),
		AttestationObjectCBORHex: hex.EncodeToString(objectRaw),
		AAGUID:                   uuid.Nil().String(),
		UserPresent:              true,
	}
	return input, result
}

func assertionVector(
	t *testing.T,
	previous *uint32,
) (
	appwebauthn.GetAssertionInput,
	appwebauthn.GetAssertionResult,
	[]appwebauthn.CredentialVerificationMaterial,
) {
	t.Helper()

	const rpID = "example.com"
	clientData := []byte(`{"origin":"not interpreted"}`)
	credentialKey, coseRaw := p256Credential(t)
	credentialID := []byte("credential-id")
	authData := assertionAuthData(rpID, 4)
	clientDataHash := sha256.Sum256(clientData)
	message := append(append([]byte(nil), authData...), clientDataHash[:]...)
	signature := signECDSA(t, credentialKey, message, false)

	input := appwebauthn.GetAssertionInput{
		RPID:           rpID,
		ClientDataJSON: clientData,
	}
	result := appwebauthn.GetAssertionResult{
		RPID: rpID,
		Assertions: []appwebauthn.Assertion{{
			Credential: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   credentialID,
			},
			AuthenticatorDataHex: hex.EncodeToString(authData),
			SignatureHex:         hex.EncodeToString(signature),
			NumberOfCredentials:  1,
			SignCount:            4,
			UserPresent:          true,
		}},
	}
	material := []appwebauthn.CredentialVerificationMaterial{{
		CredentialIDHex:   hex.EncodeToString(credentialID),
		PublicKeyCOSEHex:  hex.EncodeToString(coseRaw),
		PreviousSignCount: previous,
	}}

	return input, result, material
}

func p256Credential(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	key := generateP256Key(t)
	encoded, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode P-256 public key: %v", err)
	}
	coseKey := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   append([]byte(nil), encoded[1:33]...),
		cose.EC2KeyParameterY:   append([]byte(nil), encoded[33:]...),
	}
	raw, err := cbor.Marshal(coseKey)
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}

	return key, raw
}

func makeCredentialAuthData(rpID string, credentialID, coseKey []byte) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37, 37+16+2+len(credentialID)+len(coseKey))
	copy(authData, rpIDHash[:])
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagAttestedCredentialDataIncluded)
	authData = append(authData, make([]byte, 16)...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(credentialID)))
	authData = append(authData, length...)
	authData = append(authData, credentialID...)
	authData = append(authData, coseKey...)

	return authData
}

func assertionAuthData(rpID string, signCount uint32) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData, rpIDHash[:])
	authData[32] = byte(protocol.AuthDataFlagUserPresent)
	binary.BigEndian.PutUint32(authData[33:], signCount)

	return authData
}

func generateP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}

	return key
}

func signECDSA(t *testing.T, key *ecdsa.PrivateKey, message []byte, corrupt bool) []byte {
	t.Helper()

	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	if corrupt {
		signature[len(signature)-1] ^= 1
	}

	return signature
}

func certificateDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test attestation"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return der
}

func boolPointer(value bool) *bool {
	return &value
}

func equalOptionalBool(left, right *bool) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func containsIssue(issues []appwebauthn.VerificationIssueCode, want appwebauthn.VerificationIssueCode) bool {
	for _, issue := range issues {
		if issue == want {
			return true
		}
	}

	return false
}
