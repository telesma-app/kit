package ctapkit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/protocol"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func VerifyMakeCredential(
	input appwebauthn.MakeCredentialInput,
	result appwebauthn.MakeCredentialResult,
) appwebauthn.MakeCredentialVerification {
	outcome := newVerificationOutcome()
	verification := appwebauthn.MakeCredentialVerification{
		Status:            appwebauthn.VerificationStatusVerified,
		AttestationFormat: result.Format,
		AttestationType:   appwebauthn.AttestationTypeUnsupported,
	}

	if result.RPID != input.RP.ID {
		outcome.fail(appwebauthn.VerificationIssueResultRPIDMismatch)
	}

	authDataRaw, err := hex.DecodeString(result.AuthenticatorDataHex)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueResultMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}
	authData, err := protocol.ParseMakeCredentialAuthData(authDataRaw)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueAuthenticatorDataMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}

	expectedRPIDHash := sha256.Sum256([]byte(input.RP.ID))
	verification.RPIDHashMatches = bytes.Equal(authData.RPIDHash, expectedRPIDHash[:])
	if !verification.RPIDHashMatches {
		outcome.fail(appwebauthn.VerificationIssueRPIDHashMismatch)
	}
	verification.UserPresenceRequirementMet = requirementMet(
		optionRequired(input.Options.UserPresence, true),
		authData.Flags.UserPresent(),
	)
	if !verification.UserPresenceRequirementMet {
		outcome.fail(appwebauthn.VerificationIssueUserPresenceMissing)
	}
	verification.UserVerificationRequirementMet = requirementMet(
		optionRequired(input.Options.UserVerification, false),
		authData.Flags.UserVerified(),
	)
	if !verification.UserVerificationRequirementMet {
		outcome.fail(appwebauthn.VerificationIssueUserVerificationMissing)
	}

	if authData.AttestedCredentialData == nil {
		outcome.fail(appwebauthn.VerificationIssueAttestedCredentialDataMissing)
		return finishMakeCredentialVerification(verification, outcome)
	}
	attested := authData.AttestedCredentialData
	if !makeCredentialResultMatches(result, authData, attested.CredentialID, attested.CredentialPublicKey) {
		outcome.fail(appwebauthn.VerificationIssueResultMismatch)
	}

	algorithm, err := attested.CredentialPublicKey.Algorithm()
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueCredentialKeyMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}
	verification.CredentialAlgorithmAllowed = algorithmAllowed(input.PubKeyCredParams, algorithm)
	if !verification.CredentialAlgorithmAllowed {
		outcome.fail(appwebauthn.VerificationIssueCredentialAlgorithmDisallowed)
	}

	credentialPublicKey, err := attested.CredentialPublicKey.PublicKey()
	if err != nil {
		if unsupportedCrypto(err) {
			outcome.unavailable(appwebauthn.VerificationIssueCredentialAlgorithmUnsupported)
		} else {
			outcome.fail(appwebauthn.VerificationIssueCredentialKeyMalformed)
		}
		return finishMakeCredentialVerification(verification, outcome)
	}

	objectRaw, err := hex.DecodeString(result.AttestationObjectCBORHex)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueAttestationObjectMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}
	object, err := attestation.ParseObject(objectRaw)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueAttestationObjectMalformed)
		return finishMakeCredentialVerification(verification, outcome)
	}
	if object.Format != result.Format || !bytes.Equal(object.AuthData, authDataRaw) {
		outcome.fail(appwebauthn.VerificationIssueAttestationObjectMismatch)
	}
	verification.AttestationFormat = object.Format

	clientDataHash := sha256.Sum256(input.ClientDataJSON)
	signedData := make([]byte, 0, len(authDataRaw)+len(clientDataHash))
	signedData = append(signedData, authDataRaw...)
	signedData = append(signedData, clientDataHash[:]...)

	switch object.Format {
	case attestation.AttestationStatementFormatIdentifierPacked:
		statement, parsed := attestation.ParsePackedStatement(object.Statement)
		if !parsed {
			outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
			break
		}
		_, ecdaaPresent := object.Statement["ecdaaKeyId"]
		statementVerification, err := attestation.VerifyPacked(
			statement,
			ecdaaPresent,
			credentialPublicKey,
			algorithm,
			signedData,
		)
		applyAttestationStatementVerification(&verification, &outcome, statementVerification, err)
	case attestation.AttestationStatementFormatIdentifierFIDOU2F:
		statement, parsed := attestation.ParseFIDOU2FStatement(object.Statement)
		if !parsed {
			outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
			break
		}
		statementVerification, err := attestation.VerifyFIDOU2F(
			statement,
			credentialPublicKey,
			algorithm,
			authData.RPIDHash,
			clientDataHash[:],
			attested.CredentialID,
		)
		applyAttestationStatementVerification(&verification, &outcome, statementVerification, err)
	case attestation.AttestationStatementFormatIdentifierNone:
		verification.AttestationType = appwebauthn.AttestationTypeNone
		if len(object.Statement) != 0 {
			outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
		}
	default:
		verification.AttestationType = appwebauthn.AttestationTypeUnsupported
		outcome.unavailable(appwebauthn.VerificationIssueAttestationFormatUnsupported)
	}

	return finishMakeCredentialVerification(verification, outcome)
}

func makeCredentialResultMatches(
	result appwebauthn.MakeCredentialResult,
	authData protocol.MakeCredentialAuthData,
	credentialID []byte,
	credentialKey cose.Key,
) bool {
	resultCredentialID, err := hex.DecodeString(result.CredentialIDHex)
	if err != nil || !bytes.Equal(resultCredentialID, credentialID) {
		return false
	}
	resultKey, err := decodeCredentialKeyHex(result.PublicKeyCOSEHex)
	if err != nil || !credentialKeysEqual(resultKey, credentialKey) {
		return false
	}

	return result.SignCount == authData.SignCount &&
		result.UserPresent == authData.Flags.UserPresent() &&
		result.UserVerified == authData.Flags.UserVerified() &&
		result.AAGUID == authData.AttestedCredentialData.AAGUID.String()
}

func credentialKeysEqual(left, right cose.Key) bool {
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return false
	}
	leftEncoded, err := encMode.Marshal(left)
	if err != nil {
		return false
	}
	rightEncoded, err := encMode.Marshal(right)
	if err != nil {
		return false
	}

	return bytes.Equal(leftEncoded, rightEncoded)
}

func applyAttestationStatementVerification(
	verification *appwebauthn.MakeCredentialVerification,
	outcome *verificationOutcome,
	statementVerification attestation.Verification,
	err error,
) {
	verification.AttestationType = appwebauthn.AttestationType(statementVerification.Type)
	verification.SignatureValid = statementVerification.SignatureValid
	switch {
	case err == nil:
	case errors.Is(err, attestation.ErrFormatUnsupported):
		outcome.unavailable(appwebauthn.VerificationIssueAttestationFormatUnsupported)
	case errors.Is(err, attestation.ErrAlgorithmUnsupported):
		outcome.unavailable(appwebauthn.VerificationIssueCredentialAlgorithmUnsupported)
	case errors.Is(err, attestation.ErrCredentialKeyMalformed):
		outcome.fail(appwebauthn.VerificationIssueCredentialKeyMalformed)
	case errors.Is(err, attestation.ErrSignatureInvalid):
		outcome.fail(appwebauthn.VerificationIssueAttestationSignatureInvalid)
	default:
		outcome.fail(appwebauthn.VerificationIssueAttestationStatementMalformed)
	}
}

func finishMakeCredentialVerification(
	verification appwebauthn.MakeCredentialVerification,
	outcome verificationOutcome,
) appwebauthn.MakeCredentialVerification {
	verification.Status = outcome.status
	verification.Issues = outcome.issues

	return verification
}
