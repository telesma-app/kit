package ctapkit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/telesma-app/ctap/protocol"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func VerifyGetAssertion(
	input appwebauthn.GetAssertionInput,
	result appwebauthn.GetAssertionResult,
	material []appwebauthn.CredentialVerificationMaterial,
) appwebauthn.GetAssertionVerification {
	top := verificationOutcome{status: appwebauthn.VerificationStatusVerified}

	verification := appwebauthn.GetAssertionVerification{
		Status:     appwebauthn.VerificationStatusVerified,
		Assertions: make([]appwebauthn.AssertionVerification, 0, len(result.Assertions)),
	}
	if result.RPID != input.RPID {
		top.fail(appwebauthn.VerificationIssueResultRPIDMismatch)
	}

	if len(result.Assertions) == 0 {
		top.fail(appwebauthn.VerificationIssueAssertionMissing)
	}

	if len(input.AllowList) != 0 && len(result.Assertions) != 1 {
		top.fail(appwebauthn.VerificationIssueAssertionCountUnexpected)
	}

	if len(result.Assertions) != 0 &&
		result.Assertions[0].NumberOfCredentials != 0 &&
		int(result.Assertions[0].NumberOfCredentials) != len(result.Assertions) {
		top.fail(appwebauthn.VerificationIssueAssertionCountUnexpected)
	}

	materialByCredentialID := indexVerificationMaterial(material)
	for _, assertion := range result.Assertions {
		assertionVerification := verifyAssertion(input, assertion, materialByCredentialID)
		verification.Assertions = append(verification.Assertions, assertionVerification)
		top.status = aggregateStatus(top.status, assertionVerification.Status)
	}

	verification.Status = top.status
	verification.Issues = top.issues

	return verification
}

func verifyAssertion(
	input appwebauthn.GetAssertionInput,
	assertion appwebauthn.Assertion,
	material map[string][]appwebauthn.CredentialVerificationMaterial,
) appwebauthn.AssertionVerification {
	outcome := verificationOutcome{status: appwebauthn.VerificationStatusVerified}
	credentialID := assertion.Credential.ID
	credentialIDHex := hex.EncodeToString(credentialID)

	verification := appwebauthn.AssertionVerification{
		Index:           assertion.Index,
		CredentialIDHex: credentialIDHex,
		Status:          appwebauthn.VerificationStatusVerified,
		CredentialAllowed: credentialTypeSupported(assertion.Credential.Type) &&
			credentialAllowed(input.AllowList, credentialID),
		SignCount: appwebauthn.SignCountStatusNotChecked,
	}
	if !verification.CredentialAllowed {
		outcome.fail(appwebauthn.VerificationIssueCredentialDisallowed)
	}

	authDataRaw, err := hex.DecodeString(assertion.AuthenticatorDataHex)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueResultMalformed)
		return finishAssertionVerification(verification, outcome)
	}

	authData, err := protocol.ParseGetAssertionAuthData(authDataRaw)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueAuthenticatorDataMalformed)
		return finishAssertionVerification(verification, outcome)
	}

	if authData.AttestedCredentialData != nil {
		outcome.fail(appwebauthn.VerificationIssueAttestedCredentialDataUnexpected)
	}

	if assertion.SignCount != authData.SignCount ||
		assertion.UserPresent != authData.Flags.UserPresent() ||
		assertion.UserVerified != authData.Flags.UserVerified() {
		outcome.fail(appwebauthn.VerificationIssueResultMismatch)
	}

	expectedRPIDHash := sha256.Sum256([]byte(input.RPID))

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

	matches := material[credentialIDHex]
	if len(matches) == 0 {
		outcome.unavailable(appwebauthn.VerificationIssueVerificationMaterialMissing)
		return finishAssertionVerification(verification, outcome)
	}

	if len(matches) != 1 {
		outcome.unavailable(appwebauthn.VerificationIssueVerificationMaterialAmbiguous)
		return finishAssertionVerification(verification, outcome)
	}

	verification.SignCount, verification.Warnings = compareSignCount(matches[0].PreviousSignCount, authData.SignCount)

	key, err := decodeCredentialKeyHex(matches[0].PublicKeyCOSEHex)
	if err != nil {
		outcome.unavailable(appwebauthn.VerificationIssueVerificationKeyMalformed)
		return finishAssertionVerification(verification, outcome)
	}

	algorithm, err := key.Algorithm()
	if err != nil {
		outcome.unavailable(appwebauthn.VerificationIssueVerificationKeyMalformed)
		return finishAssertionVerification(verification, outcome)
	}

	publicKey, err := key.PublicKey()
	if err != nil {
		if unsupportedCrypto(err) {
			outcome.unavailable(appwebauthn.VerificationIssueCredentialAlgorithmUnsupported)
		} else {
			outcome.unavailable(appwebauthn.VerificationIssueVerificationKeyMalformed)
		}

		return finishAssertionVerification(verification, outcome)
	}

	signature, err := hex.DecodeString(assertion.SignatureHex)
	if err != nil {
		outcome.fail(appwebauthn.VerificationIssueSignatureMalformed)
		return finishAssertionVerification(verification, outcome)
	}

	clientDataHash := sha256.Sum256(input.ClientDataJSON)
	signedData := make([]byte, 0, len(authDataRaw)+len(clientDataHash))
	signedData = append(signedData, authDataRaw...)
	signedData = append(signedData, clientDataHash[:]...)
	verification.SignatureValid = verifySignature(
		&outcome,
		publicKey,
		algorithm,
		signedData,
		signature,
		appwebauthn.VerificationIssueAssertionSignatureInvalid,
	)

	return finishAssertionVerification(verification, outcome)
}

func indexVerificationMaterial(
	material []appwebauthn.CredentialVerificationMaterial,
) map[string][]appwebauthn.CredentialVerificationMaterial {
	indexed := make(map[string][]appwebauthn.CredentialVerificationMaterial, len(material))
	for _, item := range material {
		credentialID, err := hex.DecodeString(item.CredentialIDHex)
		if err != nil {
			continue
		}

		key := hex.EncodeToString(credentialID)
		indexed[key] = append(indexed[key], item)
	}

	return indexed
}

func compareSignCount(
	previous *uint32,
	current uint32,
) (appwebauthn.SignCountStatus, []appwebauthn.VerificationIssueCode) {
	if previous == nil {
		return appwebauthn.SignCountStatusNotChecked, nil
	}

	if *previous == 0 && current == 0 {
		return appwebauthn.SignCountStatusUnsupported, nil
	}

	if current > *previous {
		return appwebauthn.SignCountStatusAdvanced, nil
	}

	return appwebauthn.SignCountStatusNotAdvanced, []appwebauthn.VerificationIssueCode{
		appwebauthn.VerificationWarningSignCountNotAdvanced,
	}
}

func finishAssertionVerification(
	verification appwebauthn.AssertionVerification,
	outcome verificationOutcome,
) appwebauthn.AssertionVerification {
	verification.Status = outcome.status
	verification.Issues = outcome.issues

	return verification
}
