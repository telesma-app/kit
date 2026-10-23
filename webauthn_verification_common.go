package ctapkit

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

type verificationOutcome struct {
	status appwebauthn.VerificationStatus
	issues []appwebauthn.VerificationIssueCode
}

func (o *verificationOutcome) fail(issue appwebauthn.VerificationIssueCode) {
	o.addIssue(issue)
	o.status = appwebauthn.VerificationStatusFailed
}

func (o *verificationOutcome) unavailable(issue appwebauthn.VerificationIssueCode) {
	o.addIssue(issue)

	if o.status == appwebauthn.VerificationStatusVerified {
		o.status = appwebauthn.VerificationStatusUnavailable
	}
}

func (o *verificationOutcome) addIssue(issue appwebauthn.VerificationIssueCode) {
	for _, existing := range o.issues {
		if existing == issue {
			return
		}
	}

	o.issues = append(o.issues, issue)
}

func decodeCredentialKey(raw []byte) (cose.Key, error) {
	var key cose.Key
	if err := cbor.Unmarshal(raw, &key); err != nil {
		return nil, err
	}

	if key == nil {
		return nil, errors.New("nil COSE key")
	}

	return key, nil
}

func decodeCredentialKeyHex(value string) (cose.Key, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}

	return decodeCredentialKey(raw)
}

func unsupportedCrypto(err error) bool {
	return errors.Is(err, cose.ErrUnsupportedAlgorithm) || errors.Is(err, cose.ErrUnsupportedKey)
}

func algorithmAllowed(parameters []credential.PublicKeyCredentialParameters, algorithm cose.Algorithm) bool {
	for _, parameter := range parameters {
		if credentialTypeSupported(parameter.Type) && parameter.Algorithm == algorithm {
			return true
		}
	}

	return false
}

func credentialAllowed(
	allowList []credential.PublicKeyCredentialDescriptor,
	credentialID []byte,
) bool {
	if len(allowList) == 0 {
		return true
	}

	for _, descriptor := range allowList {
		if credentialTypeSupported(descriptor.Type) && bytes.Equal(descriptor.ID, credentialID) {
			return true
		}
	}

	return false
}

func credentialTypeSupported(credentialType credential.PublicKeyCredentialType) bool {
	return credentialType == "" || credentialType == credential.PublicKeyCredentialTypePublicKey
}

func optionRequired(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
	}

	return *value
}

func requirementMet(required, observed bool) bool {
	return !required || observed
}

func verifySignature(
	outcome *verificationOutcome,
	publicKey crypto.PublicKey,
	algorithm cose.Algorithm,
	message []byte,
	signature []byte,
	invalidIssue appwebauthn.VerificationIssueCode,
) *bool {
	err := cose.VerifySignature(publicKey, algorithm, message, signature)
	if unsupportedCrypto(err) {
		outcome.unavailable(appwebauthn.VerificationIssueCredentialAlgorithmUnsupported)

		return nil
	}

	valid := err == nil
	if !valid {
		outcome.fail(invalidIssue)
	}

	return &valid
}

func aggregateStatus(current, candidate appwebauthn.VerificationStatus) appwebauthn.VerificationStatus {
	if current == appwebauthn.VerificationStatusFailed || candidate == appwebauthn.VerificationStatusFailed {
		return appwebauthn.VerificationStatusFailed
	}

	if current == appwebauthn.VerificationStatusUnavailable || candidate == appwebauthn.VerificationStatusUnavailable {
		return appwebauthn.VerificationStatusUnavailable
	}

	return appwebauthn.VerificationStatusVerified
}
