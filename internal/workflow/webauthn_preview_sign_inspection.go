package workflow

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/protocol"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func inspectPreviewSignGeneratedKey(
	generated *ctapwebauthn.PreviewSignGeneratedKey,
) (*appwebauthn.PreviewSignGeneratedKeyInspection, error) {
	if generated == nil {
		return nil, nil
	}

	var key cose.Key
	if err := cbor.Unmarshal(generated.PublicKey, &key); err != nil {
		return nil, fmt.Errorf("decode previewSign COSE key: %w", err)
	}
	keyInspection, err := inspectPreviewSignCOSEKey(key)
	if err != nil {
		return nil, err
	}

	object, err := attestation.ParseObject(generated.AttestationObject)
	if err != nil {
		return nil, fmt.Errorf("decode previewSign attestation object: %w", err)
	}
	authData, err := protocol.ParseMakeCredentialAuthData(object.AuthData)
	if err != nil {
		return nil, fmt.Errorf("decode previewSign attestation authData: %w", err)
	}
	if authData.AttestedCredentialData == nil || authData.Extensions == nil ||
		authData.Extensions.PreviewSign == nil || authData.Extensions.PreviewSign.Flags == nil {
		return nil, errors.New("decode previewSign attestation: required signing-key data is absent")
	}

	attestationType := attestation.TypeUnsupported
	certificateCount := 0
	if currentType, chain, typeErr := object.TypeAndCertificateChain(); typeErr == nil {
		attestationType = currentType
		certificateCount = len(chain)
	}

	attested := authData.AttestedCredentialData
	return &appwebauthn.PreviewSignGeneratedKeyInspection{
		Key: *keyInspection,
		Attestation: appwebauthn.PreviewSignAttestationInspection{
			Format:                      object.Format,
			Type:                        attestationType,
			CertificateCount:            certificateCount,
			AAGUID:                      attested.AAGUID.String(),
			SigningPolicy:               previewSignSigningPolicy(*authData.Extensions.PreviewSign.Flags),
			KeyHandleMatchesAttestation: bytes.Equal(generated.KeyHandle, attested.CredentialID),
			PublicKeyMatchesAttestation: previewSignCOSEKeysEqual(key, attested.CredentialPublicKey),
		},
	}, nil
}

func previewSignCOSEKeysEqual(left, right cose.Key) bool {
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

func inspectPreviewSignCOSEKey(key cose.Key) (*appwebauthn.PreviewSignCOSEKeyInspection, error) {
	keyType, ok := previewSignInteger(key[cose.KeyParameterKty])
	if !ok {
		return nil, errors.New("decode previewSign COSE key: kty is absent or is not an integer")
	}

	inspection := &appwebauthn.PreviewSignCOSEKeyInspection{
		Kind:    appwebauthn.PreviewSignKeyMaterialPublicKey,
		KeyType: keyType,
	}
	if value, found := key[cose.KeyParameterAlg]; found {
		algorithm, valid := previewSignInteger(value)
		if !valid {
			return nil, errors.New("decode previewSign COSE key: alg is not an integer")
		}
		inspection.Algorithm = new(cose.Algorithm(algorithm))
	}

	if value, found := key[cose.EC2KeyParameterCrv]; found && keyType != cose.KeyTypeARKGPublicSeedPlaceholder {
		curve, valid := previewSignInteger(value)
		if valid {
			inspection.Curve = new(curve)
		}
	}

	if keyType == cose.KeyTypeARKGPublicSeedPlaceholder {
		inspection.Kind = appwebauthn.PreviewSignKeyMaterialARKGPublicSeed
		if value, found := key[-3]; found {
			algorithm, valid := previewSignInteger(value)
			if !valid {
				return nil, errors.New("decode previewSign ARKG public seed: dkalg is not an integer")
			}
			inspection.DerivedAlgorithm = new(cose.Algorithm(algorithm))
		}

		blindingKey, err := previewSignNestedKey(key[-1])
		if err != nil {
			return nil, fmt.Errorf("decode previewSign ARKG blinding key: %w", err)
		}
		inspection.BlindingKey, err = inspectPreviewSignCOSEKey(blindingKey)
		if err != nil {
			return nil, fmt.Errorf("decode previewSign ARKG blinding key: %w", err)
		}

		kemKey, err := previewSignNestedKey(key[-2])
		if err != nil {
			return nil, fmt.Errorf("decode previewSign ARKG KEM key: %w", err)
		}
		inspection.KEMKey, err = inspectPreviewSignCOSEKey(kemKey)
		if err != nil {
			return nil, fmt.Errorf("decode previewSign ARKG KEM key: %w", err)
		}

		return inspection, nil
	}

	publicKey, err := key.PublicKey()
	if err != nil {
		return inspection, nil
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return inspection, nil
	}
	inspection.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))

	return inspection, nil
}

func previewSignSigningPolicy(flags protocol.AuthDataFlag) appwebauthn.PreviewSignSigningPolicy {
	if flags.UserVerified() {
		return appwebauthn.PreviewSignSigningPolicyUserVerification
	}
	if flags.UserPresent() {
		return appwebauthn.PreviewSignSigningPolicyUserPresence
	}

	return appwebauthn.PreviewSignSigningPolicyUnattended
}

func inspectPreviewSignSignature(
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	response protocol.AuthenticatorGetAssertionResponse,
) *appwebauthn.PreviewSignSignatureInspection {
	inspection := &appwebauthn.PreviewSignSignatureInspection{
		Encoding: appwebauthn.PreviewSignSignatureEncodingOpaque,
	}
	if response.ExtensionOutputs == nil || response.ExtensionOutputs.PreviewSignOutputs == nil {
		return nil
	}

	algorithm := previewSignAlgorithmFromInput(input, response)
	if algorithm == nil {
		return inspection
	}
	inspection.Algorithm = algorithm

	verificationAlgorithm, scalarSize, ecdsaSignature := previewSignECDSASignature(*algorithm)
	if !ecdsaSignature {
		return inspection
	}
	inspection.VerificationAlgorithm = new(verificationAlgorithm)
	inspection.Encoding = appwebauthn.PreviewSignSignatureEncodingASN1DERECDSA

	valid := false
	inspection.StructureValid = &valid
	var signature struct {
		R *big.Int
		S *big.Int
	}
	raw := response.ExtensionOutputs.PreviewSign.Signature
	rest, err := asn1.Unmarshal(raw, &signature)
	if err != nil || len(rest) != 0 || !validECDSAScalar(signature.R, scalarSize) ||
		!validECDSAScalar(signature.S, scalarSize) {
		return inspection
	}

	valid = true
	inspection.RHex = fixedWidthIntegerHex(signature.R, scalarSize)
	inspection.SHex = fixedWidthIntegerHex(signature.S, scalarSize)

	return inspection
}

func previewSignAlgorithmFromInput(
	input *ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	response protocol.AuthenticatorGetAssertionResponse,
) *cose.Algorithm {
	if input == nil || input.PreviewSignInputs == nil || response.Credential.ID == nil {
		return nil
	}
	encodedCredentialID := base64.RawURLEncoding.EncodeToString(response.Credential.ID)
	signInput, found := input.PreviewSign.SignByCredential[encodedCredentialID]
	if !found || len(signInput.AdditionalArguments) == 0 {
		return nil
	}

	var arguments map[int]any
	if err := cbor.Unmarshal(signInput.AdditionalArguments, &arguments); err != nil {
		return nil
	}
	value, ok := previewSignInteger(arguments[3])
	if !ok {
		return nil
	}

	return new(cose.Algorithm(value))
}

func previewSignECDSASignature(algorithm cose.Algorithm) (cose.Algorithm, int, bool) {
	switch algorithm {
	case cose.AlgorithmESP256SplitARKGPlaceholder:
		return cose.AlgorithmESP256, 32, true
	case cose.AlgorithmES256, cose.AlgorithmESP256, cose.AlgorithmES256K:
		return algorithm, 32, true
	case cose.AlgorithmES384, cose.AlgorithmESP384:
		return algorithm, 48, true
	case cose.AlgorithmES512, cose.AlgorithmESP512:
		return algorithm, 66, true
	default:
		return 0, 0, false
	}
}

func validECDSAScalar(value *big.Int, size int) bool {
	return value != nil && value.Sign() > 0 && value.BitLen() <= size*8
}

func fixedWidthIntegerHex(value *big.Int, size int) string {
	encoded := value.Text(16)

	return strings.Repeat("0", size*2-len(encoded)) + encoded
}

func previewSignNestedKey(value any) (cose.Key, error) {
	switch value := value.(type) {
	case cose.Key:
		return value, nil
	case map[int]any:
		return cose.Key(value), nil
	case map[any]any:
		key := make(cose.Key, len(value))
		for rawLabel, parameter := range value {
			label, ok := previewSignInteger(rawLabel)
			if !ok {
				return nil, fmt.Errorf("parameter label has type %T", rawLabel)
			}
			key[int(label)] = parameter
		}

		return key, nil
	default:
		return nil, fmt.Errorf("key has type %T", value)
	}
}

func previewSignInteger(value any) (int64, bool) {
	switch value := value.(type) {
	case cose.Algorithm:
		return int64(value), true
	case int:
		return int64(value), true
	case int8:
		return int64(value), true
	case int16:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case uint:
		return int64(value), uint64(value) <= uint64(^uint64(0)>>1)
	case uint8:
		return int64(value), true
	case uint16:
		return int64(value), true
	case uint32:
		return int64(value), true
	case uint64:
		return int64(value), value <= uint64(^uint64(0)>>1)
	default:
		return 0, false
	}
}
