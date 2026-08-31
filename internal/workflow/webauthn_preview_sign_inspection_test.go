package workflow

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"uuid"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func TestInspectPreviewSignGeneratedKeyDescribesARKGAndAttestation(t *testing.T) {
	key := previewSignARKGPublicSeed(t)
	encodedKey := previewSignMarshalCBOR(t, key)
	keyHandle := []byte("preview-sign-key-handle")
	aaguid := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	policy := protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified
	authData := previewSignInspectionAuthData(t, aaguid, keyHandle, encodedKey, policy)
	object := previewSignMarshalCBOR(t, attestation.Object{
		Format:    attestation.AttestationStatementFormatIdentifierNone,
		AuthData:  authData,
		Statement: map[string]any{},
	})

	inspection, err := inspectPreviewSignGeneratedKey(&ctapwebauthn.PreviewSignGeneratedKey{
		KeyHandle:         keyHandle,
		PublicKey:         encodedKey,
		Algorithm:         cose.AlgorithmESP256SplitARKGPlaceholder,
		AttestationObject: object,
	})
	if err != nil {
		t.Fatalf("inspect previewSign generated key: %v", err)
	}
	if inspection.Key.Kind != appwebauthn.PreviewSignKeyMaterialARKGPublicSeed ||
		inspection.Key.KeyType != cose.KeyTypeARKGPublicSeedPlaceholder ||
		inspection.Key.Algorithm == nil ||
		*inspection.Key.Algorithm != cose.AlgorithmARKGP256Placeholder ||
		inspection.Key.DerivedAlgorithm == nil ||
		*inspection.Key.DerivedAlgorithm != cose.AlgorithmESP256 {
		t.Fatalf("ARKG key inspection = %#v", inspection.Key)
	}
	if inspection.Key.BlindingKey == nil || inspection.Key.BlindingKey.Curve == nil ||
		*inspection.Key.BlindingKey.Curve != cose.EllipticCurveP256 ||
		inspection.Key.KEMKey == nil || inspection.Key.KEMKey.Algorithm == nil ||
		*inspection.Key.KEMKey.Algorithm != cose.AlgorithmECDHESHKDF256 {
		t.Fatalf("ARKG nested key inspection = %#v", inspection.Key)
	}
	if inspection.Attestation.Format != attestation.AttestationStatementFormatIdentifierNone ||
		inspection.Attestation.Type != attestation.TypeNone ||
		inspection.Attestation.AAGUID != aaguid.String() ||
		inspection.Attestation.SigningPolicy != appwebauthn.PreviewSignSigningPolicyUserVerification ||
		!inspection.Attestation.KeyHandleMatchesAttestation ||
		!inspection.Attestation.PublicKeyMatchesAttestation {
		t.Fatalf("previewSign attestation inspection = %#v", inspection.Attestation)
	}
}

func TestInspectPreviewSignCOSEKeyExportsStandardPublicKeyPEM(t *testing.T) {
	curve := elliptic.P256()
	key := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   curve.Params().Gx.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   curve.Params().Gy.FillBytes(make([]byte, 32)),
	}

	inspection, err := inspectPreviewSignCOSEKey(key)
	if err != nil {
		t.Fatalf("inspect standard previewSign public key: %v", err)
	}
	if inspection.Kind != appwebauthn.PreviewSignKeyMaterialPublicKey ||
		!strings.HasPrefix(inspection.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("standard public key inspection = %#v", inspection)
	}
}

func TestInspectPreviewSignSignatureDecodesECDSAScalars(t *testing.T) {
	credentialID := []byte{0x01, 0x02}
	encodedCredentialID := base64.RawURLEncoding.EncodeToString(credentialID)
	additionalArguments := previewSignMarshalCBOR(t, map[int]any{
		3: cose.AlgorithmESP256SplitARKGPlaceholder,
	})
	input := &ctapwebauthn.GetAuthenticationExtensionsClientInputs{
		PreviewSignInputs: &ctapwebauthn.PreviewSignInputs{
			PreviewSign: ctapwebauthn.AuthenticationExtensionsPreviewSignInputs{
				SignByCredential: map[string]ctapwebauthn.PreviewSignSignInputs{
					encodedCredentialID: {AdditionalArguments: additionalArguments},
				},
			},
		},
	}
	signature := previewSignMarshalASN1(t, big.NewInt(1), big.NewInt(2))
	response := previewSignSignatureResponse(credentialID, signature)

	inspection := inspectPreviewSignSignature(input, response)
	if inspection == nil || inspection.Algorithm == nil ||
		*inspection.Algorithm != cose.AlgorithmESP256SplitARKGPlaceholder ||
		inspection.VerificationAlgorithm == nil ||
		*inspection.VerificationAlgorithm != cose.AlgorithmESP256 ||
		inspection.Encoding != appwebauthn.PreviewSignSignatureEncodingASN1DERECDSA ||
		inspection.StructureValid == nil || !*inspection.StructureValid ||
		inspection.RHex != strings.Repeat("0", 63)+"1" ||
		inspection.SHex != strings.Repeat("0", 63)+"2" {
		t.Fatalf("previewSign signature inspection = %#v", inspection)
	}

	malformed := inspectPreviewSignSignature(input, previewSignSignatureResponse(credentialID, []byte{0x01}))
	if malformed == nil || malformed.StructureValid == nil || *malformed.StructureValid ||
		malformed.RHex != "" || malformed.SHex != "" {
		t.Fatalf("malformed previewSign signature inspection = %#v", malformed)
	}
}

func previewSignARKGPublicSeed(t *testing.T) cose.Key {
	t.Helper()
	curve := elliptic.P256()
	x := curve.Params().Gx.FillBytes(make([]byte, 32))
	y := curve.Params().Gy.FillBytes(make([]byte, 32))

	return cose.Key{
		cose.KeyParameterKty: cose.KeyTypeARKGPublicSeedPlaceholder,
		cose.KeyParameterAlg: cose.AlgorithmARKGP256Placeholder,
		-1: cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeEC2,
			cose.KeyParameterAlg:    cose.AlgorithmES256,
			cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
			cose.EC2KeyParameterX:   x,
			cose.EC2KeyParameterY:   y,
		},
		-2: cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeEC2,
			cose.KeyParameterAlg:    cose.AlgorithmECDHESHKDF256,
			cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
			cose.EC2KeyParameterX:   x,
			cose.EC2KeyParameterY:   y,
		},
		-3: cose.AlgorithmESP256,
	}
}

func previewSignInspectionAuthData(
	t *testing.T,
	aaguid uuid.UUID,
	credentialID, encodedKey []byte,
	policy protocol.AuthDataFlag,
) []byte {
	t.Helper()
	flags := protocol.AuthDataFlagUserPresent |
		protocol.AuthDataFlagUserVerified |
		protocol.AuthDataFlagAttestedCredentialDataIncluded |
		protocol.AuthDataFlagExtensionDataIncluded
	authData := make([]byte, 37, 37+16+2+len(credentialID)+len(encodedKey)+32)
	authData[32] = byte(flags)
	authData = append(authData, aaguid[:]...)
	credentialIDLength := make([]byte, 2)
	binary.BigEndian.PutUint16(credentialIDLength, uint16(len(credentialID)))
	authData = append(authData, credentialIDLength...)
	authData = append(authData, credentialID...)
	authData = append(authData, encodedKey...)
	authData = append(authData, previewSignMarshalCBOR(t, protocol.CreateExtensionOutputs{
		CreatePreviewSignOutput: protocol.CreatePreviewSignOutput{
			PreviewSign: &protocol.PreviewSignOutput{Flags: &policy},
		},
	})...)

	return authData
}

func previewSignSignatureResponse(
	credentialID, signature []byte,
) protocol.AuthenticatorGetAssertionResponse {
	return protocol.AuthenticatorGetAssertionResponse{
		Credential: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   credentialID,
		},
		ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
			PreviewSignOutputs: &ctapwebauthn.PreviewSignOutputs{
				PreviewSign: ctapwebauthn.AuthenticationExtensionsPreviewSignOutputs{
					Signature: signature,
				},
			},
		},
	}
}

func previewSignMarshalCBOR(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := cbor.Marshal(value)
	if err != nil {
		t.Fatalf("marshal previewSign CBOR: %v", err)
	}

	return encoded
}

func previewSignMarshalASN1(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal previewSign ECDSA signature: %v", err)
	}

	return encoded
}
