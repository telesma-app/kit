package ctapkit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/arkg"
	"github.com/telesma-app/ctap/cose"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

const previewSignARKGP256InputKeyMaterialLength = 32

// DerivePreviewSignARKGP256 derives the caller-side ESP256 verification key and
// COSE signing arguments for a previewSign key generated with ARKG-P256.
func DerivePreviewSignARKGP256(
	generated appwebauthn.PreviewSignGeneratedKey,
	context []byte,
) (appwebauthn.PreviewSignARKGP256Derivation, error) {
	return derivePreviewSignARKGP256(generated, context, rand.Reader)
}

func derivePreviewSignARKGP256(
	generated appwebauthn.PreviewSignGeneratedKey,
	context []byte,
	random io.Reader,
) (appwebauthn.PreviewSignARKGP256Derivation, error) {
	if generated.Algorithm != cose.AlgorithmESP256SplitARKGPlaceholder {
		return appwebauthn.PreviewSignARKGP256Derivation{}, fmt.Errorf(
			"ctapkit: derive previewSign ARKG-P256: unsupported algorithm %d",
			generated.Algorithm,
		)
	}

	encodedSeed, err := hex.DecodeString(generated.PublicKeyCOSEHex)
	if err != nil {
		return appwebauthn.PreviewSignARKGP256Derivation{}, fmt.Errorf(
			"ctapkit: derive previewSign ARKG-P256: decode public seed: %w",
			err,
		)
	}

	var publicSeed cose.Key
	if err := cbor.Unmarshal(encodedSeed, &publicSeed); err != nil {
		return appwebauthn.PreviewSignARKGP256Derivation{}, fmt.Errorf(
			"ctapkit: derive previewSign ARKG-P256: decode public seed COSE: %w",
			err,
		)
	}

	inputKeyMaterial := make([]byte, previewSignARKGP256InputKeyMaterialLength)
	defer clear(inputKeyMaterial)
	if _, err := io.ReadFull(random, inputKeyMaterial); err != nil {
		return appwebauthn.PreviewSignARKGP256Derivation{}, fmt.Errorf(
			"ctapkit: derive previewSign ARKG-P256: generate input key material: %w",
			err,
		)
	}

	verificationKey, arkgKeyHandle, err := arkg.DeriveP256(publicSeed, inputKeyMaterial, context)
	if err != nil {
		return appwebauthn.PreviewSignARKGP256Derivation{}, fmt.Errorf(
			"ctapkit: derive previewSign ARKG-P256: derive signing key: %w",
			err,
		)
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return appwebauthn.PreviewSignARKGP256Derivation{}, fmt.Errorf(
			"ctapkit: derive previewSign ARKG-P256: create CTAP2 CBOR encoder: %w",
			err,
		)
	}

	additionalArguments, err := encMode.Marshal(map[int]any{
		3:  generated.Algorithm,
		-1: arkgKeyHandle,
		-2: context,
	})
	if err != nil {
		return appwebauthn.PreviewSignARKGP256Derivation{}, fmt.Errorf(
			"ctapkit: derive previewSign ARKG-P256: encode COSE signing arguments: %w",
			err,
		)
	}

	encodedVerificationKey, err := encMode.Marshal(verificationKey)
	if err != nil {
		return appwebauthn.PreviewSignARKGP256Derivation{}, fmt.Errorf(
			"ctapkit: derive previewSign ARKG-P256: encode verification key: %w",
			err,
		)
	}

	return appwebauthn.PreviewSignARKGP256Derivation{
		AdditionalArgumentsHex: hex.EncodeToString(additionalArguments),
		VerificationKeyCOSEHex: hex.EncodeToString(encodedVerificationKey),
	}, nil
}
