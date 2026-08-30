package ctapkit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func TestDerivePreviewSignARKGP256(t *testing.T) {
	generated := previewSignGeneratedKey(t)
	context := []byte("example.com")
	inputKeyMaterial := previewSignHexBytes(
		t,
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
	)

	prepared, err := derivePreviewSignARKGP256(
		generated,
		context,
		bytes.NewReader(inputKeyMaterial),
	)
	if err != nil {
		t.Fatalf("derivePreviewSignARKGP256() error = %v", err)
	}

	additionalArguments := previewSignDecodeHex(t, prepared.AdditionalArgumentsHex)
	var arguments map[int]any
	if err := cbor.Unmarshal(additionalArguments, &arguments); err != nil {
		t.Fatalf("decode additional arguments: %v", err)
	}
	if got := arguments[3]; got != int64(cose.AlgorithmESP256SplitARKGPlaceholder) {
		t.Fatalf("algorithm = %#v, want %d", got, cose.AlgorithmESP256SplitARKGPlaceholder)
	}
	if got := arguments[-2]; !bytes.Equal(got.([]byte), context) {
		t.Fatalf("context = %x, want %x", got, context)
	}
	if got := arguments[-1].([]byte); len(got) == 0 {
		t.Fatal("ARKG key handle is empty")
	}

	encodedVerificationKey := previewSignDecodeHex(t, prepared.VerificationKeyCOSEHex)
	var verificationKey cose.Key
	if err := cbor.Unmarshal(encodedVerificationKey, &verificationKey); err != nil {
		t.Fatalf("decode verification key: %v", err)
	}
	algorithm, err := verificationKey.Algorithm()
	if err != nil {
		t.Fatalf("verification key algorithm: %v", err)
	}
	if algorithm != cose.AlgorithmESP256 {
		t.Fatalf("verification key algorithm = %d, want %d", algorithm, cose.AlgorithmESP256)
	}
}

func TestDerivePreviewSignARKGP256RejectsUnsupportedAlgorithm(t *testing.T) {
	generated := previewSignGeneratedKey(t)
	generated.Algorithm = cose.AlgorithmES256

	_, err := derivePreviewSignARKGP256(generated, nil, bytes.NewReader(make([]byte, 32)))
	if err == nil || err.Error() != "ctapkit: derive previewSign ARKG-P256: unsupported algorithm -7" {
		t.Fatalf("error = %v", err)
	}
}

func TestDerivePreviewSignARKGP256ReportsRandomFailure(t *testing.T) {
	_, err := derivePreviewSignARKGP256(
		previewSignGeneratedKey(t),
		nil,
		readerReturningError{errors.New("entropy unavailable")},
	)
	if err == nil || err.Error() != "ctapkit: derive previewSign ARKG-P256: generate input key material: entropy unavailable" {
		t.Fatalf("error = %v", err)
	}
}

type readerReturningError struct {
	err error
}

func (reader readerReturningError) Read([]byte) (int, error) {
	return 0, reader.err
}

func previewSignGeneratedKey(t *testing.T) appwebauthn.PreviewSignGeneratedKey {
	t.Helper()
	seed := cose.Key{
		cose.KeyParameterKty: cose.KeyTypeARKGPublicSeedPlaceholder,
		cose.KeyParameterAlg: cose.AlgorithmARKGP256Placeholder,
		-1: cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeEC2,
			cose.KeyParameterAlg:    cose.AlgorithmES256,
			cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
			cose.EC2KeyParameterX:   previewSignHexBytes(t, "6d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df"),
			cose.EC2KeyParameterY:   previewSignHexBytes(t, "65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7"),
		},
		-2: cose.Key{
			cose.KeyParameterKty:    cose.KeyTypeEC2,
			cose.KeyParameterAlg:    cose.AlgorithmECDHESHKDF256,
			cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
			cose.EC2KeyParameterX:   previewSignHexBytes(t, "c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5"),
			cose.EC2KeyParameterY:   previewSignHexBytes(t, "dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35"),
		},
		-3: cose.AlgorithmESP256,
	}
	encoded, err := cbor.Marshal(seed)
	if err != nil {
		t.Fatalf("encode public seed: %v", err)
	}

	return appwebauthn.PreviewSignGeneratedKey{
		PublicKeyCOSEHex: hex.EncodeToString(encoded),
		Algorithm:        cose.AlgorithmESP256SplitARKGPlaceholder,
	}
}

func previewSignDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

func previewSignHexBytes(t *testing.T, value string) []byte {
	t.Helper()
	return previewSignDecodeHex(t, value)
}
