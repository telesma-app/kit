package ctap23

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/kit/conformance"
)

var clientPINKeyAgreementCTAP2EncMode = func() cbor.EncMode {
	mode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}

	return mode
}()

func validateClientPINKeyAgreementResponse(data []byte) error {
	if err := validateCanonicalClientPINResponse(data); err != nil {
		return err
	}

	var response map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(data, &response); err != nil {
		return conformance.Failf("invalid authenticatorClientPIN response CBOR: %v", err)
	}

	keyRaw, present := response[1]
	if !present {
		return conformance.Fail("authenticatorClientPIN response is missing keyAgreement")
	}
	if !hasCBORMajorType(keyRaw, 5) {
		return conformance.Fail("keyAgreement is not a CBOR map")
	}

	var rawKey map[int64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(keyRaw, &rawKey); err != nil {
		return conformance.Failf("invalid keyAgreement COSE key: %v", err)
	}
	for _, coordinate := range []struct {
		label int64
		name  string
	}{
		{label: cose.EC2KeyParameterX, name: "x"},
		{label: cose.EC2KeyParameterY, name: "y"},
	} {
		raw, present := rawKey[coordinate.label]
		if present && !hasCBORMajorType(raw, 2) {
			return conformance.Failf("keyAgreement %s coordinate is not a CBOR byte string", coordinate.name)
		}
	}

	var key cose.Key
	if err := getInfoDecMode.Unmarshal(keyRaw, &key); err != nil {
		return conformance.Failf("invalid keyAgreement COSE key: %v", err)
	}
	if _, err := key.P256PublicKey(); err != nil {
		return conformance.Failf("invalid keyAgreement COSE key: %v", err)
	}

	return nil
}

func validateCanonicalClientPINResponse(data []byte) error {
	var value any
	if err := getInfoDecMode.Unmarshal(data, &value); err != nil {
		return conformance.Failf("invalid authenticatorClientPIN response CBOR: %v", err)
	}

	canonical, err := clientPINKeyAgreementCTAP2EncMode.Marshal(value)
	if err != nil {
		return conformance.Failf("invalid authenticatorClientPIN response value: %v", err)
	}
	if !bytes.Equal(data, canonical) {
		return conformance.Fail("authenticatorClientPIN response is not CTAP2 canonical CBOR")
	}

	return nil
}
