package ctap23

import (
	"bytes"
	"encoding/binary"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance"
)

// authDataExtensionView borrows its raw bytes from the supplied authenticator
// data. Callers must finish using the view before releasing or wiping that
// response buffer.
type authDataExtensionView struct {
	Included bool
	Raw      cbor.RawMessage
	Values   map[string]cbor.RawMessage
}

func (view *authDataExtensionView) clearValues() {
	clearAuthDataExtensionValues(view.Values)
	view.Values = nil
}

func observeMakeCredentialAuthDataExtensions(data []byte) (authDataExtensionView, error) {
	if _, err := protocol.ParseMakeCredentialAuthData(data); err != nil {
		return authDataExtensionView{}, conformance.Failf(
			"invalid authenticatorMakeCredential authData: %v",
			err,
		)
	}

	return observeAuthDataExtensions("authenticatorMakeCredential", data)
}

func observeGetAssertionAuthDataExtensions(data []byte) (authDataExtensionView, error) {
	if _, err := protocol.ParseGetAssertionAuthData(data); err != nil {
		return authDataExtensionView{}, conformance.Failf(
			"invalid authenticatorGetAssertion authData: %v",
			err,
		)
	}

	return observeAuthDataExtensions("authenticatorGetAssertion", data)
}

func observeAuthDataExtensions(operation string, data []byte) (authDataExtensionView, error) {
	flags := protocol.AuthDataFlag(data[32])
	if !flags.ExtensionDataIncluded() {
		return authDataExtensionView{}, nil
	}

	offset := 37
	if flags.AttestedCredentialDataIncluded() {
		offset += 16
		credentialIDLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2 + credentialIDLength

		decoder := cbor.NewDecoder(bytes.NewReader(data[offset:]))
		var key cose.Key
		if err := decoder.Decode(&key); err != nil {
			return authDataExtensionView{}, conformance.Failf(
				"invalid %s credential public key: %v",
				operation,
				err,
			)
		}
		offset += decoder.NumBytesRead()
	}

	raw := cbor.RawMessage(data[offset:])
	if err := validateCanonicalCTAP2Response(operation+" authData extensions", raw); err != nil {
		return authDataExtensionView{}, err
	}

	var values map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &values); err != nil {
		clearAuthDataExtensionValues(values)

		return authDataExtensionView{}, conformance.Failf(
			"invalid %s authData extensions: %v",
			operation,
			err,
		)
	}
	if values == nil {
		return authDataExtensionView{}, conformance.Failf(
			"%s authData extensions are not a CBOR map",
			operation,
		)
	}

	return authDataExtensionView{Included: true, Raw: raw, Values: values}, nil
}

func clearAuthDataExtensionValues(values map[string]cbor.RawMessage) {
	for key, value := range values {
		clear(value)
		delete(values, key)
	}
}
