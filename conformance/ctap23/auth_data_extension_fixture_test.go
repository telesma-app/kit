package ctap23

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/protocol"
)

func TestObserveAuthDataExtensionsPreservesCanonicalWireForBothCommands(t *testing.T) {
	makeCredentialExtensions := marshalGetAssertionFixture(t, map[string]any{"hmac-secret": true})

	makeCredentialAuthData := getAssertionFixtureMakeCredentialAuthData(t, bytes.Repeat([]byte{0x31}, 32))
	makeCredentialAuthData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
	makeCredentialAuthData = append(makeCredentialAuthData, makeCredentialExtensions...)
	makeCredential, err := observeMakeCredentialAuthDataExtensions(makeCredentialAuthData)
	if err != nil {
		t.Fatal(err)
	}
	assertObservedHMACSecretExtension(t, makeCredential, makeCredentialExtensions, []byte{0xf5})

	getAssertionExtensions := marshalGetAssertionFixture(t, map[string]any{"hmac-secret": []byte{0x51}})
	getAssertionAuthData := getAssertionFixtureAuthData()
	getAssertionAuthData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
	getAssertionAuthData = append(getAssertionAuthData, getAssertionExtensions...)
	getAssertion, err := observeGetAssertionAuthDataExtensions(getAssertionAuthData)
	if err != nil {
		t.Fatal(err)
	}
	assertObservedHMACSecretExtension(t, getAssertion, getAssertionExtensions, []byte{0x41, 0x51})

	makeCredentialExtensions[0] = 0xa0
	getAssertionExtensions[0] = 0xa0
	if makeCredential.Raw[0] != 0xa1 || getAssertion.Raw[0] != 0xa1 {
		t.Fatal("observed extension bytes alias the separately supplied source slice")
	}
	makeCredentialAuthData[len(makeCredentialAuthData)-len(makeCredential.Raw)] = 0xa0
	if makeCredential.Raw[0] != 0xa0 {
		t.Fatal("observer did not preserve the documented borrowed raw authData view")
	}
}

func TestObserveAuthDataExtensionsReportsAbsenceAndRejectsNonCanonicalEncoding(t *testing.T) {
	view, err := observeGetAssertionAuthDataExtensions(getAssertionFixtureAuthData())
	if err != nil {
		t.Fatal(err)
	}
	if view.Included || view.Raw != nil || view.Values != nil {
		t.Fatalf("absent extension view = %#v", view)
	}

	authData := getAssertionFixtureAuthData()
	authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
	authData = append(authData,
		0xbf,
		0x6b, 'h', 'm', 'a', 'c', '-', 's', 'e', 'c', 'r', 'e', 't',
		0x41, 0x51,
		0xff,
	)
	if _, err := observeGetAssertionAuthDataExtensions(authData); err == nil {
		t.Fatal("observer accepted a non-canonical indefinite extension map")
	}
}

func TestClearAuthDataExtensionValuesWipesRetainedPartialDecodeBuffers(t *testing.T) {
	first := cbor.RawMessage(bytes.Repeat([]byte{0x51}, 16))
	second := cbor.RawMessage(bytes.Repeat([]byte{0x52}, 32))
	values := map[string]cbor.RawMessage{
		"hmac-secret": first,
		"future":      second,
	}

	clearAuthDataExtensionValues(values)

	if len(values) != 0 || !allZeroHMACSecret(first) || !allZeroHMACSecret(second) {
		t.Fatalf("cleared values = %#v, retained = %x/%x", values, first, second)
	}
}

func TestObserveAuthDataExtensionsRejectsMixedKeyMapAfterPartialDecode(t *testing.T) {
	raw, err := ctap2EncMode.Marshal(map[any]any{
		"hmac-secret": []byte{0x51},
		uint64(1):     []byte{0x52},
	})
	if err != nil {
		t.Fatal(err)
	}
	authData := getAssertionFixtureAuthData()
	authData[32] |= byte(protocol.AuthDataFlagExtensionDataIncluded)
	authData = append(authData, raw...)

	if _, err := observeAuthDataExtensions("authenticatorGetAssertion", authData); err == nil {
		t.Fatal("observer accepted a canonical extension map with a non-text key")
	}
}

func assertObservedHMACSecretExtension(
	t testing.TB,
	view authDataExtensionView,
	wantRaw []byte,
	wantValue []byte,
) {
	t.Helper()

	if !view.Included {
		t.Fatal("extension data was not observed")
	}
	if !bytes.Equal(view.Raw, wantRaw) {
		t.Fatalf("raw extensions = %x, want %x", view.Raw, wantRaw)
	}
	value, present := view.Values["hmac-secret"]
	if !present || !bytes.Equal(value, wantValue) {
		t.Fatalf("hmac-secret raw value = %x, present %t", value, present)
	}
}
