package ctap23

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestValidateTemporaryPINEnforcesCTAPEncodingContract(t *testing.T) {
	request := TemporaryPINRequest{MinCodePoints: 4, MaxCodePoints: 63}
	for _, valid := range [][]byte{
		[]byte("1234"),
		[]byte("Caf\u00e9123"),
	} {
		if err := validateTemporaryPIN(valid, request); err != nil {
			t.Fatalf("valid PIN rejected: %v", err)
		}
	}

	for _, testCase := range []struct {
		name    string
		pin     []byte
		request TemporaryPINRequest
	}{
		{name: "invalid UTF-8", pin: []byte{0xff}, request: request},
		{name: "more than 63 UTF-8 bytes", pin: []byte(strings.Repeat("\u00e9", 32)), request: request},
		{name: "not NFC", pin: []byte("Cafe\u0301123"), request: request},
		{name: "below code-point minimum", pin: []byte("123"), request: request},
		{
			name:    "above code-point maximum",
			pin:     []byte("123456"),
			request: TemporaryPINRequest{MinCodePoints: 4, MaxCodePoints: 5},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			before := slices.Clone(testCase.pin)
			if err := validateTemporaryPIN(testCase.pin, testCase.request); err == nil {
				t.Fatal("validation passed")
			}
			if !bytes.Equal(testCase.pin, before) {
				t.Fatal("validation mutated provider-owned PIN buffer")
			}
		})
	}
}

func TestSetPINForPolicyTestUsesExactPaddedPINForBothProtocols(t *testing.T) {
	for _, pinUvAuthProtocol := range []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	} {
		t.Run(fmt.Sprintf("protocol-%d", pinUvAuthProtocol), func(t *testing.T) {
			var paddedPIN [64]byte
			copy(paddedPIN[:], "policy-test-pin")
			before := paddedPIN
			transport := newPINPolicyTransport(t, pinUvAuthProtocol, paddedPIN)
			ctapClient, err := client.NewClient(options.WithTransport(transport))
			if err != nil {
				t.Fatal(err)
			}

			if err := setPINForPolicyTest(
				t.Context(),
				ctapClient,
				transport,
				pinUvAuthProtocol,
				&paddedPIN,
			); err != nil {
				t.Fatal(err)
			}
			if transport.calls != 2 || !transport.setPINVerified {
				t.Fatalf("transport = %#v", transport)
			}
			if paddedPIN != before {
				t.Fatal("helper mutated the caller-owned padded PIN")
			}
			clear(paddedPIN[:])
			if slices.ContainsFunc(paddedPIN[:], func(value byte) bool { return value != 0 }) {
				t.Fatal("caller failed to wipe its padded PIN")
			}
		})
	}
}

func TestSetPINForPolicyTestPreservesStatusAndTransportErrors(t *testing.T) {
	var paddedPIN [64]byte
	copy(paddedPIN[:], "123")

	t.Run("CTAP status", func(t *testing.T) {
		transport := newPINPolicyTransport(t, protocol.PinUvAuthProtocolOne, paddedPIN)
		transport.status = ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION
		ctapClient, err := client.NewClient(options.WithTransport(transport))
		if err != nil {
			t.Fatal(err)
		}

		err = setPINForPolicyTest(
			t.Context(),
			ctapClient,
			transport,
			protocol.PinUvAuthProtocolOne,
			&paddedPIN,
		)
		var ctapError *ctaptransport.CTAPError
		if !errors.As(err, &ctapError) || ctapError.StatusCode != ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION {
			t.Fatalf("error = %#v", err)
		}
	})

	t.Run("transport", func(t *testing.T) {
		transportFailure := errors.New("device disconnected")
		transport := newPINPolicyTransport(t, protocol.PinUvAuthProtocolTwo, paddedPIN)
		transport.err = transportFailure
		ctapClient, err := client.NewClient(options.WithTransport(transport))
		if err != nil {
			t.Fatal(err)
		}

		err = setPINForPolicyTest(
			t.Context(),
			ctapClient,
			transport,
			protocol.PinUvAuthProtocolTwo,
			&paddedPIN,
		)
		if !errors.Is(err, transportFailure) {
			t.Fatalf("error = %v, want %v", err, transportFailure)
		}
	})
}

func TestReadClientPINRetriesUsesProtocolAndValidatesRange(t *testing.T) {
	for _, pinUvAuthProtocol := range []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	} {
		for _, want := range []uint64{0, 8} {
			t.Run(fmt.Sprintf("protocol-%d/value-%d", pinUvAuthProtocol, want), func(t *testing.T) {
				response := marshalClientPINRetryFixture(t, map[uint64]any{
					3: want,
					4: true,
					9: "ignored extension",
				})
				transport := newScriptedCBORTransport(t, scriptedCBORExchange{
					request: []byte{
						byte(protocol.AuthenticatorClientPIN),
						0xa2,
						0x01, byte(pinUvAuthProtocol),
						0x02, byte(protocol.ClientPINSubCommandGetPINRetries),
					},
					response: ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: response},
				})

				retries, err := readClientPINRetries(t.Context(), transport, pinUvAuthProtocol)
				if err != nil {
					t.Fatal(err)
				}
				if retries != uint(want) {
					t.Fatalf("retries = %d, want %d", retries, want)
				}
			})
		}
	}
}

func TestReadClientUVRetriesUsesProtocolAndValidatesRange(t *testing.T) {
	for _, pinUvAuthProtocol := range []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	} {
		for _, want := range []uint64{1, 25} {
			t.Run(fmt.Sprintf("protocol-%d/value-%d", pinUvAuthProtocol, want), func(t *testing.T) {
				transport := newScriptedCBORTransport(t, scriptedCBORExchange{
					request: []byte{
						byte(protocol.AuthenticatorClientPIN),
						0xa2,
						0x01, byte(pinUvAuthProtocol),
						0x02, byte(protocol.ClientPINSubCommandGetUVRetries),
					},
					response: ctaptransport.CBORResponse{
						StatusCode: ctaptransport.CTAP2_OK,
						Data:       marshalClientPINRetryFixture(t, map[uint64]any{5: want}),
					},
				})

				retries, err := readClientUVRetries(t.Context(), transport, pinUvAuthProtocol)
				if err != nil {
					t.Fatal(err)
				}
				if retries != uint(want) {
					t.Fatalf("retries = %d, want %d", retries, want)
				}
			})
		}
	}
}

func TestReadClientPINRetriesRejectsMalformedMissingWrongTypeRangeAndEncoding(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "malformed", data: []byte{0xff}},
		{name: "not map", data: marshalClientPINRetryFixture(t, uint64(8))},
		{name: "missing", data: marshalClientPINRetryFixture(t, map[uint64]any{5: uint64(8)})},
		{name: "negative", data: marshalClientPINRetryFixture(t, map[uint64]any{3: int64(-1)})},
		{name: "text", data: marshalClientPINRetryFixture(t, map[uint64]any{3: "8"})},
		{name: "float", data: marshalClientPINRetryFixture(t, map[uint64]any{3: 8.0})},
		{name: "null", data: marshalClientPINRetryFixture(t, map[uint64]any{3: nil})},
		{name: "boolean", data: marshalClientPINRetryFixture(t, map[uint64]any{3: true})},
		{name: "above maximum", data: marshalClientPINRetryFixture(t, map[uint64]any{3: uint64(9)})},
		{name: "nonminimal map length", data: []byte{0xb8, 0x01, 0x03, 0x08}},
		{name: "nonminimal key", data: []byte{0xa1, 0x18, 0x03, 0x08}},
		{name: "nonminimal value", data: []byte{0xa1, 0x03, 0x18, 0x08}},
		{name: "unordered keys", data: []byte{0xa2, 0x04, 0xf5, 0x03, 0x08}},
		{name: "duplicate key", data: []byte{0xa2, 0x03, 0x08, 0x03, 0x07}},
		{name: "indefinite map", data: []byte{0xbf, 0x03, 0x08, 0xff}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := newScriptedCBORTransport(t, scriptedCBORExchange{
				request: []byte{
					byte(protocol.AuthenticatorClientPIN),
					0xa2, 0x01, 0x01,
					0x02, byte(protocol.ClientPINSubCommandGetPINRetries),
				},
				response: ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: test.data},
			})

			_, err := readClientPINRetries(t.Context(), transport, protocol.PinUvAuthProtocolOne)
			assertClientPINRetryFailure(t, err)
		})
	}
}

func TestReadClientUVRetriesRejectsMissingWrongTypeAndRange(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "missing", data: marshalClientPINRetryFixture(t, map[uint64]any{3: uint64(1)})},
		{name: "negative", data: marshalClientPINRetryFixture(t, map[uint64]any{5: int64(-1)})},
		{name: "text", data: marshalClientPINRetryFixture(t, map[uint64]any{5: "1"})},
		{name: "zero", data: marshalClientPINRetryFixture(t, map[uint64]any{5: uint64(0)})},
		{name: "above maximum", data: marshalClientPINRetryFixture(t, map[uint64]any{5: uint64(26)})},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := newScriptedCBORTransport(t, scriptedCBORExchange{
				request: []byte{
					byte(protocol.AuthenticatorClientPIN),
					0xa2, 0x01, 0x02,
					0x02, byte(protocol.ClientPINSubCommandGetUVRetries),
				},
				response: ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: test.data},
			})

			_, err := readClientUVRetries(t.Context(), transport, protocol.PinUvAuthProtocolTwo)
			assertClientPINRetryFailure(t, err)
		})
	}
}

func TestReadClientPINRetriesClassifiesCTAPStatusAndPreservesTransportError(t *testing.T) {
	t.Run("CTAP status", func(t *testing.T) {
		transport := newScriptedCBORTransport(t, scriptedCBORExchange{
			request: []byte{
				byte(protocol.AuthenticatorClientPIN),
				0xa2, 0x01, 0x01,
				0x02, byte(protocol.ClientPINSubCommandGetPINRetries),
			},
			response: ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID},
		})

		_, err := readClientPINRetries(t.Context(), transport, protocol.PinUvAuthProtocolOne)
		assertClientPINRetryFailure(t, err)
	})

	t.Run("transport", func(t *testing.T) {
		transportFailure := errors.New("device disconnected")
		transport := newScriptedCBORTransport(t, scriptedCBORExchange{
			request: []byte{
				byte(protocol.AuthenticatorClientPIN),
				0xa2, 0x01, 0x02,
				0x02, byte(protocol.ClientPINSubCommandGetPINRetries),
			},
			err: transportFailure,
		})

		_, err := readClientPINRetries(t.Context(), transport, protocol.PinUvAuthProtocolTwo)
		if !errors.Is(err, transportFailure) {
			t.Fatalf("error = %v, want %v", err, transportFailure)
		}
	})
}

func TestGetLegacyPINTokenUsesTypedClientCryptoForBothProtocols(t *testing.T) {
	for _, pinUvAuthProtocol := range []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	} {
		t.Run(fmt.Sprintf("protocol-%d", pinUvAuthProtocol), func(t *testing.T) {
			wantToken := bytes.Repeat([]byte{byte(pinUvAuthProtocol)}, 32)
			transport := newLegacyPINTokenTransport(t, pinUvAuthProtocol, wantToken)
			ctapClient, err := client.NewClient(options.WithTransport(transport))
			if err != nil {
				t.Fatal(err)
			}

			token, err := getLegacyPINToken(t.Context(), ctapClient, pinUvAuthProtocol, "1234")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(token, wantToken) {
				t.Fatalf("token = %x, want %x", token, wantToken)
			}
			if transport.calls != 2 {
				t.Fatalf("calls = %d, want 2", transport.calls)
			}
		})
	}
}

func TestGetLegacyPINTokenPreservesClientPINStatus(t *testing.T) {
	transport := newLegacyPINTokenTransport(t, protocol.PinUvAuthProtocolOne, bytes.Repeat([]byte{1}, 32))
	transport.status = ctaptransport.CTAP2_ERR_PIN_INVALID
	ctapClient, err := client.NewClient(options.WithTransport(transport))
	if err != nil {
		t.Fatal(err)
	}

	_, err = getLegacyPINToken(t.Context(), ctapClient, protocol.PinUvAuthProtocolOne, "9999")
	var ctapError *ctaptransport.CTAPError
	if !errors.As(err, &ctapError) || ctapError.StatusCode != ctaptransport.CTAP2_ERR_PIN_INVALID {
		t.Fatalf("error = %v, want PIN_INVALID CTAPError", err)
	}
}

func TestMakeCredentialWithPINTokenUsesStableMinimalTypedRequest(t *testing.T) {
	for _, pinUvAuthProtocol := range []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	} {
		t.Run(fmt.Sprintf("protocol-%d", pinUvAuthProtocol), func(t *testing.T) {
			transport := &makeCredentialPINTokenTransport{t: t}
			ctapClient, err := client.NewClient(options.WithTransport(transport))
			if err != nil {
				t.Fatal(err)
			}
			token := bytes.Repeat([]byte{0x5a}, 32)
			algorithms := []credential.PublicKeyCredentialParameters{
				{Type: "vendor", Algorithm: cose.AlgorithmRS256},
				{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256},
				{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmRS256},
			}

			response, err := makeCredentialWithPINToken(
				t.Context(),
				ctapClient,
				pinUvAuthProtocol,
				token,
				algorithms,
			)
			if err != nil {
				t.Fatal(err)
			}
			if response.Format != attestation.AttestationStatementFormatIdentifierNone {
				t.Fatalf("format = %q, want none", response.Format)
			}

			request := decodeMakeCredentialPINTokenRequest(t, transport.request)
			if !bytes.Equal(request.ClientDataHash, clientPINRetryClientDataHash[:]) {
				t.Fatalf("clientDataHash = %x", request.ClientDataHash)
			}
			if request.RP.ID != clientPINRetryRPID || request.RP.Name != clientPINRetryName {
				t.Fatalf("RP = %#v", request.RP)
			}
			if string(request.User.ID) != "pin-retries-user" ||
				request.User.Name != "pin-retries-user" ||
				request.User.DisplayName != clientPINRetryName {
				t.Fatalf("user = %#v", request.User)
			}
			if !slices.Equal(request.PubKeyCredParams, algorithms[1:]) {
				t.Fatalf("algorithms = %#v, want %#v", request.PubKeyCredParams, algorithms[1:])
			}
			if request.PinUvAuthProtocol != pinUvAuthProtocol {
				t.Fatalf("protocol = %d, want %d", request.PinUvAuthProtocol, pinUvAuthProtocol)
			}
			wantAuthParamLength := 16
			if pinUvAuthProtocol == protocol.PinUvAuthProtocolTwo {
				wantAuthParamLength = 32
			}
			if len(request.PinUvAuthParam) != wantAuthParamLength {
				t.Fatalf("pinUvAuthParam length = %d, want %d", len(request.PinUvAuthParam), wantAuthParamLength)
			}
		})
	}
}

func TestMakeCredentialWithPINTokenRequiresAdvertisedPublicKeyAlgorithm(t *testing.T) {
	transport := &makeCredentialPINTokenTransport{t: t}
	ctapClient, err := client.NewClient(options.WithTransport(transport))
	if err != nil {
		t.Fatal(err)
	}

	_, err = makeCredentialWithPINToken(
		t.Context(),
		ctapClient,
		protocol.PinUvAuthProtocolTwo,
		bytes.Repeat([]byte{1}, 32),
		[]credential.PublicKeyCredentialParameters{{Type: "vendor", Algorithm: cose.AlgorithmES256}},
	)
	assertClientPINRetryFailure(t, err)
	if transport.request != nil {
		t.Fatalf("unexpected request = %x", transport.request)
	}
}

func TestMakeCredentialWithPINTokenClassifiesCTAPStatusAndPreservesTransportError(t *testing.T) {
	algorithm := []credential.PublicKeyCredentialParameters{{
		Type:      credential.PublicKeyCredentialTypePublicKey,
		Algorithm: cose.AlgorithmES256,
	}}
	token := bytes.Repeat([]byte{1}, 32)

	t.Run("CTAP status", func(t *testing.T) {
		transport := &makeCredentialPINTokenTransport{
			t:      t,
			status: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
		}
		ctapClient, err := client.NewClient(options.WithTransport(transport))
		if err != nil {
			t.Fatal(err)
		}

		_, err = makeCredentialWithPINToken(
			t.Context(),
			ctapClient,
			protocol.PinUvAuthProtocolTwo,
			token,
			algorithm,
		)
		assertClientPINRetryFailure(t, err)
	})

	t.Run("transport", func(t *testing.T) {
		transportFailure := errors.New("device disconnected")
		transport := &makeCredentialPINTokenTransport{t: t, err: transportFailure}
		ctapClient, err := client.NewClient(options.WithTransport(transport))
		if err != nil {
			t.Fatal(err)
		}

		_, err = makeCredentialWithPINToken(
			t.Context(),
			ctapClient,
			protocol.PinUvAuthProtocolTwo,
			token,
			algorithm,
		)
		if !errors.Is(err, transportFailure) {
			t.Fatalf("error = %v, want %v", err, transportFailure)
		}
	})
}

func marshalClientPINRetryFixture(t testing.TB, value any) []byte {
	t.Helper()

	data, err := clientPINKeyAgreementCTAP2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func assertClientPINRetryFailure(t testing.TB, err error) {
	t.Helper()

	var assertion *conformance.AssertionError
	if !errors.As(err, &assertion) {
		t.Fatalf("error = %v, want conformance failure", err)
	}
}

type legacyPINTokenTransport struct {
	t                    testing.TB
	pinUvAuthProtocol    protocol.PinUvAuthProtocol
	authenticatorPrivate *ecdh.PrivateKey
	authenticatorKey     cose.Key
	token                []byte
	status               ctaptransport.StatusCode
	calls                int
}

func newLegacyPINTokenTransport(
	t testing.TB,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	token []byte,
) *legacyPINTokenTransport {
	t.Helper()

	privateKeyBytes := make([]byte, 32)
	privateKeyBytes[len(privateKeyBytes)-1] = 1
	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	return &legacyPINTokenTransport{
		t:                    t,
		pinUvAuthProtocol:    pinUvAuthProtocol,
		authenticatorPrivate: privateKey,
		authenticatorKey:     key,
		token:                token,
	}
}

func (l *legacyPINTokenTransport) CBOR(
	_ context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	l.t.Helper()

	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorClientPIN {
		l.t.Fatalf("request = %x, want authenticatorClientPIN", request)
	}
	var body protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
		l.t.Fatal(err)
	}
	if body.PinUvAuthProtocol != l.pinUvAuthProtocol {
		l.t.Fatalf("protocol = %d, want %d", body.PinUvAuthProtocol, l.pinUvAuthProtocol)
	}

	l.calls++
	switch l.calls {
	case 1:
		if body.SubCommand != protocol.ClientPINSubCommandGetKeyAgreement {
			l.t.Fatalf("subcommand = %d, want getKeyAgreement", body.SubCommand)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalClientPINRetryFixture(l.t, map[uint64]any{
				1: l.authenticatorKey,
			}),
		}, nil
	case 2:
		if body.SubCommand != protocol.ClientPINSubCommandGetPinToken {
			l.t.Fatalf("subcommand = %d, want getPinToken", body.SubCommand)
		}
		if l.status != ctaptransport.CTAP2_OK {
			return ctaptransport.ValidateCBORResponse(protocol.AuthenticatorClientPIN, ctaptransport.CBORResponse{
				StatusCode: l.status,
			})
		}

		platformPublicKey, err := body.KeyAgreement.P256PublicKey()
		if err != nil {
			l.t.Fatal(err)
		}
		sharedSecret, err := l.authenticatorPrivate.ECDH(platformPublicKey)
		if err != nil {
			l.t.Fatal(err)
		}
		pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(l.pinUvAuthProtocol)
		if err != nil {
			l.t.Fatal(err)
		}
		sharedSecret, err = pinProtocol.KDF(sharedSecret)
		if err != nil {
			l.t.Fatal(err)
		}
		encryptedToken, err := pinProtocol.Encrypt(sharedSecret, l.token)
		if err != nil {
			l.t.Fatal(err)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       marshalClientPINRetryFixture(l.t, map[uint64]any{2: encryptedToken}),
		}, nil
	default:
		l.t.Fatalf("unexpected request %d", l.calls)

		return ctaptransport.CBORResponse{}, nil
	}
}

type pinPolicyTransport struct {
	t                    testing.TB
	pinUvAuthProtocol    protocol.PinUvAuthProtocol
	authenticatorPrivate *ecdh.PrivateKey
	authenticatorKey     cose.Key
	wantPaddedPIN        [64]byte
	status               ctaptransport.StatusCode
	err                  error
	calls                int
	setPINVerified       bool
}

func newPINPolicyTransport(
	t testing.TB,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	wantPaddedPIN [64]byte,
) *pinPolicyTransport {
	t.Helper()
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	return &pinPolicyTransport{
		t:                    t,
		pinUvAuthProtocol:    pinUvAuthProtocol,
		authenticatorPrivate: privateKey,
		authenticatorKey:     key,
		wantPaddedPIN:        wantPaddedPIN,
	}
}

func (transport *pinPolicyTransport) CBOR(
	_ context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	transport.t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorClientPIN {
		transport.t.Fatalf("request = %x, want authenticatorClientPIN", request)
	}
	var body protocol.AuthenticatorClientPINRequest
	if err := getInfoDecMode.Unmarshal(request[1:], &body); err != nil {
		transport.t.Fatal(err)
	}
	if body.PinUvAuthProtocol != transport.pinUvAuthProtocol {
		transport.t.Fatalf("protocol = %d, want %d", body.PinUvAuthProtocol, transport.pinUvAuthProtocol)
	}

	transport.calls++
	switch transport.calls {
	case 1:
		if body.SubCommand != protocol.ClientPINSubCommandGetKeyAgreement {
			transport.t.Fatalf("subcommand = %d, want getKeyAgreement", body.SubCommand)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: marshalClientPINRetryFixture(transport.t, map[uint64]any{
				1: transport.authenticatorKey,
			}),
		}, nil
	case 2:
		if body.SubCommand != protocol.ClientPINSubCommandSetPIN {
			transport.t.Fatalf("subcommand = %d, want setPIN", body.SubCommand)
		}
		var fields map[uint64]cbor.RawMessage
		if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
			transport.t.Fatal(err)
		}
		if len(fields) != 5 {
			transport.t.Fatalf("setPIN field count = %d, want 5", len(fields))
		}
		for key := uint64(1); key <= 5; key++ {
			if _, present := fields[key]; !present {
				transport.t.Fatalf("setPIN is missing field %d", key)
			}
		}
		if transport.err != nil {
			return ctaptransport.CBORResponse{}, transport.err
		}
		transport.verifySetPIN(body)

		return ctaptransport.CBORResponse{StatusCode: transport.status}, nil
	default:
		transport.t.Fatalf("unexpected request %d", transport.calls)

		return ctaptransport.CBORResponse{}, nil
	}
}

func (transport *pinPolicyTransport) verifySetPIN(body protocol.AuthenticatorClientPINRequest) {
	transport.t.Helper()
	platformPublicKey, err := body.KeyAgreement.P256PublicKey()
	if err != nil {
		transport.t.Fatal(err)
	}
	z, err := transport.authenticatorPrivate.ECDH(platformPublicKey)
	if err != nil {
		transport.t.Fatal(err)
	}
	defer clear(z)
	pinProtocol, err := ctapcrypto.NewPinUvAuthProtocol(transport.pinUvAuthProtocol)
	if err != nil {
		transport.t.Fatal(err)
	}
	sharedSecret, err := pinProtocol.KDF(z)
	if err != nil {
		transport.t.Fatal(err)
	}
	defer clear(sharedSecret)
	wantAuthParam := ctapcrypto.Authenticate(transport.pinUvAuthProtocol, sharedSecret, body.NewPinEnc)
	defer clear(wantAuthParam)
	if !bytes.Equal(body.PinUvAuthParam, wantAuthParam) {
		transport.t.Fatalf("pinUvAuthParam = %x, want %x", body.PinUvAuthParam, wantAuthParam)
	}
	plaintext, err := pinProtocol.Decrypt(sharedSecret, body.NewPinEnc)
	if err != nil {
		transport.t.Fatal(err)
	}
	defer clear(plaintext)
	if !bytes.Equal(plaintext, transport.wantPaddedPIN[:]) {
		transport.t.Fatal("setPIN plaintext does not match the exact padded PIN")
	}
	transport.setPINVerified = true
}

type makeCredentialPINTokenTransport struct {
	t       testing.TB
	request []byte
	status  ctaptransport.StatusCode
	err     error
}

func (m *makeCredentialPINTokenTransport) CBOR(
	_ context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	m.t.Helper()

	if m.request != nil {
		m.t.Fatal("unexpected second request")
	}
	m.request = slices.Clone(request)
	if m.err != nil {
		return ctaptransport.CBORResponse{}, m.err
	}
	if m.status != ctaptransport.CTAP2_OK {
		return ctaptransport.ValidateCBORResponse(
			protocol.AuthenticatorMakeCredential,
			ctaptransport.CBORResponse{StatusCode: m.status},
		)
	}

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data: marshalClientPINRetryFixture(m.t, protocol.AuthenticatorMakeCredentialResponse{
			Format:               attestation.AttestationStatementFormatIdentifierNone,
			AuthDataRaw:          make([]byte, 37),
			AttestationStatement: map[string]any{},
		}),
	}, nil
}

func decodeMakeCredentialPINTokenRequest(
	t testing.TB,
	request []byte,
) protocol.AuthenticatorMakeCredentialRequest {
	t.Helper()

	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
		t.Fatalf("request = %x, want authenticatorMakeCredential", request)
	}
	var body protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(request[1:], &body); err != nil {
		t.Fatal(err)
	}

	return body
}
