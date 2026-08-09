package ctap23

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/kit/conformance"
)

func TestNFC1CaseMatrix(t *testing.T) {
	t.Parallel()

	tests := nfc1Tests(Config{})
	want := []struct {
		id          conformance.TestID
		marker      string
		destructive bool
	}{
		{TestIDNFC1P1, "P-1", false},
		{TestIDNFC1P2, "P-2", true},
		{TestIDNFC1P3, "P-3", true},
		{TestIDNFC1P4, "P-4", true},
		{TestIDNFC1F1, "F-1", false},
		{TestIDNFC1F2, "F-2", false},
		{TestIDNFC1F3, "F-3", false},
		{TestIDNFC1F4, "F-4", false},
	}
	if len(tests) != len(want) {
		t.Fatalf("nfc1Tests returned %d cases, want %d", len(tests), len(want))
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != nfc1SourcePath ||
			test.Source.Case != expected.marker || test.Destructive != expected.destructive {
			t.Fatalf("case %d metadata = %#v", index, test)
		}
		if len(test.References) == 0 {
			t.Fatalf("case %s has no normative references", expected.marker)
		}
	}
}

func TestNFC1CasesPassWithExactRawAPDUs(t *testing.T) {
	t.Parallel()

	for _, marker := range []string{"P-1", "P-2", "P-3", "P-4", "F-1", "F-2", "F-3", "F-4"} {
		marker := marker
		t.Run(marker, func(t *testing.T) {
			t.Parallel()

			environment := newNFC1TestEnvironment(t, marker)
			result := runNFC1Case(t, environment.config, marker, environment.device)
			assertNFC1Status(t, result, conformance.StatusPassed)
			environment.assertTranscript(t)
		})
	}
}

func TestNFC1AppletSelectionUsesAdvertisedU2FCompatibility(t *testing.T) {
	t.Parallel()

	environment := newNFC1TestEnvironment(t, "P-1")
	environment.config.Metadata.GetInfo.Versions = protocol.Versions{protocol.FIDO_2_3, protocol.U2F_V2}
	environment.card.appletVersion = protocol.U2F_V2

	result := runNFC1Case(t, environment.config, "P-1", environment.device)
	assertNFC1Status(t, result, conformance.StatusPassed)
	environment.assertTranscript(t)
}

func TestNFC1ApplicabilitySkipsBeforeMutation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*nfc1TestEnvironment)
	}{
		{
			name: "transport mismatch",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.config.Transport = AuthenticatorTransportHID
			},
		},
		{
			name: "provider absent",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.config.NFCCardProvider = nil
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			environment := newNFC1TestEnvironment(t, "P-2")
			testCase.mutate(environment)

			result := runNFC1Case(t, environment.config, "P-2", environment.device)
			assertNFC1Status(t, result, conformance.StatusSkipped)
			if len(environment.events) != 0 || environment.device.calls != 0 ||
				environment.providerCalls != 0 || environment.tokenCalls != 0 {
				t.Fatalf(
					"skip mutated environment: events=%v CBOR=%d provider=%d token=%d",
					environment.events,
					environment.device.calls,
					environment.providerCalls,
					environment.tokenCalls,
				)
			}
		})
	}
}

func TestNFC1ResponseAndTransportClassification(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("card removed")
	tests := []struct {
		name       string
		marker     string
		mutate     func(*nfc1TestEnvironment)
		wantStatus conformance.Status
	}{
		{
			name:   "transport error",
			marker: "P-1",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.card.err = transportErr
			},
			wantStatus: conformance.StatusError,
		},
		{
			name:   "selection status",
			marker: "P-1",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.card.selectStatus = 0x6a82
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name:   "selection payload",
			marker: "P-1",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.card.appletVersion = protocol.U2F_V2
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name:   "make credential APDU status",
			marker: "P-2",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.card.commandStatus = 0x6f00
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name:   "make credential CTAP status",
			marker: "P-2",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.card.ctapStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name:   "negative wrong status",
			marker: "F-1",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.card.commandStatus = iso7816.StatusSuccess
			},
			wantStatus: conformance.StatusFailed,
		},
		{
			name:   "malformed response APDU",
			marker: "F-3",
			mutate: func(environment *nfc1TestEnvironment) {
				environment.card.malformedTargetResponse = true
			},
			wantStatus: conformance.StatusFailed,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			environment := newNFC1TestEnvironment(t, testCase.marker)
			testCase.mutate(environment)

			result := runNFC1Case(t, environment.config, testCase.marker, environment.device)
			assertNFC1Status(t, result, testCase.wantStatus)
		})
	}
}

type nfc1TestEnvironment struct {
	marker        string
	config        Config
	device        *nfc1CBORDevice
	card          *nfc1Card
	events        []string
	providerCalls int
	tokenCalls    int
	token         []byte
	tokenSnapshot []byte
	tokenRequest  PinUvAuthTokenRequest
}

func newNFC1TestEnvironment(t *testing.T, marker string) *nfc1TestEnvironment {
	t.Helper()

	info := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: true,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Algorithms: []credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
	}
	environment := &nfc1TestEnvironment{
		marker: marker,
		device: &nfc1CBORDevice{info: info},
		card: &nfc1Card{
			appletVersion: protocol.FIDO_2_0,
			selectStatus:  iso7816.StatusSuccess,
			commandStatus: nfc1ExpectedStatus(marker),
			ctapStatus:    ctaptransport.CTAP2_OK,
		},
		token: make([]byte, 32),
	}
	for index := range environment.token {
		environment.token[index] = byte(index + 1)
	}
	environment.tokenSnapshot = slices.Clone(environment.token)
	environment.config = Config{
		Metadata:  Metadata{GetInfo: info},
		Transport: AuthenticatorTransportNFC,
		PowerCycler: func(context.Context) error {
			environment.events = append(environment.events, "power")

			return nil
		},
	}
	// Assign callbacks separately so their concrete function signatures remain
	// checked against the public conformance environment contract.
	environment.config.Resetter = func(context.Context, *client.Client) error {
		environment.events = append(environment.events, "reset")

		return nil
	}
	environment.config.TokenProvider = func(
		_ context.Context,
		_ *client.Client,
		request PinUvAuthTokenRequest,
	) (PinUvAuthToken, error) {
		environment.tokenCalls++
		environment.tokenRequest = request

		return PinUvAuthToken{Protocol: protocol.PinUvAuthProtocolTwo, Value: environment.token}, nil
	}
	environment.config.NFCCardProvider = func(
		ctx context.Context,
		callback func(context.Context, iso7816.Card) error,
	) error {
		environment.providerCalls++
		environment.events = append(environment.events, "provider")

		return callback(ctx, environment.card)
	}

	return environment
}

func (environment *nfc1TestEnvironment) assertTranscript(t *testing.T) {
	t.Helper()

	if environment.providerCalls != 1 {
		t.Fatalf("provider calls = %d, want 1", environment.providerCalls)
	}
	selectAPDU, err := (iso7816.Command{
		CLA: nfc1CLAISO, INS: nfc1INSSelect, P1: nfc1P1SelectByName,
		Data: nfc1FIDOAppletAID[:], Le: 256, Encoding: iso7816.EncodingShort,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(environment.card.requests) == 0 || !bytes.Equal(environment.card.requests[0], selectAPDU) {
		t.Fatalf("selection APDU = %x, want %x", environment.card.requests, selectAPDU)
	}

	switch environment.marker {
	case "P-1":
		if len(environment.card.requests) != 1 || len(environment.events) != 1 {
			t.Fatalf("P-1 transcript requests=%x events=%v", environment.card.requests, environment.events)
		}
	case "P-2", "P-3", "P-4":
		wantEvents := []string{"power", "reset", "power", "provider", "power", "reset"}
		if !slices.Equal(environment.events, wantEvents) {
			t.Fatalf("lifecycle events = %v, want %v", environment.events, wantEvents)
		}
		if environment.device.calls != 1 || environment.tokenCalls != 1 {
			t.Fatalf("CBOR calls=%d token calls=%d, want 1/1", environment.device.calls, environment.tokenCalls)
		}
		wantRPID := environment.marker + "." + nfc1RPIDSuffix
		if environment.tokenRequest.Permission != protocol.PermissionMakeCredential ||
			environment.tokenRequest.RPID != wantRPID {
			t.Fatalf("token scope = %#v, want MakeCredential/%q", environment.tokenRequest, wantRPID)
		}
		if !nfc1AllZero(environment.token) {
			t.Fatalf("authorization token was not wiped: %x", environment.token)
		}
		command := environment.card.reassembledCommand(t, environment.marker)
		defer clear(command)
		if len(command) < 2 || protocol.Command(command[0]) != protocol.AuthenticatorMakeCredential {
			t.Fatalf("CTAP command = %x, want authenticatorMakeCredential", command)
		}
		var request protocol.AuthenticatorMakeCredentialRequest
		if err := getInfoDecMode.Unmarshal(command[1:], &request); err != nil {
			t.Fatalf("decode MakeCredential request: %v", err)
		}
		defer clear(request.PinUvAuthParam)
		if request.RP.ID != wantRPID || request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
			t.Fatalf("MakeCredential request RP/protocol = %q/%d", request.RP.ID, request.PinUvAuthProtocol)
		}
		wantAuth := ctapcrypto.Authenticate(
			protocol.PinUvAuthProtocolTwo,
			environment.tokenSnapshot,
			request.ClientDataHash,
		)
		defer clear(wantAuth)
		if !bytes.Equal(request.PinUvAuthParam, wantAuth) {
			t.Fatalf("pinUvAuthParam = %x, want %x", request.PinUvAuthParam, wantAuth)
		}
	case "F-1", "F-2", "F-3", "F-4":
		if len(environment.card.requests) != 2 || len(environment.events) != 1 {
			t.Fatalf("negative transcript requests=%x events=%v", environment.card.requests, environment.events)
		}
		want := nfc1ExpectedNegativeAPDU(t, environment.marker)
		if !bytes.Equal(environment.card.requests[1], want) {
			t.Fatalf("target APDU = %x, want %x", environment.card.requests[1], want)
		}
	default:
		t.Fatalf("unknown marker %q", environment.marker)
	}
}

type nfc1CBORDevice struct {
	info  protocol.AuthenticatorGetInfoResponse
	calls int
}

func (device *nfc1CBORDevice) CBOR(
	_ context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.calls++
	if !bytes.Equal(request, []byte{byte(protocol.AuthenticatorGetInfo)}) {
		return ctaptransport.CBORResponse{}, fmt.Errorf("unexpected runner-bound CTAP request %x", request)
	}
	data, err := ctap2EncMode.Marshal(device.info)
	if err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}, nil
}

type nfc1Card struct {
	requests                [][]byte
	appletVersion           protocol.Version
	selectStatus            iso7816.StatusWord
	commandStatus           iso7816.StatusWord
	ctapStatus              ctaptransport.StatusCode
	err                     error
	malformedTargetResponse bool
}

func (card *nfc1Card) Transmit(_ context.Context, apdu []byte) ([]byte, error) {
	card.requests = append(card.requests, slices.Clone(apdu))
	if card.err != nil {
		return nil, card.err
	}
	if len(card.requests) == 1 {
		return slices.Concat(
			[]byte(card.appletVersion),
			[]byte{card.selectStatus.SW1(), card.selectStatus.SW2()},
		), nil
	}
	if card.malformedTargetResponse {
		return []byte{0x67}, nil
	}
	if len(apdu) > 0 && apdu[0]&iso7816.CommandChainingBit != 0 {
		return []byte{0x90, 0x00}, nil
	}
	if card.commandStatus == iso7816.StatusSuccess {
		return []byte{byte(card.ctapStatus), 0x90, 0x00}, nil
	}

	return []byte{card.commandStatus.SW1(), card.commandStatus.SW2()}, nil
}

func (card *nfc1Card) reassembledCommand(t *testing.T, marker string) []byte {
	t.Helper()

	targets := card.requests[1:]
	if marker == "P-2" {
		if len(targets) != 1 {
			t.Fatalf("extended APDU count = %d, want 1", len(targets))
		}
		apdu := targets[0]
		if len(apdu) < 9 || !bytes.Equal(apdu[:5], []byte{0x80, 0x10, 0x00, 0x00, 0x00}) {
			t.Fatalf("extended APDU header = %x", apdu)
		}
		length := int(apdu[5])<<8 | int(apdu[6])
		if len(apdu) != 7+length+2 || !bytes.Equal(apdu[len(apdu)-2:], []byte{0x00, 0x00}) {
			t.Fatalf("extended APDU length/Le = %x", apdu)
		}

		return slices.Clone(apdu[7 : 7+length])
	}

	command := make([]byte, 0)
	for index, apdu := range targets {
		if len(apdu) < 5 || apdu[1] != nfc1INSNFCCTAPMsg || apdu[2] != 0 || apdu[3] != 0 {
			t.Fatalf("short APDU %d header = %x", index, apdu)
		}
		length := int(apdu[4])
		final := index == len(targets)-1
		wantCLA := byte(nfc1CLACTAP | iso7816.CommandChainingBit)
		wantLength := 5 + length
		if final {
			wantCLA = nfc1CLACTAP
			wantLength++
		}
		if apdu[0] != wantCLA || len(apdu) != wantLength || (final && apdu[len(apdu)-1] != 0) {
			t.Fatalf("short APDU %d = %x", index, apdu)
		}
		if marker == "P-3" && length > nfc1ShortChunkSize {
			t.Fatalf("P-3 fragment length = %d, want <= %d", length, nfc1ShortChunkSize)
		}
		if marker == "P-4" && !final && length != nfc1MixedChunkSize {
			t.Fatalf("P-4 intermediate fragment length = %d, want %d", length, nfc1MixedChunkSize)
		}
		command = append(command, apdu[5:5+length]...)
	}
	if marker == "P-4" && len(targets) < 2 {
		t.Fatalf("P-4 used %d APDU, want mixed-size chaining", len(targets))
	}

	return command
}

func runNFC1Case(
	t *testing.T,
	config Config,
	marker string,
	device ctaptransport.CBOR,
) conformance.SuiteResult {
	t.Helper()

	tests := nfc1Tests(config)
	index := slices.IndexFunc(tests, func(test conformance.Test) bool {
		return test.Source.Case == marker
	})
	if index < 0 {
		t.Fatalf("NFC-1 marker %s is absent", marker)
	}
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), conformance.Suite{
		ID:    "nfc-1-test",
		Name:  "NFC-1 test",
		Tests: []conformance.Test{tests[index]},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertNFC1Status(t *testing.T, result conformance.SuiteResult, want conformance.Status) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("NFC-1 status = %s/%v, want %s", result.Status, result.Tests, want)
	}
}

func nfc1ExpectedStatus(marker string) iso7816.StatusWord {
	switch marker {
	case "F-1", "F-2":
		return nfc1SWINSUnsupported
	case "F-3", "F-4":
		return nfc1SWWrongLength
	default:
		return iso7816.StatusSuccess
	}
}

func nfc1ExpectedNegativeAPDU(t *testing.T, marker string) []byte {
	t.Helper()

	command := iso7816.Command{
		CLA:  nfc1CLACTAP,
		Data: []byte{byte(protocol.AuthenticatorGetInfo)},
	}
	switch marker {
	case "F-1":
		command.INS = nfc1INSInvalid
		command.Le = 256
		command.Encoding = iso7816.EncodingShort
	case "F-2":
		command.INS = nfc1INSInvalid
		command.Le = 65536
		command.Encoding = iso7816.EncodingExtended
	case "F-3":
		command.INS = nfc1INSNFCCTAPMsg
		command.Le = 256
		command.Encoding = iso7816.EncodingShort
	case "F-4":
		command.INS = nfc1INSNFCCTAPMsg
		command.Le = 65536
		command.Encoding = iso7816.EncodingExtended
	default:
		t.Fatalf("marker %q is not negative", marker)
	}
	apdu, err := command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if marker == "F-3" {
		apdu[4] = 0xff
	}
	if marker == "F-4" {
		apdu[6] = 0xff
	}

	return apdu
}

func nfc1AllZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}

	return true
}
