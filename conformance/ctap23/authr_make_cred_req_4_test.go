package ctap23

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrMakeCredReq4Definitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrMakeCredReq4P1, "P-1"},
		{TestIDAuthrMakeCredReq4F1, "F-1"},
		{TestIDAuthrMakeCredReq4F2, "F-2"},
		{TestIDAuthrMakeCredReq4F3, "F-3"},
		{TestIDAuthrMakeCredReq4F4, "F-4"},
		{TestIDAuthrMakeCredReq4F5, "F-5"},
		{TestIDAuthrMakeCredReq4F6, "F-6"},
		{TestIDAuthrMakeCredReq4F7, "F-7"},
	}
	tests := authrMakeCredReq4Tests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrMakeCredReq4SourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		wantReferences := []conformance.RequirementRef{
			authrMakeCredReq4ParametersReference(),
			authrMakeCredReq4AlgorithmReference(),
		}
		if test.ID == TestIDAuthrMakeCredReq4P1 {
			wantReferences = append(
				wantReferences,
				ctapMessageEncodingReference(),
				makeCredentialResponseRequiredReference(),
			)
		}
		if !slices.Equal(test.References, wantReferences) {
			t.Fatalf("references for %s = %#v, want %#v", test.ID, test.References, wantReferences)
		}
	}
}

func TestAuthrMakeCredReq4CasesPass(t *testing.T) {
	cases := []struct {
		id     conformance.TestID
		marker string
		status ctaptransport.StatusCode
	}{
		{TestIDAuthrMakeCredReq4P1, "P-1", ctaptransport.CTAP2_OK},
		{TestIDAuthrMakeCredReq4F1, "F-1", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq4F2, "F-2", ctaptransport.CTAP2_ERR_INVALID_CBOR},
		{TestIDAuthrMakeCredReq4F3, "F-3", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq4F4, "F-4", ctaptransport.CTAP2_ERR_INVALID_CBOR},
		{TestIDAuthrMakeCredReq4F5, "F-5", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq4F6, "F-6", ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM},
		{TestIDAuthrMakeCredReq4F7, "F-7", ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM},
	}

	for _, tc := range cases {
		t.Run(tc.marker, func(t *testing.T) {
			device := newAuthrMakeCredReq4Device(t)
			device.makeCredentialStatus = tc.status
			lifecycle := &authrMakeCredReq4Lifecycle{t: t}
			result := runAuthrMakeCredReq4Test(t, device, lifecycle.config(), tc.id)

			assertAuthrMakeCredReq4Status(t, result, conformance.StatusPassed)
			assertAuthrMakeCredReq4Lifecycle(t, device, lifecycle)
			assertAuthrMakeCredReq4WireMutation(t, tc.marker, device.makeCredentialRequest)
		})
	}
}

func TestAuthrMakeCredReq4MalformedParameterSuccessFails(t *testing.T) {
	ids := []conformance.TestID{
		TestIDAuthrMakeCredReq4F1,
		TestIDAuthrMakeCredReq4F2,
		TestIDAuthrMakeCredReq4F3,
		TestIDAuthrMakeCredReq4F4,
		TestIDAuthrMakeCredReq4F5,
	}
	for _, id := range ids {
		t.Run(string(id), func(t *testing.T) {
			device := newAuthrMakeCredReq4Device(t)
			lifecycle := &authrMakeCredReq4Lifecycle{t: t}
			result := runAuthrMakeCredReq4Test(t, device, lifecycle.config(), id)

			assertAuthrMakeCredReq4Status(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq4Lifecycle(t, device, lifecycle)
		})
	}
}

func TestAuthrMakeCredReq4UnsupportedAlgorithmRequiresExactStatus(t *testing.T) {
	for _, id := range []conformance.TestID{TestIDAuthrMakeCredReq4F6, TestIDAuthrMakeCredReq4F7} {
		t.Run(string(id), func(t *testing.T) {
			device := newAuthrMakeCredReq4Device(t)
			device.makeCredentialStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			lifecycle := &authrMakeCredReq4Lifecycle{t: t}
			result := runAuthrMakeCredReq4Test(t, device, lifecycle.config(), id)

			assertAuthrMakeCredReq4Status(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq4Lifecycle(t, device, lifecycle)
		})
	}
}

func TestAuthrMakeCredReq4PositiveValidatesReturnedAlgorithm(t *testing.T) {
	device := newAuthrMakeCredReq4Device(t)
	device.responseAlgorithm = cose.AlgorithmEdDSA
	lifecycle := &authrMakeCredReq4Lifecycle{t: t}
	result := runAuthrMakeCredReq4Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq4P1)

	assertAuthrMakeCredReq4Status(t, result, conformance.StatusFailed)
	assertAuthrMakeCredReq4Lifecycle(t, device, lifecycle)
}

func TestAuthrMakeCredReq4TransportErrorIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrMakeCredReq4Device(t)
	device.makeCredentialError = transportFailure
	lifecycle := &authrMakeCredReq4Lifecycle{t: t}
	result := runAuthrMakeCredReq4Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq4F3)

	assertAuthrMakeCredReq4Status(t, result, conformance.StatusError)
	assertAuthrMakeCredReq4Lifecycle(t, device, lifecycle)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("action error = %q", got)
	}
}

type authrMakeCredReq4Lifecycle struct {
	t           testing.TB
	powerCycles int
	token       []byte
}

func (l *authrMakeCredReq4Lifecycle) config() Config {
	return Config{
		PowerCycler: func(context.Context) error {
			l.powerCycles++

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			if request.Permission != protocol.PermissionMakeCredential || request.RPID != authrMakeCredReq4RPID {
				l.t.Fatalf("token request = %#v", request)
			}

			l.token = bytes.Repeat([]byte{0x74}, 32)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    l.token,
			}, nil
		},
	}
}

type authrMakeCredReq4Device struct {
	t                     testing.TB
	commands              []protocol.Command
	resets                int
	makeCredentialStatus  ctaptransport.StatusCode
	makeCredentialError   error
	makeCredentialRequest []byte
	responseAlgorithm     cose.Algorithm
}

func newAuthrMakeCredReq4Device(t testing.TB) *authrMakeCredReq4Device {
	t.Helper()

	return &authrMakeCredReq4Device{
		t:                 t,
		responseAlgorithm: cose.AlgorithmES256,
	}
}

func (d *authrMakeCredReq4Device) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	d.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		d.t.Fatal("empty request")
	}

	command := protocol.Command(request[0])
	d.commands = append(d.commands, command)
	switch command {
	case protocol.AuthenticatorReset:
		if len(request) != 1 {
			d.t.Fatalf("reset request = %x", request)
		}
		d.resets++

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}, nil
	case protocol.AuthenticatorGetInfo:
		if len(request) != 1 {
			d.t.Fatalf("GetInfo request = %x", request)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: authrMakeCredReq4Marshal(d.t, protocol.AuthenticatorGetInfoResponse{
				Versions:           []protocol.Version{protocol.FIDO_2_3},
				Extensions:         []extension.ExtensionIdentifier{},
				AAGUID:             uuid.Nil,
				Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
				PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
				Algorithms: []credential.PublicKeyCredentialParameters{
					{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmES256},
					{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: cose.AlgorithmEdDSA},
				},
			}),
		}, nil
	case protocol.AuthenticatorMakeCredential:
		d.makeCredentialRequest = slices.Clone(request)
		if d.makeCredentialError != nil {
			return ctaptransport.CBORResponse{}, d.makeCredentialError
		}
		response := ctaptransport.CBORResponse{StatusCode: d.makeCredentialStatus}
		if response.StatusCode == ctaptransport.CTAP2_OK {
			response.Data = authrMakeCredReq4Marshal(d.t, protocol.AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AuthDataRaw:          authrMakeCredReq4AuthData(d.t, d.responseAlgorithm),
				AttestationStatement: map[string]any{},
			})
		}

		return response, nil
	default:
		d.t.Fatalf("unexpected command 0x%02x", byte(command))

		return ctaptransport.CBORResponse{}, nil
	}
}

func authrMakeCredReq4AuthData(t testing.TB, algorithm cose.Algorithm) []byte {
	t.Helper()

	curve := elliptic.P256().Params()
	key := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    algorithm,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   curve.Gx.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   curve.Gy.FillBytes(make([]byte, 32)),
	}
	encodedKey := authrMakeCredReq4Marshal(t, key)
	authData := make([]byte, 37)
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagAttestedCredentialDataIncluded)
	authData = append(authData, make([]byte, 16)...)
	credentialID := bytes.Repeat([]byte{0x63}, 16)
	authData = append(authData, 0, byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, encodedKey...)

	return authData
}

func runAuthrMakeCredReq4Test(
	t *testing.T,
	device *authrMakeCredReq4Device,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrMakeCredReq4Tests(config) {
		if test.ID == id {
			selected = test
			break
		}
	}
	if selected.Run == nil {
		t.Fatalf("test %q not found", id)
	}

	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "authr-make-cred-req-4-test",
		Name:  "Authr MakeCred Req 4 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredReq4WireMutation(t *testing.T, marker string, request []byte) {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
		t.Fatalf("request = %x", request)
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []uint64{1, 2, 3, 4, 8, 9} {
		if _, present := fields[key]; !present {
			t.Fatalf("request field %d is absent", key)
		}
	}
	var parameters []cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[4], &parameters); err != nil {
		t.Fatal(err)
	}

	switch marker {
	case "P-1":
		if len(parameters) != 3 {
			t.Fatalf("parameters = %d, want 3", len(parameters))
		}
		first := decodeAuthrMakeCredReq4Parameter(t, parameters[0])
		second := decodeAuthrMakeCredReq4Parameter(t, parameters[1])
		if decodeAuthrMakeCredReq4Text(t, first["type"]) != "public-key" ||
			decodeAuthrMakeCredReq4Integer(t, first["alg"]) != -99 ||
			decodeAuthrMakeCredReq4Integer(t, second["alg"]) != int64(cose.AlgorithmES256) {
			t.Fatalf("algorithm order = %x", fields[4])
		}
	case "F-1":
		if len(parameters) != 3 || !bytes.Equal(parameters[2], cbor.RawMessage{0xf5}) {
			t.Fatalf("parameters = %x, want trailing true", fields[4])
		}
	case "F-2":
		first := decodeAuthrMakeCredReq4Parameter(t, parameters[0])
		if _, present := first["type"]; present {
			t.Fatalf("first parameter = %x, want type absent", parameters[0])
		}
	case "F-3":
		second := decodeAuthrMakeCredReq4Parameter(t, parameters[1])
		if !bytes.Equal(second["type"], cbor.RawMessage{0xf4}) {
			t.Fatalf("second type = %x, want false", second["type"])
		}
	case "F-4":
		second := decodeAuthrMakeCredReq4Parameter(t, parameters[1])
		if _, present := second["alg"]; present {
			t.Fatalf("second parameter = %x, want alg absent", parameters[1])
		}
	case "F-5":
		second := decodeAuthrMakeCredReq4Parameter(t, parameters[1])
		if decodeAuthrMakeCredReq4Text(t, second["alg"]) != "not-an-integer" {
			t.Fatalf("second alg = %x", second["alg"])
		}
	case "F-6":
		first := decodeAuthrMakeCredReq4Parameter(t, parameters[0])
		if len(parameters) != 1 || decodeAuthrMakeCredReq4Text(t, first["type"]) != "public-key" ||
			decodeAuthrMakeCredReq4Integer(t, first["alg"]) != 0x45 {
			t.Fatalf("parameters = %x", fields[4])
		}
	case "F-7":
		first := decodeAuthrMakeCredReq4Parameter(t, parameters[0])
		if len(parameters) != 1 || decodeAuthrMakeCredReq4Text(t, first["type"]) != "not-public-key" ||
			decodeAuthrMakeCredReq4Integer(t, first["alg"]) != int64(cose.AlgorithmES256) {
			t.Fatalf("parameters = %x", fields[4])
		}
	default:
		t.Fatalf("unknown marker %q", marker)
	}
}

func decodeAuthrMakeCredReq4Parameter(t testing.TB, raw cbor.RawMessage) map[string]cbor.RawMessage {
	t.Helper()

	var parameter map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &parameter); err != nil {
		t.Fatal(err)
	}

	return parameter
}

func decodeAuthrMakeCredReq4Text(t testing.TB, raw cbor.RawMessage) string {
	t.Helper()

	var value string
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}

	return value
}

func decodeAuthrMakeCredReq4Integer(t testing.TB, raw cbor.RawMessage) int64 {
	t.Helper()

	var value int64
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}

	return value
}

func assertAuthrMakeCredReq4Lifecycle(
	t *testing.T,
	device *authrMakeCredReq4Device,
	lifecycle *authrMakeCredReq4Lifecycle,
) {
	t.Helper()

	if lifecycle.powerCycles != 3 || device.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/2", lifecycle.powerCycles, device.resets)
	}
	if !slices.Equal(device.commands, []protocol.Command{
		protocol.AuthenticatorReset,
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorMakeCredential,
		protocol.AuthenticatorReset,
	}) {
		t.Fatalf("commands = %v", device.commands)
	}
	if len(lifecycle.token) != 32 || slices.ContainsFunc(lifecycle.token, func(value byte) bool { return value != 0 }) {
		t.Fatal("PIN/UV token was not wiped")
	}
}

func assertAuthrMakeCredReq4Status(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrMakeCredReq4Marshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
