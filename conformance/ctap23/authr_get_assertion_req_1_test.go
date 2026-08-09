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

func TestAuthrGetAssertionReq1Definitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrGetAssertionReq1P1, "P-1"},
		{TestIDAuthrGetAssertionReq1F1, "F-1"},
		{TestIDAuthrGetAssertionReq1F2, "F-2"},
		{TestIDAuthrGetAssertionReq1F3, "F-3"},
		{TestIDAuthrGetAssertionReq1F4, "F-4"},
		{TestIDAuthrGetAssertionReq1F5, "F-5"},
		{TestIDAuthrGetAssertionReq1F6, "F-6"},
	}
	tests := authrGetAssertionReq1Tests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrGetAssertionReq1SourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}

		wantReferences := []conformance.RequirementRef{authrGetAssertionReq1CommandReference()}
		switch test.ID {
		case TestIDAuthrGetAssertionReq1P1:
			wantReferences = append(
				wantReferences,
				ctapMessageEncodingReference(),
				authrGetAssertionReq1ResponseCredentialReference(),
			)
		case TestIDAuthrGetAssertionReq1F1:
			wantReferences = append(
				wantReferences,
				authrGetAssertionReq1ParameterReference("rp-id-required-text-string"),
				authrGetAssertionReq1MissingParameterReference(),
			)
		case TestIDAuthrGetAssertionReq1F2:
			wantReferences = append(
				wantReferences,
				authrGetAssertionReq1ParameterReference("rp-id-required-text-string"),
				authrGetAssertionReq1WrongTypeReference(),
			)
		case TestIDAuthrGetAssertionReq1F3:
			wantReferences = append(
				wantReferences,
				authrGetAssertionReq1ParameterReference("client-data-hash-required-byte-string"),
				authrGetAssertionReq1MissingParameterReference(),
			)
		case TestIDAuthrGetAssertionReq1F4:
			wantReferences = append(
				wantReferences,
				authrGetAssertionReq1ParameterReference("client-data-hash-required-byte-string"),
				authrGetAssertionReq1WrongTypeReference(),
			)
		case TestIDAuthrGetAssertionReq1F5, TestIDAuthrGetAssertionReq1F6:
			wantReferences = append(
				wantReferences,
				authrGetAssertionReq1ParameterReference("allow-list-optional-array"),
				authrGetAssertionReq1WrongTypeReference(),
			)
		}
		if !slices.Equal(test.References, wantReferences) {
			t.Fatalf("references for %s = %#v, want %#v", test.ID, test.References, wantReferences)
		}
	}
}

func TestAuthrGetAssertionReq1CasesPassWithExactStatus(t *testing.T) {
	cases := []struct {
		id     conformance.TestID
		marker string
		status ctaptransport.StatusCode
	}{
		{TestIDAuthrGetAssertionReq1P1, "P-1", ctaptransport.CTAP2_OK},
		{TestIDAuthrGetAssertionReq1F1, "F-1", ctaptransport.CTAP2_ERR_MISSING_PARAMETER},
		{TestIDAuthrGetAssertionReq1F2, "F-2", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrGetAssertionReq1F3, "F-3", ctaptransport.CTAP2_ERR_MISSING_PARAMETER},
		{TestIDAuthrGetAssertionReq1F4, "F-4", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrGetAssertionReq1F5, "F-5", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrGetAssertionReq1F6, "F-6", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
	}

	for _, testCase := range cases {
		t.Run(testCase.marker, func(t *testing.T) {
			device := newAuthrGetAssertionReq1Device(t)
			device.getAssertionStatus = testCase.status
			lifecycle := &authrGetAssertionReq1Lifecycle{t: t}

			result := runAuthrGetAssertionReq1Test(t, device, lifecycle.config(), testCase.id)

			assertAuthrGetAssertionReq1Status(t, result, conformance.StatusPassed)
			assertAuthrGetAssertionReq1Lifecycle(t, device, lifecycle)
			assertAuthrGetAssertionReq1WireMutation(t, testCase.marker, device.getAssertionRequest)
		})
	}
}

func TestAuthrGetAssertionReq1MalformedCasesRejectSuccessAndDifferentStatus(t *testing.T) {
	for _, id := range []conformance.TestID{
		TestIDAuthrGetAssertionReq1F1,
		TestIDAuthrGetAssertionReq1F2,
		TestIDAuthrGetAssertionReq1F3,
		TestIDAuthrGetAssertionReq1F4,
		TestIDAuthrGetAssertionReq1F5,
		TestIDAuthrGetAssertionReq1F6,
	} {
		for _, testCase := range []struct {
			name   string
			status ctaptransport.StatusCode
		}{
			{name: "success", status: ctaptransport.CTAP2_OK},
			{name: "different CTAP status", status: ctaptransport.CTAP2_ERR_INVALID_CBOR},
		} {
			t.Run(string(id)+"/"+testCase.name, func(t *testing.T) {
				device := newAuthrGetAssertionReq1Device(t)
				device.getAssertionStatus = testCase.status
				lifecycle := &authrGetAssertionReq1Lifecycle{t: t}

				result := runAuthrGetAssertionReq1Test(t, device, lifecycle.config(), id)

				assertAuthrGetAssertionReq1Status(t, result, conformance.StatusFailed)
				assertAuthrGetAssertionReq1Lifecycle(t, device, lifecycle)
			})
		}
	}
}

func TestAuthrGetAssertionReq1PositiveRequiresSuccessAndCreatedCredential(t *testing.T) {
	t.Run("CTAP error", func(t *testing.T) {
		device := newAuthrGetAssertionReq1Device(t)
		device.getAssertionStatus = ctaptransport.CTAP2_ERR_NO_CREDENTIALS
		lifecycle := &authrGetAssertionReq1Lifecycle{t: t}

		result := runAuthrGetAssertionReq1Test(
			t,
			device,
			lifecycle.config(),
			TestIDAuthrGetAssertionReq1P1,
		)

		assertAuthrGetAssertionReq1Status(t, result, conformance.StatusFailed)
		assertAuthrGetAssertionReq1Lifecycle(t, device, lifecycle)
	})

	t.Run("different credential ID", func(t *testing.T) {
		device := newAuthrGetAssertionReq1Device(t)
		device.responseCredentialID = []byte{0xff}
		lifecycle := &authrGetAssertionReq1Lifecycle{t: t}

		result := runAuthrGetAssertionReq1Test(
			t,
			device,
			lifecycle.config(),
			TestIDAuthrGetAssertionReq1P1,
		)

		assertAuthrGetAssertionReq1Status(t, result, conformance.StatusFailed)
		assertAuthrGetAssertionReq1Lifecycle(t, device, lifecycle)
		if got := result.Tests[0].Steps[1].Message; got !=
			"authenticatorGetAssertion returned a different credential ID" {
			t.Fatalf("message = %q", got)
		}
	})
}

func TestAuthrGetAssertionReq1TransportErrorIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrGetAssertionReq1Device(t)
	device.getAssertionError = transportFailure
	lifecycle := &authrGetAssertionReq1Lifecycle{t: t}

	result := runAuthrGetAssertionReq1Test(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrGetAssertionReq1F2,
	)

	assertAuthrGetAssertionReq1Status(t, result, conformance.StatusError)
	assertAuthrGetAssertionReq1Lifecycle(t, device, lifecycle)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("action error = %q", got)
	}
}

func TestAuthrGetAssertionReq1CleanupErrorIsVisibleAndTokensAreWiped(t *testing.T) {
	cleanupFailure := errors.New("cleanup power cycle failed")
	device := newAuthrGetAssertionReq1Device(t)
	lifecycle := &authrGetAssertionReq1Lifecycle{t: t, cleanupFailure: cleanupFailure}

	result := runAuthrGetAssertionReq1Test(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrGetAssertionReq1P1,
	)

	assertAuthrGetAssertionReq1Status(t, result, conformance.StatusError)
	assertAuthrGetAssertionReq1TokensWiped(t, lifecycle.tokens)
	if lifecycle.powerCycles != 3 || device.resets != 1 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/1", lifecycle.powerCycles, device.resets)
	}
	steps := result.Tests[0].Steps
	last := steps[len(steps)-1]
	if last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusError ||
		last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
}

type authrGetAssertionReq1Lifecycle struct {
	t              testing.TB
	powerCycles    int
	tokens         [][]byte
	cleanupFailure error
}

func (l *authrGetAssertionReq1Lifecycle) config() Config {
	return Config{
		PowerCycler: func(context.Context) error {
			l.powerCycles++
			if l.powerCycles == 3 && l.cleanupFailure != nil {
				return l.cleanupFailure
			}

			return nil
		},
		TokenProvider: func(
			_ context.Context,
			_ *client.Client,
			request PinUvAuthTokenRequest,
		) (PinUvAuthToken, error) {
			wantPermissions := []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionGetAssertion,
			}
			if len(l.tokens) >= len(wantPermissions) ||
				request.Permission != wantPermissions[len(l.tokens)] ||
				request.RPID != authrGetAssertionReq1RPID {
				l.t.Fatalf("token request %d = %#v", len(l.tokens), request)
			}
			if len(l.tokens) == 1 {
				if slices.ContainsFunc(l.tokens[0], func(value byte) bool { return value != 0 }) {
					l.t.Fatal("MakeCredential token was not wiped before GetAssertion authorization")
				}
			}

			token := bytes.Repeat([]byte{byte(0x71 + len(l.tokens))}, 32)
			l.tokens = append(l.tokens, token)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    token,
			}, nil
		},
	}
}

type authrGetAssertionReq1Device struct {
	t                      testing.TB
	commands               []protocol.Command
	resets                 int
	credentialID           []byte
	responseCredentialID   []byte
	getAssertionStatus     ctaptransport.StatusCode
	getAssertionError      error
	getAssertionRequest    []byte
	makeCredentialRequests int
}

func newAuthrGetAssertionReq1Device(t testing.TB) *authrGetAssertionReq1Device {
	t.Helper()

	return &authrGetAssertionReq1Device{
		t:            t,
		credentialID: bytes.Repeat([]byte{0x81}, 16),
	}
}

func (d *authrGetAssertionReq1Device) CBOR(
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
			Data: authrGetAssertionReq1Marshal(d.t, protocol.AuthenticatorGetInfoResponse{
				Versions:           []protocol.Version{protocol.FIDO_2_3},
				Extensions:         []extension.ExtensionIdentifier{},
				AAGUID:             uuid.UUID{},
				Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
				PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
				Algorithms: []credential.PublicKeyCredentialParameters{{
					Type:      credential.PublicKeyCredentialTypePublicKey,
					Algorithm: cose.AlgorithmES256,
				}},
			}),
		}, nil
	case protocol.AuthenticatorMakeCredential:
		d.makeCredentialRequests++

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: authrGetAssertionReq1Marshal(d.t, protocol.AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AuthDataRaw:          authrGetAssertionReq1MakeCredentialAuthData(d.t, d.credentialID),
				AttestationStatement: map[string]any{},
			}),
		}, nil
	case protocol.AuthenticatorGetAssertion:
		d.getAssertionRequest = slices.Clone(request)
		if d.getAssertionError != nil {
			return ctaptransport.CBORResponse{}, d.getAssertionError
		}

		response := ctaptransport.CBORResponse{StatusCode: d.getAssertionStatus}
		if response.StatusCode == ctaptransport.CTAP2_OK {
			credentialID := d.responseCredentialID
			if credentialID == nil {
				credentialID = d.credentialID
			}
			response.Data = authrGetAssertionReq1Marshal(
				d.t,
				protocol.AuthenticatorGetAssertionResponse{
					Credential: credential.PublicKeyCredentialDescriptor{
						Type: credential.PublicKeyCredentialTypePublicKey,
						ID:   credentialID,
					},
					AuthDataRaw: authrGetAssertionReq1AuthData(),
					Signature:   []byte{0x30, 0x00},
				},
			)
		}

		return response, nil
	default:
		d.t.Fatalf("unexpected command 0x%02x", byte(command))

		return ctaptransport.CBORResponse{}, nil
	}
}

func authrGetAssertionReq1MakeCredentialAuthData(t testing.TB, credentialID []byte) []byte {
	t.Helper()

	curve := elliptic.P256().Params()
	key := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   curve.Gx.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   curve.Gy.FillBytes(make([]byte, 32)),
	}
	authData := make([]byte, 37)
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagAttestedCredentialDataIncluded)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, byte(len(credentialID)>>8), byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, authrGetAssertionReq1Marshal(t, key)...)

	return authData
}

func authrGetAssertionReq1AuthData() []byte {
	authData := make([]byte, 37)
	authData[32] = byte(protocol.AuthDataFlagUserPresent)

	return authData
}

func runAuthrGetAssertionReq1Test(
	t *testing.T,
	device *authrGetAssertionReq1Device,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrGetAssertionReq1Tests(config) {
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
		ID:    "authr-get-assertion-req-1-test",
		Name:  "Authr GetAssertion Req 1 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrGetAssertionReq1WireMutation(t *testing.T, marker string, request []byte) {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorGetAssertion {
		t.Fatalf("request = %x", request)
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		t.Fatal(err)
	}

	missingKey := uint64(0)
	wrongKey := uint64(0)
	wantMajorType := byte(0)
	switch marker {
	case "P-1":
	case "F-1":
		missingKey = 1
	case "F-2":
		wrongKey, wantMajorType = 1, 4
	case "F-3":
		missingKey = 2
	case "F-4":
		wrongKey, wantMajorType = 2, 3
	case "F-5":
		wrongKey, wantMajorType = 3, 5
	case "F-6":
		wrongKey, wantMajorType = 3, 4
	default:
		t.Fatalf("unknown marker %q", marker)
	}

	wantFields := 5
	if missingKey != 0 {
		wantFields--
	}
	if len(fields) != wantFields {
		t.Fatalf("fields = %#v, want %d entries", fields, wantFields)
	}
	for _, key := range []uint64{1, 2, 3, 6, 7} {
		_, present := fields[key]
		if present == (key == missingKey) {
			t.Fatalf("field %d presence = %v, missing key = %d", key, present, missingKey)
		}
	}
	if wrongKey != 0 {
		raw := fields[wrongKey]
		if len(raw) == 0 || raw[0]>>5 != wantMajorType {
			t.Fatalf("field %d = %x, want CBOR major type %d", wrongKey, raw, wantMajorType)
		}
	}
	if marker == "F-6" {
		var allowList []cbor.RawMessage
		if err := getInfoDecMode.Unmarshal(fields[3], &allowList); err != nil {
			t.Fatal(err)
		}
		if len(allowList) != 2 || allowList[0][0]>>5 != 5 || allowList[1][0]>>5 == 5 {
			t.Fatalf("allowList = %x", fields[3])
		}
	}
}

func assertAuthrGetAssertionReq1Lifecycle(
	t *testing.T,
	device *authrGetAssertionReq1Device,
	lifecycle *authrGetAssertionReq1Lifecycle,
) {
	t.Helper()

	if lifecycle.powerCycles != 3 || device.resets != 2 || device.makeCredentialRequests != 1 {
		t.Fatalf(
			"power cycles/resets/MakeCredential = %d/%d/%d, want 3/2/1",
			lifecycle.powerCycles,
			device.resets,
			device.makeCredentialRequests,
		)
	}
	if !slices.Equal(device.commands, []protocol.Command{
		protocol.AuthenticatorReset,
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorMakeCredential,
		protocol.AuthenticatorGetAssertion,
		protocol.AuthenticatorReset,
	}) {
		t.Fatalf("commands = %v", device.commands)
	}
	assertAuthrGetAssertionReq1TokensWiped(t, lifecycle.tokens)
}

func assertAuthrGetAssertionReq1TokensWiped(t testing.TB, tokens [][]byte) {
	t.Helper()

	if len(tokens) != 2 {
		t.Fatalf("tokens = %d, want 2", len(tokens))
	}
	for index, token := range tokens {
		if len(token) != 32 || slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
			t.Fatalf("token %d was not wiped", index)
		}
	}
}

func assertAuthrGetAssertionReq1Status(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrGetAssertionReq1Marshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
