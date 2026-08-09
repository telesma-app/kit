package ctap23

import (
	"bytes"
	"context"
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

func TestAuthrMakeCredReq1Definitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrMakeCredReq1P1, "P-1"},
		{TestIDAuthrMakeCredReq1F1, "F-1"},
		{TestIDAuthrMakeCredReq1F2, "F-2"},
		{TestIDAuthrMakeCredReq1F3, "F-3"},
		{TestIDAuthrMakeCredReq1F4, "F-4"},
		{TestIDAuthrMakeCredReq1F5, "F-5"},
		{TestIDAuthrMakeCredReq1F6, "F-6"},
		{TestIDAuthrMakeCredReq1F7, "F-7"},
		{TestIDAuthrMakeCredReq1F8, "F-8"},
		{TestIDAuthrMakeCredReq1F9, "F-9"},
		{TestIDAuthrMakeCredReq1F10, "F-10"},
		{TestIDAuthrMakeCredReq1F11, "F-11"},
	}
	tests := authrMakeCredReq1Tests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrMakeCredReq1SourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		if len(test.References) == 0 {
			t.Fatalf("test %s has no references", test.ID)
		}
		wantReferences := []conformance.RequirementRef{authrMakeCredReq1CommandReference()}
		switch test.ID {
		case TestIDAuthrMakeCredReq1P1:
			wantReferences = append(
				wantReferences,
				ctapMessageEncodingReference(),
				makeCredentialResponseRequiredReference(),
			)
		case TestIDAuthrMakeCredReq1F1, TestIDAuthrMakeCredReq1F2:
			wantReferences = append(wantReferences, authrMakeCredReq1ParameterReference("client-data-hash-required-byte-string"))
		case TestIDAuthrMakeCredReq1F3, TestIDAuthrMakeCredReq1F4:
			wantReferences = append(wantReferences, authrMakeCredReq1ParameterReference("rp-required-map"))
		case TestIDAuthrMakeCredReq1F5, TestIDAuthrMakeCredReq1F6:
			wantReferences = append(wantReferences, authrMakeCredReq1ParameterReference("user-required-map"))
		case TestIDAuthrMakeCredReq1F7, TestIDAuthrMakeCredReq1F8:
			wantReferences = append(wantReferences, authrMakeCredReq1ParameterReference("public-key-credential-parameters-required-array"))
		case TestIDAuthrMakeCredReq1F9:
			wantReferences = append(wantReferences, authrMakeCredReq1ParameterReference("exclude-list-optional-array"))
		case TestIDAuthrMakeCredReq1F10:
			wantReferences = append(wantReferences, authrMakeCredReq1ParameterReference("extensions-optional-map"))
		case TestIDAuthrMakeCredReq1F11:
			wantReferences = append(wantReferences, authrMakeCredReq1ParameterReference("options-optional-map"))
		}
		if !slices.Equal(test.References, wantReferences) {
			t.Fatalf("references for %s = %#v, want %#v", test.ID, test.References, wantReferences)
		}
	}
}

func TestAuthrMakeCredReq1CasesPass(t *testing.T) {
	cases := []struct {
		id     conformance.TestID
		marker string
		status ctaptransport.StatusCode
	}{
		{TestIDAuthrMakeCredReq1P1, "P-1", ctaptransport.CTAP2_OK},
		{TestIDAuthrMakeCredReq1F1, "F-1", ctaptransport.CTAP2_ERR_MISSING_PARAMETER},
		{TestIDAuthrMakeCredReq1F2, "F-2", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq1F3, "F-3", ctaptransport.CTAP2_ERR_MISSING_PARAMETER},
		{TestIDAuthrMakeCredReq1F4, "F-4", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq1F5, "F-5", ctaptransport.CTAP2_ERR_MISSING_PARAMETER},
		{TestIDAuthrMakeCredReq1F6, "F-6", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq1F7, "F-7", ctaptransport.CTAP2_ERR_MISSING_PARAMETER},
		{TestIDAuthrMakeCredReq1F8, "F-8", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq1F9, "F-9", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq1F10, "F-10", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
		{TestIDAuthrMakeCredReq1F11, "F-11", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
	}

	for _, tc := range cases {
		t.Run(tc.marker, func(t *testing.T) {
			device := newAuthrMakeCredReq1Device(t)
			device.makeCredentialStatus = tc.status
			lifecycle := &authrMakeCredReq1Lifecycle{t: t}
			result := runAuthrMakeCredReq1Test(t, device, lifecycle.config(), tc.id)

			assertAuthrMakeCredReq1Status(t, result, conformance.StatusPassed)
			assertAuthrMakeCredReq1Lifecycle(t, device, lifecycle)
			assertAuthrMakeCredReq1WireMutation(t, tc.marker, device.makeCredentialRequest)
		})
	}
}

func TestAuthrMakeCredReq1MalformedRequestSuccessFails(t *testing.T) {
	ids := []conformance.TestID{
		TestIDAuthrMakeCredReq1F1,
		TestIDAuthrMakeCredReq1F2,
		TestIDAuthrMakeCredReq1F3,
		TestIDAuthrMakeCredReq1F4,
		TestIDAuthrMakeCredReq1F5,
		TestIDAuthrMakeCredReq1F6,
		TestIDAuthrMakeCredReq1F7,
		TestIDAuthrMakeCredReq1F8,
		TestIDAuthrMakeCredReq1F9,
		TestIDAuthrMakeCredReq1F10,
		TestIDAuthrMakeCredReq1F11,
	}

	for _, id := range ids {
		t.Run(string(id), func(t *testing.T) {
			device := newAuthrMakeCredReq1Device(t)
			lifecycle := &authrMakeCredReq1Lifecycle{t: t}
			result := runAuthrMakeCredReq1Test(t, device, lifecycle.config(), id)

			assertAuthrMakeCredReq1Status(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq1Lifecycle(t, device, lifecycle)
		})
	}
}

func TestAuthrMakeCredReq1PositiveCTAPErrorFails(t *testing.T) {
	device := newAuthrMakeCredReq1Device(t)
	device.makeCredentialStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
	lifecycle := &authrMakeCredReq1Lifecycle{t: t}
	result := runAuthrMakeCredReq1Test(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq1P1,
	)

	assertAuthrMakeCredReq1Status(t, result, conformance.StatusFailed)
	assertAuthrMakeCredReq1Lifecycle(t, device, lifecycle)
}

func TestAuthrMakeCredReq1TransportErrorIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrMakeCredReq1Device(t)
	device.makeCredentialError = transportFailure
	lifecycle := &authrMakeCredReq1Lifecycle{t: t}
	result := runAuthrMakeCredReq1Test(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq1F2,
	)

	assertAuthrMakeCredReq1Status(t, result, conformance.StatusError)
	assertAuthrMakeCredReq1Lifecycle(t, device, lifecycle)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("action error = %q", got)
	}
}

func TestAuthrMakeCredReq1CleanupErrorIsVisible(t *testing.T) {
	cleanupFailure := errors.New("cleanup power cycle failed")
	device := newAuthrMakeCredReq1Device(t)
	lifecycle := &authrMakeCredReq1Lifecycle{t: t, cleanupFailure: cleanupFailure}
	result := runAuthrMakeCredReq1Test(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq1P1,
	)

	assertAuthrMakeCredReq1Status(t, result, conformance.StatusError)
	assertZeroedAuthrMakeCredReq1Token(t, lifecycle.token)
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

type authrMakeCredReq1Lifecycle struct {
	t              testing.TB
	powerCycles    int
	token          []byte
	cleanupFailure error
}

func (l *authrMakeCredReq1Lifecycle) config() Config {
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
			if request.Permission != protocol.PermissionMakeCredential || request.RPID != authrMakeCredReq1RPID {
				l.t.Fatalf("token request = %#v", request)
			}

			l.token = bytes.Repeat([]byte{0x6d}, 32)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    l.token,
			}, nil
		},
	}
}

type authrMakeCredReq1Device struct {
	t                     testing.TB
	commands              []protocol.Command
	resets                int
	makeCredentialStatus  ctaptransport.StatusCode
	makeCredentialError   error
	makeCredentialRequest []byte
}

func newAuthrMakeCredReq1Device(t testing.TB) *authrMakeCredReq1Device {
	t.Helper()

	return &authrMakeCredReq1Device{t: t}
}

func (d *authrMakeCredReq1Device) CBOR(
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
			Data: authrMakeCredReq1Marshal(d.t, protocol.AuthenticatorGetInfoResponse{
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
		d.makeCredentialRequest = slices.Clone(request)
		if d.makeCredentialError != nil {
			return ctaptransport.CBORResponse{}, d.makeCredentialError
		}

		response := ctaptransport.CBORResponse{StatusCode: d.makeCredentialStatus}
		if d.makeCredentialStatus == ctaptransport.CTAP2_OK {
			response.Data = authrMakeCredReq1Marshal(d.t, protocol.AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AuthDataRaw:          make([]byte, 37),
				AttestationStatement: map[string]any{},
			})
		}

		return ctaptransport.ValidateCBORResponse(command, response)
	default:
		d.t.Fatalf("unexpected command 0x%02x", byte(command))

		return ctaptransport.CBORResponse{}, nil
	}
}

func runAuthrMakeCredReq1Test(
	t *testing.T,
	device *authrMakeCredReq1Device,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrMakeCredReq1Tests(config) {
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
		ID:    "authr-make-cred-req-1-test",
		Name:  "Authr MakeCred Req 1 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredReq1WireMutation(t *testing.T, marker string, request []byte) {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
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
		wrongKey, wantMajorType = 1, 3
	case "F-3":
		missingKey = 2
	case "F-4":
		wrongKey, wantMajorType = 2, 4
	case "F-5":
		missingKey = 3
	case "F-6":
		wrongKey, wantMajorType = 3, 7
	case "F-7":
		missingKey = 4
	case "F-8":
		wrongKey, wantMajorType = 4, 5
	case "F-9":
		wrongKey, wantMajorType = 5, 5
	case "F-10":
		wrongKey, wantMajorType = 6, 4
	case "F-11":
		wrongKey, wantMajorType = 7, 4
	default:
		t.Fatalf("unknown marker %q", marker)
	}

	wantFields := 6
	if missingKey != 0 {
		wantFields--
	}
	if wrongKey >= 5 {
		wantFields++
	}
	if len(fields) != wantFields {
		t.Fatalf("fields = %#v, want %d entries", fields, wantFields)
	}
	for key := uint64(1); key <= 4; key++ {
		_, present := fields[key]
		if present == (key == missingKey) {
			t.Fatalf("field %d presence = %v, missing key = %d", key, present, missingKey)
		}
	}
	for _, key := range []uint64{8, 9} {
		if _, present := fields[key]; !present {
			t.Fatalf("authorization field %d is absent", key)
		}
	}
	if wrongKey != 0 {
		raw := fields[wrongKey]
		if len(raw) == 0 || raw[0]>>5 != wantMajorType {
			t.Fatalf("field %d = %x, want CBOR major type %d", wrongKey, raw, wantMajorType)
		}
	}
}

func assertAuthrMakeCredReq1Lifecycle(
	t *testing.T,
	device *authrMakeCredReq1Device,
	lifecycle *authrMakeCredReq1Lifecycle,
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
	assertZeroedAuthrMakeCredReq1Token(t, lifecycle.token)
}

func assertZeroedAuthrMakeCredReq1Token(t *testing.T, token []byte) {
	t.Helper()

	if len(token) != 32 || slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
		t.Fatalf("token was not wiped")
	}
}

func assertAuthrMakeCredReq1Status(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrMakeCredReq1Marshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
