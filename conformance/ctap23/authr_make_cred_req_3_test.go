package ctap23

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrMakeCredReq3Definitions(t *testing.T) {
	want := []struct {
		id          conformance.TestID
		marker      string
		destructive bool
		reference   conformance.RequirementRef
	}{
		{
			id:          TestIDAuthrMakeCredReq3F1,
			marker:      "F-1",
			destructive: true,
			reference:   authrMakeCredReq3UserReference("user-id-required-byte-string", conformance.RequirementConstraint),
		},
		{
			id:          TestIDAuthrMakeCredReq3F2,
			marker:      "F-2",
			destructive: true,
			reference:   authrMakeCredReq3UserReference("user-name-optional-text-string", conformance.RequirementConstraint),
		},
		{
			id:          TestIDAuthrMakeCredReq3F3,
			marker:      "F-3",
			destructive: true,
			reference:   authrMakeCredReq3UserReference("user-display-name-optional-text-string", conformance.RequirementConstraint),
		},
		{
			id:        TestIDAuthrMakeCredReq3F4,
			marker:    "F-4",
			reference: authrMakeCredReq3UserReference("user-icon-presence-must-not-error", conformance.RequirementMustNot),
		},
	}
	tests := authrMakeCredReq3Tests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrMakeCredReq3SourcePath ||
			test.Source.Case != want[index].marker || test.Destructive != want[index].destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		wantReferences := []conformance.RequirementRef{
			authrMakeCredReq1CommandReference(),
			want[index].reference,
		}
		if !slices.Equal(test.References, wantReferences) {
			t.Fatalf("references for %s = %#v, want %#v", test.ID, test.References, wantReferences)
		}
	}
}

func TestAuthrMakeCredReq3ExecutableCasesPass(t *testing.T) {
	for _, testCase := range []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrMakeCredReq3F1, "F-1"},
		{TestIDAuthrMakeCredReq3F2, "F-2"},
		{TestIDAuthrMakeCredReq3F3, "F-3"},
	} {
		t.Run(testCase.marker, func(t *testing.T) {
			device := newAuthrMakeCredReq3Device(t)
			device.makeCredentialStatus = ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE
			lifecycle := &authrMakeCredReq3Lifecycle{t: t}
			result := runAuthrMakeCredReq3Test(t, device, lifecycle.config(), testCase.id)

			assertAuthrMakeCredReq3Status(t, result, conformance.StatusPassed)
			assertAuthrMakeCredReq3Lifecycle(t, device, lifecycle)
			assertAuthrMakeCredReq3WireMutation(t, device.makeCredentialRequest, testCase.marker)
		})
	}
}

func TestAuthrMakeCredReq3MalformedRequestSuccessFails(t *testing.T) {
	for _, id := range []conformance.TestID{
		TestIDAuthrMakeCredReq3F1,
		TestIDAuthrMakeCredReq3F2,
		TestIDAuthrMakeCredReq3F3,
	} {
		t.Run(string(id), func(t *testing.T) {
			device := newAuthrMakeCredReq3Device(t)
			lifecycle := &authrMakeCredReq3Lifecycle{t: t}
			result := runAuthrMakeCredReq3Test(t, device, lifecycle.config(), id)

			assertAuthrMakeCredReq3Status(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq3Lifecycle(t, device, lifecycle)
		})
	}
}

func TestAuthrMakeCredReq3TransportFailureIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrMakeCredReq3Device(t)
	device.makeCredentialError = transportFailure
	lifecycle := &authrMakeCredReq3Lifecycle{t: t}
	result := runAuthrMakeCredReq3Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq3F1)

	assertAuthrMakeCredReq3Status(t, result, conformance.StatusError)
	assertAuthrMakeCredReq3Lifecycle(t, device, lifecycle)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("exchange error = %q, want %q", got, transportFailure)
	}
}

func TestAuthrMakeCredReq3CleanupFailureIsVisible(t *testing.T) {
	cleanupFailure := errors.New("cleanup power cycle failed")
	device := newAuthrMakeCredReq3Device(t)
	lifecycle := &authrMakeCredReq3Lifecycle{t: t, cleanupFailure: cleanupFailure}
	result := runAuthrMakeCredReq3Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq3F1)

	assertAuthrMakeCredReq3Status(t, result, conformance.StatusError)
	if lifecycle.powerCycles != 3 || device.resets != 1 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/1", lifecycle.powerCycles, device.resets)
	}
	assertAuthrMakeCredReq3TokenWiped(t, lifecycle.token)
	steps := result.Tests[0].Steps
	last := steps[len(steps)-1]
	if last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusError ||
		last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
}

func TestAuthrMakeCredReq3F4SkipsWithoutIOOrEnvironment(t *testing.T) {
	device := authrMakeCredReq3NoIO{t: t}
	result := runAuthrMakeCredReq3Test(t, device, Config{
		PowerCycler: func(context.Context) error {
			t.Fatal("F-4 called PowerCycler")

			return nil
		},
		TokenProvider: func(context.Context, *client.Client, PinUvAuthTokenRequest) (PinUvAuthToken, error) {
			t.Fatal("F-4 called TokenProvider")

			return PinUvAuthToken{}, nil
		},
	}, TestIDAuthrMakeCredReq3F4)

	assertAuthrMakeCredReq3Status(t, result, conformance.StatusSkipped)
	steps := result.Tests[0].Steps
	if len(steps) != 1 || steps[0].ID != "make-cred-req-3.f-4.adjudication" ||
		steps[0].Status != conformance.StatusSkipped {
		t.Fatalf("steps = %#v", steps)
	}
}

type authrMakeCredReq3Lifecycle struct {
	t              testing.TB
	powerCycles    int
	token          []byte
	cleanupFailure error
}

func (l *authrMakeCredReq3Lifecycle) config() Config {
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
			if request.Permission != protocol.PermissionMakeCredential || request.RPID != authrMakeCredReq3RPID {
				l.t.Fatalf("token request = %#v", request)
			}

			l.token = bytes.Repeat([]byte{0x73}, 32)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    l.token,
			}, nil
		},
	}
}

type authrMakeCredReq3Device struct {
	t                     testing.TB
	commands              []protocol.Command
	resets                int
	makeCredentialStatus  ctaptransport.StatusCode
	makeCredentialError   error
	makeCredentialRequest []byte
}

func newAuthrMakeCredReq3Device(t testing.TB) *authrMakeCredReq3Device {
	t.Helper()

	return &authrMakeCredReq3Device{t: t}
}

func (d *authrMakeCredReq3Device) CBOR(
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
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: authrMakeCredReq3Marshal(d.t, protocol.AuthenticatorGetInfoResponse{
				Versions:           []protocol.Version{protocol.FIDO_2_3},
				Extensions:         []extension.ExtensionIdentifier{},
				AAGUID:             uuid.Nil,
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

		return ctaptransport.CBORResponse{StatusCode: d.makeCredentialStatus}, nil
	default:
		d.t.Fatalf("unexpected command 0x%02x", byte(command))

		return ctaptransport.CBORResponse{}, nil
	}
}

type authrMakeCredReq3NoIO struct {
	t testing.TB
}

func (d authrMakeCredReq3NoIO) CBOR(context.Context, []byte) (ctaptransport.CBORResponse, error) {
	d.t.Fatal("F-4 performed CBOR I/O")

	return ctaptransport.CBORResponse{}, nil
}

func runAuthrMakeCredReq3Test(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrMakeCredReq3Tests(config) {
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
		ID:    "authr-make-cred-req-3-test",
		Name:  "Authr MakeCred Req 3 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredReq3WireMutation(t *testing.T, request []byte, marker string) {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
		t.Fatalf("request = %x", request)
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 6 {
		t.Fatalf("outer fields = %#v, want six-entry valid baseline", fields)
	}
	for _, key := range []uint64{1, 2, 3, 4, 8, 9} {
		if _, present := fields[key]; !present {
			t.Fatalf("outer field %d is absent", key)
		}

	}

	var user map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[3], &user); err != nil {
		t.Fatal(err)
	}
	if len(user) != 3 {
		t.Fatalf("user entity = %#v, want id, name, and displayName", user)
	}
	wantMajorTypes := map[string]byte{"id": 2, "name": 3, "displayName": 3}
	switch marker {
	case "F-1":
		wantMajorTypes["id"] = 3
	case "F-2":
		wantMajorTypes["name"] = 7
	case "F-3":
		wantMajorTypes["displayName"] = 0
	default:
		t.Fatalf("unknown marker %q", marker)
	}
	for field, majorType := range wantMajorTypes {
		raw, present := user[field]
		if !present || len(raw) == 0 || raw[0]>>5 != majorType {
			t.Fatalf("user %s = %x, want CBOR major type %d", field, raw, majorType)
		}
	}
}

func assertAuthrMakeCredReq3Lifecycle(
	t *testing.T,
	device *authrMakeCredReq3Device,
	lifecycle *authrMakeCredReq3Lifecycle,
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
	assertAuthrMakeCredReq3TokenWiped(t, lifecycle.token)
}

func assertAuthrMakeCredReq3TokenWiped(t *testing.T, token []byte) {
	t.Helper()

	if len(token) != 32 || slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
		t.Fatal("PIN/UV token was not wiped")
	}
}

func assertAuthrMakeCredReq3Status(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrMakeCredReq3Marshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
