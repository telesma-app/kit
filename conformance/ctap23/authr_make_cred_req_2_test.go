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

func TestAuthrMakeCredReq2Definitions(t *testing.T) {
	tests := authrMakeCredReq2Tests(Config{})
	want := []struct {
		id          conformance.TestID
		marker      string
		destructive bool
		reference   conformance.RequirementRef
	}{
		{
			id:          TestIDAuthrMakeCredReq2F1,
			marker:      "F-1",
			destructive: true,
			reference:   authrMakeCredReq2RPReference("rp-id-required-text-string", conformance.RequirementConstraint),
		},
		{
			id:          TestIDAuthrMakeCredReq2F2,
			marker:      "F-2",
			destructive: true,
			reference:   authrMakeCredReq2RPReference("rp-name-optional-text-string", conformance.RequirementConstraint),
		},
		{
			id:        TestIDAuthrMakeCredReq2F3,
			marker:    "F-3",
			reference: authrMakeCredReq2RPReference("rp-icon-presence-must-not-error", conformance.RequirementMustNot),
		},
	}
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrMakeCredReq2SourcePath ||
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

func TestAuthrMakeCredReq2ExecutableCasesPass(t *testing.T) {
	cases := []struct {
		id     conformance.TestID
		marker string
	}{
		{id: TestIDAuthrMakeCredReq2F1, marker: "F-1"},
		{id: TestIDAuthrMakeCredReq2F2, marker: "F-2"},
	}

	for _, testCase := range cases {
		t.Run(testCase.marker, func(t *testing.T) {
			device := newAuthrMakeCredReq2Device(t)
			device.makeCredentialStatus = ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE
			lifecycle := &authrMakeCredReq2Lifecycle{t: t}
			result := runAuthrMakeCredReq2Test(t, device, lifecycle.config(), testCase.id)

			assertAuthrMakeCredReq2Status(t, result, conformance.StatusPassed)
			assertAuthrMakeCredReq2Lifecycle(t, device, lifecycle)
			assertAuthrMakeCredReq2WireMutation(t, device.makeCredentialRequest, testCase.marker)
		})
	}
}

func TestAuthrMakeCredReq2MalformedRequestSuccessFails(t *testing.T) {
	for _, id := range []conformance.TestID{TestIDAuthrMakeCredReq2F1, TestIDAuthrMakeCredReq2F2} {
		t.Run(string(id), func(t *testing.T) {
			device := newAuthrMakeCredReq2Device(t)
			lifecycle := &authrMakeCredReq2Lifecycle{t: t}
			result := runAuthrMakeCredReq2Test(t, device, lifecycle.config(), id)

			assertAuthrMakeCredReq2Status(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq2Lifecycle(t, device, lifecycle)
		})
	}
}

func TestAuthrMakeCredReq2TransportFailureIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrMakeCredReq2Device(t)
	device.makeCredentialError = transportFailure
	lifecycle := &authrMakeCredReq2Lifecycle{t: t}
	result := runAuthrMakeCredReq2Test(t, device, lifecycle.config(), TestIDAuthrMakeCredReq2F1)

	assertAuthrMakeCredReq2Status(t, result, conformance.StatusError)
	assertAuthrMakeCredReq2Lifecycle(t, device, lifecycle)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("exchange error = %q, want %q", got, transportFailure)
	}
}

func TestAuthrMakeCredReq2F3SkipsWithoutIOOrEnvironment(t *testing.T) {
	device := authrMakeCredReq2NoIO{t: t}
	result := runAuthrMakeCredReq2Test(t, device, Config{
		PowerCycler: func(context.Context) error {
			t.Fatal("F-3 called PowerCycler")

			return nil
		},
		TokenProvider: func(context.Context, *client.Client, PinUvAuthTokenRequest) (PinUvAuthToken, error) {
			t.Fatal("F-3 called TokenProvider")

			return PinUvAuthToken{}, nil
		},
	}, TestIDAuthrMakeCredReq2F3)

	assertAuthrMakeCredReq2Status(t, result, conformance.StatusSkipped)
	steps := result.Tests[0].Steps
	if len(steps) != 1 || steps[0].ID != "make-cred-req-2.f-3.adjudication" ||
		steps[0].Status != conformance.StatusSkipped {
		t.Fatalf("steps = %#v", steps)
	}
}

type authrMakeCredReq2Lifecycle struct {
	t           testing.TB
	powerCycles int
	token       []byte
}

func (l *authrMakeCredReq2Lifecycle) config() Config {
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
			if request.Permission != protocol.PermissionMakeCredential || request.RPID != authrMakeCredReq2RPID {
				l.t.Fatalf("token request = %#v", request)
			}

			l.token = bytes.Repeat([]byte{0x72}, 32)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    l.token,
			}, nil
		},
	}
}

type authrMakeCredReq2Device struct {
	t                     testing.TB
	commands              []protocol.Command
	resets                int
	makeCredentialStatus  ctaptransport.StatusCode
	makeCredentialError   error
	makeCredentialRequest []byte
}

func newAuthrMakeCredReq2Device(t testing.TB) *authrMakeCredReq2Device {
	t.Helper()

	return &authrMakeCredReq2Device{t: t}
}

func (d *authrMakeCredReq2Device) CBOR(
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
			Data: authrMakeCredReq2Marshal(d.t, protocol.AuthenticatorGetInfoResponse{
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

		return ctaptransport.ValidateCBORResponse(command, ctaptransport.CBORResponse{
			StatusCode: d.makeCredentialStatus,
		})
	default:
		d.t.Fatalf("unexpected command 0x%02x", byte(command))

		return ctaptransport.CBORResponse{}, nil
	}
}

type authrMakeCredReq2NoIO struct {
	t testing.TB
}

func (d authrMakeCredReq2NoIO) CBOR(context.Context, []byte) (ctaptransport.CBORResponse, error) {
	d.t.Fatal("F-3 performed CBOR I/O")

	return ctaptransport.CBORResponse{}, nil
}

func runAuthrMakeCredReq2Test(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrMakeCredReq2Tests(config) {
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
		ID:    "authr-make-cred-req-2-test",
		Name:  "Authr MakeCred Req 2 test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredReq2WireMutation(t *testing.T, request []byte, marker string) {
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

	var rp map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[2], &rp); err != nil {
		t.Fatal(err)
	}
	if len(rp) != 2 {
		t.Fatalf("RP entity = %#v, want id and name", rp)
	}
	wantMajorTypes := map[string]byte{"id": 3, "name": 3}
	switch marker {
	case "F-1":
		wantMajorTypes["id"] = 2
	case "F-2":
		wantMajorTypes["name"] = 0
	default:
		t.Fatalf("unknown marker %q", marker)
	}
	for field, majorType := range wantMajorTypes {
		raw, present := rp[field]
		if !present || len(raw) == 0 || raw[0]>>5 != majorType {
			t.Fatalf("RP %s = %x, want CBOR major type %d", field, raw, majorType)
		}
	}
}

func assertAuthrMakeCredReq2Lifecycle(
	t *testing.T,
	device *authrMakeCredReq2Device,
	lifecycle *authrMakeCredReq2Lifecycle,
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

func assertAuthrMakeCredReq2Status(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrMakeCredReq2Marshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
