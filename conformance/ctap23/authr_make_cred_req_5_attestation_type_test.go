package ctap23

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
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

func TestAuthrMakeCredReq5AttestationTypeDefinition(t *testing.T) {
	tests := authrMakeCredReq5AttestationTypeTests(Config{})
	if len(tests) != 1 {
		t.Fatalf("tests = %d, want 1", len(tests))
	}

	test := tests[0]
	if test.ID != TestIDAuthrMakeCredReq5AttestationTypeP4 ||
		test.Source.Path != authrMakeCredReq5AttestationTypeSourcePath ||
		test.Source.Case != "P-4" || !test.Destructive {
		t.Fatalf("test = %#v", test)
	}
	wantReferences := []conformance.RequirementRef{
		authrMakeCredReq1CommandReference(),
		authrMakeCredReq5AttestationTypePreferenceReference(),
		authrMakeCredReq5AttestationTypeWrongTypeReference(),
	}
	if !slices.Equal(test.References, wantReferences) {
		t.Fatalf("references = %#v, want %#v", test.References, wantReferences)
	}
	if wantReferences[1].Section != "6.1" || wantReferences[1].Level != conformance.RequirementConstraint ||
		!strings.HasSuffix(wantReferences[1].URL, "#authenticatorMakeCredential") {
		t.Fatalf("preference reference = %#v", wantReferences[1])
	}
	if wantReferences[2].Section != "8" || wantReferences[2].Level != conformance.RequirementShould ||
		!strings.HasSuffix(wantReferences[2].URL, "#message-encoding") {
		t.Fatalf("wrong-type reference = %#v", wantReferences[2])
	}
	if !strings.Contains(test.Description, "omitted request member") {
		t.Fatalf("source adjudication is absent from description: %q", test.Description)
	}
}

func TestAuthrMakeCredReq5AttestationTypePassesWithExactStatusAndWire(t *testing.T) {
	device := newAuthrMakeCredReq5AttestationTypeDevice(t)
	device.makeCredentialStatus = ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE
	lifecycle := &authrMakeCredReq5AttestationTypeLifecycle{t: t}
	result := runAuthrMakeCredReq5AttestationTypeTest(t, device, lifecycle.config())

	assertAuthrMakeCredReq5AttestationTypeStatus(t, result, conformance.StatusPassed)
	assertAuthrMakeCredReq5AttestationTypeLifecycle(t, device, lifecycle)
	assertAuthrMakeCredReq5AttestationTypeWire(t, device.makeCredentialRequest)
}

func TestAuthrMakeCredReq5AttestationTypeRequiresExactStatus(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		status ctaptransport.StatusCode
	}{
		{name: "success", status: ctaptransport.CTAP2_OK},
		{name: "different CTAP error", status: ctaptransport.CTAP2_ERR_INVALID_CBOR},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newAuthrMakeCredReq5AttestationTypeDevice(t)
			device.makeCredentialStatus = testCase.status
			lifecycle := &authrMakeCredReq5AttestationTypeLifecycle{t: t}
			result := runAuthrMakeCredReq5AttestationTypeTest(t, device, lifecycle.config())

			assertAuthrMakeCredReq5AttestationTypeStatus(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq5AttestationTypeLifecycle(t, device, lifecycle)
		})
	}
}

func TestAuthrMakeCredReq5AttestationTypeTransportFailureIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrMakeCredReq5AttestationTypeDevice(t)
	device.makeCredentialError = transportFailure
	lifecycle := &authrMakeCredReq5AttestationTypeLifecycle{t: t}
	result := runAuthrMakeCredReq5AttestationTypeTest(t, device, lifecycle.config())

	assertAuthrMakeCredReq5AttestationTypeStatus(t, result, conformance.StatusError)
	assertAuthrMakeCredReq5AttestationTypeLifecycle(t, device, lifecycle)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("exchange error = %q, want %q", got, transportFailure)
	}
}

func TestAuthrMakeCredReq5AttestationTypeCleanupFailureIsVisible(t *testing.T) {
	cleanupFailure := errors.New("cleanup power cycle failed")
	device := newAuthrMakeCredReq5AttestationTypeDevice(t)
	device.makeCredentialStatus = ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE
	lifecycle := &authrMakeCredReq5AttestationTypeLifecycle{
		t:              t,
		cleanupFailure: cleanupFailure,
	}
	result := runAuthrMakeCredReq5AttestationTypeTest(t, device, lifecycle.config())

	assertAuthrMakeCredReq5AttestationTypeStatus(t, result, conformance.StatusError)
	if lifecycle.powerCycles != 3 || device.resets != 1 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/1", lifecycle.powerCycles, device.resets)
	}
	assertAuthrMakeCredReq5AttestationTypeTokenWiped(t, lifecycle.token)
	steps := result.Tests[0].Steps
	last := steps[len(steps)-1]
	if last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusError ||
		last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
}

type authrMakeCredReq5AttestationTypeLifecycle struct {
	t              testing.TB
	powerCycles    int
	token          []byte
	cleanupFailure error
}

func (l *authrMakeCredReq5AttestationTypeLifecycle) config() Config {
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
			if request.Permission != protocol.PermissionMakeCredential ||
				request.RPID != authrMakeCredReq5AttestationTypeRPID {
				l.t.Fatalf("token request = %#v", request)
			}

			l.token = bytes.Repeat([]byte{0x76}, 32)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    l.token,
			}, nil
		},
	}
}

type authrMakeCredReq5AttestationTypeDevice struct {
	t                     testing.TB
	commands              []protocol.Command
	resets                int
	makeCredentialStatus  ctaptransport.StatusCode
	makeCredentialError   error
	makeCredentialRequest []byte
}

func newAuthrMakeCredReq5AttestationTypeDevice(t testing.TB) *authrMakeCredReq5AttestationTypeDevice {
	t.Helper()

	return &authrMakeCredReq5AttestationTypeDevice{t: t}
}

func (d *authrMakeCredReq5AttestationTypeDevice) CBOR(
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
			Data: authrMakeCredReq5AttestationTypeMarshal(d.t, protocol.AuthenticatorGetInfoResponse{
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

func runAuthrMakeCredReq5AttestationTypeTest(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
) conformance.SuiteResult {
	t.Helper()

	tests := authrMakeCredReq5AttestationTypeTests(config)
	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "authr-make-cred-req-5-attestation-type-test",
		Name:  "Authr MakeCred Req 5 attestation type test",
		Tests: tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredReq5AttestationTypeWire(t *testing.T, request []byte) {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
		t.Fatalf("request = %x", request)
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []uint64{1, 2, 3, 4, 8, 9, 11} {
		if _, present := fields[key]; !present {
			t.Fatalf("outer field %d is absent", key)
		}
	}
	if len(fields) != 7 {
		t.Fatalf("outer fields = %#v, want baseline plus attestationFormatsPreference", fields)
	}
	if !bytes.Equal(fields[11], cbor.RawMessage{0xf5}) {
		t.Fatalf("attestationFormatsPreference = %x, want true", fields[11])
	}
}

func assertAuthrMakeCredReq5AttestationTypeLifecycle(
	t *testing.T,
	device *authrMakeCredReq5AttestationTypeDevice,
	lifecycle *authrMakeCredReq5AttestationTypeLifecycle,
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
	assertAuthrMakeCredReq5AttestationTypeTokenWiped(t, lifecycle.token)
}

func assertAuthrMakeCredReq5AttestationTypeTokenWiped(t *testing.T, token []byte) {
	t.Helper()

	if len(token) != 32 || slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
		t.Fatal("PIN/UV token was not wiped")
	}
}

func assertAuthrMakeCredReq5AttestationTypeStatus(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrMakeCredReq5AttestationTypeMarshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
