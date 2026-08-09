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
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrMakeCredReq5PositiveDefinitions(t *testing.T) {
	want := []struct {
		id        conformance.TestID
		marker    string
		reference conformance.RequirementRef
	}{
		{
			id:        TestIDAuthrMakeCredReq5PositiveP1,
			marker:    "P-1",
			reference: authrMakeCredReq5PositiveReference("exclude-list-unknown-credential-type"),
		},
		{
			id:        TestIDAuthrMakeCredReq5PositiveP2,
			marker:    "P-2",
			reference: authrMakeCredReq5PositiveReference("attestation-formats-preference-array-of-strings"),
		},
		{
			id:        TestIDAuthrMakeCredReq5PositiveP3,
			marker:    "P-3",
			reference: authrMakeCredReq5PositiveReference("attestation-formats-preference-array-of-strings"),
		},
	}
	tests := authrMakeCredReq5PositiveTests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrMakeCredReq5PositiveSourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		wantReferences := []conformance.RequirementRef{
			authrMakeCredReq1CommandReference(),
			want[index].reference,
		}
		if !slices.Equal(test.References, wantReferences) {
			t.Fatalf("references for %s = %#v, want %#v", test.ID, test.References, wantReferences)
		}
		if (test.ID == TestIDAuthrMakeCredReq5PositiveP2 ||
			test.ID == TestIDAuthrMakeCredReq5PositiveP3) &&
			!strings.Contains(test.Description, "pinned source's omitted generator argument") {
			t.Fatalf("source adjudication is absent from %s description: %q", test.ID, test.Description)
		}
	}
}

func TestAuthrMakeCredReq5PositiveCasesPassAndSendIntendedWire(t *testing.T) {
	for _, testCase := range []struct {
		id          conformance.TestID
		marker      string
		advertised  []attestation.AttestationStatementFormatIdentifier
		wantFormats []string
	}{
		{id: TestIDAuthrMakeCredReq5PositiveP1, marker: "P-1"},
		{
			id:     TestIDAuthrMakeCredReq5PositiveP2,
			marker: "P-2",
			advertised: []attestation.AttestationStatementFormatIdentifier{
				attestation.AttestationStatementFormatIdentifierPacked,
				attestation.AttestationStatementFormatIdentifierTPM,
			},
			wantFormats: []string{"packed", "tpm"},
		},
		{
			id:          TestIDAuthrMakeCredReq5PositiveP3,
			marker:      "P-3",
			wantFormats: []string{"none"},
		},
	} {
		t.Run(testCase.marker, func(t *testing.T) {
			device := newAuthrMakeCredReq5PositiveDevice(t)
			device.attestationFormats = testCase.advertised
			lifecycle := &authrMakeCredReq5PositiveLifecycle{t: t}
			result := runAuthrMakeCredReq5PositiveTest(t, device, lifecycle.config(), testCase.id)

			assertAuthrMakeCredReq5PositiveStatus(t, result, conformance.StatusPassed)
			assertAuthrMakeCredReq5PositiveLifecycle(t, device, lifecycle)
			assertAuthrMakeCredReq5PositiveWire(t, device.makeCredentialRequest, testCase.marker, testCase.wantFormats)
		})
	}
}

func TestAuthrMakeCredReq5PositiveP2UsesPinnedFallbackOnAbsentGetInfoFormats(t *testing.T) {
	device := newAuthrMakeCredReq5PositiveDevice(t)
	lifecycle := &authrMakeCredReq5PositiveLifecycle{t: t}
	result := runAuthrMakeCredReq5PositiveTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5PositiveP2,
	)

	assertAuthrMakeCredReq5PositiveStatus(t, result, conformance.StatusPassed)
	assertAuthrMakeCredReq5PositiveLifecycle(t, device, lifecycle)
	assertAuthrMakeCredReq5PositiveWire(t, device.makeCredentialRequest, "P-2", []string{"packed", "tpm"})
}

func TestAuthrMakeCredReq5PositiveCTAPErrorsFail(t *testing.T) {
	for _, id := range []conformance.TestID{
		TestIDAuthrMakeCredReq5PositiveP1,
		TestIDAuthrMakeCredReq5PositiveP2,
		TestIDAuthrMakeCredReq5PositiveP3,
	} {
		t.Run(string(id), func(t *testing.T) {
			device := newAuthrMakeCredReq5PositiveDevice(t)
			device.makeCredentialStatus = ctaptransport.CTAP2_ERR_INVALID_CBOR
			lifecycle := &authrMakeCredReq5PositiveLifecycle{t: t}
			result := runAuthrMakeCredReq5PositiveTest(t, device, lifecycle.config(), id)

			assertAuthrMakeCredReq5PositiveStatus(t, result, conformance.StatusFailed)
			assertAuthrMakeCredReq5PositiveLifecycle(t, device, lifecycle)
		})
	}
}

func TestAuthrMakeCredReq5PositiveTransportFailureIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrMakeCredReq5PositiveDevice(t)
	device.makeCredentialError = transportFailure
	lifecycle := &authrMakeCredReq5PositiveLifecycle{t: t}
	result := runAuthrMakeCredReq5PositiveTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5PositiveP2,
	)

	assertAuthrMakeCredReq5PositiveStatus(t, result, conformance.StatusError)
	assertAuthrMakeCredReq5PositiveLifecycle(t, device, lifecycle)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("exchange error = %q, want %q", got, transportFailure)
	}
}

func TestAuthrMakeCredReq5PositiveCleanupFailureIsVisible(t *testing.T) {
	cleanupFailure := errors.New("cleanup power cycle failed")
	device := newAuthrMakeCredReq5PositiveDevice(t)
	lifecycle := &authrMakeCredReq5PositiveLifecycle{t: t, cleanupFailure: cleanupFailure}
	result := runAuthrMakeCredReq5PositiveTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5PositiveP3,
	)

	assertAuthrMakeCredReq5PositiveStatus(t, result, conformance.StatusError)
	if lifecycle.powerCycles != 3 || device.resets != 1 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/1", lifecycle.powerCycles, device.resets)
	}
	assertAuthrMakeCredReq5PositiveTokenWiped(t, lifecycle.token)
	steps := result.Tests[0].Steps
	last := steps[len(steps)-1]
	if last.ID != "make-credential-fixture.cleanup" || last.Status != conformance.StatusError ||
		last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
}

type authrMakeCredReq5PositiveLifecycle struct {
	t              testing.TB
	powerCycles    int
	token          []byte
	cleanupFailure error
}

func (l *authrMakeCredReq5PositiveLifecycle) config() Config {
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
				request.RPID != authrMakeCredReq5PositiveRPID {
				l.t.Fatalf("token request = %#v", request)
			}

			l.token = bytes.Repeat([]byte{0x75}, 32)

			return PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    l.token,
			}, nil
		},
	}
}

type authrMakeCredReq5PositiveDevice struct {
	t                     testing.TB
	commands              []protocol.Command
	resets                int
	attestationFormats    []attestation.AttestationStatementFormatIdentifier
	makeCredentialStatus  ctaptransport.StatusCode
	makeCredentialError   error
	makeCredentialRequest []byte
}

func newAuthrMakeCredReq5PositiveDevice(t testing.TB) *authrMakeCredReq5PositiveDevice {
	t.Helper()

	return &authrMakeCredReq5PositiveDevice{t: t}
}

func (d *authrMakeCredReq5PositiveDevice) CBOR(
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
			Data: authrMakeCredReq5PositiveMarshal(d.t, protocol.AuthenticatorGetInfoResponse{
				Versions:           []protocol.Version{protocol.FIDO_2_3},
				Extensions:         []extension.ExtensionIdentifier{},
				AAGUID:             uuid.Nil,
				Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
				PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
				Algorithms: []credential.PublicKeyCredentialParameters{{
					Type:      credential.PublicKeyCredentialTypePublicKey,
					Algorithm: cose.AlgorithmES256,
				}},
				AttestationFormats: d.attestationFormats,
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

func runAuthrMakeCredReq5PositiveTest(
	t *testing.T,
	device ctaptransport.CBOR,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrMakeCredReq5PositiveTests(config) {
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
		ID:    "authr-make-cred-req-5-positive-test",
		Name:  "Authr MakeCred Req 5 positive test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredReq5PositiveWire(
	t *testing.T,
	request []byte,
	marker string,
	wantFormats []string,
) {
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
			t.Fatalf("outer field %d is absent", key)
		}
	}

	switch marker {
	case "P-1":
		if len(fields) != 7 {
			t.Fatalf("outer fields = %#v, want baseline plus excludeList", fields)
		}
		if _, present := fields[11]; present {
			t.Fatal("P-1 unexpectedly sent attestationFormatsPreference")
		}

		var descriptors []map[string]cbor.RawMessage
		if err := getInfoDecMode.Unmarshal(fields[5], &descriptors); err != nil {
			t.Fatal(err)
		}
		if len(descriptors) != 2 {
			t.Fatalf("excludeList = %#v, want two descriptors", descriptors)
		}
		wantTypes := []string{
			string(credential.PublicKeyCredentialTypePublicKey),
			"mangoPapayaCoconutIamNotAPublicKey",
		}
		for index, descriptor := range descriptors {
			if len(descriptor) != 2 {
				t.Fatalf("descriptor %d = %#v, want type and id", index, descriptor)
			}
			var credentialType string
			if err := getInfoDecMode.Unmarshal(descriptor["type"], &credentialType); err != nil {
				t.Fatal(err)
			}
			if credentialType != wantTypes[index] {
				t.Fatalf("descriptor %d type = %q, want %q", index, credentialType, wantTypes[index])
			}
			var id []byte
			if err := getInfoDecMode.Unmarshal(descriptor["id"], &id); err != nil {
				t.Fatal(err)
			}
			if len(id) != 32 {
				t.Fatalf("descriptor %d id length = %d, want 32", index, len(id))
			}
		}
	case "P-2", "P-3":
		if len(fields) != 7 {
			t.Fatalf("outer fields = %#v, want baseline plus attestationFormatsPreference", fields)
		}
		if _, present := fields[5]; present {
			t.Fatalf("%s unexpectedly sent excludeList", marker)
		}

		var formats []string
		if err := getInfoDecMode.Unmarshal(fields[11], &formats); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(formats, wantFormats) {
			t.Fatalf("attestationFormatsPreference = %v, want %v", formats, wantFormats)
		}
	default:
		t.Fatalf("unknown marker %q", marker)
	}
}

func assertAuthrMakeCredReq5PositiveLifecycle(
	t *testing.T,
	device *authrMakeCredReq5PositiveDevice,
	lifecycle *authrMakeCredReq5PositiveLifecycle,
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
	assertAuthrMakeCredReq5PositiveTokenWiped(t, lifecycle.token)
}

func assertAuthrMakeCredReq5PositiveTokenWiped(t *testing.T, token []byte) {
	t.Helper()

	if len(token) != 32 || slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
		t.Fatal("PIN/UV token was not wiped")
	}
}

func assertAuthrMakeCredReq5PositiveStatus(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrMakeCredReq5PositiveMarshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
