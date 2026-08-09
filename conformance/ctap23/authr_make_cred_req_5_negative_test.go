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
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestAuthrMakeCredReq5NegativeDefinitions(t *testing.T) {
	want := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrMakeCredReq5NegativeF1, "F-1"},
		{TestIDAuthrMakeCredReq5NegativeF2, "F-2"},
		{TestIDAuthrMakeCredReq5NegativeF3, "F-3"},
		{TestIDAuthrMakeCredReq5NegativeF5, "F-5"},
		{TestIDAuthrMakeCredReq5NegativeF6, "F-6"},
		{TestIDAuthrMakeCredReq5NegativeF7, "F-7"},
	}
	tests := authrMakeCredReq5NegativeTests(Config{})
	if len(tests) != len(want) {
		t.Fatalf("tests = %d, want %d", len(tests), len(want))
	}

	for index, test := range tests {
		if test.ID != want[index].id || test.Source.Path != authrMakeCredReq5NegativeSourcePath ||
			test.Source.Case != want[index].marker || !test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}

		wantReferences := []conformance.RequirementRef{
			authrMakeCredReq1CommandReference(),
			authrMakeCredReq5DescriptorReference(),
		}
		if test.ID == TestIDAuthrMakeCredReq5NegativeF7 {
			wantReferences = append(
				wantReferences,
				authrMakeCredReq5CredentialExcludedReference(),
				makeCredentialResponseRequiredReference(),
				ctapMessageEncodingReference(),
			)
		} else {
			wantReferences = append(
				wantReferences,
				authrMakeCredReq5AttestationTypeWrongTypeReference(),
			)
		}
		if !slices.Equal(test.References, wantReferences) {
			t.Fatalf("references for %s = %#v, want %#v", test.ID, test.References, wantReferences)
		}
	}
}

func TestAuthrMakeCredReq5NegativeMalformedCasesPass(t *testing.T) {
	cases := []struct {
		id     conformance.TestID
		marker string
	}{
		{TestIDAuthrMakeCredReq5NegativeF1, "F-1"},
		{TestIDAuthrMakeCredReq5NegativeF2, "F-2"},
		{TestIDAuthrMakeCredReq5NegativeF3, "F-3"},
		{TestIDAuthrMakeCredReq5NegativeF5, "F-5"},
		{TestIDAuthrMakeCredReq5NegativeF6, "F-6"},
	}

	for _, testCase := range cases {
		t.Run(testCase.marker, func(t *testing.T) {
			device := newAuthrMakeCredReq5NegativeDevice(t)
			device.makeCredentialStatuses = []ctaptransport.StatusCode{
				ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			}
			lifecycle := &authrMakeCredReq5NegativeLifecycle{t: t}
			result := runAuthrMakeCredReq5NegativeTest(t, device, lifecycle.config(), testCase.id)

			assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusPassed)
			assertAuthrMakeCredReq5NegativeLifecycle(t, device, lifecycle, 1, 1)
			assertAuthrMakeCredReq5NegativeMalformedWire(t, device.makeCredentialRequests[0], testCase.marker)
			wantReferences := []conformance.RequirementRef{
				authrMakeCredReq1CommandReference(),
				authrMakeCredReq5DescriptorReference(),
				authrMakeCredReq5AttestationTypeWrongTypeReference(),
			}
			if got := result.Tests[0].Steps[1].References; !slices.Equal(got, wantReferences) {
				t.Fatalf("exchange references = %#v, want %#v", got, wantReferences)
			}
		})
	}
}

func TestAuthrMakeCredReq5NegativeMalformedCasesRequireExactStatus(t *testing.T) {
	for _, id := range []conformance.TestID{
		TestIDAuthrMakeCredReq5NegativeF1,
		TestIDAuthrMakeCredReq5NegativeF2,
		TestIDAuthrMakeCredReq5NegativeF3,
		TestIDAuthrMakeCredReq5NegativeF5,
		TestIDAuthrMakeCredReq5NegativeF6,
	} {
		for _, testCase := range []struct {
			name   string
			status ctaptransport.StatusCode
		}{
			{name: "success", status: ctaptransport.CTAP2_OK},
			{name: "different CTAP error", status: ctaptransport.CTAP2_ERR_INVALID_CBOR},
		} {
			t.Run(string(id)+"/"+testCase.name, func(t *testing.T) {
				device := newAuthrMakeCredReq5NegativeDevice(t)
				device.makeCredentialStatuses = []ctaptransport.StatusCode{testCase.status}
				lifecycle := &authrMakeCredReq5NegativeLifecycle{t: t}
				result := runAuthrMakeCredReq5NegativeTest(t, device, lifecycle.config(), id)

				assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusFailed)
				assertAuthrMakeCredReq5NegativeLifecycle(t, device, lifecycle, 1, 1)
			})
		}
	}
}

func TestAuthrMakeCredReq5NegativeTransportFailureIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	device := newAuthrMakeCredReq5NegativeDevice(t)
	device.makeCredentialErrorAt = 1
	device.makeCredentialError = transportFailure
	lifecycle := &authrMakeCredReq5NegativeLifecycle{t: t}
	result := runAuthrMakeCredReq5NegativeTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5NegativeF3,
	)

	assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusError)
	assertAuthrMakeCredReq5NegativeLifecycle(t, device, lifecycle, 1, 1)
	if got := result.Tests[0].Steps[1].Message; got != transportFailure.Error() {
		t.Fatalf("action error = %q, want %q", got, transportFailure)
	}
}

func TestAuthrMakeCredReq5NegativeF7Passes(t *testing.T) {
	device := newAuthrMakeCredReq5NegativeDevice(t)
	device.makeCredentialStatuses = []ctaptransport.StatusCode{
		ctaptransport.CTAP2_OK,
		ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED,
	}
	lifecycle := &authrMakeCredReq5NegativeLifecycle{t: t}
	result := runAuthrMakeCredReq5NegativeTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5NegativeF7,
	)

	assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusPassed)
	assertAuthrMakeCredReq5NegativeLifecycle(t, device, lifecycle, 2, 2)
	assertAuthrMakeCredReq5NegativeF7Wire(t, device, lifecycle)
}

func TestAuthrMakeCredReq5NegativeF7RequiresExactStatus(t *testing.T) {
	device := newAuthrMakeCredReq5NegativeDevice(t)
	device.makeCredentialStatuses = []ctaptransport.StatusCode{
		ctaptransport.CTAP2_OK,
		ctaptransport.CTAP2_ERR_INVALID_CBOR,
	}
	lifecycle := &authrMakeCredReq5NegativeLifecycle{t: t}
	result := runAuthrMakeCredReq5NegativeTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5NegativeF7,
	)

	assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusFailed)
	assertAuthrMakeCredReq5NegativeLifecycle(t, device, lifecycle, 2, 2)
}

func TestAuthrMakeCredReq5NegativeF7FirstCommandErrorFails(t *testing.T) {
	device := newAuthrMakeCredReq5NegativeDevice(t)
	device.makeCredentialStatuses = []ctaptransport.StatusCode{ctaptransport.CTAP2_ERR_INVALID_CBOR}
	lifecycle := &authrMakeCredReq5NegativeLifecycle{t: t}
	result := runAuthrMakeCredReq5NegativeTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5NegativeF7,
	)

	assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusFailed)
	assertAuthrMakeCredReq5NegativeLifecycle(t, device, lifecycle, 1, 1)
}

func TestAuthrMakeCredReq5NegativeF7SecondCommandTransportFailureIsExecutionError(t *testing.T) {
	transportFailure := errors.New("device disconnected during exclusion check")
	device := newAuthrMakeCredReq5NegativeDevice(t)
	device.makeCredentialErrorAt = 2
	device.makeCredentialError = transportFailure
	lifecycle := &authrMakeCredReq5NegativeLifecycle{t: t}
	result := runAuthrMakeCredReq5NegativeTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5NegativeF7,
	)

	assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusError)
	assertAuthrMakeCredReq5NegativeLifecycle(t, device, lifecycle, 2, 2)
	if got := result.Tests[0].Steps[2].Message; got != transportFailure.Error() {
		t.Fatalf("second-command error = %q, want %q", got, transportFailure)
	}
}

func TestAuthrMakeCredReq5NegativeF7SecondTokenFailureIsExecutionErrorAndWipes(t *testing.T) {
	providerFailure := errors.New("PIN entry canceled")
	device := newAuthrMakeCredReq5NegativeDevice(t)
	lifecycle := &authrMakeCredReq5NegativeLifecycle{
		t:                  t,
		secondTokenFailure: providerFailure,
	}
	result := runAuthrMakeCredReq5NegativeTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5NegativeF7,
	)

	assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusError)
	assertAuthrMakeCredReq5NegativeLifecycle(t, device, lifecycle, 1, 2)
	if got := result.Tests[0].Steps[2].Message; got != providerFailure.Error() {
		t.Fatalf("second-token error = %q, want %q", got, providerFailure)
	}
}

func TestAuthrMakeCredReq5NegativeCleanupFailureIsVisible(t *testing.T) {
	cleanupFailure := errors.New("authenticator did not reconnect")
	device := newAuthrMakeCredReq5NegativeDevice(t)
	device.makeCredentialStatuses = []ctaptransport.StatusCode{ctaptransport.CTAP2_ERR_INVALID_CBOR}
	lifecycle := &authrMakeCredReq5NegativeLifecycle{
		t:              t,
		cleanupFailure: cleanupFailure,
	}
	result := runAuthrMakeCredReq5NegativeTest(
		t,
		device,
		lifecycle.config(),
		TestIDAuthrMakeCredReq5NegativeF1,
	)

	assertAuthrMakeCredReq5NegativeStatus(t, result, conformance.StatusError)
	if lifecycle.powerCycles != 3 || device.resets != 1 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/1", lifecycle.powerCycles, device.resets)
	}
	assertAuthrMakeCredReq5NegativeTokensWiped(t, lifecycle.tokens, 1)
	steps := result.Tests[0].Steps
	if last := steps[len(steps)-1]; last.ID != "make-credential-fixture.cleanup" ||
		last.Status != conformance.StatusError || last.Message != cleanupFailure.Error() {
		t.Fatalf("cleanup = %#v", last)
	}
}

type authrMakeCredReq5NegativeLifecycle struct {
	t                  testing.TB
	powerCycles        int
	tokens             [][]byte
	secondTokenFailure error
	cleanupFailure     error
}

func (l *authrMakeCredReq5NegativeLifecycle) config() Config {
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
				request.RPID != authrMakeCredReq5NegativeRPID {
				l.t.Fatalf("token request = %#v", request)
			}

			token := bytes.Repeat([]byte{byte(0x85 + len(l.tokens))}, 32)
			l.tokens = append(l.tokens, token)
			authorization := PinUvAuthToken{
				Protocol: protocol.PinUvAuthProtocolTwo,
				Value:    token,
			}
			if len(l.tokens) == 2 && l.secondTokenFailure != nil {
				return authorization, l.secondTokenFailure
			}

			return authorization, nil
		},
	}
}

type authrMakeCredReq5NegativeDevice struct {
	t                      testing.TB
	commands               []protocol.Command
	resets                 int
	makeCredentialStatuses []ctaptransport.StatusCode
	makeCredentialErrorAt  int
	makeCredentialError    error
	makeCredentialRequests [][]byte
	credentialID           []byte
}

func newAuthrMakeCredReq5NegativeDevice(t testing.TB) *authrMakeCredReq5NegativeDevice {
	t.Helper()

	return &authrMakeCredReq5NegativeDevice{
		t:            t,
		credentialID: bytes.Repeat([]byte{0x57}, 16),
	}
}

func (d *authrMakeCredReq5NegativeDevice) CBOR(
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
			Data: authrMakeCredReq5NegativeMarshal(d.t, protocol.AuthenticatorGetInfoResponse{
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
		d.makeCredentialRequests = append(d.makeCredentialRequests, slices.Clone(request))
		call := len(d.makeCredentialRequests)
		if call == d.makeCredentialErrorAt {
			return ctaptransport.CBORResponse{}, d.makeCredentialError
		}

		var status ctaptransport.StatusCode
		if call <= len(d.makeCredentialStatuses) {
			status = d.makeCredentialStatuses[call-1]
		}
		response := ctaptransport.CBORResponse{StatusCode: status}
		if status == ctaptransport.CTAP2_OK {
			response.Data = authrMakeCredReq5NegativeMarshal(
				d.t,
				protocol.AuthenticatorMakeCredentialResponse{
					Format:               attestation.AttestationStatementFormatIdentifierNone,
					AuthDataRaw:          authrMakeCredReq5NegativeAuthData(d.t, d.credentialID),
					AttestationStatement: map[string]any{},
				},
			)
		}

		return response, nil
	default:
		d.t.Fatalf("unexpected command 0x%02x", byte(command))

		return ctaptransport.CBORResponse{}, nil
	}
}

func authrMakeCredReq5NegativeAuthData(t testing.TB, credentialID []byte) []byte {
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
	authData = append(authData, authrMakeCredReq5NegativeMarshal(t, key)...)

	return authData
}

func runAuthrMakeCredReq5NegativeTest(
	t *testing.T,
	device *authrMakeCredReq5NegativeDevice,
	config Config,
	id conformance.TestID,
) conformance.SuiteResult {
	t.Helper()

	var selected conformance.Test
	for _, test := range authrMakeCredReq5NegativeTests(config) {
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
		ID:    "authr-make-cred-req-5-negative-test",
		Name:  "Authr MakeCred Req 5 negative test",
		Tests: []conformance.Test{selected},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertAuthrMakeCredReq5NegativeMalformedWire(t *testing.T, request []byte, marker string) {
	t.Helper()
	fields := decodeAuthrMakeCredReq5NegativeFields(t, request)
	assertAuthrMakeCredReq5NegativeBaseline(t, fields, true)

	var descriptors []cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[5], &descriptors); err != nil {
		t.Fatal(err)
	}
	if len(descriptors) != 2 {
		t.Fatalf("excludeList = %d entries, want 2", len(descriptors))
	}
	assertAuthrMakeCredReq5NegativeValidDescriptor(t, descriptors[0], authrMakeCredReq5NegativeDescriptorID[:])

	switch marker {
	case "F-1":
		if !bytes.Equal(descriptors[1], cbor.RawMessage{0xf4}) {
			t.Fatalf("second descriptor = %x, want false", descriptors[1])
		}
	case "F-2":
		descriptor := decodeAuthrMakeCredReq5NegativeDescriptor(t, descriptors[1])
		if len(descriptor) != 1 || !decodeAuthrMakeCredReq5NegativeBytes(t, descriptor["id"], authrMakeCredReq5NegativeDescriptorID[:]) {
			t.Fatalf("second descriptor = %x, want only valid id", descriptors[1])
		}
	case "F-3":
		descriptor := decodeAuthrMakeCredReq5NegativeDescriptor(t, descriptors[1])
		if len(descriptor) != 2 || !bytes.Equal(descriptor["type"], cbor.RawMessage{0xf4}) ||
			!decodeAuthrMakeCredReq5NegativeBytes(t, descriptor["id"], authrMakeCredReq5NegativeDescriptorID[:]) {
			t.Fatalf("second descriptor = %x, want false type and valid id", descriptors[1])
		}
	case "F-5":
		descriptor := decodeAuthrMakeCredReq5NegativeDescriptor(t, descriptors[1])
		if len(descriptor) != 1 || decodeAuthrMakeCredReq5NegativeText(t, descriptor["type"]) != "public-key" {
			t.Fatalf("second descriptor = %x, want only public-key type", descriptors[1])
		}
	case "F-6":
		descriptor := decodeAuthrMakeCredReq5NegativeDescriptor(t, descriptors[1])
		if len(descriptor) != 2 || decodeAuthrMakeCredReq5NegativeText(t, descriptor["type"]) != "public-key" ||
			decodeAuthrMakeCredReq5NegativeText(t, descriptor["id"]) != "not-a-byte-string" {
			t.Fatalf("second descriptor = %x, want text id", descriptors[1])
		}
	default:
		t.Fatalf("unknown marker %q", marker)
	}
}

func assertAuthrMakeCredReq5NegativeF7Wire(
	t *testing.T,
	device *authrMakeCredReq5NegativeDevice,
	lifecycle *authrMakeCredReq5NegativeLifecycle,
) {
	t.Helper()
	if len(device.makeCredentialRequests) != 2 {
		t.Fatalf("MakeCredential requests = %d, want 2", len(device.makeCredentialRequests))
	}
	first := decodeAuthrMakeCredReq5NegativeFields(t, device.makeCredentialRequests[0])
	assertAuthrMakeCredReq5NegativeBaseline(t, first, false)
	second := decodeAuthrMakeCredReq5NegativeFields(t, device.makeCredentialRequests[1])
	assertAuthrMakeCredReq5NegativeBaseline(t, second, true)

	var clientDataHash []byte
	if err := getInfoDecMode.Unmarshal(second[1], &clientDataHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientDataHash, authrMakeCredReq5NegativeSecondClientDataHash[:]) {
		t.Fatalf("second clientDataHash = %x", clientDataHash)
	}

	var descriptors []cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(second[5], &descriptors); err != nil {
		t.Fatal(err)
	}
	if len(descriptors) != 1 {
		t.Fatalf("second excludeList = %d entries, want 1", len(descriptors))
	}
	assertAuthrMakeCredReq5NegativeValidDescriptor(t, descriptors[0], device.credentialID)

	var protocolID uint64
	if err := getInfoDecMode.Unmarshal(second[9], &protocolID); err != nil {
		t.Fatal(err)
	}
	var authParam []byte
	if err := getInfoDecMode.Unmarshal(second[8], &authParam); err != nil {
		t.Fatal(err)
	}
	wantAuthParam := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		bytes.Repeat([]byte{0x86}, 32),
		authrMakeCredReq5NegativeSecondClientDataHash[:],
	)
	if protocolID != uint64(protocol.PinUvAuthProtocolTwo) || !bytes.Equal(authParam, wantAuthParam) {
		t.Fatalf("second authorization = protocol %d, param %x", protocolID, authParam)
	}
	if len(lifecycle.tokens) != 2 {
		t.Fatalf("tokens = %d, want 2", len(lifecycle.tokens))
	}
}

func decodeAuthrMakeCredReq5NegativeFields(t testing.TB, request []byte) map[uint64]cbor.RawMessage {
	t.Helper()
	if len(request) == 0 || protocol.Command(request[0]) != protocol.AuthenticatorMakeCredential {
		t.Fatalf("request = %x", request)
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(request[1:], &fields); err != nil {
		t.Fatal(err)
	}

	return fields
}

func assertAuthrMakeCredReq5NegativeBaseline(
	t testing.TB,
	fields map[uint64]cbor.RawMessage,
	hasExcludeList bool,
) {
	t.Helper()
	wantFields := 6
	if hasExcludeList {
		wantFields++
	}
	if len(fields) != wantFields {
		t.Fatalf("outer fields = %#v, want %d", fields, wantFields)
	}
	for _, key := range []uint64{1, 2, 3, 4, 8, 9} {
		if _, present := fields[key]; !present {
			t.Fatalf("request field %d is absent", key)
		}
	}
	if _, present := fields[5]; present != hasExcludeList {
		t.Fatalf("excludeList presence = %t, want %t", present, hasExcludeList)
	}
	if _, present := fields[11]; present {
		t.Fatal("attestationFormatsPreference is unexpectedly present")
	}
}

func assertAuthrMakeCredReq5NegativeValidDescriptor(
	t testing.TB,
	raw cbor.RawMessage,
	wantID []byte,
) {
	t.Helper()
	descriptor := decodeAuthrMakeCredReq5NegativeDescriptor(t, raw)
	if len(descriptor) != 2 || decodeAuthrMakeCredReq5NegativeText(t, descriptor["type"]) != "public-key" ||
		!decodeAuthrMakeCredReq5NegativeBytes(t, descriptor["id"], wantID) {
		t.Fatalf("descriptor = %x, want public-key/%x", raw, wantID)
	}
}

func decodeAuthrMakeCredReq5NegativeDescriptor(
	t testing.TB,
	raw cbor.RawMessage,
) map[string]cbor.RawMessage {
	t.Helper()

	var descriptor map[string]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(raw, &descriptor); err != nil {
		t.Fatal(err)
	}

	return descriptor
}

func decodeAuthrMakeCredReq5NegativeText(t testing.TB, raw cbor.RawMessage) string {
	t.Helper()

	var value string
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}

	return value
}

func decodeAuthrMakeCredReq5NegativeBytes(t testing.TB, raw cbor.RawMessage, want []byte) bool {
	t.Helper()

	var value []byte
	if err := getInfoDecMode.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}

	return bytes.Equal(value, want)
}

func assertAuthrMakeCredReq5NegativeLifecycle(
	t *testing.T,
	device *authrMakeCredReq5NegativeDevice,
	lifecycle *authrMakeCredReq5NegativeLifecycle,
	wantMakeCredentialCalls int,
	wantTokens int,
) {
	t.Helper()

	if lifecycle.powerCycles != 3 || device.resets != 2 {
		t.Fatalf("power cycles/resets = %d/%d, want 3/2", lifecycle.powerCycles, device.resets)
	}
	wantCommands := []protocol.Command{protocol.AuthenticatorReset, protocol.AuthenticatorGetInfo}
	wantCommands = append(
		wantCommands,
		slices.Repeat([]protocol.Command{protocol.AuthenticatorMakeCredential}, wantMakeCredentialCalls)...,
	)
	wantCommands = append(wantCommands, protocol.AuthenticatorReset)
	if !slices.Equal(device.commands, wantCommands) {
		t.Fatalf("commands = %v, want %v", device.commands, wantCommands)
	}
	assertAuthrMakeCredReq5NegativeTokensWiped(t, lifecycle.tokens, wantTokens)
}

func assertAuthrMakeCredReq5NegativeTokensWiped(t testing.TB, tokens [][]byte, want int) {
	t.Helper()
	if len(tokens) != want {
		t.Fatalf("tokens = %d, want %d", len(tokens), want)
	}
	for index, token := range tokens {
		if len(token) != 32 || slices.ContainsFunc(token, func(value byte) bool { return value != 0 }) {
			t.Fatalf("token %d was not wiped", index)
		}
	}
}

func assertAuthrMakeCredReq5NegativeStatus(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func authrMakeCredReq5NegativeMarshal(t testing.TB, value any) []byte {
	t.Helper()

	encoded, err := ctap2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}
