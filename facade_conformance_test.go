package ctapkit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"testing"
	"unicode/utf8"

	fxcbor "github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/crypto/protocolone"
	"github.com/telesma-app/ctap/crypto/protocoltwo"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/ctap23"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
	appoperation "github.com/telesma-app/kit/model/operation"
	"github.com/telesma-app/kit/transport"
)

func TestRunCTAP23ConformanceSafeUsesSelectedAuthenticatorWithoutReset(t *testing.T) {
	info := facadeConformanceInfo()
	raw := newFacadeConformanceCBOR(t, info, info, info)
	device := &facadeConformanceAuthenticator{info: info}
	opened := openFacadeConformanceAuthenticator(t, device, raw)

	result, err := opened.RunCTAP23Conformance(t.Context(), ctap23.RunRequest{
		Metadata: ctap23.Metadata{
			GetInfo:                 info,
			GetInfoFields:           []uint64{1, 2, 3},
			UserVerificationMethods: protocol.UserVerifyPresenceInternal,
			StatementJSON:           facadeConformanceMetadataStatement,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != conformance.StatusPassed || len(result.Tests) != 43 {
		t.Fatalf("result = %#v, want 43 safe tests", result)
	}
	if result.Tests[2].ID != ctap23.TestIDAuthrGeneric1P3 || result.Tests[2].Status != conformance.StatusSkipped {
		t.Fatalf("P-3 result = %#v", result.Tests[2])
	}
	if result.Tests[3].ID != ctap23.TestIDAuthrMakeCredReq2F3 || result.Tests[3].Status != conformance.StatusSkipped {
		t.Fatalf("MakeCredential Req-2 F-3 result = %#v", result.Tests[3])
	}
	if result.Tests[4].ID != ctap23.TestIDAuthrMakeCredReq3F4 || result.Tests[4].Status != conformance.StatusSkipped {
		t.Fatalf("MakeCredential Req-3 F-4 result = %#v", result.Tests[4])
	}
	if result.Tests[5].ID != ctap23.TestIDAuthrClientPIN1GetRetriesP4 || result.Tests[5].Status != conformance.StatusSkipped {
		t.Fatalf("ClientPIN1 P-4 result = %#v", result.Tests[5])
	}
	if result.Tests[40].ID != ctap23.TestIDMetadataStmt1P41 || result.Tests[40].Status != conformance.StatusSkipped {
		t.Fatalf("metadata P-41 result = %#v", result.Tests[40])
	}
	if slices.ContainsFunc(result.Tests, func(result conformance.TestResult) bool { return result.Destructive }) {
		t.Fatalf("safe result contains a destructive test: %#v", result.Tests)
	}
	if device.resetCalls != 0 || device.setPINCalls != 0 || device.pinTokenCalls != 0 {
		t.Fatalf("destructive calls = reset %d, set PIN %d, token %d", device.resetCalls, device.setPINCalls, device.pinTokenCalls)
	}
	if len(raw.commands) != 3 {
		t.Fatalf("raw commands = %x, want three GetInfo commands", raw.commands)
	}
}

func TestRunCTAP23ConformanceFullRoutesPINAndResetThroughRuntime(t *testing.T) {
	token := make([]byte, 32)
	for index := range token {
		token[index] = byte(index + 1)
	}

	initial := facadeConformanceInfo()
	initial.Options = map[protocol.Option]bool{
		protocol.OptionClientPIN:      false,
		protocol.OptionPinUvAuthToken: true,
	}
	initial.MinPINLength = 4
	initial.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{
		protocol.PinUvAuthProtocolOne,
		protocol.PinUvAuthProtocolTwo,
	}

	identifierBefore := [aes.BlockSize]byte{1, 2, 3, 4}
	identifierAfter := [aes.BlockSize]byte{5, 6, 7, 8}
	stateBefore := [aes.BlockSize]byte{9, 10, 11, 12}
	stateAfter := [aes.BlockSize]byte{13, 14, 15, 16}
	infos := make([]protocol.AuthenticatorGetInfoResponse, 159)
	for index := range infos {
		infos[index] = initial
		infos[index].Options = maps.Clone(initial.Options)
		if index >= 11 && index <= 50 {
			infos[index].Options = map[protocol.Option]bool{}
			infos[index].Algorithms = []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}}
			infos[index].AttestationFormats = []attestation.AttestationStatementFormatIdentifier{
				attestation.AttestationStatementFormatIdentifierPacked,
				attestation.AttestationStatementFormatIdentifierNone,
			}
		}
		if index >= 51 && index <= 153 {
			infos[index].Algorithms = []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}}
			infos[index].AttestationFormats = []attestation.AttestationStatementFormatIdentifier{
				attestation.AttestationStatementFormatIdentifierPacked,
				attestation.AttestationStatementFormatIdentifierNone,
			}
		}
		if index >= 110 && index <= 112 || index >= 154 {
			delete(infos[index].Options, protocol.OptionClientPIN)
		}

		identifier := identifierBefore
		if index >= 6 {
			identifier = identifierAfter
		}
		state := stateBefore
		if index >= 10 {
			state = stateAfter
		}
		infos[index].EncIdentifier = encryptFacadeConformanceMember(
			t,
			token,
			identifier,
			facadeConformanceIV(byte(2*index+1)),
			"encIdentifier",
		)
		infos[index].EncCredStoreState = encryptFacadeConformanceMember(
			t,
			token,
			state,
			facadeConformanceIV(byte(2*index+2)),
			"encCredStoreState",
		)
	}

	privateKeyBytes := make([]byte, 32)
	privateKeyBytes[len(privateKeyBytes)-1] = 1
	privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	keyAgreement, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	raw := newFacadeFullConformanceCBOR(t, infos, keyAgreement, privateKey, token)
	wantToken := slices.Clone(token)
	device := &facadeConformanceAuthenticator{
		info:  initial,
		token: token,
	}
	device.onReset = raw.resetClientPIN
	opened := openFacadeConformanceAuthenticator(t, device, raw)
	opened.setPowerCycler(func(ctx context.Context, action func(context.Context) error) error {
		return action(ctx)
	})

	var interactions []model.InteractionRequest
	handler := interactionHandlerFunc(func(request model.InteractionRequest) (model.InteractionResponse, error) {
		interactions = append(interactions, request)
		if request.Kind == model.InteractionKindPIN {
			return model.InteractionResponse{PIN: []byte("123456")}, nil
		}

		return model.InteractionResponse{}, nil
	})
	result, err := opened.RunCTAP23Conformance(
		t.Context(),
		ctap23.RunRequest{
			Mode: ctap23.RunModeFull,
			Metadata: ctap23.Metadata{
				GetInfo:                 infos[0],
				GetInfoFields:           []uint64{1, 2, 3, 4, 6, 13, 25, 30},
				UserVerificationMethods: protocol.UserVerifyPresenceInternal | protocol.UserVerifyPasscodeExternal,
				StatementJSON:           facadeConformanceMetadataStatement,
			},
		},
		WithInteractionHandler(handler),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Tests) != 152 {
		t.Fatalf("tests = %d, want 152", len(result.Tests))
	}
	for _, testResult := range result.Tests {
		want := conformance.StatusPassed
		if testResult.ID == ctap23.TestIDAuthrMakeCredReq2F3 ||
			testResult.ID == ctap23.TestIDAuthrMakeCredReq3F4 ||
			testResult.ID == ctap23.TestIDAuthrMakeCredReq6P2 ||
			testResult.ID == ctap23.TestIDAuthrMakeCredResp1P04 ||
			testResult.ID == ctap23.TestIDAuthrGetAssertionReq2P3 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN1NewPINP6 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN1NewPINF1 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN1PinPolicyF4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN1GetRetriesP1 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN1GetRetriesP2 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN1GetRetriesP3 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN1GetRetriesP4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2NewPINP3 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2NewPINP4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetPINTokenF1 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetPINTokenF2 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetPINTokenF3 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetPINTokenF4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetPINTokenF5 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2PinPolicyF4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP1 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP2 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP3 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP5 ||
			testResult.ID == ctap23.TestIDMetadataStmt1P41 {
			want = conformance.StatusSkipped
		}
		if testResult.Status != want {
			t.Fatalf("test %q = %#v, want %q", testResult.ID, testResult, want)
		}
	}
	if result.Status != conformance.StatusPassed {
		t.Fatalf("suite status = %q, want %q", result.Status, conformance.StatusPassed)
	}
	for index, testResult := range result.Tests {
		wantDestructive := index >= 3 && index <= 18 ||
			index >= 20 && index <= 89 && index != 23 ||
			index >= 91 && index <= 114
		if testResult.Destructive != wantDestructive {
			t.Fatalf("test %q destructive = %t, want %t", testResult.ID, testResult.Destructive, wantDestructive)
		}
	}
	if device.resetCalls != 174 || device.setPINCalls != 31 || device.pinTokenCalls != 53 {
		t.Fatalf("runtime calls = reset %d, set PIN %d, token %d; want 174, 31, 53", device.resetCalls, device.setPINCalls, device.pinTokenCalls)
	}
	interactionCounts := map[model.InteractionKind]int{}
	for index, interaction := range interactions {
		interactionCounts[interaction.Kind]++
		if (interaction.Kind == model.InteractionKindTouch ||
			interaction.Kind == model.InteractionKindPowerCycle) && !interaction.Destructive {
			t.Fatalf("interaction %d of kind %q is not marked destructive", index, interaction.Kind)
		}
	}
	if interactionCounts[model.InteractionKindPIN] != 65 ||
		interactionCounts[model.InteractionKindTouch] != 174 ||
		interactionCounts[model.InteractionKindPowerCycle] != 236 {
		t.Fatalf("interaction counts = %v, want PIN 65, touch 174, power cycle 236", interactionCounts)
	}
	if len(raw.commands) != 315 ||
		raw.getInfoCalls != 159 ||
		raw.makeCredentialCalls != 71 ||
		raw.getAssertionCalls != 25 ||
		raw.clientPINCalls != 60 {
		t.Fatalf(
			"raw commands = %d (GetInfo %d, MakeCredential %d, GetAssertion %d, ClientPIN %d), want 315 (159, 71, 25, 60)",
			len(raw.commands),
			raw.getInfoCalls,
			raw.makeCredentialCalls,
			raw.getAssertionCalls,
			raw.clientPINCalls,
		)
	}
	if !slices.Equal(device.token, wantToken) {
		t.Fatal("device-owned token was mutated")
	}
}

const facadeConformanceMetadataStatement = `{
	"legalHeader":"Telesma test metadata",
	"aaguid":"00112233-4455-6677-8899-aabbccddeeff",
	"description":"Telesma conformance fixture",
	"alternativeDescriptions":{"en-US":"Telesma conformance fixture"},
	"friendlyNames":{"en-US":"Telesma conformance fixture"},
	"authenticatorVersion":1,
	"protocolFamily":"fido2",
	"schema":3,
	"upv":[{"major":1,"minor":3}],
	"authenticationAlgorithms":["secp256r1_ecdsa_sha256_raw"],
	"publicKeyAlgAndEncodings":["cose"],
	"attestationTypes":["basic_surrogate","ecdaa"],
	"attestationRootCertificates":[],
	"ecdaaTrustAnchors":[{"X":"AQ","Y":"Ag==","c":"Aw","sx":"BA==","sy":"BQ","G1Curve":"BN_P256"}],
	"userVerificationDetails":[[{"userVerificationMethod":"presence_internal"}]],
	"keyProtection":["hardware"],
	"isKeyRestricted":false,
	"isFreshUserVerificationRequired":false,
	"matcherProtection":["on_chip"],
	"cryptoStrength":128,
	"attachmentHint":["internal"],
	"tcDisplay":[],
	"icon":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgdmlld0JveD0iMCAwIDEgMSI+PHRpdGxlPkF1dGhlbnRpY2F0b3I8L3RpdGxlPjwvc3ZnPg==",
	"iconDark":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgdmlld0JveD0iMCAwIDEgMSI+PHRpdGxlPkF1dGhlbnRpY2F0b3I8L3RpdGxlPjwvc3ZnPg==",
	"providerLogoLight":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMiIgYmFzZVByb2ZpbGU9InRpbnktcHMiIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHRpdGxlPlRlbGVzbWEgY29uZm9ybWFuY2UgZml4dHVyZTwvdGl0bGU+PHBhdGggZD0iTTAgMGgzMnYzMkgweiIvPjwvc3ZnPg==",
	"providerLogoDark":"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMiIgYmFzZVByb2ZpbGU9InRpbnktcHMiIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHRpdGxlPlRlbGVzbWEgY29uZm9ybWFuY2UgZml4dHVyZTwvdGl0bGU+PHBhdGggZD0iTTAgMGgzMnYzMkgweiIvPjwvc3ZnPg==",
	"multiDeviceCredentialSupport":"unsupported",
	"authenticatorGetInfo":{"versions":["FIDO_2_3"],"extensions":["hmac-secret"],"aaguid":"00112233445566778899aabbccddeeff"},
	"cxConfigURL":"https://example.test/credential-exchange/config.json"
}`

func TestRunCTAP23ConformanceRejectsInvalidModeBeforeDeviceAccess(t *testing.T) {
	opened := &Authenticator{}
	result, err := opened.RunCTAP23Conformance(t.Context(), ctap23.RunRequest{
		Mode: "invalid",
	})
	if !failure.IsCode(err, failure.CodeConformanceModeInvalid) {
		t.Fatalf("error = %v, want conformance mode failure", err)
	}
	normalized := failure.Snapshot(err)
	if normalized.Operation != string(appoperation.ConformanceCTAP23) || normalized.Phase != failure.PhaseValidation {
		t.Fatalf("failure = %#v, want conformance validation operation", normalized)
	}
	requireZero(t, result)
}

type facadeConformanceAuthenticator struct {
	contractAuthenticator
	info          protocol.AuthenticatorGetInfoResponse
	token         []byte
	configured    bool
	resetCalls    int
	setPINCalls   int
	pinTokenCalls int
	onReset       func()
}

func (a *facadeConformanceAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return a.info, true
}

func (a *facadeConformanceAuthenticator) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	return a.info, nil
}

func (a *facadeConformanceAuthenticator) SetPIN(_ context.Context, pin string) error {
	if pin != "123456" {
		return fmt.Errorf("unexpected conformance PIN")
	}

	a.setPINCalls++
	a.configured = true
	a.info.Options[protocol.OptionClientPIN] = true

	return nil
}

func (a *facadeConformanceAuthenticator) GetPinUvAuthTokenUsingPIN(
	_ context.Context,
	pin string,
	permission protocol.Permission,
	rpID string,
) ([]byte, error) {
	if !a.configured || pin != "123456" {
		return nil, fmt.Errorf("PIN is not configured")
	}
	if permission != protocol.PermissionPersistentCredentialManagementReadOnly &&
		((permission != protocol.PermissionMakeCredential &&
			permission != protocol.PermissionGetAssertion) || rpID == "") {
		return nil, fmt.Errorf("permission = %v", permission)
	}

	a.pinTokenCalls++

	return slices.Clone(a.token), nil
}

func (a *facadeConformanceAuthenticator) Reset(context.Context) error {
	a.resetCalls++
	a.configured = false
	a.info.Options[protocol.OptionClientPIN] = false
	if a.onReset != nil {
		a.onReset()
	}

	return nil
}

type facadeConformanceCBOR struct {
	t         *testing.T
	requests  [][]byte
	responses [][]byte
	commands  []protocol.Command
}

func newFacadeConformanceCBOR(
	t *testing.T,
	infos ...protocol.AuthenticatorGetInfoResponse,
) *facadeConformanceCBOR {
	t.Helper()

	responses := make([][]byte, len(infos))
	requests := make([][]byte, len(infos))
	for index, info := range infos {
		requests[index] = []byte{byte(protocol.AuthenticatorGetInfo)}
		responses[index] = encodeFacadeConformanceCBOR(t, info)
	}

	return &facadeConformanceCBOR{t: t, requests: requests, responses: responses}
}

func (cbor *facadeConformanceCBOR) CBOR(
	_ context.Context,
	data []byte,
) (ctaptransport.CBORResponse, error) {
	index := len(cbor.commands)
	if index >= len(cbor.responses) {
		cbor.t.Fatalf("unexpected conformance command %x", data)
	}
	if !slices.Equal(data, cbor.requests[index]) {
		cbor.t.Fatalf("conformance request %d = %x, want %x", index+1, data, cbor.requests[index])
	}
	cbor.commands = append(cbor.commands, protocol.Command(data[0]))

	return ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       cbor.responses[index],
	}, nil
}

type facadeFullConformanceCBOR struct {
	t                      *testing.T
	infos                  [][]byte
	keyAgreementResponse   []byte
	clientPINPrivateKey    *ecdh.PrivateKey
	clientPIN              []byte
	clientPINToken         []byte
	makeCredentialStatuses []ctaptransport.StatusCode
	credentialPrivateKey   *ecdsa.PrivateKey
	getAssertionStatuses   []ctaptransport.StatusCode
	commands               []protocol.Command
	getInfoCalls           int
	clientPINCalls         int
	makeCredentialCalls    int
	getAssertionCalls      int
}

func newFacadeFullConformanceCBOR(
	t *testing.T,
	infos []protocol.AuthenticatorGetInfoResponse,
	keyAgreement cose.Key,
	privateKey *ecdh.PrivateKey,
	token []byte,
) *facadeFullConformanceCBOR {
	t.Helper()

	encodedInfos := make([][]byte, len(infos))
	for index, info := range infos {
		encodedInfos[index] = encodeFacadeConformanceCBOR(t, info)
	}

	statuses := make([]ctaptransport.StatusCode, 0, 64)
	appendStatuses := func(count int, status ctaptransport.StatusCode) {
		for range count {
			statuses = append(statuses, status)
		}
	}
	// Req-1: one valid request followed by eleven malformed top-level members.
	appendStatuses(1, ctaptransport.CTAP2_OK)
	appendStatuses(11, ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
	// Req-2 and Req-3: malformed RP and user entity members. Their commented
	// legacy-icon markers are non-destructive and issue no command.
	appendStatuses(2, ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
	appendStatuses(3, ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
	// Req-4: valid algorithm ordering, five malformed entries, and two lists
	// with no supported public-key algorithm.
	appendStatuses(1, ctaptransport.CTAP2_OK)
	appendStatuses(5, ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
	appendStatuses(2, ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM)
	// Req-5: three valid preferences, one malformed attestation preference,
	// five malformed descriptors, then the two-command credential-exclusion case.
	appendStatuses(3, ctaptransport.CTAP2_OK)
	appendStatuses(1, ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
	appendStatuses(5, ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
	appendStatuses(1, ctaptransport.CTAP2_OK)
	appendStatuses(1, ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED)
	// Req-6 P-2 skips on this fixture's absent uv option. P-1/P-3 succeed and
	// F-1 rejects up=false.
	appendStatuses(2, ctaptransport.CTAP2_OK)
	appendStatuses(1, ctaptransport.CTAP2_ERR_INVALID_OPTION)
	// Resp-1 executes one packed self-attestation request per marker for the
	// fixture's single ES256 metadata algorithm.
	appendStatuses(6, ctaptransport.CTAP2_OK)
	// GetAssertion Req-1 provisions one credential independently per marker.
	appendStatuses(7, ctaptransport.CTAP2_OK)
	// GetAssertion Req-2 provisions a credential before each marker. P-3 then
	// skips because this fixture does not advertise built-in UV.
	appendStatuses(3, ctaptransport.CTAP2_OK)
	// GetAssertion Req-3 provisions one credential independently per marker.
	appendStatuses(7, ctaptransport.CTAP2_OK)
	// GetAssertion Resp-1 provisions one credential independently per marker.
	appendStatuses(5, ctaptransport.CTAP2_OK)
	// ClientPIN1 NewPIN P-4/P-5 each create one UV-authenticated credential.
	appendStatuses(2, ctaptransport.CTAP2_OK)
	// ClientPIN2 GetPinToken P-2/P-3 each create one credential with a fresh
	// legacy protocol-2 token. The remaining negative feature cases skip.
	appendStatuses(2, ctaptransport.CTAP2_OK)

	transport := &facadeFullConformanceCBOR{
		t:                      t,
		infos:                  encodedInfos,
		keyAgreementResponse:   encodeFacadeConformanceCBOR(t, map[uint64]any{1: keyAgreement}),
		clientPINPrivateKey:    privateKey,
		clientPINToken:         slices.Clone(token),
		makeCredentialStatuses: statuses,
		getAssertionStatuses: []ctaptransport.StatusCode{
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_ERR_MISSING_PARAMETER,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_ERR_MISSING_PARAMETER,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
			ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
		},
	}
	t.Cleanup(func() {
		transport.resetClientPIN()
		clear(transport.clientPINToken)
	})

	return transport
}

func (cbor *facadeFullConformanceCBOR) resetClientPIN() {
	clear(cbor.clientPIN)
	cbor.clientPIN = nil
}

func (cbor *facadeFullConformanceCBOR) clientPINResponse(
	body []byte,
) ctaptransport.CBORResponse {
	cbor.t.Helper()
	cbor.clientPINCalls++

	var request protocol.AuthenticatorClientPINRequest
	if err := fxcbor.Unmarshal(body, &request); err != nil {
		cbor.t.Fatalf("decode ClientPIN request: %v", err)
	}
	if request.SubCommand == protocol.ClientPINSubCommandGetKeyAgreement {
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       cbor.keyAgreementResponse,
		}
	}
	if request.PinUvAuthProtocol != protocol.PinUvAuthProtocolOne &&
		request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
		cbor.t.Fatalf("ClientPIN subcommand %s uses invalid protocol %d", request.SubCommand, request.PinUvAuthProtocol)
	}
	if request.KeyAgreement == nil {
		cbor.t.Fatalf(
			"ClientPIN call %d after GetInfo call %d subcommand %s has no key agreement",
			cbor.clientPINCalls,
			cbor.getInfoCalls,
			request.SubCommand,
		)
	}

	sharedSecret := cbor.clientPINSharedSecret(request.PinUvAuthProtocol, request.KeyAgreement)
	defer clear(sharedSecret)
	switch request.SubCommand {
	case protocol.ClientPINSubCommandSetPIN:
		cbor.requireClientPINAuth(request.PinUvAuthProtocol, sharedSecret, request.NewPinEnc, request.PinUvAuthParam)
		pin := cbor.decryptClientPIN(request.PinUvAuthProtocol, sharedSecret, request.NewPinEnc)
		if !utf8.Valid(pin) || utf8.RuneCount(pin) < 4 || len(pin) > 63 {
			clear(pin)
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION}
		}
		cbor.replaceClientPIN(pin)

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
	case protocol.ClientPINSubCommandChangePIN:
		cbor.requireClientPINAuth(
			request.PinUvAuthProtocol,
			sharedSecret,
			slices.Concat(request.NewPinEnc, request.PinHashEnc),
			request.PinUvAuthParam,
		)
		if !cbor.matchesClientPINHash(request.PinUvAuthProtocol, sharedSecret, request.PinHashEnc) {
			cbor.t.Fatal("ChangePIN pinHashEnc does not match the configured PIN")
		}
		cbor.replaceClientPIN(cbor.decryptClientPIN(request.PinUvAuthProtocol, sharedSecret, request.NewPinEnc))

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
	case protocol.ClientPINSubCommandGetPinToken:
		if !cbor.matchesClientPINHash(request.PinUvAuthProtocol, sharedSecret, request.PinHashEnc) {
			cbor.t.Fatal("getPinToken pinHashEnc does not match the configured PIN")
		}
		encrypted, err := cbor.encryptClientPIN(request.PinUvAuthProtocol, sharedSecret, cbor.clientPINToken)
		if err != nil {
			cbor.t.Fatal(err)
		}

		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data: encodeFacadeConformanceCBOR(cbor.t, map[uint64]any{
				2: encrypted,
			}),
		}
	default:
		cbor.t.Fatalf("unexpected ClientPIN subcommand %s", request.SubCommand)

		return ctaptransport.CBORResponse{}
	}
}

func (cbor *facadeFullConformanceCBOR) clientPINSharedSecret(
	protocolNumber protocol.PinUvAuthProtocol,
	platformKey cose.Key,
) []byte {
	cbor.t.Helper()
	publicKey, err := platformKey.P256PublicKey()
	if err != nil {
		cbor.t.Fatal(err)
	}
	z, err := cbor.clientPINPrivateKey.ECDH(publicKey)
	if err != nil {
		cbor.t.Fatal(err)
	}
	defer clear(z)

	switch protocolNumber {
	case protocol.PinUvAuthProtocolOne:
		return protocolone.KDF(z)
	case protocol.PinUvAuthProtocolTwo:
		sharedSecret, err := protocoltwo.KDF(z)
		if err != nil {
			cbor.t.Fatal(err)
		}

		return sharedSecret
	default:
		cbor.t.Fatalf("invalid PIN/UV protocol %d", protocolNumber)

		return nil
	}
}

func (cbor *facadeFullConformanceCBOR) requireClientPINAuth(
	protocolNumber protocol.PinUvAuthProtocol,
	sharedSecret []byte,
	message []byte,
	authParam []byte,
) {
	cbor.t.Helper()
	want := ctapcrypto.Authenticate(protocolNumber, sharedSecret, message)
	if !bytes.Equal(authParam, want) {
		cbor.t.Fatalf("ClientPIN pinUvAuthParam = %x, want %x", authParam, want)
	}
}

func (cbor *facadeFullConformanceCBOR) encryptClientPIN(
	protocolNumber protocol.PinUvAuthProtocol,
	sharedSecret []byte,
	plaintext []byte,
) ([]byte, error) {
	switch protocolNumber {
	case protocol.PinUvAuthProtocolOne:
		return protocolone.Encrypt(sharedSecret, plaintext)
	case protocol.PinUvAuthProtocolTwo:
		return protocoltwo.Encrypt(sharedSecret, plaintext)
	default:
		panic("invalid PIN/UV protocol")
	}
}

func (cbor *facadeFullConformanceCBOR) decryptClientPIN(
	protocolNumber protocol.PinUvAuthProtocol,
	sharedSecret []byte,
	ciphertext []byte,
) []byte {
	cbor.t.Helper()
	var plaintext []byte
	var err error
	switch protocolNumber {
	case protocol.PinUvAuthProtocolOne:
		plaintext, err = protocolone.Decrypt(sharedSecret, ciphertext)
	case protocol.PinUvAuthProtocolTwo:
		plaintext, err = protocoltwo.Decrypt(sharedSecret, ciphertext)
	}
	if err != nil {
		cbor.t.Fatal(err)
	}
	defer clear(plaintext)
	length := bytes.IndexByte(plaintext, 0)
	if length < 0 {
		length = len(plaintext)
	}

	return slices.Clone(plaintext[:length])
}

func (cbor *facadeFullConformanceCBOR) matchesClientPINHash(
	protocolNumber protocol.PinUvAuthProtocol,
	sharedSecret []byte,
	ciphertext []byte,
) bool {
	cbor.t.Helper()
	var plaintext []byte
	var err error
	switch protocolNumber {
	case protocol.PinUvAuthProtocolOne:
		plaintext, err = protocolone.Decrypt(sharedSecret, ciphertext)
	case protocol.PinUvAuthProtocolTwo:
		plaintext, err = protocoltwo.Decrypt(sharedSecret, ciphertext)
	}
	if err != nil {
		cbor.t.Fatal(err)
	}
	defer clear(plaintext)

	return bytes.Equal(plaintext, cbor.clientPINHash())
}

func (cbor *facadeFullConformanceCBOR) clientPINHash() []byte {
	hash := sha256.Sum256(cbor.clientPIN)

	return hash[:16]
}

func (cbor *facadeFullConformanceCBOR) replaceClientPIN(pin []byte) {
	clear(cbor.clientPIN)
	cbor.clientPIN = pin
}

func (cbor *facadeFullConformanceCBOR) CBOR(
	_ context.Context,
	data []byte,
) (ctaptransport.CBORResponse, error) {
	cbor.t.Helper()
	if len(data) == 0 {
		cbor.t.Fatal("empty conformance command")
	}

	command := protocol.Command(data[0])
	cbor.commands = append(cbor.commands, command)
	switch command {
	case protocol.AuthenticatorGetInfo:
		if len(data) != 1 {
			cbor.t.Fatalf("GetInfo request = %x", data)
		}
		if cbor.getInfoCalls >= len(cbor.infos) {
			cbor.t.Fatalf("unexpected GetInfo call %d", cbor.getInfoCalls+1)
		}

		response := cbor.infos[cbor.getInfoCalls]
		cbor.getInfoCalls++

		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: response}, nil
	case protocol.AuthenticatorClientPIN:
		return cbor.clientPINResponse(data[1:]), nil
	case protocol.AuthenticatorMakeCredential:
		if cbor.makeCredentialCalls >= len(cbor.makeCredentialStatuses) {
			cbor.t.Fatalf("unexpected MakeCredential call %d", cbor.makeCredentialCalls+1)
		}
		status := cbor.makeCredentialStatuses[cbor.makeCredentialCalls]
		cbor.makeCredentialCalls++
		response := ctaptransport.CBORResponse{StatusCode: status}
		if status == ctaptransport.CTAP2_OK {
			var request protocol.AuthenticatorMakeCredentialRequest
			if err := fxcbor.Unmarshal(data[1:], &request); err != nil {
				cbor.t.Fatalf("decode MakeCredential request: %v", err)
			}
			response.Data, cbor.credentialPrivateKey = facadeConformanceMakeCredentialResponse(cbor.t, request)
		}

		return response, nil
	case protocol.AuthenticatorGetAssertion:
		if cbor.getAssertionCalls >= len(cbor.getAssertionStatuses) {
			cbor.t.Fatalf("unexpected GetAssertion call %d", cbor.getAssertionCalls+1)
		}
		status := cbor.getAssertionStatuses[cbor.getAssertionCalls]
		cbor.getAssertionCalls++
		response := ctaptransport.CBORResponse{StatusCode: status}
		if status == ctaptransport.CTAP2_OK {
			var request protocol.AuthenticatorGetAssertionRequest
			if err := fxcbor.Unmarshal(data[1:], &request); err != nil {
				cbor.t.Fatalf("decode GetAssertion request: %v", err)
			}
			response.Data = facadeConformanceGetAssertionResponse(
				cbor.t,
				request,
				cbor.credentialPrivateKey,
			)
		}

		return response, nil
	default:
		cbor.t.Fatalf("unexpected conformance command %x", data)

		return ctaptransport.CBORResponse{}, nil
	}
}

func facadeConformanceMakeCredentialResponse(
	t *testing.T,
	request protocol.AuthenticatorMakeCredentialRequest,
) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   privateKey.X.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   privateKey.Y.FillBytes(make([]byte, 32)),
	}
	authData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte(request.RP.ID))
	copy(authData, rpIDHash[:])
	authData[32] = byte(
		protocol.AuthDataFlagUserPresent |
			protocol.AuthDataFlagUserVerified |
			protocol.AuthDataFlagAttestedCredentialDataIncluded,
	)
	aaguid := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	authData = append(authData, aaguid[:]...)
	credentialID := bytes.Repeat([]byte{0x63}, 16)
	authData = append(authData, 0, byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, encodeFacadeConformanceCBOR(t, key)...)
	digest := sha256.Sum256(slices.Concat(authData, request.ClientDataHash))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	return encodeFacadeConformanceCBOR(t, protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: authData,
		AttestationStatement: map[string]any{
			"alg": cose.AlgorithmES256,
			"sig": signature,
		},
	}), privateKey
}

func facadeConformanceGetAssertionResponse(
	t *testing.T,
	request protocol.AuthenticatorGetAssertionRequest,
	privateKey *ecdsa.PrivateKey,
) []byte {
	t.Helper()
	if privateKey == nil {
		t.Fatal("GetAssertion has no credential private key")
	}

	authData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte(request.RPID))
	copy(authData, rpIDHash[:])
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified)
	digest := sha256.Sum256(slices.Concat(authData, request.ClientDataHash))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	return encodeFacadeConformanceCBOR(t, protocol.AuthenticatorGetAssertionResponse{
		Credential: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   bytes.Repeat([]byte{0x63}, 16),
		},
		AuthDataRaw: authData,
		Signature:   signature,
	})
}

func openFacadeConformanceAuthenticator(
	t *testing.T,
	device *facadeConformanceAuthenticator,
	cbor ctaptransport.CBOR,
) *Authenticator {
	t.Helper()

	opened, err := openAuthenticatorHandle(
		t.Context(),
		newContractDevice(),
		func(context.Context, transport.Mode, string) (*authenticator.Opened, error) {
			capabilities := contractOpened(device)
			capabilities.CBOR = cbor

			return capabilities, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return opened
}

func facadeConformanceInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		AAGUID:     uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff"),
	}
}

func encodeFacadeConformanceCBOR(t *testing.T, value any) []byte {
	t.Helper()

	mode, err := fxcbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	data, err := mode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func encryptFacadeConformanceMember(
	t *testing.T,
	token []byte,
	plaintext [aes.BlockSize]byte,
	initializationVector [aes.BlockSize]byte,
	label string,
) []byte {
	t.Helper()

	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	_, _ = extract.Write(token)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	_, _ = expand.Write([]byte(label))
	_, _ = expand.Write([]byte{1})
	key := expand.Sum(nil)[:aes.BlockSize]

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	encrypted := make([]byte, 2*aes.BlockSize)
	copy(encrypted, initializationVector[:])
	cipher.NewCBCEncrypter(block, initializationVector[:]).CryptBlocks(encrypted[aes.BlockSize:], plaintext[:])

	return encrypted
}

func facadeConformanceIV(value byte) [aes.BlockSize]byte {
	var initializationVector [aes.BlockSize]byte
	for index := range initializationVector {
		initializationVector[index] = value
	}

	return initializationVector
}
