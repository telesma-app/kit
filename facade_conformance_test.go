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
	raw := newFacadeConformanceCBOR(t, info, info, info, info, info, info)
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
	if result.Status != conformance.StatusPassed || len(result.Tests) != 78 {
		t.Fatalf("result = %#v, want 78 safe tests", result)
	}
	if result.Tests[0].ID != ctap23.TestIDHID1P1 || result.Tests[0].Status != conformance.StatusSkipped {
		t.Fatalf("HID P-1 result = %#v", result.Tests[0])
	}
	if result.Tests[34].ID != ctap23.TestIDAuthrGeneric1P3 || result.Tests[34].Status != conformance.StatusSkipped {
		t.Fatalf("P-3 result = %#v", result.Tests[34])
	}
	if result.Tests[35].ID != ctap23.TestIDAuthrMakeCredReq2F3 || result.Tests[35].Status != conformance.StatusSkipped {
		t.Fatalf("MakeCredential Req-2 F-3 result = %#v", result.Tests[35])
	}
	if result.Tests[36].ID != ctap23.TestIDAuthrMakeCredReq3F4 || result.Tests[36].Status != conformance.StatusSkipped {
		t.Fatalf("MakeCredential Req-3 F-4 result = %#v", result.Tests[36])
	}
	if result.Tests[37].ID != ctap23.TestIDCredBlobP1 || result.Tests[37].Status != conformance.StatusSkipped {
		t.Fatalf("credBlob P-1 result = %#v", result.Tests[37])
	}
	if result.Tests[38].ID != ctap23.TestIDAuthrClientPIN1GetRetriesP4 || result.Tests[38].Status != conformance.StatusSkipped {
		t.Fatalf("ClientPIN1 P-4 result = %#v", result.Tests[38])
	}
	if result.Tests[75].ID != ctap23.TestIDMetadataStmt1P41 || result.Tests[75].Status != conformance.StatusSkipped {
		t.Fatalf("metadata P-41 result = %#v", result.Tests[75])
	}
	if slices.ContainsFunc(result.Tests, func(result conformance.TestResult) bool { return result.Destructive }) {
		t.Fatalf("safe result contains a destructive test: %#v", result.Tests)
	}
	if device.resetCalls != 0 || device.setPINCalls != 0 || device.pinTokenCalls != 0 {
		t.Fatalf("destructive calls = reset %d, set PIN %d, token %d", device.resetCalls, device.setPINCalls, device.pinTokenCalls)
	}
	if len(raw.commands) != 6 {
		t.Fatalf("raw commands = %x, want six GetInfo commands", raw.commands)
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
	infos := make([]protocol.AuthenticatorGetInfoResponse, 267)
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
		if index >= 51 && index <= 212 {
			infos[index].Algorithms = []credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: cose.AlgorithmES256,
			}}
			infos[index].AttestationFormats = []attestation.AttestationStatementFormatIdentifier{
				attestation.AttestationStatementFormatIdentifierPacked,
				attestation.AttestationStatementFormatIdentifierNone,
			}
		}
		// The six hmacSecret cases are intentionally inapplicable in this
		// facade-routing fixture; their protocol-1 crypto is covered by the
		// package's deterministic authenticator. Keeping protocol 2 advertised
		// preserves the profile needed by every following shard.
		if index >= 89 && index <= 94 {
			infos[index].PinUvAuthProtocols = []protocol.PinUvAuthProtocol{
				protocol.PinUvAuthProtocolTwo,
			}
		}
		// The strict protocol-2 hmacSecret2 cases are likewise skipped by
		// advertising only protocol 1 for their applicability reads.
		if index >= 95 && index <= 100 {
			infos[index].PinUvAuthProtocols = []protocol.PinUvAuthProtocol{
				protocol.PinUvAuthProtocolOne,
			}
		}
		if index >= 169 && index <= 171 || index >= 233 {
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
	if len(result.Tests) != 295 {
		t.Fatalf("tests = %d, want 295", len(result.Tests))
	}
	for _, testResult := range result.Tests {
		want := conformance.StatusPassed
		if testResult.ID == ctap23.TestIDAuthrMakeCredReq2F3 ||
			facadeNewPortSkip(testResult.ID) ||
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
			testResult.ID == ctap23.TestIDAuthrClientPIN2PermissionsF1 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2PermissionsP4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2UVPermissionsP1 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2UVPermissionsP2 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2UVPermissionsP3 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2UVPermissionsP4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2PinPolicyF4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP1 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP2 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP3 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP4 ||
			testResult.ID == ctap23.TestIDAuthrClientPIN2GetRetriesP5 ||
			testResult.ID == ctap23.TestIDHMACSecretP1 ||
			testResult.ID == ctap23.TestIDHMACSecretP2 ||
			testResult.ID == ctap23.TestIDHMACSecretP3 ||
			testResult.ID == ctap23.TestIDHMACSecretF1 ||
			testResult.ID == ctap23.TestIDHMACSecretF2 ||
			testResult.ID == ctap23.TestIDHMACSecretF3 ||
			testResult.ID == ctap23.TestIDLargeBlobP1 ||
			testResult.ID == ctap23.TestIDLargeBlobP2 ||
			testResult.ID == ctap23.TestIDLargeBlobP3 ||
			testResult.ID == ctap23.TestIDLargeBlobP4 ||
			testResult.ID == ctap23.TestIDLargeBlobP5 ||
			testResult.ID == ctap23.TestIDLargeBlobP6 ||
			testResult.ID == ctap23.TestIDLargeBlobP7 ||
			testResult.ID == ctap23.TestIDLargeBlobF1 ||
			testResult.ID == ctap23.TestIDLargeBlobF2 ||
			testResult.ID == ctap23.TestIDLargeBlobF3 ||
			testResult.ID == ctap23.TestIDLargeBlobF4 ||
			testResult.ID == ctap23.TestIDLargeBlobF5 ||
			testResult.ID == ctap23.TestIDLargeBlobKeyP1 ||
			testResult.ID == ctap23.TestIDLargeBlobKeyP2 ||
			testResult.ID == ctap23.TestIDLargeBlobKeyF1 ||
			testResult.ID == ctap23.TestIDLargeBlobKeyF2 ||
			testResult.ID == ctap23.TestIDLargeBlobKeyF3 ||
			testResult.ID == ctap23.TestIDLargeBlobKeyF4 ||
			testResult.ID == ctap23.TestIDMinPINLengthP1 ||
			testResult.ID == ctap23.TestIDMinPINLengthF1 ||
			testResult.ID == ctap23.TestIDPINComplexityPolicyP1 ||
			testResult.ID == ctap23.TestIDPINComplexityPolicyP2 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateRPsP1 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateRPsP2 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateRPsP3 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateRPsP4 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateRPsP5 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateRPsP6 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateCredentialsP1 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateCredentialsP2 ||
			testResult.ID == ctap23.TestIDCredentialManagementEnumerateCredentialsP3 ||
			testResult.ID == ctap23.TestIDCredentialManagementUpdateAndDeleteP1 ||
			testResult.ID == ctap23.TestIDCredentialManagementUpdateAndDeleteP2 ||
			testResult.ID == ctap23.TestIDAuthenticatorConfigP1 ||
			testResult.ID == ctap23.TestIDAuthenticatorConfigP2 ||
			testResult.ID == ctap23.TestIDAuthenticatorConfigP3 ||
			testResult.ID == ctap23.TestIDAuthenticatorConfigP4 ||
			testResult.ID == ctap23.TestIDAuthenticatorConfigP5 ||
			testResult.ID == ctap23.TestIDAuthenticatorConfigP6 ||
			testResult.ID == ctap23.TestIDAuthenticatorConfigP7 ||
			testResult.ID == ctap23.TestIDBioEnrollBioModAndSensorInfoP1 ||
			testResult.ID == ctap23.TestIDBioEnrollBioModAndSensorInfoP2 ||
			testResult.ID == ctap23.TestIDBioEnrollEnrollP1 ||
			testResult.ID == ctap23.TestIDBioEnrollEnrollP2 ||
			testResult.ID == ctap23.TestIDBioEnrollEnumerateRenameRemoveP1 ||
			testResult.ID == ctap23.TestIDBioEnrollEnumerateRenameRemoveP2 ||
			testResult.ID == ctap23.TestIDBioEnrollEnumerateRenameRemoveP3 ||
			testResult.ID == ctap23.TestIDLargeBlobs1P1 ||
			testResult.ID == ctap23.TestIDLargeBlobs1P2 ||
			testResult.ID == ctap23.TestIDLargeBlobs1P3 ||
			testResult.ID == ctap23.TestIDLargeBlobs1P4 ||
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
	definitions := ctap23.Suite(ctap23.Config{}).Tests
	for index, testResult := range result.Tests {
		if testResult.ID != definitions[index].ID ||
			testResult.Destructive != definitions[index].Destructive {
			t.Fatalf(
				"test %d = %q destructive %t, want %q destructive %t",
				index,
				testResult.ID,
				testResult.Destructive,
				definitions[index].ID,
				definitions[index].Destructive,
			)
		}
	}
	if device.resetCalls != 183 || device.setPINCalls != 33 || device.pinTokenCalls != 56 {
		t.Fatalf("runtime calls = reset %d, set PIN %d, token %d; want 183, 33, 56", device.resetCalls, device.setPINCalls, device.pinTokenCalls)
	}
	interactionCounts := map[model.InteractionKind]int{}
	for index, interaction := range interactions {
		interactionCounts[interaction.Kind]++
		if (interaction.Kind == model.InteractionKindTouch ||
			interaction.Kind == model.InteractionKindPowerCycle) && !interaction.Destructive {
			t.Fatalf("interaction %d of kind %q is not marked destructive", index, interaction.Kind)
		}
	}
	if interactionCounts[model.InteractionKindPIN] != 71 ||
		interactionCounts[model.InteractionKindTouch] != 183 ||
		interactionCounts[model.InteractionKindPowerCycle] != 246 {
		t.Fatalf("interaction counts = %v, want PIN 71, touch 183, power cycle 246", interactionCounts)
	}
	if len(raw.commands) != 443 ||
		raw.getInfoCalls != 267 ||
		raw.makeCredentialCalls != 74 ||
		raw.getAssertionCalls != 28 ||
		raw.clientPINCalls != 74 {
		t.Fatalf(
			"raw commands = %d (GetInfo %d, MakeCredential %d, GetAssertion %d, ClientPIN %d), want 443 (267, 74, 28, 74)",
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

func facadeNewPortSkip(id conformance.TestID) bool {
	switch id {
	case ctap23.TestIDHID1P1,
		ctap23.TestIDHID1P2,
		ctap23.TestIDHID1P3,
		ctap23.TestIDHID1P4,
		ctap23.TestIDHID1P5,
		ctap23.TestIDHID1P6,
		ctap23.TestIDHID1P7,
		ctap23.TestIDHID1P8,
		ctap23.TestIDHID1P9,
		ctap23.TestIDHID1P10,
		ctap23.TestIDHID1P11,
		ctap23.TestIDHID1P12,
		ctap23.TestIDHID1P13,
		ctap23.TestIDHID1P14,
		ctap23.TestIDHID1P15,
		ctap23.TestIDHID1F1,
		ctap23.TestIDHID1F2,
		ctap23.TestIDHID1F3,
		ctap23.TestIDHID1F4,
		ctap23.TestIDNFC1P1,
		ctap23.TestIDNFC1P2,
		ctap23.TestIDNFC1P3,
		ctap23.TestIDNFC1P4,
		ctap23.TestIDNFC1F1,
		ctap23.TestIDNFC1F2,
		ctap23.TestIDNFC1F3,
		ctap23.TestIDNFC1F4,
		ctap23.TestIDBLE1P1,
		ctap23.TestIDBLE1P2,
		ctap23.TestIDBLE1P3,
		ctap23.TestIDBLE1P4,
		ctap23.TestIDBLE1P5,
		ctap23.TestIDBLE1P6,
		ctap23.TestIDBLE1P7,
		ctap23.TestIDBLE1P8,
		ctap23.TestIDBLE1P9,
		ctap23.TestIDBLE1P10,
		ctap23.TestIDResidentKeyP1,
		ctap23.TestIDResidentKeyP2,
		ctap23.TestIDResidentKeyP3,
		ctap23.TestIDResidentKeyP4,
		ctap23.TestIDResidentKeyP5,
		ctap23.TestIDResidentKeyP6,
		ctap23.TestIDEnterpriseAttestationP1,
		ctap23.TestIDEnterpriseAttestationP2,
		ctap23.TestIDEnterpriseAttestationP3,
		ctap23.TestIDEnterpriseAttestationF1,
		ctap23.TestIDEnterpriseAttestationF2,
		ctap23.TestIDEnterpriseAttestationF3,
		ctap23.TestIDEnterpriseAttestationF4,
		ctap23.TestIDEnterpriseAttestationF5,
		ctap23.TestIDEnterpriseAttestationF6,
		ctap23.TestIDHMACSecret2P1,
		ctap23.TestIDHMACSecret2P2,
		ctap23.TestIDHMACSecret2P3,
		ctap23.TestIDHMACSecret2F1,
		ctap23.TestIDHMACSecret2F2,
		ctap23.TestIDHMACSecret2F3,
		ctap23.TestIDHMACSecretMCP1,
		ctap23.TestIDHMACSecretMCP2,
		ctap23.TestIDHMACSecretMCP3,
		ctap23.TestIDHMACSecretMCF1,
		ctap23.TestIDHMACSecretMCF2,
		ctap23.TestIDHMACSecretMCF3,
		ctap23.TestIDHMACSecretMCF4,
		ctap23.TestIDCredProtectP1,
		ctap23.TestIDCredProtectP2,
		ctap23.TestIDCredProtectP3,
		ctap23.TestIDCredProtectP4,
		ctap23.TestIDCredBlobP1,
		ctap23.TestIDCredBlobP2,
		ctap23.TestIDCredBlobP3,
		ctap23.TestIDThirdPartyPaymentP1,
		ctap23.TestIDThirdPartyPaymentP2,
		ctap23.TestIDThirdPartyPaymentF1,
		ctap23.TestIDUVMP1:
		return true
	default:
		return false
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
	// Reset-1 creates one credential before proving reset invalidation.
	appendStatuses(1, ctaptransport.CTAP2_OK)
	// ClientPIN1 NewPIN P-4/P-5 each create one UV-authenticated credential.
	appendStatuses(2, ctaptransport.CTAP2_OK)
	// ClientPIN2 GetPinToken P-2/P-3 each create one credential with a fresh
	// legacy protocol-2 token. The remaining negative feature cases skip.
	appendStatuses(2, ctaptransport.CTAP2_OK)
	// ClientPIN2 PIN-permissions P-2/P-3 each create an independently
	// authorized discoverable credential.
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
			// Reset-1 proves the credential before reset and its absence after reset.
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
			ctaptransport.CTAP2_OK,
			ctaptransport.CTAP2_OK,
			// ClientPIN2 PIN-permissions P-3 proves its fresh ga token.
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
	case protocol.ClientPINSubCommandGetPinToken,
		protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions:
		if !cbor.matchesClientPINHash(request.PinUvAuthProtocol, sharedSecret, request.PinHashEnc) {
			cbor.t.Fatalf("%s pinHashEnc does not match the configured PIN", request.SubCommand)
		}
		if request.SubCommand == protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions {
			if request.Permissions == protocol.PermissionNone {
				cbor.t.Fatal("permission token request has no permissions")
			}
			rpBound := request.Permissions&(protocol.PermissionMakeCredential|protocol.PermissionGetAssertion) != 0
			if rpBound != (request.RPID != "") {
				cbor.t.Fatalf(
					"permission token request permissions = %s, RP ID = %q",
					request.Permissions,
					request.RPID,
				)
			}
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
		if len(cbor.clientPIN) != 0 {
			var info protocol.AuthenticatorGetInfoResponse
			if err := fxcbor.Unmarshal(response, &info); err != nil {
				cbor.t.Fatalf("decode GetInfo response: %v", err)
			}
			if _, present := info.Options[protocol.OptionClientPIN]; present {
				info.Options = maps.Clone(info.Options)
				info.Options[protocol.OptionClientPIN] = true
				response = encodeFacadeConformanceCBOR(cbor.t, info)
			}
		}

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
				cbor.t.Fatalf(
					"decode MakeCredential request after %d GetInfo calls: %v",
					cbor.getInfoCalls,
					err,
				)
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
