package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestCredentialManagementEnumerateRPsDefinitions(t *testing.T) {
	tests := credentialManagementEnumerateRPsTests(Config{})
	wantIDs := []conformance.TestID{
		TestIDCredentialManagementEnumerateRPsP1,
		TestIDCredentialManagementEnumerateRPsP2,
		TestIDCredentialManagementEnumerateRPsP3,
		TestIDCredentialManagementEnumerateRPsP4,
		TestIDCredentialManagementEnumerateRPsP5,
		TestIDCredentialManagementEnumerateRPsP6,
	}
	wantMarkers := []string{"P-1", "P-2", "P-3", "P-4", "P-5", "P-6"}
	if len(tests) != len(wantIDs) {
		t.Fatalf("tests = %d, want %d", len(tests), len(wantIDs))
	}
	for i, test := range tests {
		if test.ID != wantIDs[i] || test.Source.Path != credentialManagementEnumerateRPsSourcePath ||
			test.Source.Case != wantMarkers[i] || !test.Destructive {
			t.Fatalf("test %d = %#v", i, test)
		}
		for _, id := range []conformance.RequirementID{
			credentialManagementEnumerateRPsFeatureReference().ID,
			credentialManagementEnumerateRPsCommandReference().ID,
			clientPIN2KeyAgreementProtocolTwoReference().ID,
			clientPIN2NewPINPermissionsReference().ID,
			clientPINPowerCycleReference().ID,
			resetReference().ID,
			ctapMessageEncodingReference().ID,
		} {
			if !credentialManagementEnumerateRPsHasReference(test.References, id) {
				t.Errorf("test %s missing reference %q", test.ID, id)
			}
		}
	}
	for _, index := range []int{0, 3} {
		if !credentialManagementEnumerateRPsHasReference(
			tests[index].References,
			credentialManagementEnumerateRPsMetadataReference().ID,
		) {
			t.Errorf("test %s missing metadata reference", tests[index].ID)
		}
	}
	if !credentialManagementEnumerateRPsHasReference(
		tests[3].References,
		clientPIN2PermissionsPCMRReference().ID,
	) {
		t.Errorf("test %s missing pcmr metadata reference", tests[3].ID)
	}
	for _, index := range []int{2, 5} {
		if !credentialManagementEnumerateRPsHasReference(
			tests[index].References,
			credentialManagementEnumerateRPsStateReference().ID,
		) {
			t.Errorf("test %s missing state reference", tests[index].ID)
		}
	}

	for _, reference := range []conformance.RequirementRef{
		credentialManagementEnumerateRPsFeatureReference(),
		credentialManagementEnumerateRPsMetadataReference(),
		credentialManagementEnumerateRPsCommandReference(),
		credentialManagementEnumerateRPsStateReference(),
	} {
		if reference.Specification != conformance.SpecificationCTAP23 ||
			reference.URL == "" || reference.Section == "" || reference.Clause == "" {
			t.Fatalf("reference = %#v", reference)
		}
	}
	stateReference := credentialManagementEnumerateRPsStateReference()
	if stateReference.ID != "ctap-2.3-ps-20260226:6:stateful-command-sequencing" ||
		stateReference.Section != "6" ||
		stateReference.URL != "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticator-api" {
		t.Fatalf("state reference = %#v", stateReference)
	}
}

func TestCredentialManagementEnumerateRPsCasesUseExactIndependentFlows(t *testing.T) {
	tests := []struct {
		name              string
		index             int
		wantSubCommands   []protocol.CredentialManagementSubCommand
		wantPermissions   []protocol.Permission
		wantMatchedTokens []protocol.Permission
	}{
		{
			name:  "P-1",
			index: 0,
			wantSubCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandGetCredsMetadata,
				protocol.CredentialManagementSubCommandGetCredsMetadata,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionCredentialManagement,
				protocol.PermissionMakeCredential,
				protocol.PermissionCredentialManagement,
			},
			wantMatchedTokens: []protocol.Permission{
				protocol.PermissionCredentialManagement,
				protocol.PermissionCredentialManagement,
			},
		},
		{
			name:  "P-2",
			index: 1,
			wantSubCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandEnumerateRPsBegin,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionMakeCredential,
				protocol.PermissionCredentialManagement,
			},
			wantMatchedTokens: []protocol.Permission{protocol.PermissionCredentialManagement},
		},
		{
			name:  "P-3",
			index: 2,
			wantSubCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandEnumerateRPsBegin,
				protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionMakeCredential,
				protocol.PermissionCredentialManagement,
			},
			wantMatchedTokens: []protocol.Permission{protocol.PermissionCredentialManagement},
		},
		{
			name:  "P-4",
			index: 3,
			wantSubCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandGetCredsMetadata,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionMakeCredential,
				protocol.PermissionPersistentCredentialManagementReadOnly,
			},
			wantMatchedTokens: []protocol.Permission{
				protocol.PermissionPersistentCredentialManagementReadOnly,
			},
		},
		{
			name:  "P-5",
			index: 4,
			wantSubCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandEnumerateRPsBegin,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionMakeCredential,
				protocol.PermissionPersistentCredentialManagementReadOnly,
			},
			wantMatchedTokens: []protocol.Permission{
				protocol.PermissionPersistentCredentialManagementReadOnly,
			},
		},
		{
			name:  "P-6",
			index: 5,
			wantSubCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandEnumerateRPsBegin,
				protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionMakeCredential,
				protocol.PermissionPersistentCredentialManagementReadOnly,
			},
			wantMatchedTokens: []protocol.Permission{
				protocol.PermissionPersistentCredentialManagementReadOnly,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, authenticator, suppliedPIN := runCredentialManagementEnumerateRPsCase(
				t,
				testCase.index,
				nil,
			)
			if result.Status != conformance.StatusPassed {
				t.Fatalf("status = %s; result = %#v", result.Status, result)
			}
			if authenticator.powerCycles != 2 || authenticator.resets != 2 {
				t.Fatalf(
					"power cycles/resets = %d/%d, want 2/2",
					authenticator.powerCycles,
					authenticator.resets,
				)
			}
			if len(authenticator.makeCredentialRequests) != 2 ||
				authenticator.maxConcurrentCredentials != 2 {
				t.Fatalf(
					"makeCredential requests/max concurrent = %d/%d, want 2/2",
					len(authenticator.makeCredentialRequests),
					authenticator.maxConcurrentCredentials,
				)
			}
			if authenticator.makeCredentialRequests[0].RP.ID != credentialManagementEnumerateRPsRP1 ||
				authenticator.makeCredentialRequests[1].RP.ID != credentialManagementEnumerateRPsRP2 ||
				bytes.Equal(
					authenticator.makeCredentialRequests[0].User.ID,
					authenticator.makeCredentialRequests[1].User.ID,
				) {
				t.Fatalf("provisioned credentials = %#v", authenticator.makeCredentialRequests)
			}
			if !authenticator.makeCredentialWiresExact ||
				!authenticator.permissionWiresExact ||
				!authenticator.credentialManagementWiresExact {
				t.Fatal("one or more MakeCredential, permission-token, or credential-management wires were inexact")
			}
			if !slices.Equal(authenticator.subCommands, testCase.wantSubCommands) {
				t.Fatalf("subcommands = %v, want %v", authenticator.subCommands, testCase.wantSubCommands)
			}
			if !slices.Equal(authenticator.permissionScopes, testCase.wantPermissions) {
				t.Fatalf("permission scopes = %v, want %v", authenticator.permissionScopes, testCase.wantPermissions)
			}
			if !slices.Equal(authenticator.matchedTokens, testCase.wantMatchedTokens) {
				t.Fatalf("matched tokens = %v, want %v", authenticator.matchedTokens, testCase.wantMatchedTokens)
			}
			makeCredentialIndex := 0
			for i, permission := range authenticator.permissionScopes {
				wantRPID := ""
				if permission == protocol.PermissionMakeCredential {
					wantRPID = []string{
						credentialManagementEnumerateRPsRP1,
						credentialManagementEnumerateRPsRP2,
					}[makeCredentialIndex]
					makeCredentialIndex++
				}
				if authenticator.permissionRPIDs[i] != wantRPID {
					t.Fatalf(
						"permission RP ID %d = %q, want %q",
						i,
						authenticator.permissionRPIDs[i],
						wantRPID,
					)
				}
			}
			if len(authenticator.currentCredentialIDs) != 0 || len(authenticator.issuedTokens) != 0 {
				t.Fatalf(
					"cleanup retained credential IDs/tokens: %x/%v",
					authenticator.currentCredentialIDs,
					authenticator.issuedTokens,
				)
			}
			assertCredentialManagementFixtureZeroed(t, suppliedPIN, "temporary PIN")
			for _, token := range authenticator.issuedTokenBuffers {
				assertCredentialManagementFixtureZeroed(t, token, "issued permission token")
			}
			steps := result.Tests[0].Steps
			if len(steps) == 0 ||
				steps[len(steps)-1].ID != "credential-management-fixture.cleanup" ||
				steps[len(steps)-1].Status != conformance.StatusPassed {
				t.Fatalf("cleanup step = %#v", steps)
			}
		})
	}
}

func TestCredentialManagementEnumerateRPsApplicabilityDoesNotMutateState(t *testing.T) {
	t.Run("credMgmt false skips", func(t *testing.T) {
		result, authenticator, _ := runCredentialManagementEnumerateRPsCase(
			t,
			0,
			func(authenticator *credentialManagementEnumerateRPsAuthenticator, config *Config) {
				authenticator.credentialManagementEnabled = false
			},
		)
		assertCredentialManagementEnumerateRPsPreflight(
			t,
			result,
			authenticator,
			conformance.StatusSkipped,
		)
	})

	t.Run("featureful credMgmt false fails", func(t *testing.T) {
		result, authenticator, _ := runCredentialManagementEnumerateRPsCase(
			t,
			0,
			func(authenticator *credentialManagementEnumerateRPsAuthenticator, config *Config) {
				authenticator.credentialManagementEnabled = false
				config.Featureful = true
			},
		)
		assertCredentialManagementEnumerateRPsPreflight(
			t,
			result,
			authenticator,
			conformance.StatusFailed,
		)
	})

	for _, testCase := range []struct {
		name  string
		index int
	}{
		{name: "P-4 pcmr unsupported", index: 3},
		{name: "P-5 pcmr unsupported", index: 4},
		{name: "P-6 pcmr unsupported", index: 5},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result, authenticator, _ := runCredentialManagementEnumerateRPsCase(
				t,
				testCase.index,
				func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
					authenticator.perCredROEnabled = false
				},
			)
			assertCredentialManagementEnumerateRPsPreflight(
				t,
				result,
				authenticator,
				conformance.StatusSkipped,
			)
		})
	}
}

func TestCredentialManagementEnumerateRPsClassifiesProtocolAndTransportFailures(t *testing.T) {
	tests := []struct {
		name      string
		index     int
		configure func(*credentialManagementEnumerateRPsAuthenticator, *Config)
		want      conformance.Status
	}{
		{
			name:  "unexpected CTAP status",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
				authenticator.credentialManagementStatus = ctaptransport.CTAP2_ERR_NOT_ALLOWED
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "transport error",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
				authenticator.credentialManagementError = errors.New("device disconnected")
			},
			want: conformance.StatusError,
		},
		{
			name:  "missing metadata field",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateRPsMissingRemaining
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "wrong total RPs",
			index: 1,
			configure: func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateRPsWrongTotal
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "wrong RP hash",
			index: 1,
			configure: func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateRPsWrongHash
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "duplicate continuation RP",
			index: 2,
			configure: func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateRPsDuplicateNext
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "extra begin field",
			index: 4,
			configure: func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateRPsExtraField
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "noncanonical response",
			index: 1,
			configure: func(authenticator *credentialManagementEnumerateRPsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateRPsNoncanonical
			},
			want: conformance.StatusFailed,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, authenticator, suppliedPIN := runCredentialManagementEnumerateRPsCase(
				t,
				testCase.index,
				testCase.configure,
			)
			if result.Status != testCase.want {
				t.Fatalf("status = %s, want %s; result = %#v", result.Status, testCase.want, result)
			}
			if authenticator.powerCycles != 2 || authenticator.resets != 2 {
				t.Fatalf(
					"cleanup lifecycle = cycles %d, resets %d",
					authenticator.powerCycles,
					authenticator.resets,
				)
			}
			assertCredentialManagementFixtureZeroed(t, suppliedPIN, "temporary PIN")
		})
	}
}

func TestCredentialManagementEnumerateRPsInvalidContinuationIsNotAllowed(t *testing.T) {
	authenticator := newCredentialManagementEnumerateRPsAuthenticator(t)
	request := credentialManagementContinuationRequest(
		protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP,
	)

	_, err := exchangeRawCredentialManagement(t.Context(), authenticator, request)
	if statusErr := expectCTAPStatus(err, ctaptransport.CTAP2_ERR_NOT_ALLOWED); statusErr != nil {
		t.Fatal(statusErr)
	}

	authenticator.enumerationActive = true
	authenticator.enumerationRPs = []credential.PublicKeyCredentialRpEntity{{
		ID: credentialManagementEnumerateRPsRP1,
	}}
	authenticator.enumerationIndex = len(authenticator.enumerationRPs)
	_, err = exchangeRawCredentialManagement(t.Context(), authenticator, request)
	if statusErr := expectCTAPStatus(err, ctaptransport.CTAP2_ERR_NOT_ALLOWED); statusErr != nil {
		t.Fatal(statusErr)
	}
	if !authenticator.credentialManagementWiresExact {
		t.Fatal("continuation request contained fields other than subCommand")
	}
}

func TestCredentialManagementEnumerateRPsCleanupErrorRemainsVisible(t *testing.T) {
	result, _, suppliedPIN := runCredentialManagementEnumerateRPsCase(
		t,
		1,
		func(authenticator *credentialManagementEnumerateRPsAuthenticator, config *Config) {
			resetCalls := 0
			config.Resetter = func(context.Context, *client.Client) error {
				resetCalls++
				if resetCalls == 2 {
					return errors.New("cleanup reset failed")
				}
				authenticator.reset()

				return nil
			}
		},
	)
	if result.Status != conformance.StatusError {
		t.Fatalf("status = %s, want error; result = %#v", result.Status, result)
	}
	assertCredentialManagementFixtureZeroed(t, suppliedPIN, "temporary PIN")
}

type credentialManagementEnumerateRPsMutation uint8

const (
	credentialManagementEnumerateRPsNoMutation credentialManagementEnumerateRPsMutation = iota
	credentialManagementEnumerateRPsMissingRemaining
	credentialManagementEnumerateRPsWrongTotal
	credentialManagementEnumerateRPsWrongHash
	credentialManagementEnumerateRPsDuplicateNext
	credentialManagementEnumerateRPsExtraField
	credentialManagementEnumerateRPsNoncanonical
)

type credentialManagementEnumerateRPsAuthenticator struct {
	*credentialManagementFixtureAuthenticator

	credentialManagementStatus     ctaptransport.StatusCode
	credentialManagementError      error
	responseMutation               credentialManagementEnumerateRPsMutation
	credentialManagementWiresExact bool
	subCommands                    []protocol.CredentialManagementSubCommand
	matchedTokens                  []protocol.Permission
	issuedTokenBuffers             [][]byte
	enumerationRPs                 []credential.PublicKeyCredentialRpEntity
	enumerationIndex               int
	enumerationActive              bool
}

func newCredentialManagementEnumerateRPsAuthenticator(
	t *testing.T,
) *credentialManagementEnumerateRPsAuthenticator {
	t.Helper()

	return &credentialManagementEnumerateRPsAuthenticator{
		credentialManagementFixtureAuthenticator: newCredentialManagementFixtureAuthenticator(t),
		credentialManagementWiresExact:           true,
		responseMutation:                         credentialManagementEnumerateRPsNoMutation,
	}
}

func (a *credentialManagementEnumerateRPsAuthenticator) CBOR(
	ctx context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	a.t.Helper()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(request) == 0 {
		a.t.Fatal("empty CTAP request")
	}

	command := protocol.Command(request[0])
	if command == protocol.AuthenticatorCredentialManagement {
		if a.credentialManagementError != nil {
			return ctaptransport.CBORResponse{}, a.credentialManagementError
		}
		response := a.credentialManagementResponse(request[1:])

		return ctaptransport.ValidateCBORResponse(command, response)
	}

	permissionCount := len(a.permissionScopes)
	response, err := a.credentialManagementFixtureAuthenticator.CBOR(ctx, request)
	if err == nil && command == protocol.AuthenticatorClientPIN &&
		len(a.permissionScopes) == permissionCount+1 {
		permission := a.permissionScopes[len(a.permissionScopes)-1]
		a.issuedTokenBuffers = append(a.issuedTokenBuffers, a.issuedTokens[permission])
	}

	return response, err
}

func (a *credentialManagementEnumerateRPsAuthenticator) credentialManagementResponse(
	body []byte,
) ctaptransport.CBORResponse {
	if a.credentialManagementStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.credentialManagementStatus}
	}

	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		a.t.Fatal(err)
	}
	var request protocol.AuthenticatorCredentialManagementRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	canonical, err := ctap2EncMode.Marshal(request)
	if err != nil {
		a.t.Fatal(err)
	}
	if !bytes.Equal(body, canonical) {
		a.credentialManagementWiresExact = false
		a.t.Fatalf("credential-management request = %x, want canonical %x", body, canonical)
	}
	a.subCommands = append(a.subCommands, request.SubCommand)

	switch request.SubCommand {
	case protocol.CredentialManagementSubCommandGetCredsMetadata,
		protocol.CredentialManagementSubCommandEnumerateRPsBegin:
		if len(fields) != 3 || fields[1] == nil || fields[2] != nil ||
			fields[3] == nil || fields[4] == nil ||
			request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
			a.credentialManagementWiresExact = false
			a.t.Fatalf("authorized credential-management request = %#v, fields = %#v", request, fields)
		}
		permission, ok := a.matchManagementToken(request)
		if !ok {
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID}
		}
		a.matchedTokens = append(a.matchedTokens, permission)
	case protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP:
		if len(fields) != 1 || fields[1] == nil || fields[2] != nil ||
			fields[3] != nil || fields[4] != nil ||
			request.PinUvAuthProtocol != 0 || len(request.PinUvAuthParam) != 0 {
			a.credentialManagementWiresExact = false
			a.t.Fatalf("continuation request = %#v, fields = %#v", request, fields)
		}
	default:
		a.t.Fatalf("unexpected credential-management subcommand %s", request.SubCommand)
	}

	if a.responseMutation == credentialManagementEnumerateRPsNoncanonical {
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       []byte{0xbf, 0x03, 0xa1, 0x62, 'i', 'd', 0x61, 'x', 0xff},
		}
	}

	switch request.SubCommand {
	case protocol.CredentialManagementSubCommandGetCredsMetadata:
		return a.metadataResponse()
	case protocol.CredentialManagementSubCommandEnumerateRPsBegin:
		return a.beginResponse()
	case protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP:
		return a.nextResponse()
	default:
		panic("unreachable")
	}
}

func (a *credentialManagementEnumerateRPsAuthenticator) matchManagementToken(
	request protocol.AuthenticatorCredentialManagementRequest,
) (protocol.Permission, bool) {
	for _, permission := range []protocol.Permission{
		protocol.PermissionCredentialManagement,
		protocol.PermissionPersistentCredentialManagementReadOnly,
	} {
		token := a.issuedTokens[permission]
		if len(token) == 0 {
			continue
		}
		want := ctapcrypto.Authenticate(
			protocol.PinUvAuthProtocolTwo,
			token,
			[]byte{byte(request.SubCommand)},
		)
		matches := bytes.Equal(request.PinUvAuthParam, want)
		clear(want)
		if matches {
			return permission, true
		}
	}

	return protocol.PermissionNone, false
}

func (a *credentialManagementEnumerateRPsAuthenticator) metadataResponse() ctaptransport.CBORResponse {
	existing := uint(len(a.makeCredentialRequests))
	remaining := uint(10) - existing
	response := map[uint64]any{1: existing, 2: remaining}
	if a.responseMutation == credentialManagementEnumerateRPsMissingRemaining {
		delete(response, 2)
	}

	return a.success(response)
}

func (a *credentialManagementEnumerateRPsAuthenticator) beginResponse() ctaptransport.CBORResponse {
	a.enumerationRPs = a.currentRPs()
	a.enumerationIndex = 0
	a.enumerationActive = len(a.enumerationRPs) != 0
	if !a.enumerationActive {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS}
	}

	response := a.rpResponse(a.enumerationRPs[0], true)
	a.enumerationIndex = 1

	return response
}

func (a *credentialManagementEnumerateRPsAuthenticator) nextResponse() ctaptransport.CBORResponse {
	if !a.enumerationActive || a.enumerationIndex >= len(a.enumerationRPs) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED}
	}

	rp := a.enumerationRPs[a.enumerationIndex]
	if a.responseMutation == credentialManagementEnumerateRPsDuplicateNext {
		rp = a.enumerationRPs[0]
	}
	a.enumerationIndex++

	return a.rpResponse(rp, false)
}

func (a *credentialManagementEnumerateRPsAuthenticator) rpResponse(
	rp credential.PublicKeyCredentialRpEntity,
	begin bool,
) ctaptransport.CBORResponse {
	digest := sha256.Sum256([]byte(rp.ID))
	hash := digest[:]
	if a.responseMutation == credentialManagementEnumerateRPsWrongHash {
		hash = bytes.Repeat([]byte{0xff}, 32)
	}
	response := map[uint64]any{
		3: rp,
		4: hash,
	}
	if begin {
		total := uint(len(a.enumerationRPs))
		if a.responseMutation == credentialManagementEnumerateRPsWrongTotal {
			total++
		}
		response[5] = total
	}
	if a.responseMutation == credentialManagementEnumerateRPsExtraField {
		response[6] = map[string]any{"id": []byte{0x01}}
	}

	return a.success(response)
}

func (a *credentialManagementEnumerateRPsAuthenticator) currentRPs() []credential.PublicKeyCredentialRpEntity {
	seen := make(map[string]struct{}, len(a.makeCredentialRequests))
	rps := make([]credential.PublicKeyCredentialRpEntity, 0, len(a.makeCredentialRequests))
	for _, request := range a.makeCredentialRequests {
		if _, ok := seen[request.RP.ID]; ok {
			continue
		}
		seen[request.RP.ID] = struct{}{}
		rps = append(rps, request.RP)
	}

	return rps
}

func (a *credentialManagementEnumerateRPsAuthenticator) reset() {
	a.enumerationRPs = nil
	a.enumerationIndex = 0
	a.enumerationActive = false
	a.credentialManagementFixtureAuthenticator.reset()
}

func runCredentialManagementEnumerateRPsCase(
	t *testing.T,
	index int,
	configure func(*credentialManagementEnumerateRPsAuthenticator, *Config),
) (conformance.SuiteResult, *credentialManagementEnumerateRPsAuthenticator, []byte) {
	t.Helper()

	authenticator := newCredentialManagementEnumerateRPsAuthenticator(t)
	var suppliedPIN []byte
	config := credentialManagementFixtureConfig(
		authenticator.credentialManagementFixtureAuthenticator,
		&suppliedPIN,
	)
	config.Resetter = func(context.Context, *client.Client) error {
		authenticator.reset()

		return nil
	}
	if configure != nil {
		configure(authenticator, &config)
	}
	tests := credentialManagementEnumerateRPsTests(config)
	runner, err := conformance.NewRunner(authenticator)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:   "credential-management-enumerate-rps-test",
		Name: "Credential management enumerate RPs test",
		Tests: []conformance.Test{
			tests[index],
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result, authenticator, suppliedPIN
}

func assertCredentialManagementEnumerateRPsPreflight(
	t *testing.T,
	result conformance.SuiteResult,
	authenticator *credentialManagementEnumerateRPsAuthenticator,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want {
		t.Fatalf("status = %s, want %s; result = %#v", result.Status, want, result)
	}
	if authenticator.powerCycles != 0 || authenticator.resets != 0 ||
		authenticator.setPINCalls != 0 || len(authenticator.makeCredentialRequests) != 0 ||
		len(authenticator.subCommands) != 0 || len(authenticator.permissionScopes) != 0 {
		t.Fatalf(
			"preflight mutated state: cycles=%d resets=%d setPIN=%d make=%d commands=%v permissions=%v",
			authenticator.powerCycles,
			authenticator.resets,
			authenticator.setPINCalls,
			len(authenticator.makeCredentialRequests),
			authenticator.subCommands,
			authenticator.permissionScopes,
		)
	}
}

func credentialManagementEnumerateRPsHasReference(
	references []conformance.RequirementRef,
	id conformance.RequirementID,
) bool {
	return slices.ContainsFunc(references, func(reference conformance.RequirementRef) bool {
		return reference.ID == id
	})
}

var _ ctaptransport.CBOR = (*credentialManagementEnumerateRPsAuthenticator)(nil)
