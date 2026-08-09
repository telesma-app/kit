package ctap23

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestCredentialManagementEnumerateCredentialsDefinitions(t *testing.T) {
	tests := credentialManagementEnumerateCredentialsTests(Config{})
	wantIDs := []conformance.TestID{
		TestIDCredentialManagementEnumerateCredentialsP1,
		TestIDCredentialManagementEnumerateCredentialsP2,
		TestIDCredentialManagementEnumerateCredentialsP3,
	}
	wantMarkers := []string{"P-1", "P-2", "P-3"}
	if len(tests) != len(wantIDs) {
		t.Fatalf("tests = %d, want %d", len(tests), len(wantIDs))
	}
	for index, test := range tests {
		if test.ID != wantIDs[index] ||
			test.Source.Path != credentialManagementEnumerateCredentialsSourcePath ||
			test.Source.Case != wantMarkers[index] ||
			!test.Destructive {
			t.Fatalf("test %d = %#v", index, test)
		}
		for _, id := range []conformance.RequirementID{
			credentialManagementEnumerateCredentialsFeatureReference().ID,
			credentialManagementEnumerateCredentialsCommandReference().ID,
			clientPIN2KeyAgreementProtocolTwoReference().ID,
			clientPIN2NewPINPermissionsReference().ID,
			clientPINSetReference().ID,
			clientPINPowerCycleReference().ID,
			resetReference().ID,
			ctapMessageEncodingReference().ID,
		} {
			if !credentialManagementEnumerateCredentialsHasReference(test.References, id) {
				t.Errorf("test %s missing reference %q", test.ID, id)
			}
		}
	}
	if !credentialManagementEnumerateCredentialsHasReference(
		tests[1].References,
		credentialManagementEnumerateCredentialsStateReference().ID,
	) {
		t.Errorf("test %s missing stateful-command reference", tests[1].ID)
	}
	stateReference := credentialManagementEnumerateCredentialsStateReference()
	if stateReference.ID != "ctap-2.3-ps-20260226:6:stateful-command-sequencing" ||
		stateReference.Section != "6" ||
		stateReference.Clause != "stateful-command-sequencing" ||
		stateReference.URL != "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticator-api" ||
		stateReference.Level != conformance.RequirementConstraint {
		t.Fatalf("state reference = %#v", stateReference)
	}
	if !credentialManagementEnumerateCredentialsHasReference(
		tests[2].References,
		credentialManagementEnumerateCredentialsPCMRReference().ID,
	) {
		t.Errorf("test %s missing pcmr authorization reference", tests[2].ID)
	}

	for _, reference := range []conformance.RequirementRef{
		credentialManagementEnumerateCredentialsFeatureReference(),
		credentialManagementEnumerateCredentialsCommandReference(),
		credentialManagementEnumerateCredentialsStateReference(),
		credentialManagementEnumerateCredentialsPCMRReference(),
	} {
		if reference.Specification != conformance.SpecificationCTAP23 ||
			reference.URL == "" || reference.Section == "" || reference.Clause == "" {
			t.Fatalf("reference = %#v", reference)
		}
	}
}

func TestCredentialManagementEnumerateCredentialsCasesUseExactIndependentFlows(t *testing.T) {
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
				protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionMakeCredential,
				protocol.PermissionCredentialManagement,
			},
			wantMatchedTokens: []protocol.Permission{protocol.PermissionCredentialManagement},
		},
		{
			name:  "P-2",
			index: 1,
			wantSubCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
				protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
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
				protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
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
			result, authenticator, suppliedPIN := runCredentialManagementEnumerateCredentialsCase(
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
			if authenticator.makeCredentialRequests[0].RP.ID !=
				credentialManagementEnumerateCredentialsRP ||
				authenticator.makeCredentialRequests[1].RP.ID !=
					credentialManagementEnumerateCredentialsRP ||
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
			for index, permission := range authenticator.permissionScopes {
				wantRPID := ""
				if permission == protocol.PermissionMakeCredential {
					wantRPID = credentialManagementEnumerateCredentialsRP
				}
				if authenticator.permissionRPIDs[index] != wantRPID {
					t.Fatalf(
						"permission RP ID %d = %q, want %q",
						index,
						authenticator.permissionRPIDs[index],
						wantRPID,
					)
				}
			}
			if len(authenticator.currentCredentialIDs) != 0 ||
				len(authenticator.issuedTokens) != 0 {
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

func TestCredentialManagementEnumerateCredentialsApplicabilityDoesNotMutateState(t *testing.T) {
	tests := []struct {
		name      string
		index     int
		configure func(*credentialManagementEnumerateCredentialsAuthenticator)
		want      conformance.Status
	}{
		{
			name:  "credMgmt false skips",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator) {
				authenticator.credentialManagementEnabled = false
			},
			want: conformance.StatusSkipped,
		},
		{
			name:  "perCredMgmtRO false skips P-3",
			index: 2,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator) {
				authenticator.perCredROEnabled = false
			},
			want: conformance.StatusSkipped,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, authenticator, _ := runCredentialManagementEnumerateCredentialsCase(
				t,
				testCase.index,
				func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
					testCase.configure(authenticator)
				},
			)
			assertCredentialManagementEnumerateCredentialsPreflight(
				t,
				result,
				authenticator,
				testCase.want,
			)
		})
	}
}

func TestCredentialManagementEnumerateCredentialsClassifiesFailures(t *testing.T) {
	tests := []struct {
		name      string
		index     int
		configure func(*credentialManagementEnumerateCredentialsAuthenticator, *Config)
		want      conformance.Status
	}{
		{
			name:  "unexpected CTAP status",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.credentialManagementStatus = ctaptransport.CTAP2_ERR_NOT_ALLOWED
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "transport error",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.credentialManagementError = errors.New("device disconnected")
			},
			want: conformance.StatusError,
		},
		{
			name:  "missing user",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsMissingUser
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "wrong total credentials",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsWrongTotal
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "wrong descriptor",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsWrongDescriptor
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "wrong user",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsWrongUser
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "wrong public key",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsWrongPublicKey
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "invalid credProtect",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsInvalidCredProtect
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "wrong largeBlobKey",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsWrongLargeBlobKey
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "short largeBlobKey",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsShortLargeBlobKey
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "unsupported thirdPartyPayment",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsUnexpectedPayment
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "duplicate continuation credential",
			index: 1,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsDuplicateNext
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "continuation contains totalCredentials",
			index: 1,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsNextTotal
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "extra response field",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsExtraField
			},
			want: conformance.StatusFailed,
		},
		{
			name:  "noncanonical response",
			index: 0,
			configure: func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, _ *Config) {
				authenticator.responseMutation = credentialManagementEnumerateCredentialsNoncanonical
			},
			want: conformance.StatusFailed,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, authenticator, suppliedPIN := runCredentialManagementEnumerateCredentialsCase(
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
			for _, token := range authenticator.issuedTokenBuffers {
				assertCredentialManagementFixtureZeroed(t, token, "issued permission token")
			}
		})
	}
}

func TestCredentialManagementEnumerateCredentialsInvalidRPHashReturnsNoCredentials(t *testing.T) {
	authenticator := newCredentialManagementEnumerateCredentialsAuthenticator(t)
	token := bytes.Repeat([]byte{0x5a}, 32)
	defer clear(token)

	authenticator.issuedTokens[protocol.PermissionCredentialManagement] = token
	params := protocol.CredentialManagementSubCommandParams{
		RPIDHash: bytes.Repeat([]byte{0xff}, sha256.Size),
	}
	authorized, err := newCredentialManagementAuthorizedRequest(
		token,
		protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
		&params,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer authorized.clear()

	_, err = exchangeRawCredentialManagement(t.Context(), authenticator, authorized.Request)
	if statusErr := expectCTAPStatus(err, ctaptransport.CTAP2_ERR_NO_CREDENTIALS); statusErr != nil {
		t.Fatal(statusErr)
	}
	if !authenticator.credentialManagementWiresExact {
		t.Fatal("invalid-RP request was not a canonical authorized begin request")
	}
}

func TestCredentialManagementEnumerateCredentialsInvalidContinuationIsNotAllowed(t *testing.T) {
	authenticator := newCredentialManagementEnumerateCredentialsAuthenticator(t)
	request := credentialManagementContinuationRequest(
		protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
	)

	_, err := exchangeRawCredentialManagement(t.Context(), authenticator, request)
	if statusErr := expectCTAPStatus(err, ctaptransport.CTAP2_ERR_NOT_ALLOWED); statusErr != nil {
		t.Fatal(statusErr)
	}

	authenticator.enumerationActive = true
	authenticator.enumerationCredentials = []int{0}
	authenticator.enumerationIndex = len(authenticator.enumerationCredentials)
	_, err = exchangeRawCredentialManagement(t.Context(), authenticator, request)
	if statusErr := expectCTAPStatus(err, ctaptransport.CTAP2_ERR_NOT_ALLOWED); statusErr != nil {
		t.Fatal(statusErr)
	}
	if !authenticator.credentialManagementWiresExact {
		t.Fatal("continuation request contained fields other than subCommand")
	}
}

func TestCredentialManagementEnumerateCredentialsOptionalFieldSemantics(t *testing.T) {
	publicKey := credentialManagementEnumerateCredentialsPublicKey()
	user := credential.PublicKeyCredentialUserEntity{
		ID:          []byte("user-id"),
		Name:        "user-name",
		DisplayName: "User Display Name",
	}
	expectedDescriptor := credential.PublicKeyCredentialDescriptor{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   []byte("credential-id"),
	}
	responseDescriptor := expectedDescriptor
	responseDescriptor.Transports = []credential.AuthenticatorTransport{
		credential.AuthenticatorTransportUSB,
	}
	responseUser := credential.PublicKeyCredentialUserEntity{ID: slices.Clone(user.ID)}
	fixture := &credentialManagementFixture{
		Info: protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{
				extension.ExtensionIdentifierThirdPartyPayment,
			},
		},
		Credentials: []credentialManagementCredential{{
			RPID:       credentialManagementEnumerateCredentialsRP,
			Descriptor: expectedDescriptor,
			User:       user,
			PublicKey:  publicKey,
		}},
	}
	newResult := func(payment *bool) (credentialManagementResponse, []byte, []byte) {
		largeBlobKey := bytes.Repeat([]byte{0xa5}, 32)
		largeBlobField := slices.Concat([]byte{0x58, 0x20}, bytes.Repeat([]byte{0xa5}, 32))

		return credentialManagementResponse{
			Fields: map[uint64]cbor.RawMessage{
				6:  {0x00},
				7:  {0x00},
				8:  {0x00},
				9:  {0x00},
				10: {0x00},
				11: largeBlobField,
				12: {0x00},
			},
			Response: protocol.AuthenticatorCredentialManagementResponse{
				User:              responseUser,
				CredentialID:      responseDescriptor,
				PublicKey:         publicKey,
				TotalCredentials:  1,
				CredProtect:       1,
				LargeBlobKey:      largeBlobKey,
				ThirdPartyPayment: payment,
			},
		}, largeBlobKey, largeBlobField
	}

	thirdPartyPayment := false
	result, largeBlobKey, largeBlobField := newResult(&thirdPartyPayment)
	if _, err := validateCredentialManagementEnumeratedCredential(result, fixture, true); err != nil {
		t.Fatalf("valid advertised optional fields: %v", err)
	}
	assertCredentialManagementFixtureZeroed(t, largeBlobKey, "validated largeBlobKey")
	assertCredentialManagementFixtureZeroed(t, largeBlobField, "validated largeBlobKey field")

	result, largeBlobKey, largeBlobField = newResult(nil)
	delete(result.Fields, 12)
	if _, err := validateCredentialManagementEnumeratedCredential(result, fixture, true); err == nil {
		t.Fatal("missing thirdPartyPayment for advertised support was accepted")
	}
	assertCredentialManagementFixtureZeroed(t, largeBlobKey, "failed largeBlobKey")
	assertCredentialManagementFixtureZeroed(t, largeBlobField, "failed largeBlobKey field")

	thirdPartyPayment = true
	result, largeBlobKey, largeBlobField = newResult(&thirdPartyPayment)
	if _, err := validateCredentialManagementEnumeratedCredential(result, fixture, true); err == nil {
		t.Fatal("true thirdPartyPayment for a credential created without the extension was accepted")
	}
	assertCredentialManagementFixtureZeroed(t, largeBlobKey, "true-payment largeBlobKey")
	assertCredentialManagementFixtureZeroed(t, largeBlobField, "true-payment largeBlobKey field")
}

func TestCredentialManagementEnumerateCredentialsCleanupErrorRemainsVisible(t *testing.T) {
	result, _, suppliedPIN := runCredentialManagementEnumerateCredentialsCase(
		t,
		0,
		func(authenticator *credentialManagementEnumerateCredentialsAuthenticator, config *Config) {
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

type credentialManagementEnumerateCredentialsMutation uint8

const (
	credentialManagementEnumerateCredentialsNoMutation credentialManagementEnumerateCredentialsMutation = iota
	credentialManagementEnumerateCredentialsMissingUser
	credentialManagementEnumerateCredentialsWrongTotal
	credentialManagementEnumerateCredentialsWrongDescriptor
	credentialManagementEnumerateCredentialsWrongUser
	credentialManagementEnumerateCredentialsWrongPublicKey
	credentialManagementEnumerateCredentialsInvalidCredProtect
	credentialManagementEnumerateCredentialsWrongLargeBlobKey
	credentialManagementEnumerateCredentialsShortLargeBlobKey
	credentialManagementEnumerateCredentialsUnexpectedPayment
	credentialManagementEnumerateCredentialsDuplicateNext
	credentialManagementEnumerateCredentialsNextTotal
	credentialManagementEnumerateCredentialsExtraField
	credentialManagementEnumerateCredentialsNoncanonical
)

type credentialManagementEnumerateCredentialsAuthenticator struct {
	*credentialManagementFixtureAuthenticator

	credentialManagementStatus     ctaptransport.StatusCode
	credentialManagementError      error
	responseMutation               credentialManagementEnumerateCredentialsMutation
	credentialManagementWiresExact bool
	subCommands                    []protocol.CredentialManagementSubCommand
	matchedTokens                  []protocol.Permission
	issuedTokenBuffers             [][]byte
	enumerationCredentials         []int
	enumerationIndex               int
	enumerationActive              bool
}

func newCredentialManagementEnumerateCredentialsAuthenticator(
	t *testing.T,
) *credentialManagementEnumerateCredentialsAuthenticator {
	t.Helper()

	return &credentialManagementEnumerateCredentialsAuthenticator{
		credentialManagementFixtureAuthenticator: newCredentialManagementFixtureAuthenticator(t),
		credentialManagementWiresExact:           true,
		responseMutation:                         credentialManagementEnumerateCredentialsNoMutation,
	}
}

func (a *credentialManagementEnumerateCredentialsAuthenticator) CBOR(
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

func (a *credentialManagementEnumerateCredentialsAuthenticator) credentialManagementResponse(
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
	case protocol.CredentialManagementSubCommandEnumerateCredentialsBegin:
		if len(fields) != 4 || fields[1] == nil || fields[2] == nil ||
			fields[3] == nil || fields[4] == nil ||
			request.PinUvAuthProtocol != protocol.PinUvAuthProtocolTwo {
			a.credentialManagementWiresExact = false
			a.t.Fatalf("authorized credential enumeration request = %#v, fields = %#v", request, fields)
		}
		var paramsFields map[uint64]cbor.RawMessage
		if err := getInfoDecMode.Unmarshal(fields[2], &paramsFields); err != nil {
			a.t.Fatal(err)
		}
		if len(paramsFields) != 1 || paramsFields[1] == nil ||
			len(request.SubCommandParams.RPIDHash) != sha256.Size {
			a.credentialManagementWiresExact = false
			a.t.Fatalf("enumerateCredentialsBegin params = %#v, fields = %#v", request.SubCommandParams, paramsFields)
		}
		permission, ok := a.matchManagementToken(request)
		if !ok {
			return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID}
		}
		a.matchedTokens = append(a.matchedTokens, permission)
	case protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential:
		if len(fields) != 1 || fields[1] == nil || fields[2] != nil ||
			fields[3] != nil || fields[4] != nil ||
			request.PinUvAuthProtocol != 0 || len(request.PinUvAuthParam) != 0 {
			a.credentialManagementWiresExact = false
			a.t.Fatalf("continuation request = %#v, fields = %#v", request, fields)
		}
	default:
		a.t.Fatalf("unexpected credential-management subcommand %s", request.SubCommand)
	}

	if a.responseMutation == credentialManagementEnumerateCredentialsNoncanonical {
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       []byte{0xbf, 0xff},
		}
	}

	switch request.SubCommand {
	case protocol.CredentialManagementSubCommandEnumerateCredentialsBegin:
		return a.beginResponse(request.SubCommandParams.RPIDHash)
	case protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential:
		return a.nextResponse()
	default:
		panic("unreachable")
	}
}

func (a *credentialManagementEnumerateCredentialsAuthenticator) matchManagementToken(
	request protocol.AuthenticatorCredentialManagementRequest,
) (protocol.Permission, bool) {
	encodedParams, err := ctap2EncMode.Marshal(request.SubCommandParams)
	if err != nil {
		a.t.Fatal(err)
	}
	authenticatedData := slices.Concat([]byte{byte(request.SubCommand)}, encodedParams)
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
			authenticatedData,
		)
		matches := bytes.Equal(request.PinUvAuthParam, want)
		clear(want)
		if matches {
			return permission, true
		}
	}

	return protocol.PermissionNone, false
}

func (a *credentialManagementEnumerateCredentialsAuthenticator) beginResponse(
	rpIDHash []byte,
) ctaptransport.CBORResponse {
	a.enumerationCredentials = a.currentCredentials(rpIDHash)
	a.enumerationIndex = 0
	a.enumerationActive = len(a.enumerationCredentials) != 0
	if !a.enumerationActive {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS}
	}

	response := a.enumeratedCredentialResponse(a.enumerationCredentials[0], true)
	a.enumerationIndex = 1

	return response
}

func (a *credentialManagementEnumerateCredentialsAuthenticator) nextResponse() ctaptransport.CBORResponse {
	if !a.enumerationActive || a.enumerationIndex >= len(a.enumerationCredentials) {
		return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED}
	}

	credentialIndex := a.enumerationCredentials[a.enumerationIndex]
	if a.responseMutation == credentialManagementEnumerateCredentialsDuplicateNext {
		credentialIndex = a.enumerationCredentials[0]
	}
	a.enumerationIndex++

	return a.enumeratedCredentialResponse(credentialIndex, false)
}

func (a *credentialManagementEnumerateCredentialsAuthenticator) enumeratedCredentialResponse(
	credentialIndex int,
	begin bool,
) ctaptransport.CBORResponse {
	request := a.makeCredentialRequests[credentialIndex]
	descriptor := credential.PublicKeyCredentialDescriptor{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   slices.Clone(a.currentCredentialIDs[credentialIndex]),
	}
	user := request.User
	user.ID = slices.Clone(user.ID)
	publicKey := credentialManagementEnumerateCredentialsPublicKey()
	largeBlobKey := bytes.Repeat([]byte{byte(credentialIndex + 1)}, 32)
	credProtect := uint(1)

	if a.responseMutation == credentialManagementEnumerateCredentialsWrongDescriptor {
		descriptor.ID = []byte("unknown-credential")
	}
	if a.responseMutation == credentialManagementEnumerateCredentialsWrongUser {
		user.ID = []byte("unknown-user")
	}
	if a.responseMutation == credentialManagementEnumerateCredentialsWrongPublicKey {
		publicKey[cose.EC2KeyParameterX] = bytes.Repeat([]byte{0xff}, 32)
	}
	if a.responseMutation == credentialManagementEnumerateCredentialsInvalidCredProtect {
		credProtect = 4
	}
	if a.responseMutation == credentialManagementEnumerateCredentialsWrongLargeBlobKey {
		largeBlobKey = bytes.Repeat([]byte{0xff}, 32)
	}
	if a.responseMutation == credentialManagementEnumerateCredentialsShortLargeBlobKey {
		largeBlobKey = bytes.Repeat([]byte{byte(credentialIndex + 1)}, 31)
	}

	response := map[uint64]any{
		6:  user,
		7:  descriptor,
		8:  publicKey,
		10: credProtect,
		11: largeBlobKey,
	}
	if begin {
		total := uint(len(a.enumerationCredentials))
		if a.responseMutation == credentialManagementEnumerateCredentialsWrongTotal {
			total++
		}
		response[9] = total
	}
	if !begin && a.responseMutation == credentialManagementEnumerateCredentialsNextTotal {
		response[9] = uint(len(a.enumerationCredentials))
	}
	if a.responseMutation == credentialManagementEnumerateCredentialsMissingUser {
		delete(response, 6)
	}
	if a.responseMutation == credentialManagementEnumerateCredentialsUnexpectedPayment {
		response[12] = false
	}
	if a.responseMutation == credentialManagementEnumerateCredentialsExtraField {
		response[5] = uint(1)
	}

	return a.success(response)
}

func (a *credentialManagementEnumerateCredentialsAuthenticator) currentCredentials(
	rpIDHash []byte,
) []int {
	credentials := make([]int, 0, len(a.makeCredentialRequests))
	for index, request := range a.makeCredentialRequests {
		digest := sha256.Sum256([]byte(request.RP.ID))
		if bytes.Equal(rpIDHash, digest[:]) {
			credentials = append(credentials, index)
		}
	}

	return credentials
}

func credentialManagementEnumerateCredentialsPublicKey() cose.Key {
	curve := elliptic.P256().Params()

	return cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   curve.Gx.FillBytes(make([]byte, 32)),
		cose.EC2KeyParameterY:   curve.Gy.FillBytes(make([]byte, 32)),
	}
}

func (a *credentialManagementEnumerateCredentialsAuthenticator) reset() {
	a.enumerationCredentials = nil
	a.enumerationIndex = 0
	a.enumerationActive = false
	a.credentialManagementFixtureAuthenticator.reset()
}

func runCredentialManagementEnumerateCredentialsCase(
	t *testing.T,
	index int,
	configure func(*credentialManagementEnumerateCredentialsAuthenticator, *Config),
) (conformance.SuiteResult, *credentialManagementEnumerateCredentialsAuthenticator, []byte) {
	t.Helper()

	authenticator := newCredentialManagementEnumerateCredentialsAuthenticator(t)
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
	tests := credentialManagementEnumerateCredentialsTests(config)
	runner, err := conformance.NewRunner(authenticator)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:   "credential-management-enumerate-credentials-test",
		Name: "Credential management enumerate credentials test",
		Tests: []conformance.Test{
			tests[index],
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result, authenticator, suppliedPIN
}

func assertCredentialManagementEnumerateCredentialsPreflight(
	t *testing.T,
	result conformance.SuiteResult,
	authenticator *credentialManagementEnumerateCredentialsAuthenticator,
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

func credentialManagementEnumerateCredentialsHasReference(
	references []conformance.RequirementRef,
	id conformance.RequirementID,
) bool {
	return slices.ContainsFunc(references, func(reference conformance.RequirementRef) bool {
		return reference.ID == id
	})
}

var _ ctaptransport.CBOR = (*credentialManagementEnumerateCredentialsAuthenticator)(nil)
