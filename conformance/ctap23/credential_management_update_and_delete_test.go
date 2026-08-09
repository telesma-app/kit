package ctap23

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
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

func TestCredentialManagementUpdateAndDeleteDefinitions(t *testing.T) {
	tests := credentialManagementUpdateAndDeleteTests(Config{})
	if len(tests) != 2 {
		t.Fatalf("test count = %d, want 2", len(tests))
	}

	want := []struct {
		id      conformance.TestID
		marker  string
		section string
		refID   conformance.RequirementID
	}{
		{
			id:      TestIDCredentialManagementUpdateAndDeleteP1,
			marker:  "P-1",
			section: "6.8.6",
			refID:   credentialManagementUpdateUserInformationReference().ID,
		},
		{
			id:      TestIDCredentialManagementUpdateAndDeleteP2,
			marker:  "P-2",
			section: "6.8.5",
			refID:   credentialManagementDeleteCredentialReference().ID,
		},
	}
	for index, expected := range want {
		test := tests[index]
		if test.ID != expected.id || test.Source.Path != credentialManagementUpdateAndDeleteSourcePath ||
			test.Source.Case != expected.marker || !test.Destructive {
			t.Errorf("test[%d] = %#v", index, test)
		}
		if !credentialManagementUpdateAndDeleteHasReference(test.References, expected.refID) {
			t.Errorf("test %s missing reference %q", test.ID, expected.refID)
		}
		for _, id := range []conformance.RequirementID{
			credentialManagementUpdateAndDeleteFeatureReference().ID,
			clientPIN2KeyAgreementProtocolTwoReference().ID,
			clientPIN2NewPINPermissionsReference().ID,
			ctapMessageEncodingReference().ID,
		} {
			if !credentialManagementUpdateAndDeleteHasReference(test.References, id) {
				t.Errorf("test %s missing reference %q", test.ID, id)
			}
		}
	}

	update := credentialManagementUpdateUserInformationReference()
	if update.ID != "ctap-2.3-ps-20260226:6.8.6:update-user-information" ||
		update.Section != "6.8.6" || update.Clause != "update-user-information" ||
		update.URL != "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#updateUserInformation" ||
		update.Level != conformance.RequirementMust {
		t.Fatalf("update reference = %#v", update)
	}
	deleteReference := credentialManagementDeleteCredentialReference()
	if deleteReference.ID != "ctap-2.3-ps-20260226:6.8.5:delete-credential" ||
		deleteReference.Section != "6.8.5" || deleteReference.Clause != "delete-credential" ||
		deleteReference.URL != "https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#deleteCredential" ||
		deleteReference.Level != conformance.RequirementMust {
		t.Fatalf("delete reference = %#v", deleteReference)
	}
}

func TestCredentialManagementUpdateAndDeleteCasesUseExactIndependentFlows(t *testing.T) {
	tests := []struct {
		name             string
		index            int
		wantCommands     []protocol.CredentialManagementSubCommand
		wantPermissions  []protocol.Permission
		wantRPIDs        []string
		wantGetAssertion bool
	}{
		{
			name:  "P-1",
			index: 0,
			wantCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandUpdateUserInformation,
				protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionCredentialManagement,
				protocol.PermissionCredentialManagement,
			},
			wantRPIDs: []string{
				credentialManagementUpdateAndDeleteRP,
				"",
				"",
			},
		},
		{
			name:  "P-2",
			index: 1,
			wantCommands: []protocol.CredentialManagementSubCommand{
				protocol.CredentialManagementSubCommandDeleteCredential,
			},
			wantPermissions: []protocol.Permission{
				protocol.PermissionMakeCredential,
				protocol.PermissionCredentialManagement,
				protocol.PermissionGetAssertion,
			},
			wantRPIDs: []string{
				credentialManagementUpdateAndDeleteRP,
				"",
				credentialManagementUpdateAndDeleteRP,
			},
			wantGetAssertion: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, authenticator, suppliedPIN := runCredentialManagementUpdateAndDeleteCase(
				t,
				tt.index,
				nil,
			)
			assertCredentialManagementUpdateAndDeleteStatus(t, result, conformance.StatusPassed)
			assertCredentialManagementFixtureLifecycle(
				t,
				authenticator.credentialManagementFixtureAuthenticator,
				suppliedPIN,
			)
			if len(authenticator.makeCredentialRequests) != 1 ||
				authenticator.maxConcurrentCredentials != 1 ||
				!authenticator.makeCredentialWiresExact {
				t.Fatalf(
					"make requests/max/wire = %d/%d/%t",
					len(authenticator.makeCredentialRequests),
					authenticator.maxConcurrentCredentials,
					authenticator.makeCredentialWiresExact,
				)
			}
			if !slices.Equal(authenticator.subCommands, tt.wantCommands) ||
				!authenticator.credentialManagementWiresExact ||
				!slices.Equal(authenticator.permissionScopes, tt.wantPermissions) ||
				!slices.Equal(authenticator.permissionRPIDs, tt.wantRPIDs) ||
				!authenticator.permissionWiresExact {
				t.Fatalf(
					"commands/wire/permissions/rpids = %v/%t/%v/%v",
					authenticator.subCommands,
					authenticator.credentialManagementWiresExact,
					authenticator.permissionScopes,
					authenticator.permissionRPIDs,
				)
			}
			if authenticator.getAssertionCalls != boolInt(tt.wantGetAssertion) ||
				authenticator.getAssertionWiresExact != tt.wantGetAssertion {
				t.Fatalf(
					"GetAssertion calls/wire = %d/%t, want %d/%t",
					authenticator.getAssertionCalls,
					authenticator.getAssertionWiresExact,
					boolInt(tt.wantGetAssertion),
					tt.wantGetAssertion,
				)
			}
			if len(authenticator.currentCredentialIDs) != 0 || len(authenticator.issuedTokens) != 0 {
				t.Fatalf(
					"cleanup retained credentials/tokens = %d/%d",
					len(authenticator.currentCredentialIDs),
					len(authenticator.issuedTokens),
				)
			}
		})
	}
}

func TestCredentialManagementUpdateAndDeleteOptionalStoreState(t *testing.T) {
	for index, name := range []string{"P-1", "P-2"} {
		t.Run(name, func(t *testing.T) {
			result, _, _ := runCredentialManagementUpdateAndDeleteCase(
				t,
				index,
				func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
					authenticator.advertiseStoreState = false
				},
			)
			assertCredentialManagementUpdateAndDeleteStatus(t, result, conformance.StatusPassed)
		})
	}
}

func TestCredentialManagementUpdateAndDeletePreflightDoesNotMutate(t *testing.T) {
	for _, featureful := range []bool{false, true} {
		name := "optional"
		want := conformance.StatusSkipped
		if featureful {
			name = "featureful"
			want = conformance.StatusFailed
		}
		t.Run(name, func(t *testing.T) {
			result, authenticator, _ := runCredentialManagementUpdateAndDeleteCase(
				t,
				0,
				func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, config *Config) {
					authenticator.credentialManagementPresent = false
					config.Featureful = featureful
				},
			)
			assertCredentialManagementUpdateAndDeleteStatus(t, result, want)
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
		})
	}
}

func TestCredentialManagementUpdateAndDeleteFailuresAreClassified(t *testing.T) {
	tests := []struct {
		name      string
		index     int
		want      conformance.Status
		configure func(*credentialManagementUpdateAndDeleteAuthenticator, *Config)
	}{
		{
			name:  "update CTAP status",
			index: 0,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.credentialManagementStatus = ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID
			},
		},
		{
			name:  "update transport",
			index: 0,
			want:  conformance.StatusError,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.transportErrorCommand = protocol.AuthenticatorCredentialManagement
			},
		},
		{
			name:  "update nonempty success",
			index: 0,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.mutationResponseData = []byte{0xa0}
			},
		},
		{
			name:  "update null success",
			index: 0,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.mutationResponseData = []byte{0xf6}
			},
		},
		{
			name:  "update enumeration mismatch",
			index: 0,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.wrongEnumeratedUser = true
			},
		},
		{
			name:  "update reused store state IV",
			index: 0,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.reuseStoreStateIV = true
			},
		},
		{
			name:  "update unchanged store state ciphertext",
			index: 0,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.keepStoreStateCiphertext = true
			},
		},
		{
			name:  "update store state disappears",
			index: 0,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.dropStoreState = true
			},
		},
		{
			name:  "delete CTAP status",
			index: 1,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.credentialManagementStatus = ctaptransport.CTAP2_ERR_NO_CREDENTIALS
			},
		},
		{
			name:  "delete transport",
			index: 1,
			want:  conformance.StatusError,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.transportErrorCommand = protocol.AuthenticatorCredentialManagement
			},
		},
		{
			name:  "delete nonempty success",
			index: 1,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.mutationResponseData = []byte{0xa0}
			},
		},
		{
			name:  "delete null success",
			index: 1,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.mutationResponseData = []byte{0xf6}
			},
		},
		{
			name:  "deleted credential still asserts",
			index: 1,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.getAssertionStatus = ctaptransport.CTAP2_OK
			},
		},
		{
			name:  "GetAssertion transport",
			index: 1,
			want:  conformance.StatusError,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.getAssertionTransportError = true
			},
		},
		{
			name:  "delete reused store state IV",
			index: 1,
			want:  conformance.StatusFailed,
			configure: func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, _ *Config) {
				authenticator.reuseStoreStateIV = true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, authenticator, suppliedPIN := runCredentialManagementUpdateAndDeleteCase(
				t,
				tt.index,
				tt.configure,
			)
			assertCredentialManagementUpdateAndDeleteStatus(t, result, tt.want)
			assertCredentialManagementFixtureLifecycle(
				t,
				authenticator.credentialManagementFixtureAuthenticator,
				suppliedPIN,
			)
		})
	}
}

func TestCredentialManagementUpdateAndDeleteEnumerationDescriptorAndSecretSemantics(t *testing.T) {
	publicKey := credentialManagementEnumerateCredentialsPublicKey()
	record := credentialManagementCredential{
		Descriptor: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   []byte("updated-credential"),
		},
		PublicKey: publicKey,
	}
	updatedUser := credential.PublicKeyCredentialUserEntity{
		ID:          []byte("updated-user"),
		Name:        "updated@example.com",
		DisplayName: "Updated User",
	}

	for _, tt := range []struct {
		name       string
		descriptor credential.PublicKeyCredentialDescriptor
		user       credential.PublicKeyCredentialUserEntity
		wantError  bool
	}{
		{
			name: "optional transports",
			descriptor: credential.PublicKeyCredentialDescriptor{
				Type:       credential.PublicKeyCredentialTypePublicKey,
				ID:         slices.Clone(record.Descriptor.ID),
				Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB},
			},
			user: updatedUser,
		},
		{
			name: "wrong type",
			descriptor: credential.PublicKeyCredentialDescriptor{
				Type: "not-public-key",
				ID:   slices.Clone(record.Descriptor.ID),
			},
			user:      updatedUser,
			wantError: true,
		},
		{
			name: "wrong ID",
			descriptor: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte("wrong-credential"),
			},
			user:      updatedUser,
			wantError: true,
		},
		{
			name:       "wrong user",
			descriptor: record.Descriptor,
			user: credential.PublicKeyCredentialUserEntity{
				ID:          slices.Clone(updatedUser.ID),
				Name:        updatedUser.Name,
				DisplayName: "Wrong User",
			},
			wantError: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			largeBlobKey := bytes.Repeat([]byte{0xa5}, 32)
			largeBlobField := slices.Concat([]byte{0x58, 0x20}, bytes.Repeat([]byte{0xa5}, 32))
			result := credentialManagementResponse{
				Fields: map[uint64]cbor.RawMessage{
					6:  {0x00},
					7:  {0x00},
					8:  {0x00},
					9:  {0x00},
					11: largeBlobField,
				},
				Response: protocol.AuthenticatorCredentialManagementResponse{
					User:             tt.user,
					CredentialID:     tt.descriptor,
					PublicKey:        publicKey,
					TotalCredentials: 1,
					LargeBlobKey:     largeBlobKey,
				},
			}

			err := credentialManagementValidateUpdatedCredential(result, record, updatedUser)
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, wantError %t", err, tt.wantError)
			}
			assertCredentialManagementFixtureZeroed(t, largeBlobKey, "enumerated largeBlobKey")
			assertCredentialManagementFixtureZeroed(t, largeBlobField, "enumerated largeBlobKey field")
		})
	}
}

func TestCredentialManagementUpdateAndDeleteCleanupFailureIsVisible(t *testing.T) {
	result, authenticator, suppliedPIN := runCredentialManagementUpdateAndDeleteCase(
		t,
		0,
		func(authenticator *credentialManagementUpdateAndDeleteAuthenticator, config *Config) {
			calls := 0
			config.Resetter = func(context.Context, *client.Client) error {
				calls++
				if calls == 2 {
					return errors.New("cleanup reset failed")
				}
				authenticator.reset()

				return nil
			}
		},
	)
	assertCredentialManagementUpdateAndDeleteStatus(t, result, conformance.StatusError)
	assertCredentialManagementFixtureZeroed(t, suppliedPIN, "temporary PIN")
	if authenticator.powerCycles != 2 || authenticator.resets != 1 {
		t.Fatalf(
			"power cycles/resets = %d/%d, want 2/1",
			authenticator.powerCycles,
			authenticator.resets,
		)
	}
	steps := result.Tests[0].Steps
	if len(steps) == 0 || steps[len(steps)-1].ID != "credential-management-fixture.cleanup" ||
		steps[len(steps)-1].Status != conformance.StatusError {
		t.Fatalf("cleanup step = %#v", steps)
	}
}

type credentialManagementUpdateAndDeleteAuthenticator struct {
	*credentialManagementFixtureAuthenticator

	credentialManagementStatus     ctaptransport.StatusCode
	getAssertionStatus             ctaptransport.StatusCode
	advertiseStoreState            bool
	reuseStoreStateIV              bool
	keepStoreStateCiphertext       bool
	dropStoreState                 bool
	mutationResponseData           []byte
	wrongEnumeratedUser            bool
	getAssertionTransportError     bool
	credentialManagementWiresExact bool
	getAssertionWiresExact         bool
	getAssertionCalls              int
	subCommands                    []protocol.CredentialManagementSubCommand
	storeState                     []byte
	storedUser                     credential.PublicKeyCredentialUserEntity
	deleted                        bool
}

func newCredentialManagementUpdateAndDeleteAuthenticator(
	t *testing.T,
) *credentialManagementUpdateAndDeleteAuthenticator {
	t.Helper()

	return &credentialManagementUpdateAndDeleteAuthenticator{
		credentialManagementFixtureAuthenticator: newCredentialManagementFixtureAuthenticator(t),
		getAssertionStatus:                       ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
		advertiseStoreState:                      true,
		credentialManagementWiresExact:           true,
		storeState:                               credentialManagementUpdateAndDeleteStoreState(0x11, 0x22),
	}
}

func (a *credentialManagementUpdateAndDeleteAuthenticator) CBOR(
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
	if command == a.transportErrorCommand ||
		(command == protocol.AuthenticatorGetAssertion && a.getAssertionTransportError) {
		return ctaptransport.CBORResponse{}, errors.New("device disconnected")
	}

	var response ctaptransport.CBORResponse
	switch command {
	case protocol.AuthenticatorGetInfo:
		response = a.getInfoResponse()
		if a.advertiseStoreState {
			var fields map[uint64]cbor.RawMessage
			if err := getInfoDecMode.Unmarshal(response.Data, &fields); err != nil {
				a.t.Fatal(err)
			}
			encoded, err := ctap2EncMode.Marshal(a.storeState)
			if err != nil {
				a.t.Fatal(err)
			}
			fields[30] = encoded
			response.Data, err = ctap2EncMode.Marshal(fields)
			if err != nil {
				a.t.Fatal(err)
			}
		}
	case protocol.AuthenticatorCredentialManagement:
		response = a.credentialManagementResponse(request[1:])
	case protocol.AuthenticatorGetAssertion:
		response = a.deletedCredentialGetAssertionResponse(request[1:])
	default:
		return a.credentialManagementFixtureAuthenticator.CBOR(ctx, request)
	}

	return ctaptransport.ValidateCBORResponse(command, response)
}

func (a *credentialManagementUpdateAndDeleteAuthenticator) credentialManagementResponse(
	body []byte,
) ctaptransport.CBORResponse {
	if a.credentialManagementStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.credentialManagementStatus}
	}

	var request protocol.AuthenticatorCredentialManagementRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		a.t.Fatal(err)
	}
	canonical, err := ctap2EncMode.Marshal(request)
	if err != nil {
		a.t.Fatal(err)
	}
	paramsCanonical, err := ctap2EncMode.Marshal(request.SubCommandParams)
	if err != nil {
		a.t.Fatal(err)
	}
	var params map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(fields[2], &params); err != nil {
		a.t.Fatal(err)
	}

	token := a.issuedTokens[protocol.PermissionCredentialManagement]
	authenticatedData := append([]byte{byte(request.SubCommand)}, fields[2]...)
	wantAuth := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		authenticatedData,
	)
	defer clear(wantAuth)
	exact := bytes.Equal(body, canonical) &&
		len(fields) == 4 && fields[1] != nil && fields[2] != nil &&
		fields[3] != nil && fields[4] != nil &&
		bytes.Equal(fields[2], paramsCanonical) &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(request.PinUvAuthParam, wantAuth)

	a.subCommands = append(a.subCommands, request.SubCommand)
	switch request.SubCommand {
	case protocol.CredentialManagementSubCommandUpdateUserInformation:
		exact = exact && len(params) == 2 && params[1] == nil &&
			params[2] != nil && params[3] != nil &&
			a.matchesCurrentDescriptor(request.SubCommandParams.CredentialID) &&
			len(a.makeCredentialRequests) == 1 &&
			bytes.Equal(request.SubCommandParams.User.ID, a.makeCredentialRequests[0].User.ID) &&
			request.SubCommandParams.User.Name ==
				"updated-user@update-and-delete.ctap23-conformance.example" &&
			request.SubCommandParams.User.DisplayName == "Updated credential management user"
		a.storedUser = request.SubCommandParams.User
		a.changeStoreState()

		return a.mutationSuccess(exact)
	case protocol.CredentialManagementSubCommandDeleteCredential:
		exact = exact && len(params) == 1 && params[1] == nil &&
			params[2] != nil && params[3] == nil &&
			a.matchesCurrentDescriptor(request.SubCommandParams.CredentialID)
		a.deleted = true
		a.changeStoreState()

		return a.mutationSuccess(exact)
	case protocol.CredentialManagementSubCommandEnumerateCredentialsBegin:
		rpIDHash := sha256.Sum256([]byte(credentialManagementUpdateAndDeleteRP))
		exact = exact && len(params) == 1 && params[1] != nil &&
			params[2] == nil && params[3] == nil &&
			bytes.Equal(request.SubCommandParams.RPIDHash, rpIDHash[:])
		a.credentialManagementWiresExact = a.credentialManagementWiresExact && exact
		if !exact {
			a.t.Fatalf("credential management request = %#v, fields = %#v", request, fields)
		}

		user := a.storedUser
		if a.wrongEnumeratedUser {
			user.DisplayName = "Wrong user"
		}
		credentialID := a.currentCredentialIDs[0]
		authData := getAssertionFixtureMakeCredentialAuthData(a.t, credentialID)
		parsed, err := protocol.ParseMakeCredentialAuthData(authData)
		if err != nil {
			a.t.Fatal(err)
		}

		return a.success(map[uint64]any{
			6: user,
			7: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   credentialID,
			},
			8: parsed.AttestedCredentialData.CredentialPublicKey,
			9: uint(1),
		})
	default:
		a.t.Fatalf("unexpected credential-management subcommand %#x", request.SubCommand)

		return ctaptransport.CBORResponse{}
	}
}

func (a *credentialManagementUpdateAndDeleteAuthenticator) mutationSuccess(
	exact bool,
) ctaptransport.CBORResponse {
	a.credentialManagementWiresExact = a.credentialManagementWiresExact && exact
	if !exact {
		a.t.Fatal("credential-management mutation request was not exact")
	}
	if len(a.mutationResponseData) != 0 {
		return ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       slices.Clone(a.mutationResponseData),
		}
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK}
}

func (a *credentialManagementUpdateAndDeleteAuthenticator) matchesCurrentDescriptor(
	descriptor credential.PublicKeyCredentialDescriptor,
) bool {
	return len(a.currentCredentialIDs) == 1 &&
		descriptor.Type == credential.PublicKeyCredentialTypePublicKey &&
		bytes.Equal(descriptor.ID, a.currentCredentialIDs[0])
}

func (a *credentialManagementUpdateAndDeleteAuthenticator) changeStoreState() {
	switch {
	case a.dropStoreState:
		a.advertiseStoreState = false
	case a.reuseStoreStateIV:
		a.storeState = credentialManagementUpdateAndDeleteStoreState(0x11, 0x44)
	case a.keepStoreStateCiphertext:
		a.storeState = credentialManagementUpdateAndDeleteStoreState(0x33, 0x22)
	default:
		a.storeState = credentialManagementUpdateAndDeleteStoreState(0x33, 0x44)
	}
}

func (a *credentialManagementUpdateAndDeleteAuthenticator) deletedCredentialGetAssertionResponse(
	body []byte,
) ctaptransport.CBORResponse {
	a.getAssertionCalls++
	var request protocol.AuthenticatorGetAssertionRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		a.t.Fatal(err)
	}
	canonical, err := ctap2EncMode.Marshal(request)
	if err != nil {
		a.t.Fatal(err)
	}
	token := a.issuedTokens[protocol.PermissionGetAssertion]
	wantAuth := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		request.ClientDataHash,
	)
	defer clear(wantAuth)
	wantClientDataHash := credentialManagementFixtureBytes("post-delete-get-assertion", 0)
	a.getAssertionWiresExact = a.deleted &&
		bytes.Equal(body, canonical) &&
		len(fields) == 5 && fields[1] != nil && fields[2] != nil && fields[3] != nil &&
		fields[6] != nil && fields[7] != nil &&
		request.RPID == credentialManagementUpdateAndDeleteRP &&
		bytes.Equal(request.ClientDataHash, wantClientDataHash) &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(request.PinUvAuthParam, wantAuth) &&
		len(request.AllowList) == 1 &&
		a.matchesCurrentDescriptor(request.AllowList[0])
	if !a.getAssertionWiresExact {
		a.t.Fatalf("GetAssertion request = %#v, fields = %#v", request, fields)
	}
	if a.getAssertionStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.getAssertionStatus}
	}

	authData := getAssertionFixtureAuthData()
	authData[32] |= byte(protocol.AuthDataFlagUserVerified)

	return a.success(map[uint64]any{
		1: request.AllowList[0],
		2: authData,
		3: []byte{0x30, 0x00},
	})
}

func (a *credentialManagementUpdateAndDeleteAuthenticator) reset() {
	a.deleted = false
	a.storedUser = credential.PublicKeyCredentialUserEntity{}
	a.storeState = credentialManagementUpdateAndDeleteStoreState(0x11, 0x22)
	a.credentialManagementFixtureAuthenticator.reset()
}

func credentialManagementUpdateAndDeleteStoreState(iv, ciphertext byte) []byte {
	return append(bytes.Repeat([]byte{iv}, 16), bytes.Repeat([]byte{ciphertext}, 16)...)
}

func runCredentialManagementUpdateAndDeleteCase(
	t *testing.T,
	index int,
	configure func(*credentialManagementUpdateAndDeleteAuthenticator, *Config),
) (conformance.SuiteResult, *credentialManagementUpdateAndDeleteAuthenticator, []byte) {
	t.Helper()

	authenticator := newCredentialManagementUpdateAndDeleteAuthenticator(t)
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
	tests := credentialManagementUpdateAndDeleteTests(config)
	runner, err := conformance.NewRunner(authenticator)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:    "credential-management-update-and-delete-test",
		Name:  "Credential management update and delete test",
		Tests: []conformance.Test{tests[index]},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result, authenticator, suppliedPIN
}

func assertCredentialManagementUpdateAndDeleteStatus(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func credentialManagementUpdateAndDeleteHasReference(
	references []conformance.RequirementRef,
	id conformance.RequirementID,
) bool {
	return slices.ContainsFunc(references, func(reference conformance.RequirementRef) bool {
		return reference.ID == id
	})
}

func boolInt(value bool) int {
	if value {
		return 1
	}

	return 0
}

var _ ctaptransport.CBOR = (*credentialManagementUpdateAndDeleteAuthenticator)(nil)

func TestCredentialManagementUpdateAndDeleteStoreStateHelper(t *testing.T) {
	state := credentialManagementUpdateAndDeleteStoreState(0x11, 0x22)
	if len(state) != 32 ||
		!reflect.DeepEqual(state[:16], bytes.Repeat([]byte{0x11}, 16)) ||
		!reflect.DeepEqual(state[16:], bytes.Repeat([]byte{0x22}, 16)) {
		t.Fatalf("state = %x", state)
	}
}
