package ctapkit

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/model"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
)

func TestCredentialInventoryReadsFreshStateAndReusesToken(t *testing.T) {
	events := &recordingEventSink{}
	a := &refreshCredentialAuthenticator{revision: 1}
	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	first := runCredentialList(t, session)
	second := runCredentialList(t, session)
	if got := credentialIDFromInventory(t, first); got != "01" {
		t.Fatalf("first credential ID = %q, want 01", got)
	}

	if got := credentialIDFromInventory(t, second); got != "01" {
		t.Fatalf("cached credential ID = %q, want 01", got)
	}

	a.revision = 2
	refreshed := runCredentialList(t, session)
	if got := credentialIDFromInventory(t, refreshed); got != "02" {
		t.Fatalf("refreshed credential ID = %q, want 02", got)
	}

	if got := a.metadataCalls.Load(); got != 3 {
		t.Fatalf("metadata calls = %d, want 3", got)
	}

	if got := a.tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}

	assertCredentialProgress(t, events.Events(), []credentialProgress{
		{model.OperationStageEnumeratingRPs, 1, 1},
		{model.OperationStageEnumeratingCredentials, 1, 1},
		{model.OperationStageEnumeratingRPs, 1, 1},
		{model.OperationStageEnumeratingCredentials, 1, 1},
		{model.OperationStageEnumeratingRPs, 1, 1},
		{model.OperationStageEnumeratingCredentials, 1, 1},
	})
}

func TestCredentialInventoryReturnsEmptyReportWithoutEnumeratingRPs(t *testing.T) {
	a := &emptyCredentialAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output := runCredentialList(t, session)
	if output.Summary.ExistingResidentCredentialsCount != 0 {
		t.Fatalf("existing credential count = %d, want 0", output.Summary.ExistingResidentCredentialsCount)
	}

	if output.Summary.TotalCredentials != 0 || len(output.Groups) != 0 {
		t.Fatalf("empty inventory = %#v, want no groups or credentials", output)
	}

	if got := a.rpEnumerations.Load(); got != 0 {
		t.Fatalf("RP enumerations = %d, want 0", got)
	}
}

func TestCredentialInventoryRejectedToken(t *testing.T) {
	t.Run("reacquires once", func(t *testing.T) {
		a := &rejectedCredentialTokenAuthenticator{}
		session := openContractAuthenticator(t, nil, a)
		defer func() { _ = session.Close() }()

		output := runCredentialList(t, session)
		if output.Summary.ExistingResidentCredentialsCount != 0 {
			t.Fatalf("existing credential count = %d, want 0", output.Summary.ExistingResidentCredentialsCount)
		}

		assertRejectedCredentialTokens(t, a)
	})

	t.Run("stops after replacement is rejected", func(t *testing.T) {
		a := &rejectedCredentialTokenAuthenticator{rejectEveryToken: true}
		session := openContractAuthenticator(t, nil, a)
		defer func() { _ = session.Close() }()

		output, err := session.ListCredentials(
			context.Background(),
			session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
		)
		if !failure.IsCode(err, failure.CodePINUVAuthInvalid) {
			t.Fatalf("ListCredentials error = %v, want %s", err, failure.CodePINUVAuthInvalid)
		}
		requireZero(t, output)

		assertRejectedCredentialTokens(t, a)
	})
}

func TestCredentialMutationUsesInventoryFromSuccessfulRefresh(t *testing.T) {
	a := &refreshCredentialAuthenticator{revision: 1}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	_ = runCredentialList(t, session)
	a.revision = 2
	refreshed := runCredentialList(t, session)
	if got := credentialIDFromInventory(t, refreshed); got != "02" {
		t.Fatalf("refreshed credential ID = %q, want 02", got)
	}

	if _, err := session.DeleteCredential(context.Background(), appcredentials.DeleteOperation{
		CredentialIDHex: "02",
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	if len(a.deletedCredentialIDs) != 1 || !bytes.Equal(a.deletedCredentialIDs[0], []byte{2}) {
		t.Fatalf("deleted credential IDs = %x, want [02]", a.deletedCredentialIDs)
	}
}

func TestCredentialInventoryProgressEventsIncludeCounts(t *testing.T) {
	events := &recordingEventSink{}
	session := openContractAuthenticator(t, events, &progressCredentialAuthenticator{})
	defer func() { _ = session.Close() }()

	if _, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("Run: %v", err)
	}

	assertCredentialProgress(t, events.Events(), []credentialProgress{
		{model.OperationStageEnumeratingRPs, 1, 2},
		{model.OperationStageEnumeratingRPs, 2, 2},
		{model.OperationStageEnumeratingCredentials, 1, 3},
		{model.OperationStageEnumeratingCredentials, 2, 3},
		{model.OperationStageEnumeratingCredentials, 3, 3},
	})
}

func TestCredentialInventoryWorkflowReturnsZeroAfterMidstreamFailureAndWipesStagedKey(t *testing.T) {
	cause := errors.New("credential enumeration failed")
	stagedKey := bytes.Repeat([]byte{0x5a}, 32)
	a := &progressCredentialAuthenticator{
		credentialErr:      cause,
		stagedLargeBlobKey: stagedKey,
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if !errors.Is(err, cause) {
		t.Fatalf("ListCredentials error = %v, want %v", err, cause)
	}
	requireZero(t, output)

	if !bytes.Equal(stagedKey, make([]byte, len(stagedKey))) {
		t.Fatalf("staged large-blob key = %x, want wiped buffer", stagedKey)
	}
}

func TestCredentialInventoryRejectsInvalidLargeBlobKey(t *testing.T) {
	stagedKey := []byte{0x5a}
	a := &progressCredentialAuthenticator{stagedLargeBlobKey: stagedKey}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.ListCredentials(
		t.Context(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	requireFailureCode(t, err, failure.CodeLargeBlobKeyInvalid)
	requireZero(t, output)

	if stagedKey[0] != 0 {
		t.Fatalf("staged large-blob key = %x, want wiped buffer", stagedKey)
	}
}

func TestCredentialInventoryRejectsDuplicateLargeBlobKeyBinding(t *testing.T) {
	firstKey := bytes.Repeat([]byte{0x11}, 32)
	secondKey := bytes.Repeat([]byte{0x22}, 32)
	a := &progressCredentialAuthenticator{
		stagedLargeBlobKey:  firstKey,
		secondLargeBlobKey:  secondKey,
		duplicateKeyBinding: true,
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.ListCredentials(
		t.Context(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	requireFailureCode(t, err, failure.CodeCTAPSpecViolation)
	requireZero(t, output)

	if !bytes.Equal(firstKey, make([]byte, len(firstKey))) ||
		!bytes.Equal(secondKey, make([]byte, len(secondKey))) {
		t.Fatal("duplicate large-blob key buffers were not wiped")
	}
}

func TestCredentialMutationCallerInputIsValidatedBeforeInventory(t *testing.T) {
	session := openContractAuthenticator(t, nil, nil)
	defer func() { _ = session.Close() }()

	_, err := session.DeleteCredential(t.Context(), appcredentials.DeleteOperation{CredentialIDHex: "not-hex"})
	requireFailureCode(t, err, failure.CodeCTAPParameterInvalid)

	operation := credentialUpdate(true)
	operation.Target.Record.CredentialIDHex = "not-hex"
	_, err = session.UpdateCredentialUser(t.Context(), operation)
	requireFailureCode(t, err, failure.CodeCTAPParameterInvalid)
}

func TestCredentialMutationsUseUnscopedGrant(t *testing.T) {
	tests := []struct {
		name              string
		run               func(*testing.T, *contractAuthenticatorHandle) error
		used              func(*credentialMutationTokenAuthenticator) []string
		wantMetadataCalls int32
	}{
		{
			name: "delete reuses inventory grant",
			run: func(t *testing.T, session *contractAuthenticatorHandle) error {
				_, err := session.DeleteCredential(context.Background(), appcredentials.DeleteOperation{
					CredentialIDHex: "c05e",
				}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
				return err
			},
			used:              func(a *credentialMutationTokenAuthenticator) []string { return a.deleteTokens },
			wantMetadataCalls: 1,
		},
		{
			name: "update target needs no inventory",
			run: func(t *testing.T, session *contractAuthenticatorHandle) error {
				_, err := session.UpdateCredentialUser(context.Background(), credentialUpdate(false),
					session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
				return err
			},
			used:              func(a *credentialMutationTokenAuthenticator) []string { return a.updateTokens },
			wantMetadataCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &credentialMutationTokenAuthenticator{}
			session := openContractAuthenticator(t, nil, a)
			defer func() { _ = session.Close() }()

			if err := tt.run(t, session); err != nil {
				t.Fatalf("mutation: %v", err)
			}

			assertCredentialMutationToken(t, a.tokenRPIDs, tt.used(a))
			if got := a.metadataCalls.Load(); got != tt.wantMetadataCalls {
				t.Fatalf("metadata calls = %d, want %d", got, tt.wantMetadataCalls)
			}
		})
	}
}

func TestCredentialMutationErrorDoesNotRefreshGetInfo(t *testing.T) {
	mutationErr := errors.New("credential mutation failed")
	a := &failingCredentialMutationAuthenticator{mutationErr: mutationErr}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	_, err := session.UpdateCredentialUser(
		context.Background(),
		credentialUpdate(false),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if !errors.Is(err, mutationErr) {
		t.Fatalf("UpdateCredentialUser error = %v, want mutation error", err)
	}
	if got := a.freshInfoCalls.Load(); got != 0 {
		t.Fatalf("fresh GetInfo calls = %d, want 0", got)
	}
}

func TestCredentialUpdateUserDryRunUsesTargetWithoutAuthenticatorCommands(t *testing.T) {
	a := &credentialMutationTokenAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	result, err := session.UpdateCredentialUser(context.Background(), credentialUpdate(true), session.operationOptions()...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Preview.Proposed.Name != "updated" {
		t.Fatalf("proposed name = %q, want updated", result.Preview.Proposed.Name)
	}

	if got := a.metadataCalls.Load(); got != 0 {
		t.Fatalf("metadata calls = %d, want 0", got)
	}

	if len(a.tokenRPIDs) != 0 || len(a.updateTokens) != 0 {
		t.Fatalf("dry-run token/update calls = %q/%q, want none", a.tokenRPIDs, a.updateTokens)
	}
}

func credentialUpdate(dryRun bool) appcredentials.UpdateUserOperation {
	return appcredentials.UpdateUserOperation{
		Target:       credentialMutationTarget(),
		Name:         "updated",
		NameProvided: true,
		DryRun:       dryRun,
	}
}

func credentialMutationTarget() appcredentials.CredentialTarget {
	return appcredentials.CredentialTarget{
		Record: appcredentials.CredentialRecord{
			CredentialIDHex: "c05e",
			CredentialType:  string(credential.PublicKeyCredentialTypePublicKey),
		},
		RP:   appcredentials.RelyingParty{ID: "id.example", Name: "Example"},
		User: appcredentials.UserIdentity{UserIDHex: "75736572", Name: "savely", DisplayName: "Savely"},
	}
}

type progressCredentialAuthenticator struct {
	contractAuthenticator
	credentialErr       error
	stagedLargeBlobKey  []byte
	secondLargeBlobKey  []byte
	duplicateKeyBinding bool
}

type emptyCredentialAuthenticator struct {
	contractAuthenticator
	contractCredentialManager
	rpEnumerations atomic.Int32
}

type rejectedCredentialTokenAuthenticator struct {
	contractAuthenticator
	contractCredentialManager
	rejectEveryToken bool
	tokenCalls       atomic.Int32
	metadataCalls    atomic.Int32
	metadataTokens   [][]byte
}

func credentialManagementInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement: true,
			protocol.OptionPinUvAuthToken:       true,
			protocol.OptionUserVerification:     true,
		},
	}
}

func credentialMetadata(existing, remaining uint) protocol.AuthenticatorCredentialManagementResponse {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             &existing,
		MaxPossibleRemainingResidentCredentialsCount: &remaining,
	}
}

func (a *rejectedCredentialTokenAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return credentialManagementInfo(), true
}

func (a *rejectedCredentialTokenAuthenticator) GetPinUvAuthTokenUsingUV(
	context.Context,
	protocol.Permission,
	string,
) ([]byte, error) {
	return []byte{byte(a.tokenCalls.Add(1))}, nil
}

func (a *rejectedCredentialTokenAuthenticator) GetCredsMetadata(
	_ context.Context,
	token []byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	a.metadataCalls.Add(1)
	a.metadataTokens = append(a.metadataTokens, slices.Clone(token))

	if a.rejectEveryToken || bytes.Equal(token, []byte{1}) {
		return protocol.AuthenticatorCredentialManagementResponse{}, &ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorCredentialManagement,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID,
		}
	}

	return credentialMetadata(0, 25), nil
}

func assertRejectedCredentialTokens(t *testing.T, a *rejectedCredentialTokenAuthenticator) {
	t.Helper()

	if got := a.tokenCalls.Load(); got != 2 {
		t.Fatalf("token calls = %d, want 2", got)
	}
	if got := a.metadataCalls.Load(); got != 2 {
		t.Fatalf("metadata calls = %d, want 2", got)
	}
	if len(a.metadataTokens) != 2 || !bytes.Equal(a.metadataTokens[0], []byte{1}) || !bytes.Equal(a.metadataTokens[1], []byte{2}) {
		t.Fatalf("metadata tokens = %#v, want [[1] [2]]", a.metadataTokens)
	}
}

func (a *emptyCredentialAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return credentialManagementInfo(), true
}

func (a *emptyCredentialAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *emptyCredentialAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return credentialMetadata(0, 25), nil
}

func (a *emptyCredentialAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	a.rpEnumerations.Add(1)
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{}, &ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorCredentialManagement,
			StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
		})
	}
}

type refreshCredentialAuthenticator struct {
	contractAuthenticator
	contractCredentialManager
	revision             byte
	metadataErr          error
	cancelEnumeration    context.CancelFunc
	deletedCredentialIDs [][]byte
	tokenCalls           atomic.Int32
	metadataCalls        atomic.Int32
}

func (a *refreshCredentialAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return credentialManagementInfo(), true
}

func (a *refreshCredentialAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	a.tokenCalls.Add(1)

	return []byte("token"), nil
}

func (a *refreshCredentialAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	a.metadataCalls.Add(1)

	if a.metadataErr != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, a.metadataErr
	}

	return credentialMetadata(1, 10), nil
}

func (a *refreshCredentialAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		if a.cancelEnumeration != nil {
			a.cancelEnumeration()
		}
		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *refreshCredentialAuthenticator) DeleteCredential(
	_ context.Context,
	_ []byte,
	descriptor credential.PublicKeyCredentialDescriptor,
) error {
	a.deletedCredentialIDs = append(a.deletedCredentialIDs, slices.Clone(descriptor.ID))
	return nil
}

func (a *refreshCredentialAuthenticator) EnumerateCredentials(
	context.Context,
	[]byte,
	[]byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{
			User: credential.PublicKeyCredentialUserEntity{
				ID:          []byte("user"),
				Name:        "user",
				DisplayName: "User",
			},
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte{a.revision},
			},
			TotalCredentials: 1,
		}, nil)
	}
}

func runCredentialList(t *testing.T, session *contractAuthenticatorHandle) appcredentials.InventoryReport {
	t.Helper()

	var opts []OperationOption
	if session.events != nil {
		opts = append(opts, WithEventSink(session.events))
	}
	opts = append(opts, WithInteractionHandler(userVerificationHandler(t)))

	output, err := session.ListCredentials(context.Background(), opts...)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}

	return output
}

func credentialIDFromInventory(t *testing.T, output appcredentials.InventoryReport) string {
	t.Helper()

	if len(output.Groups) != 1 || len(output.Groups[0].Credentials) != 1 {
		t.Fatalf("credential inventory = %#v, want one credential", output)
	}

	return output.Groups[0].Credentials[0].CredentialIDHex
}

func (a *progressCredentialAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return credentialManagementInfo(), true
}

func (a *progressCredentialAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *progressCredentialAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return credentialMetadata(3, 10), nil
}

func (a *progressCredentialAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		if !yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "alpha.example", Name: "Alpha"},
			RPIDHash: []byte("alpha-rp-hash"),
			TotalRPs: 2,
		}, nil) {
			return
		}

		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "beta.example", Name: "Beta"},
			RPIDHash: []byte("beta-rp-hash"),
		}, nil)
	}
}

func (a *progressCredentialAuthenticator) EnumerateCredentials(
	_ context.Context,
	_ []byte,
	rpIDHash []byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		if bytes.Equal(rpIDHash, []byte("alpha-rp-hash")) {
			first := progressCredentialResponse("alpha-user-1", []byte{0xa1}, 2)
			first.LargeBlobKey = a.stagedLargeBlobKey
			if !yield(first, nil) {
				return
			}

			if a.credentialErr != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, a.credentialErr)

				return
			}

			secondCredentialID := []byte{0xa2}
			if a.duplicateKeyBinding {
				secondCredentialID = []byte{0xa1}
			}
			second := progressCredentialResponse("alpha-user-2", secondCredentialID, 0)
			second.LargeBlobKey = a.secondLargeBlobKey
			yield(second, nil)

			return
		}

		yield(progressCredentialResponse("beta-user-1", []byte{0xb1}, 1), nil)
	}
}

func progressCredentialResponse(
	userName string,
	credentialID []byte,
	totalCredentials uint,
) protocol.AuthenticatorCredentialManagementResponse {
	return protocol.AuthenticatorCredentialManagementResponse{
		User: credential.PublicKeyCredentialUserEntity{
			ID:          []byte(userName),
			Name:        userName,
			DisplayName: userName,
		},
		CredentialID: credential.PublicKeyCredentialDescriptor{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   credentialID,
		},
		TotalCredentials: totalCredentials,
	}
}

type credentialMutationTokenAuthenticator struct {
	contractAuthenticator
	metadataCalls atomic.Int32
	tokenRPIDs    []string
	deleteTokens  []string
	updateTokens  []string
}

type failingCredentialMutationAuthenticator struct {
	credentialMutationTokenAuthenticator
	mutationErr    error
	cacheInvalid   bool
	freshInfoCalls atomic.Int32
}

func (a *failingCredentialMutationAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return credentialManagementInfo(), !a.cacheInvalid
}

func (a *failingCredentialMutationAuthenticator) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	a.freshInfoCalls.Add(1)

	return protocol.AuthenticatorGetInfoResponse{}, errors.New("unexpected GetInfo refresh")
}

func (a *failingCredentialMutationAuthenticator) UpdateUserInformation(
	context.Context,
	[]byte,
	credential.PublicKeyCredentialDescriptor,
	credential.PublicKeyCredentialUserEntity,
) error {
	a.cacheInvalid = true

	return a.mutationErr
}

func (a *credentialMutationTokenAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return credentialManagementInfo(), true
}

func (a *credentialMutationTokenAuthenticator) GetPinUvAuthTokenUsingUV(
	_ context.Context,
	_ protocol.Permission,
	rpID string,
) ([]byte, error) {
	a.tokenRPIDs = append(a.tokenRPIDs, rpID)

	return []byte("token:" + rpID), nil
}

func (a *credentialMutationTokenAuthenticator) GetCredsMetadata(
	context.Context,
	[]byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	a.metadataCalls.Add(1)

	return credentialMetadata(1, 8), nil
}

func (a *credentialMutationTokenAuthenticator) EnumerateRPs(
	context.Context,
	[]byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "id.example", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *credentialMutationTokenAuthenticator) EnumerateCredentials(
	context.Context,
	[]byte,
	[]byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{
			User: credential.PublicKeyCredentialUserEntity{
				ID:          []byte("user"),
				Name:        "savely",
				DisplayName: "Savely",
			},
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte{0xc0, 0x5e},
			},
			TotalCredentials: 1,
		}, nil)
	}
}

func (a *credentialMutationTokenAuthenticator) DeleteCredential(
	_ context.Context,
	token []byte,
	_ credential.PublicKeyCredentialDescriptor,
) error {
	a.deleteTokens = append(a.deleteTokens, string(token))

	return nil
}

func (a *credentialMutationTokenAuthenticator) UpdateUserInformation(
	_ context.Context,
	token []byte,
	_ credential.PublicKeyCredentialDescriptor,
	_ credential.PublicKeyCredentialUserEntity,
) error {
	a.updateTokens = append(a.updateTokens, string(token))

	return nil
}

func assertCredentialMutationToken(
	t *testing.T,
	gotRPIDs []string,
	gotTokens []string,
) {
	t.Helper()

	if !slices.Equal(gotRPIDs, []string{""}) {
		t.Fatalf("token rpIds = %q, want [\"\"]", gotRPIDs)
	}

	if !slices.Equal(gotTokens, []string{"token:"}) {
		t.Fatalf("mutation tokens = %q, want [\"token:\"]", gotTokens)
	}
}

type credentialProgress struct {
	stage            model.OperationStage
	completed, total uint64
}

func assertCredentialProgress(t *testing.T, events []model.OperationEvent, want []credentialProgress) {
	t.Helper()

	var got []credentialProgress
	for _, event := range events {
		if event.Stage != model.OperationStageEnumeratingRPs &&
			event.Stage != model.OperationStageEnumeratingCredentials {
			continue
		}

		if event.Completed == nil || event.Total == nil {
			t.Fatalf("%s event omitted progress counts: %#v", event.Stage, event)
		}

		got = append(got, credentialProgress{event.Stage, *event.Completed, *event.Total})
	}

	if !slices.Equal(got, want) {
		t.Fatalf("credential progress events = %v, want %v", got, want)
	}
}
