package ctapkit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"iter"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
)

func TestCredentialStoreStateUsesStandalonePCMRToken(t *testing.T) {
	a := newStoreStateAuthenticator()
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	if _, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	a.readOnly.Store(true)

	result, err := session.CredentialStoreState(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("CredentialStoreState: %v", err)
	}

	if result.AuthenticatorIdentifierHex != "000102030405060708090a0b0c0d0e0f" ||
		result.CredentialStoreStateHex != "101112131415161718191a1b1c1d1e1f" {
		t.Fatalf("store state = %#v", result)
	}
	wantPermissions := []protocol.Permission{
		protocol.PermissionCredentialManagement,
		protocol.PermissionPersistentCredentialManagementReadOnly,
	}

	if !slices.Equal(a.permissions, wantPermissions) {
		t.Fatalf("token permissions = %v, want %v", a.permissions, wantPermissions)
	}

	if a.stateTokenPermission != protocol.PermissionPersistentCredentialManagementReadOnly {
		t.Fatalf("state token permission = %s, want standalone pcmr", a.stateTokenPermission)
	}
	if a.freshInfoCalls.Load() != 1 {
		t.Fatalf("fresh GetInfo calls = %d, want 1", a.freshInfoCalls.Load())
	}
}

func TestCredentialInventoryRejectsMissingMandatoryMetadataTotals(t *testing.T) {
	a := &missingTotalsAuthenticator{stage: "metadata"}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	_, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if !failure.IsCode(err, failure.CodeCTAPSpecViolation) {
		t.Fatalf("ListCredentials error = %v, want spec violation", err)
	}
}

func TestEnableLongTouchForResetDryRunAndRefreshFailureCacheEffects(t *testing.T) {
	refreshErr := errors.New("refresh failed after config command")
	a := &longTouchAuthenticator{enableErr: refreshErr}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	if _, err := session.ConfigStatus(context.Background(), session.operationOptions()...); err != nil {
		t.Fatalf("prime ConfigStatus: %v", err)
	}
	dryRun, err := session.EnableLongTouchForReset(
		context.Background(),
		appconfig.EnableLongTouchForResetOperation{DryRun: true},
		session.operationOptions()...,
	)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}

	if dryRun.Result != nil || a.enableCalls.Load() != 0 {
		t.Fatalf("dry run result/calls = %#v/%d", dryRun, a.enableCalls.Load())
	}

	result, err := session.EnableLongTouchForReset(
		context.Background(),
		appconfig.EnableLongTouchForResetOperation{},
		session.operationOptions()...,
	)
	if !failure.IsCode(err, failure.CodeInternalError) || !errors.Is(err, refreshErr) {
		t.Fatalf("execute error = %v, want refresh failure", err)
	}

	requireZero(t, result)
	if a.enableCalls.Load() != 1 {
		t.Fatalf("execute result/calls = %#v/%d", result, a.enableCalls.Load())
	}

	status, err := session.ConfigStatus(context.Background(), session.operationOptions()...)
	if err != nil {
		t.Fatalf("ConfigStatus after refresh failure: %v", err)
	}

	if got := status.ResetHints.LongTouchForReset; got != "configured" {
		t.Fatalf("long touch status = %s, want configured", got)
	}

	if a.infoCalls.Load() != 4 {
		t.Fatalf("GetInfo calls = %d, want cache refresh after mutation error", a.infoCalls.Load())
	}
}

func TestEnableLongTouchForResetSuccess(t *testing.T) {
	a := &longTouchAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	result, err := session.EnableLongTouchForReset(
		context.Background(),
		appconfig.EnableLongTouchForResetOperation{},
		session.operationOptions()...,
	)
	if err != nil {
		t.Fatalf("EnableLongTouchForReset: %v", err)
	}

	if result.Result == nil || result.Result.State != "configured" || a.enableCalls.Load() != 1 {
		t.Fatalf("output/calls = %#v/%d", result, a.enableCalls.Load())
	}
}

func TestEnableEnterpriseAttestationSuccess(t *testing.T) {
	a := &enterpriseAttestationAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	result, err := session.EnableEnterpriseAttestation(
		context.Background(),
		appconfig.EnableEnterpriseAttestationOperation{},
		session.operationOptions()...,
	)
	if err != nil {
		t.Fatalf("EnableEnterpriseAttestation: %v", err)
	}

	if result.Result == nil || result.Result.State != "configured" || a.enableCalls.Load() != 1 {
		t.Fatalf("output/calls = %#v/%d", result, a.enableCalls.Load())
	}
}

func TestSetMinPINLengthPassesParametersWithoutDefaults(t *testing.T) {
	a := &setMinPINLengthAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	result, err := session.SetMinPINLength(context.Background(), appconfig.SetMinPINLengthOperation{
		MinPINLengthRPIDs:   []string{"example.com"},
		ForceChangePIN:      true,
		PINComplexityPolicy: true,
	}, session.operationOptions()...)
	if err != nil {
		t.Fatalf("SetMinPINLength: %v", err)
	}

	if a.params.NewMinPINLength != nil || len(a.params.MinPINLengthRPIDs) != 1 ||
		!a.params.ForceChangePIN || !a.params.PINComplexityPolicy {
		t.Fatalf("upstream params = %#v", a.params)
	}

	if result.Result == nil || len(result.Result.MinPINLengthRPIDs) != 1 ||
		!result.Result.ForceChangePIN || !result.Result.PINComplexityPolicy {
		t.Fatalf("result = %#v", result.Result)
	}
}

type storeStateAuthenticator struct {
	contractAuthenticator
	contractCredentialManager
	readOnly             atomic.Bool
	permissions          []protocol.Permission
	stateTokenPermission protocol.Permission
	freshInfoCalls       atomic.Int32
	encIdentifier        []byte
	encCredStoreState    []byte
}

func newStoreStateAuthenticator() *storeStateAuthenticator {
	token := bytes.Repeat([]byte{byte(protocol.PermissionPersistentCredentialManagementReadOnly)}, sha256.Size)
	identifier := make([]byte, aes.BlockSize)
	state := make([]byte, aes.BlockSize)
	for index := range identifier {
		identifier[index] = byte(index)
		state[index] = byte(index + aes.BlockSize)
	}

	return &storeStateAuthenticator{
		encIdentifier:     encryptGetInfoMember(token, identifier, "encIdentifier"),
		encCredStoreState: encryptGetInfoMember(token, state, "encCredStoreState"),
	}
}

func (a *storeStateAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{Options: a.infoOptions()}, true
}

func (a *storeStateAuthenticator) infoOptions() map[protocol.Option]bool {
	options := enabledInfoOptions(
		protocol.OptionCredentialManagement,
		protocol.OptionPinUvAuthToken,
		protocol.OptionUserVerification,
	)

	if a.readOnly.Load() {
		options[protocol.OptionPersistentCredentialManagementReadOnly] = true
	}

	return options
}

func (a *storeStateAuthenticator) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	a.freshInfoCalls.Add(1)

	return protocol.AuthenticatorGetInfoResponse{
		Options:           a.infoOptions(),
		EncIdentifier:     a.encIdentifier,
		EncCredStoreState: a.encCredStoreState,
	}, nil
}

func (a *storeStateAuthenticator) GetPinUvAuthTokenUsingUV(
	_ context.Context,
	permission protocol.Permission,
	_ string,
) ([]byte, error) {
	a.permissions = append(a.permissions, permission)

	token := bytes.Repeat([]byte{byte(permission)}, sha256.Size)
	a.stateTokenPermission = permission

	return token, nil
}

func (a *storeStateAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(0)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(8)),
	}, nil
}

func encryptGetInfoMember(token, plaintext []byte, label string) []byte {
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	_, _ = extract.Write(token)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	_, _ = expand.Write([]byte(label))
	_, _ = expand.Write([]byte{1})
	key := expand.Sum(nil)[:aes.BlockSize]

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	return append(iv, ciphertext...)
}

type longTouchAuthenticator struct {
	contractAuthenticator
	contractConfigManager
	infoCalls   atomic.Int32
	enableCalls atomic.Int32
	enabled     atomic.Bool
	enableErr   error
}

type enterpriseAttestationAuthenticator struct {
	contractAuthenticator
	contractConfigManager
	enableCalls atomic.Int32
	enabled     atomic.Bool
}

func (a *enterpriseAttestationAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionAuthenticatorConfig:   true,
			protocol.OptionEnterpriseAttestation: a.enabled.Load(),
		},
		AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandEnableEnterpriseAttestation},
	}, true
}

func (a *enterpriseAttestationAuthenticator) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	info, _ := a.GetInfoCached()

	return info, nil
}

func (a *enterpriseAttestationAuthenticator) EnableEnterpriseAttestation(context.Context, []byte) error {
	a.enableCalls.Add(1)
	a.enabled.Store(true)

	return nil
}

type missingTotalsAuthenticator struct {
	contractAuthenticator
	stage string
}

type setMinPINLengthAuthenticator struct {
	contractAuthenticator
	contractConfigManager
	params protocol.SetMinPINLengthConfigSubCommandParams
}

func (a *setMinPINLengthAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Options:                     enabledInfoOptions(protocol.OptionAuthenticatorConfig, protocol.OptionSetMinPINLength),
		MinPINLength:                4,
		MaxPINLength:                63,
		AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength},
	}, true
}

func (a *setMinPINLengthAuthenticator) SetMinPINLength(
	_ context.Context,
	_ []byte,
	params protocol.SetMinPINLengthConfigSubCommandParams,
) error {
	a.params = params

	return nil
}

func (a *missingTotalsAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{Options: enabledInfoOptions(
		protocol.OptionCredentialManagement,
		protocol.OptionPinUvAuthToken,
		protocol.OptionUserVerification,
	)}, true
}

func (a *missingTotalsAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *missingTotalsAuthenticator) GetCredsMetadata(context.Context, []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	if a.stage == "metadata" {
		return protocol.AuthenticatorCredentialManagementResponse{}, nil
	}

	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(1)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(8)),
	}, nil
}

func (a *missingTotalsAuthenticator) EnumerateRPs(context.Context, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		response := protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "example.com"},
			RPIDHash: []byte("hash"),
		}
		response.TotalRPs = 1
		yield(response, nil)
	}
}

func (a *missingTotalsAuthenticator) EnumerateCredentials(context.Context, []byte, []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		response := protocol.AuthenticatorCredentialManagementResponse{
			User: credential.PublicKeyCredentialUserEntity{ID: []byte("user")},
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte("credential"),
			},
		}
		response.TotalCredentials = 1
		yield(response, nil)
	}
}

func (a *longTouchAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	a.infoCalls.Add(1)

	return protocol.AuthenticatorGetInfoResponse{
		Options:                     enabledInfoOptions(protocol.OptionAuthenticatorConfig),
		LongTouchForReset:           new(a.enabled.Load()),
		AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandEnableLongTouchForReset},
	}, true
}

func enabledInfoOptions(options ...protocol.Option) map[protocol.Option]bool {
	enabled := make(map[protocol.Option]bool, len(options))
	for _, option := range options {
		enabled[option] = true
	}

	return enabled
}

func (a *longTouchAuthenticator) EnableLongTouchForReset(context.Context, []byte) error {
	a.enableCalls.Add(1)
	a.enabled.Store(true)

	return a.enableErr
}
