package ctapkit

import (
	"context"
	"errors"
	"iter"
	"testing"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
	"github.com/telesma-app/kit/model"
	appconfig "github.com/telesma-app/kit/model/config"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func TestAuthenticatorMutationsInvalidateRetainedLargeBlobSnapshot(t *testing.T) {
	for _, tt := range stateMutationCases(t, false) {
		t.Run(tt.name, func(t *testing.T) {
			a, session, handler := openStateEffectAuthenticator(t)
			primeLargeBlobSnapshot(t, session, handler)

			if err := tt.mutate(session, handler); err != nil {
				t.Fatalf("mutate: %v", err)
			}

			assertNextLargeBlobReadRefreshes(t, a, session, handler)
		})
	}
}

func TestMutationDryRunsKeepRetainedLargeBlobSnapshot(t *testing.T) {
	for _, tt := range stateMutationCases(t, true) {
		t.Run(tt.name, func(t *testing.T) {
			a, session, handler := openStateEffectAuthenticator(t)
			primeLargeBlobSnapshot(t, session, handler)

			if err := tt.mutate(session, handler); err != nil {
				t.Fatalf("dry run: %v", err)
			}

			assertNextLargeBlobReadUsesSnapshot(t, a, session, handler)
		})
	}
}

func TestFailedMutationInvalidatesRetainedLargeBlobSnapshot(t *testing.T) {
	a, session, handler := openStateEffectAuthenticator(t)
	primeLargeBlobSnapshot(t, session, handler)

	a.deleteErr = errors.New("delete result unknown")

	_, err := session.DeleteCredential(t.Context(), appcredentials.DeleteOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err == nil {
		t.Fatal("DeleteCredential error = nil")
	}

	assertNextLargeBlobReadRefreshes(t, a, session, handler)
}

func TestFailedLargeBlobWriteInvalidatesRetainedSnapshot(t *testing.T) {
	a, session, handler := openStateEffectAuthenticator(t)
	primeLargeBlobSnapshot(t, session, handler)

	a.setErr = errors.New("large blob write result unknown")

	_, err := session.WriteLargeBlob(t.Context(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("updated"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err == nil {
		t.Fatal("WriteLargeBlob error = nil")
	}

	assertNextLargeBlobReadRefreshes(t, a, session, handler)
}

type stateMutationCase struct {
	name   string
	mutate func(*contractAuthenticatorHandle, InteractionHandler) error
}

func stateMutationCases(t *testing.T, dryRun bool) []stateMutationCase {
	t.Helper()

	return []stateMutationCase{
		{
			name: "delete credential",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.DeleteCredential(t.Context(), appcredentials.DeleteOperation{
					CredentialIDHex: "c05e",
					DryRun:          dryRun,
				}, session.operationOptions(WithInteractionHandler(handler))...)

				return err
			},
		},
		{
			name: "update credential user",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.UpdateCredentialUser(t.Context(), appcredentials.UpdateUserOperation{
					Target:       credentialMutationTarget(),
					Name:         "updated",
					NameProvided: true,
					DryRun:       dryRun,
				}, session.operationOptions(WithInteractionHandler(handler))...)

				return err
			},
		},
		{
			name: "make credential",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.MakeCredential(
					t.Context(),
					sampleMakeCredentialOperation(dryRun),
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
		{
			name: "write large blob through WebAuthn",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.GetAssertion(t.Context(), largeBlobWriteAssertionOperation(dryRun),
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
		{
			name: "factory reset",
			mutate: func(session *contractAuthenticatorHandle, handler InteractionHandler) error {
				_, err := session.ResetFactory(t.Context(), appconfig.ResetFactoryOperation{DryRun: dryRun},
					session.operationOptions(WithInteractionHandler(handler))...,
				)

				return err
			},
		},
	}
}

func openStateEffectAuthenticator(
	t *testing.T,
) (*stateEffectAuthenticator, *contractAuthenticatorHandle, InteractionHandler) {
	t.Helper()

	a := &stateEffectAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	t.Cleanup(func() { _ = session.Close() })

	handler := interactionHandlerFunc(func(model.InteractionRequest) (model.InteractionResponse, error) {
		return model.InteractionResponse{}, nil
	})

	return a, session, handler
}

func primeLargeBlobSnapshot(
	t *testing.T,
	session *contractAuthenticatorHandle,
	handler InteractionHandler,
) {
	t.Helper()

	_, err := session.ListLargeBlobs(
		t.Context(),
		session.operationOptions(WithInteractionHandler(handler))...,
	)
	if err != nil {
		t.Fatalf("ListLargeBlobs: %v", err)
	}
}

func assertNextLargeBlobReadRefreshes(
	t *testing.T,
	a *stateEffectAuthenticator,
	session *contractAuthenticatorHandle,
	handler InteractionHandler,
) {
	t.Helper()

	credentialReads := a.credentialEnumerations.Load()
	largeBlobReads := a.largeBlobReads.Load()

	readLargeBlob(t, session, handler)

	if got := a.credentialEnumerations.Load(); got != credentialReads+1 {
		t.Fatalf("credential enumerations = %d, want %d", got, credentialReads+1)
	}

	if got := a.largeBlobReads.Load(); got != largeBlobReads+1 {
		t.Fatalf("large blob reads = %d, want %d", got, largeBlobReads+1)
	}
}

func assertNextLargeBlobReadUsesSnapshot(
	t *testing.T,
	a *stateEffectAuthenticator,
	session *contractAuthenticatorHandle,
	handler InteractionHandler,
) {
	t.Helper()

	credentialReads := a.credentialEnumerations.Load()
	largeBlobReads := a.largeBlobReads.Load()

	readLargeBlob(t, session, handler)

	if got := a.credentialEnumerations.Load(); got != credentialReads {
		t.Fatalf("credential enumerations = %d, want %d", got, credentialReads)
	}

	if got := a.largeBlobReads.Load(); got != largeBlobReads {
		t.Fatalf("large blob reads = %d, want %d", got, largeBlobReads)
	}
}

func readLargeBlob(
	t *testing.T,
	session *contractAuthenticatorHandle,
	handler InteractionHandler,
) {
	t.Helper()

	_, err := session.ReadLargeBlob(t.Context(), applargeblobs.ReadOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("ReadLargeBlob: %v", err)
	}
}

func largeBlobWriteAssertionOperation(dryRun bool) appwebauthn.GetAssertionOperation {
	return appwebauthn.GetAssertionOperation{
		GetAssertionInput: appwebauthn.GetAssertionInput{
			RPID:           "id.example",
			ClientDataJSON: []byte(`{"type":"webauthn.get"}`),
			Extensions: &ctapwebauthn.GetAuthenticationExtensionsClientInputs{
				LargeBlobInputs: &ctapwebauthn.LargeBlobInputs{
					LargeBlob: ctapwebauthn.AuthenticationExtensionsLargeBlobInputs{
						Write: []byte{},
					},
				},
			},
		},
		DryRun: dryRun,
	}
}

type stateEffectAuthenticator struct {
	largeBlobWriteEventAuthenticator
	contractConfigManager
	deleteErr error
}

func (a *stateEffectAuthenticator) DeleteCredential(
	context.Context,
	[]byte,
	credential.PublicKeyCredentialDescriptor,
) error {
	return a.deleteErr
}

func (a *stateEffectAuthenticator) UpdateUserInformation(
	context.Context,
	[]byte,
	credential.PublicKeyCredentialDescriptor,
	credential.PublicKeyCredentialUserEntity,
) error {
	return nil
}

func (a *stateEffectAuthenticator) Reset(context.Context) error {
	return nil
}

func (a *stateEffectAuthenticator) MakeCredential(
	context.Context,
	[]byte,
	[]byte,
	credential.PublicKeyCredentialRpEntity,
	credential.PublicKeyCredentialUserEntity,
	[]credential.PublicKeyCredentialParameters,
	[]credential.PublicKeyCredentialDescriptor,
	*ctapwebauthn.CreateAuthenticationExtensionsClientInputs,
	map[protocol.Option]bool,
	uint,
	[]attestation.AttestationStatementFormatIdentifier,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return sampleMakeCredentialResponse(), nil
}

func (a *stateEffectAuthenticator) GetAssertion(
	context.Context,
	[]byte,
	string,
	[]byte,
	[]credential.PublicKeyCredentialDescriptor,
	*ctapwebauthn.GetAuthenticationExtensionsClientInputs,
	map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {
		yield(sampleAssertionResponse([]byte{0xc0, 0x5e}, []byte{0xaa}, []byte("user"), 1), nil)
	}
}
