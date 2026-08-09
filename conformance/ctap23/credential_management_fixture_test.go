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

const (
	credentialManagementFixtureTestRP1 = "one.credential-management.example"
	credentialManagementFixtureTestRP2 = "two.credential-management.example"
)

func TestCredentialManagementFixturePreflightDoesNotMutateUnsupportedAuthenticators(t *testing.T) {
	tests := []struct {
		name         string
		configure    func(*credentialManagementFixtureAuthenticator)
		config       Config
		requirements credentialManagementFixtureRequirements
		want         conformance.Status
	}{
		{
			name: "credential management absent",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.credentialManagementPresent = false
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "credential management false",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.credentialManagementEnabled = false
			},
			want: conformance.StatusSkipped,
		},
		{
			name: "credential management malformed",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.malformedCredentialManagement = true
			},
			want: conformance.StatusFailed,
		},
		{
			name: "featureful credential management false",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.credentialManagementEnabled = false
			},
			config: Config{Featureful: true},
			want:   conformance.StatusFailed,
		},
		{
			name: "resident keys absent",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.residentKeysPresent = false
			},
			want: conformance.StatusFailed,
		},
		{
			name: "resident keys false",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.residentKeysEnabled = false
			},
			want: conformance.StatusFailed,
		},
		{
			name: "resident keys malformed",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.malformedResidentKeys = true
			},
			want: conformance.StatusFailed,
		},
		{
			name: "persistent read-only false",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.perCredROEnabled = false
			},
			requirements: credentialManagementFixtureRequirements{PersistentReadOnly: true},
			want:         conformance.StatusSkipped,
		},
		{
			name: "persistent read-only malformed",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.malformedPerCredRO = true
			},
			requirements: credentialManagementFixtureRequirements{PersistentReadOnly: true},
			want:         conformance.StatusFailed,
		},
		{
			name: "protocol two absent",
			configure: func(authenticator *credentialManagementFixtureAuthenticator) {
				authenticator.protocolTwo = false
			},
			want: conformance.StatusSkipped,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			authenticator := newCredentialManagementFixtureAuthenticator(t)
			testCase.configure(authenticator)
			var suppliedPIN []byte
			config := credentialManagementFixtureConfig(authenticator, &suppliedPIN)
			config.Featureful = testCase.config.Featureful

			result := runCredentialManagementFixtureTest(t, authenticator, func(test *conformance.TestContext) {
				test.Step(conformance.Step{
					ID:   "fixture.prepare",
					Name: "Prepare credential-management fixture",
					Run: func(ctx context.Context) error {
						_, err := prepareCredentialManagementFixture(
							ctx,
							test,
							config,
							testCase.requirements,
						)

						return err
					},
				})
			})

			assertCredentialManagementFixtureStatus(t, result, testCase.want)
			if authenticator.powerCycles != 0 || authenticator.resets != 0 ||
				authenticator.setPINCalls != 0 || len(authenticator.permissionScopes) != 0 ||
				len(authenticator.makeCredentialRequests) != 0 {
				t.Fatalf(
					"preflight mutated state: cycles=%d resets=%d setPIN=%d scopes=%v makeCredential=%d",
					authenticator.powerCycles,
					authenticator.resets,
					authenticator.setPINCalls,
					authenticator.permissionScopes,
					len(authenticator.makeCredentialRequests),
				)
			}
			if suppliedPIN != nil {
				t.Fatalf("temporary PIN requested during preflight: %x", suppliedPIN)
			}
		})
	}
}

func TestCredentialManagementFixtureCreatesMultipleCredentialsAndWipesOwnedBuffers(t *testing.T) {
	authenticator := newCredentialManagementFixtureAuthenticator(t)
	var suppliedPIN []byte
	config := credentialManagementFixtureConfig(authenticator, &suppliedPIN)
	var fixture *credentialManagementFixture
	var cmToken []byte
	var pcmrToken []byte
	var largeBlobKeys [][]byte

	result := runCredentialManagementFixtureTest(t, authenticator, func(test *conformance.TestContext) {
		if !test.Step(conformance.Step{
			ID:   "fixture.prepare",
			Name: "Prepare credential-management fixture",
			Run: func(ctx context.Context) error {
				var err error
				fixture, err = prepareCredentialManagementFixture(
					ctx,
					test,
					config,
					credentialManagementFixtureRequirements{PersistentReadOnly: true},
				)

				return err
			},
		}) {
			return
		}

		test.Step(conformance.Step{
			ID:   "fixture.provision",
			Name: "Provision credentials and management tokens",
			Run: func(ctx context.Context) error {
				for _, rpID := range []string{
					credentialManagementFixtureTestRP1,
					credentialManagementFixtureTestRP1,
					credentialManagementFixtureTestRP2,
				} {
					record, err := fixture.createDiscoverableCredential(ctx, rpID)
					if err != nil {
						return err
					}
					largeBlobKeys = append(largeBlobKeys, record.LargeBlobKey)
				}

				var err error
				cmToken, err = fixture.refreshManagementToken(
					ctx,
					protocol.PermissionCredentialManagement,
				)
				if err != nil {
					return err
				}
				pcmrToken, err = fixture.refreshManagementToken(
					ctx,
					protocol.PermissionPersistentCredentialManagementReadOnly,
				)
				if err != nil {
					return err
				}
				if !allZero(cmToken) {
					return conformance.Fail("replaced credential-management token was not wiped")
				}

				return nil
			},
		})
	})

	assertCredentialManagementFixtureStatus(t, result, conformance.StatusPassed)
	if authenticator.powerCycles != 2 || authenticator.resets != 2 ||
		authenticator.setPINCalls != 1 {
		t.Fatalf(
			"power cycles/resets/setPIN = %d/%d/%d, want 2/2/1",
			authenticator.powerCycles,
			authenticator.resets,
			authenticator.setPINCalls,
		)
	}
	if authenticator.maxConcurrentCredentials != 3 {
		t.Fatalf("max concurrent credentials = %d, want 3", authenticator.maxConcurrentCredentials)
	}
	if !authenticator.permissionWiresExact || !authenticator.makeCredentialWiresExact {
		t.Fatalf(
			"wire validation = permission %t, MakeCredential %t",
			authenticator.permissionWiresExact,
			authenticator.makeCredentialWiresExact,
		)
	}
	wantPermissions := []protocol.Permission{
		protocol.PermissionMakeCredential,
		protocol.PermissionMakeCredential,
		protocol.PermissionMakeCredential,
		protocol.PermissionCredentialManagement,
		protocol.PermissionPersistentCredentialManagementReadOnly,
	}
	if !slices.Equal(authenticator.permissionScopes, wantPermissions) {
		t.Fatalf("permission scopes = %v, want %v", authenticator.permissionScopes, wantPermissions)
	}
	wantRPIDs := []string{
		credentialManagementFixtureTestRP1,
		credentialManagementFixtureTestRP1,
		credentialManagementFixtureTestRP2,
		"",
		"",
	}
	if !slices.Equal(authenticator.permissionRPIDs, wantRPIDs) {
		t.Fatalf("permission RP IDs = %q, want %q", authenticator.permissionRPIDs, wantRPIDs)
	}
	if fixture == nil || len(fixture.Credentials) != 3 {
		t.Fatalf("credentials = %#v", fixture)
	}
	for i, record := range fixture.Credentials {
		if len(record.Descriptor.ID) == 0 ||
			record.Descriptor.Type != credential.PublicKeyCredentialTypePublicKey ||
			len(record.User.ID) != 32 || len(record.ClientDataHash) != 32 ||
			len(record.RPIDHash) != 32 || len(record.PublicKey) == 0 {
			t.Fatalf("credential %d = %#v", i, record)
		}
		if record.LargeBlobKey != nil {
			t.Fatalf("credential %d retained largeBlobKey after cleanup", i)
		}
	}
	if bytes.Equal(fixture.Credentials[0].User.ID, fixture.Credentials[1].User.ID) ||
		bytes.Equal(fixture.Credentials[0].ClientDataHash, fixture.Credentials[1].ClientDataHash) {
		t.Fatal("same-RP credentials reused deterministic identity material")
	}
	if fixture.pin != nil || fixture.managementToken != nil {
		t.Fatalf("fixture retained PIN/token: pin=%x token=%x", fixture.pin, fixture.managementToken)
	}
	assertCredentialManagementFixtureZeroed(t, suppliedPIN, "temporary PIN")
	assertCredentialManagementFixtureZeroed(t, cmToken, "replaced cm token")
	assertCredentialManagementFixtureZeroed(t, pcmrToken, "pcmr token")
	for i, key := range largeBlobKeys {
		assertCredentialManagementFixtureZeroed(t, key, "largeBlobKey")
		if len(key) != 32 {
			t.Fatalf("largeBlobKey %d length = %d, want 32", i, len(key))
		}
	}
}

func TestCredentialManagementFixtureFailuresRunOneCleanupAndWipeSecrets(t *testing.T) {
	t.Run("MakeCredential status", func(t *testing.T) {
		authenticator := newCredentialManagementFixtureAuthenticator(t)
		authenticator.makeCredentialStatus = ctaptransport.CTAP2_ERR_KEY_STORE_FULL
		var suppliedPIN []byte
		config := credentialManagementFixtureConfig(authenticator, &suppliedPIN)
		var fixture *credentialManagementFixture

		result := runCredentialManagementFixtureTest(t, authenticator, func(test *conformance.TestContext) {
			if !test.Step(credentialManagementPrepareTestStep(test, config, &fixture)) {
				return
			}
			test.Step(conformance.Step{
				ID:   "fixture.make-credential",
				Name: "Create credential",
				Run: func(ctx context.Context) error {
					_, err := fixture.createDiscoverableCredential(
						ctx,
						credentialManagementFixtureTestRP1,
					)

					return err
				},
			})
		})

		assertCredentialManagementFixtureStatus(t, result, conformance.StatusFailed)
		assertCredentialManagementFixtureLifecycle(t, authenticator, suppliedPIN)
	})

	t.Run("empty credential ID", func(t *testing.T) {
		authenticator := newCredentialManagementFixtureAuthenticator(t)
		authenticator.emptyCredentialID = true
		var suppliedPIN []byte
		config := credentialManagementFixtureConfig(authenticator, &suppliedPIN)
		var fixture *credentialManagementFixture
		var makeCredentialToken []byte

		result := runCredentialManagementFixtureTest(t, authenticator, func(test *conformance.TestContext) {
			if !test.Step(credentialManagementPrepareTestStep(test, config, &fixture)) {
				return
			}
			test.Step(conformance.Step{
				ID:   "fixture.make-credential",
				Name: "Reject an empty returned credential ID",
				Run: func(ctx context.Context) error {
					_, err := fixture.createDiscoverableCredential(
						ctx,
						credentialManagementFixtureTestRP1,
					)
					makeCredentialToken = authenticator.issuedTokens[protocol.PermissionMakeCredential]

					return err
				},
			})
		})

		assertCredentialManagementFixtureStatus(t, result, conformance.StatusFailed)
		assertCredentialManagementFixtureLifecycle(t, authenticator, suppliedPIN)
		assertCredentialManagementFixtureZeroed(t, makeCredentialToken, "makeCredential token")
		if fixture == nil || fixture.pin != nil || fixture.managementToken != nil ||
			len(fixture.Credentials) != 0 {
			t.Fatalf("fixture retained state after failed provisioning: %#v", fixture)
		}
		cleanupSteps := 0
		for _, step := range result.Tests[0].Steps {
			if step.ID == "credential-management-fixture.cleanup" {
				cleanupSteps++
			}
		}
		if cleanupSteps != 1 {
			t.Fatalf("cleanup steps = %d, want 1", cleanupSteps)
		}
	})

	t.Run("temporary PIN provider error", func(t *testing.T) {
		authenticator := newCredentialManagementFixtureAuthenticator(t)
		providerError := errors.New("PIN unavailable")
		var suppliedPIN []byte
		config := credentialManagementFixtureConfig(authenticator, nil)
		config.TemporaryPINProvider = func(context.Context, TemporaryPINRequest) ([]byte, error) {
			suppliedPIN = []byte("1234")

			return suppliedPIN, providerError
		}

		result := runCredentialManagementFixtureTest(t, authenticator, func(test *conformance.TestContext) {
			test.Step(credentialManagementPrepareTestStep(
				test,
				config,
				new(*credentialManagementFixture),
			))
		})

		assertCredentialManagementFixtureStatus(t, result, conformance.StatusError)
		assertCredentialManagementFixtureLifecycle(t, authenticator, suppliedPIN)
		if authenticator.setPINCalls != 0 {
			t.Fatalf("setPIN calls = %d, want 0", authenticator.setPINCalls)
		}
	})

	t.Run("cleanup reset error", func(t *testing.T) {
		authenticator := newCredentialManagementFixtureAuthenticator(t)
		cleanupError := errors.New("cleanup reset failed")
		var suppliedPIN []byte
		config := credentialManagementFixtureConfig(authenticator, &suppliedPIN)
		resetCalls := 0
		config.Resetter = func(context.Context, *client.Client) error {
			resetCalls++
			if resetCalls == 2 {
				return cleanupError
			}
			authenticator.reset()

			return nil
		}
		var fixture *credentialManagementFixture
		var token []byte

		result := runCredentialManagementFixtureTest(t, authenticator, func(test *conformance.TestContext) {
			if !test.Step(credentialManagementPrepareTestStep(test, config, &fixture)) {
				return
			}
			test.Step(conformance.Step{
				ID:   "fixture.token",
				Name: "Issue management token",
				Run: func(ctx context.Context) error {
					var err error
					token, err = fixture.refreshManagementToken(
						ctx,
						protocol.PermissionCredentialManagement,
					)

					return err
				},
			})
		})

		assertCredentialManagementFixtureStatus(t, result, conformance.StatusError)
		if resetCalls != 2 || authenticator.powerCycles != 2 {
			t.Fatalf("reset calls/power cycles = %d/%d, want 2/2", resetCalls, authenticator.powerCycles)
		}
		assertCredentialManagementFixtureZeroed(t, suppliedPIN, "temporary PIN")
		assertCredentialManagementFixtureZeroed(t, token, "management token")
	})
}

func TestCredentialManagementAuthorizedRequestUsesCanonicalProtocolTwoAuth(t *testing.T) {
	token := bytes.Repeat([]byte{0x5a}, 32)
	defer clear(token)
	rpIDHash := sha256.Sum256([]byte(credentialManagementFixtureTestRP1))
	params := protocol.CredentialManagementSubCommandParams{RPIDHash: rpIDHash[:]}

	authorized, err := newCredentialManagementAuthorizedRequest(
		token,
		protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
		&params,
	)
	if err != nil {
		t.Fatal(err)
	}
	authParam := authorized.Request.PinUvAuthParam
	paramsCBOR := authorized.SubCommandParamsCBOR

	wantParams, err := ctap2EncMode.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authorized.SubCommandParamsCBOR, wantParams) {
		t.Fatalf(
			"subCommandParams CBOR = %x, want canonical %x",
			authorized.SubCommandParamsCBOR,
			wantParams,
		)
	}
	wantAuth := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		slices.Concat(
			[]byte{byte(protocol.CredentialManagementSubCommandEnumerateCredentialsBegin)},
			wantParams,
		),
	)
	defer clear(wantAuth)
	if !bytes.Equal(authorized.Request.PinUvAuthParam, wantAuth) {
		t.Fatalf("pinUvAuthParam = %x, want %x", authorized.Request.PinUvAuthParam, wantAuth)
	}

	body, err := ctap2EncMode.Marshal(authorized.Request)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 || fields[1] == nil || fields[2] == nil ||
		fields[3] == nil || fields[4] == nil {
		t.Fatalf("authorized request fields = %#v", fields)
	}
	if !bytes.Equal(fields[2], wantParams) {
		t.Fatalf("wire subCommandParams = %x, want %x", fields[2], wantParams)
	}

	existing := uint(2)
	remaining := uint(9)
	responseData, err := ctap2EncMode.Marshal(protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             &existing,
		MaxPossibleRemainingResidentCredentialsCount: &remaining,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := newScriptedCBORTransport(t, scriptedCBORExchange{
		request: slices.Concat(
			[]byte{byte(protocol.AuthenticatorCredentialManagement)},
			body,
		),
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       responseData,
		},
	})
	response, err := executeCredentialManagement(t.Context(), transport, authorized.Request)
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialManagementFixtureZeroed(t, responseData, "raw credential-management response")
	if len(response.Fields) != 2 ||
		response.Response.ExistingResidentCredentialsCount == nil ||
		*response.Response.ExistingResidentCredentialsCount != existing ||
		response.Response.MaxPossibleRemainingResidentCredentialsCount == nil ||
		*response.Response.MaxPossibleRemainingResidentCredentialsCount != remaining {
		t.Fatalf("decoded response = %#v", response)
	}

	authorized.clear()
	assertCredentialManagementFixtureZeroed(t, authParam, "pinUvAuthParam")
	assertCredentialManagementFixtureZeroed(t, paramsCBOR, "subCommandParams CBOR")

	continuation := credentialManagementContinuationRequest(
		protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
	)
	continuationBody, err := ctap2EncMode.Marshal(continuation)
	if err != nil {
		t.Fatal(err)
	}
	fields = nil
	if err := getInfoDecMode.Unmarshal(continuationBody, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields[1] == nil {
		t.Fatalf("continuation fields = %#v", fields)
	}
}

func TestExecuteCredentialManagementAcceptsEmptyMutationSuccess(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		subCommand protocol.CredentialManagementSubCommand
	}{
		{
			name:       "deleteCredential",
			subCommand: protocol.CredentialManagementSubCommandDeleteCredential,
		},
		{
			name:       "updateUserInformation",
			subCommand: protocol.CredentialManagementSubCommandUpdateUserInformation,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := protocol.AuthenticatorCredentialManagementRequest{
				SubCommand: testCase.subCommand,
			}
			body, err := ctap2EncMode.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			transport := newScriptedCBORTransport(t, scriptedCBORExchange{
				request: slices.Concat(
					[]byte{byte(protocol.AuthenticatorCredentialManagement)},
					body,
				),
				response: ctaptransport.CBORResponse{
					StatusCode: ctaptransport.CTAP2_OK,
				},
			})

			response, err := executeCredentialManagement(t.Context(), transport, request)
			if err != nil {
				t.Fatal(err)
			}
			if response.Fields != nil ||
				!reflect.DeepEqual(
					response.Response,
					protocol.AuthenticatorCredentialManagementResponse{},
				) {
				t.Fatalf("response = %#v, want zero response", response)
			}
		})
	}
}

func TestExecuteCredentialManagementWipesRawSecretResponse(t *testing.T) {
	request := protocol.AuthenticatorCredentialManagementRequest{
		SubCommand: protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
	}
	body, err := ctap2EncMode.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	responseData, err := ctap2EncMode.Marshal(map[uint64]any{
		11: bytes.Repeat([]byte{0xa5}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := newScriptedCBORTransport(t, scriptedCBORExchange{
		request: slices.Concat(
			[]byte{byte(protocol.AuthenticatorCredentialManagement)},
			body,
		),
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       responseData,
		},
	})

	response, err := executeCredentialManagement(t.Context(), transport, request)
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialManagementFixtureZeroed(t, responseData, "raw largeBlobKey response")
	if len(response.Response.LargeBlobKey) != 32 || len(response.Fields[11]) == 0 {
		t.Fatalf("decoded response = %#v", response)
	}
	clear(response.Response.LargeBlobKey)
	clear(response.Fields[11])
}

func TestValidateCredentialManagementCredentialIDRejectsEmptyAndWipesLargeBlobKey(
	t *testing.T,
) {
	largeBlobKey := bytes.Repeat([]byte{0xa5}, 32)
	created := protocol.AuthenticatorMakeCredentialResponse{
		AuthData: &protocol.MakeCredentialAuthData{
			AttestedCredentialData: &protocol.AttestedCredentialData{},
		},
		LargeBlobKey: largeBlobKey,
	}

	err := validateCredentialManagementCredentialID(&created)
	var assertionError *conformance.AssertionError
	if !errors.As(err, &assertionError) {
		t.Fatalf("error = %v, want conformance failure", err)
	}
	assertCredentialManagementFixtureZeroed(t, largeBlobKey, "returned largeBlobKey")
}

func TestDecodeCredentialManagementResponseRejectsMalformedAndNoncanonicalCBOR(t *testing.T) {
	for _, testCase := range []struct {
		name string
		data []byte
	}{
		{name: "malformed", data: []byte{0xff}},
		{name: "noncanonical", data: []byte{0xbf, 0x01, 0x00, 0xff}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := decodeCredentialManagementResponse(testCase.data)
			var assertionError *conformance.AssertionError
			if !errors.As(err, &assertionError) {
				t.Fatalf("error = %v, want conformance failure", err)
			}
		})
	}
}

func TestDecodeCredentialManagementResponseWipesSecretFieldsOnTypedDecodeFailure(t *testing.T) {
	request := protocol.AuthenticatorCredentialManagementRequest{
		SubCommand: protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
	}
	body, err := ctap2EncMode.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	largeBlobKey := bytes.Repeat([]byte{0xa5}, 32)
	responseData, err := ctap2EncMode.Marshal(map[uint64]any{
		11: largeBlobKey,
		12: "not-a-boolean",
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := newScriptedCBORTransport(t, scriptedCBORExchange{
		request: slices.Concat(
			[]byte{byte(protocol.AuthenticatorCredentialManagement)},
			body,
		),
		response: ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       responseData,
		},
	})

	response, err := executeCredentialManagement(t.Context(), transport, request)
	var assertionError *conformance.AssertionError
	if !errors.As(err, &assertionError) {
		t.Fatalf("error = %v, want conformance failure", err)
	}
	assertCredentialManagementFixtureZeroed(t, responseData, "failed raw credential-management response")
	assertCredentialManagementFixtureZeroed(t, response.Fields[11], "failed decoded largeBlobKey field")
	assertCredentialManagementFixtureZeroed(t, response.Response.LargeBlobKey, "failed decoded largeBlobKey")
}

func credentialManagementPrepareTestStep(
	test *conformance.TestContext,
	config Config,
	fixture **credentialManagementFixture,
) conformance.Step {
	return conformance.Step{
		ID:   "fixture.prepare",
		Name: "Prepare credential-management fixture",
		Run: func(ctx context.Context) error {
			var err error
			*fixture, err = prepareCredentialManagementFixture(
				ctx,
				test,
				config,
				credentialManagementFixtureRequirements{},
			)

			return err
		},
	}
}

func runCredentialManagementFixtureTest(
	t *testing.T,
	device ctaptransport.CBOR,
	run func(*conformance.TestContext),
) conformance.SuiteResult {
	t.Helper()

	runner, err := conformance.NewRunner(device)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(t.Context(), conformance.Suite{
		ID:   "credential-management-fixture-test",
		Name: "Credential management fixture test",
		Tests: []conformance.Test{{
			ID:   "credential-management-fixture-test.case",
			Name: "Credential management fixture case",
			Run:  run,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func assertCredentialManagementFixtureStatus(
	t *testing.T,
	result conformance.SuiteResult,
	want conformance.Status,
) {
	t.Helper()

	if result.Status != want || len(result.Tests) != 1 || result.Tests[0].Status != want {
		t.Fatalf("result = %#v, want %s", result, want)
	}
}

func assertCredentialManagementFixtureLifecycle(
	t *testing.T,
	authenticator *credentialManagementFixtureAuthenticator,
	pin []byte,
) {
	t.Helper()

	if authenticator.powerCycles != 2 || authenticator.resets != 2 {
		t.Fatalf(
			"power cycles/resets = %d/%d, want 2/2",
			authenticator.powerCycles,
			authenticator.resets,
		)
	}
	assertCredentialManagementFixtureZeroed(t, pin, "temporary PIN")
}

func assertCredentialManagementFixtureZeroed(t *testing.T, buffer []byte, name string) {
	t.Helper()

	if !allZero(buffer) {
		t.Fatalf("%s was not wiped: %x", name, buffer)
	}
}

func allZero(buffer []byte) bool {
	return !slices.ContainsFunc(buffer, func(value byte) bool { return value != 0 })
}

type credentialManagementFixtureAuthenticator struct {
	*clientPIN2PermissionsAuthenticator

	residentKeysPresent           bool
	residentKeysEnabled           bool
	malformedResidentKeys         bool
	malformedCredentialManagement bool
	makeCredentialStatus          ctaptransport.StatusCode
	emptyCredentialID             bool
	makeCredentialWiresExact      bool
	makeCredentialRequests        []protocol.AuthenticatorMakeCredentialRequest
	currentCredentialIDs          [][]byte
	maxConcurrentCredentials      int
}

func newCredentialManagementFixtureAuthenticator(
	t *testing.T,
) *credentialManagementFixtureAuthenticator {
	t.Helper()

	return &credentialManagementFixtureAuthenticator{
		clientPIN2PermissionsAuthenticator: newClientPIN2PermissionsAuthenticator(t),
		residentKeysPresent:                true,
		residentKeysEnabled:                true,
		makeCredentialWiresExact:           true,
	}
}

func (a *credentialManagementFixtureAuthenticator) CBOR(
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
	switch command {
	case protocol.AuthenticatorGetInfo:
		return ctaptransport.ValidateCBORResponse(command, a.getInfoResponse())
	case protocol.AuthenticatorMakeCredential:
		return ctaptransport.ValidateCBORResponse(
			command,
			a.makeCredentialResponse(request[1:]),
		)
	default:
		return a.clientPIN2PermissionsAuthenticator.CBOR(ctx, request)
	}
}

func (a *credentialManagementFixtureAuthenticator) getInfoResponse() ctaptransport.CBORResponse {
	base := a.permissionsGetInfoResponse()
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(base.Data, &fields); err != nil {
		a.t.Fatal(err)
	}
	var options map[string]any
	if err := getInfoDecMode.Unmarshal(fields[4], &options); err != nil {
		a.t.Fatal(err)
	}
	if a.malformedCredentialManagement {
		options[string(protocol.OptionCredentialManagement)] = uint64(1)
	}
	if a.residentKeysPresent {
		if a.malformedResidentKeys {
			options[string(protocol.OptionResidentKeys)] = uint64(1)
		} else {
			options[string(protocol.OptionResidentKeys)] = a.residentKeysEnabled
		}
	} else {
		delete(options, string(protocol.OptionResidentKeys))
	}

	encodedOptions, err := ctap2EncMode.Marshal(options)
	if err != nil {
		a.t.Fatal(err)
	}
	fields[4] = encodedOptions
	data, err := ctap2EncMode.Marshal(fields)
	if err != nil {
		a.t.Fatal(err)
	}

	return ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: data}
}

func (a *credentialManagementFixtureAuthenticator) makeCredentialResponse(
	body []byte,
) ctaptransport.CBORResponse {
	if a.makeCredentialStatus != ctaptransport.CTAP2_OK {
		return ctaptransport.CBORResponse{StatusCode: a.makeCredentialStatus}
	}

	var request protocol.AuthenticatorMakeCredentialRequest
	if err := getInfoDecMode.Unmarshal(body, &request); err != nil {
		a.t.Fatal(err)
	}
	var fields map[uint64]cbor.RawMessage
	if err := getInfoDecMode.Unmarshal(body, &fields); err != nil {
		a.t.Fatal(err)
	}
	token := a.issuedTokens[protocol.PermissionMakeCredential]
	wantAuth := ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolTwo,
		token,
		request.ClientDataHash,
	)
	defer clear(wantAuth)
	a.makeCredentialWiresExact = a.makeCredentialWiresExact &&
		len(fields) == 7 &&
		fields[1] != nil && fields[2] != nil && fields[3] != nil && fields[4] != nil &&
		fields[7] != nil && fields[8] != nil && fields[9] != nil &&
		request.PinUvAuthProtocol == protocol.PinUvAuthProtocolTwo &&
		bytes.Equal(request.PinUvAuthParam, wantAuth) &&
		len(request.Options) == 1 && request.Options[protocol.OptionResidentKeys] &&
		len(request.ExcludeList) == 0
	if !a.makeCredentialWiresExact {
		a.t.Fatalf("MakeCredential request = %#v, fields = %#v", request, fields)
	}

	a.makeCredentialRequests = append(a.makeCredentialRequests, request)
	credentialID := slices.Concat([]byte("credential:"), request.User.ID[:8])
	if a.emptyCredentialID {
		credentialID = nil
	}
	a.currentCredentialIDs = append(a.currentCredentialIDs, credentialID)
	a.maxConcurrentCredentials = max(
		a.maxConcurrentCredentials,
		len(a.currentCredentialIDs),
	)

	authData := getAssertionFixtureMakeCredentialAuthData(a.t, credentialID)
	rpIDHash := sha256.Sum256([]byte(request.RP.ID))
	copy(authData[:32], rpIDHash[:])
	authData[32] |= byte(protocol.AuthDataFlagUserVerified)
	largeBlobKey := bytes.Repeat(
		[]byte{byte(len(a.makeCredentialRequests))},
		32,
	)

	return a.success(map[uint64]any{
		1: "none",
		2: authData,
		3: map[string]any{},
		5: largeBlobKey,
	})
}

func (a *credentialManagementFixtureAuthenticator) reset() {
	a.clientPIN2NewPINAuthenticator.reset()
	for permission, token := range a.issuedTokens {
		clear(token)
		delete(a.issuedTokens, permission)
	}
	for _, credentialID := range a.currentCredentialIDs {
		clear(credentialID)
	}
	a.currentCredentialIDs = nil
}

func credentialManagementFixtureConfig(
	authenticator *credentialManagementFixtureAuthenticator,
	suppliedPIN *[]byte,
) Config {
	return Config{
		Transport: AuthenticatorTransportHID,
		PowerCycler: func(context.Context) error {
			authenticator.powerCycles++

			return nil
		},
		Resetter: func(context.Context, *client.Client) error {
			authenticator.reset()

			return nil
		},
		TemporaryPINProvider: func(
			_ context.Context,
			request TemporaryPINRequest,
		) ([]byte, error) {
			if request.MinCodePoints != 4 || request.MaxCodePoints != 63 {
				return nil, errors.New("unexpected temporary PIN bounds")
			}
			pin := []byte("1234")
			if suppliedPIN != nil {
				*suppliedPIN = pin
			}

			return pin, nil
		},
	}
}

var _ ctaptransport.CBOR = (*credentialManagementFixtureAuthenticator)(nil)
