package ctapkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"maps"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/telesma-app/ctap/attestation"
	ctapdevice "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/webauthn"
	"github.com/telesma-app/kit/model/failure"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func TestMakeCredentialDryRunDoesNotConfirmAcquireTokenOrMutate(t *testing.T) {
	a := &webauthnTestAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	result, err := session.MakeCredential(
		context.Background(),
		sampleMakeCredentialOperation(true),
		session.operationOptions()...,
	)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	if result.Result != nil {
		t.Fatalf("dry-run result = %#v, want nil", result.Result)
	}

	if result.Preview.Input.RP.ID != "example.com" {
		t.Fatalf("preview RP = %#v", result.Preview.Input.RP)
	}

	if a.makeCredentialCalls != 0 {
		t.Fatalf("MakeCredential calls = %d, want 0", a.makeCredentialCalls)
	}

	if len(a.tokenRPIDs) != 0 {
		t.Fatalf("token rpIDs = %v, want none", a.tokenRPIDs)
	}
}

func TestGetAssertionDryRunDoesNotAcquireTokenOrCallAuthenticator(t *testing.T) {
	a := &webauthnTestAuthenticator{alwaysUV: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	op := sampleGetAssertionOperation()
	op.DryRun = true
	result, err := session.GetAssertion(context.Background(), op, session.operationOptions()...)
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if result.Result != nil {
		t.Fatalf("dry-run result = %#v, want nil", result.Result)
	}

	if result.Preview.Input.RPID != "example.com" {
		t.Fatalf("preview RP ID = %q", result.Preview.Input.RPID)
	}

	if a.getAssertionCalls != 0 {
		t.Fatalf("GetAssertion calls = %d, want 0", a.getAssertionCalls)
	}

	if len(a.tokenRPIDs) != 0 {
		t.Fatalf("token rpIDs = %v, want none", a.tokenRPIDs)
	}
}

func TestGetAssertionLargeBlobWriteExecutesWithoutRuntimeConfirmation(t *testing.T) {
	a := &webauthnTestAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	op := sampleGetAssertionOperation()
	op.Extensions = &webauthn.GetAuthenticationExtensionsClientInputs{
		LargeBlobInputs: &webauthn.LargeBlobInputs{LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
			Write: []byte{},
		}},
	}

	if _, err := session.GetAssertion(context.Background(), op, session.operationOptions()...); err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if a.getAssertionCalls != 1 || a.getAssertionExtensions == nil ||
		a.getAssertionExtensions.LargeBlobInputs == nil || a.getAssertionExtensions.LargeBlob.Write == nil {
		t.Fatalf("confirmed write calls/extensions = %d/%#v", a.getAssertionCalls, a.getAssertionExtensions)
	}
}

func TestMakeCredentialMapsRequestAndUsesRawClientDataJSON(t *testing.T) {
	a := &webauthnTestAuthenticator{makeCredentialUvNotRequired: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	uv := true
	rk := false
	op := sampleMakeCredentialOperation(false)
	op.Options = appwebauthn.AuthenticatorOptions{
		ResidentKey:      &rk,
		UserVerification: &uv,
	}
	op.ExcludeList = []credential.PublicKeyCredentialDescriptor{
		{ID: []byte{0xc0, 0x5e}, Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB}},
	}
	op.EnterpriseAttestation = 2
	op.AttestationFormatsPreference = []attestation.AttestationStatementFormatIdentifier{
		attestation.AttestationStatementFormatIdentifierPacked,
		attestation.AttestationStatementFormatIdentifierNone,
	}

	_, err := session.MakeCredential(
		context.Background(),
		op,
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	if !bytes.Equal(a.makeCredentialClientData, op.ClientDataJSON) {
		t.Fatalf("clientDataJSON = %q, want raw %q", a.makeCredentialClientData, op.ClientDataJSON)
	}

	if a.makeCredentialRP.ID != "example.com" || !bytes.Equal(a.makeCredentialUser.ID, []byte{0x01, 0x02}) {
		t.Fatalf("mapped rp/user = %#v %#v", a.makeCredentialRP, a.makeCredentialUser)
	}

	if len(a.makeCredentialParams) != 1 || a.makeCredentialParams[0].Algorithm != -7 {
		t.Fatalf("mapped params = %#v", a.makeCredentialParams)
	}

	if len(a.makeCredentialExcludeList) != 1 ||
		!bytes.Equal(a.makeCredentialExcludeList[0].ID, []byte{0xc0, 0x5e}) ||
		a.makeCredentialExcludeList[0].Transports[0] != credential.AuthenticatorTransportUSB {
		t.Fatalf("mapped excludeList = %#v", a.makeCredentialExcludeList)
	}
	wantOptions := map[protocol.Option]bool{
		protocol.OptionResidentKeys:     false,
		protocol.OptionUserVerification: true,
	}

	if !maps.Equal(a.makeCredentialOptions, wantOptions) {
		t.Fatalf("options = %#v, want %#v", a.makeCredentialOptions, wantOptions)
	}

	if a.makeCredentialEnterpriseAttestation != op.EnterpriseAttestation ||
		!slices.Equal(a.makeCredentialAttestationFormats, op.AttestationFormatsPreference) {
		t.Fatalf(
			"attestation parameters = %d %#v, want %d %#v",
			a.makeCredentialEnterpriseAttestation,
			a.makeCredentialAttestationFormats,
			op.EnterpriseAttestation,
			op.AttestationFormatsPreference,
		)
	}

	if len(a.tokenRPIDs) != 0 || len(a.makeCredentialToken) != 0 {
		t.Fatalf("token rpIDs/token = %v/%q, want built-in UV without a token", a.tokenRPIDs, a.makeCredentialToken)
	}
}

func TestMakeCredentialAcquiresScopedTokenWhenCTAPRequiresIt(t *testing.T) {
	a := &webauthnTestAuthenticator{makeCredentialRequiresToken: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	op := sampleMakeCredentialOperation(false)
	if _, err := session.MakeCredential(
		context.Background(),
		op,
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	if a.makeCredentialCalls != 2 {
		t.Fatalf("MakeCredential calls = %d, want preflight plus authorized retry", a.makeCredentialCalls)
	}

	if !slices.Equal(a.tokenRPIDs, []string{"example.com"}) {
		t.Fatalf("token rpIDs = %v, want scoped RP ID", a.tokenRPIDs)
	}

	if string(a.makeCredentialToken) != "token:example.com" {
		t.Fatalf("MakeCredential token = %q, want scoped token", a.makeCredentialToken)
	}
}

func TestMakeCredentialReturnsNoPartialResultAndInvalidatesInventoryOnRefreshFailure(t *testing.T) {
	refreshErr := errors.New("getInfo refresh failed")
	a := &webauthnTestAuthenticator{
		makeCredentialUvNotRequired:         true,
		makeCredentialErr:                   refreshErr,
		returnMakeCredentialResponseOnError: true,
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	inventory, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("prime credentials: %v", err)
	}

	record := inventory.Groups[0].Credentials[0]
	if record.CredProtect != 0 ||
		record.ThirdPartyPayment == nil || *record.ThirdPartyPayment {
		t.Fatalf("optional inventory fields = %#v", record)
	}
	op := sampleMakeCredentialOperation(false)
	result, err := session.MakeCredential(context.Background(), op, session.operationOptions()...)
	if !errors.Is(err, refreshErr) {
		t.Fatalf("MakeCredential error = %v, want refresh error", err)
	}

	requireZero(t, result)

	a.makeCredentialErr = nil
	if _, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("credentials after failed mutation: %v", err)
	}

	if a.metadataCalls != 2 {
		t.Fatalf("metadata calls = %d, want invalidated inventory refresh", a.metadataCalls)
	}
}

func TestCredentialInventoryAlwaysReadsFreshStateAroundMakeCredential(t *testing.T) {
	a := &webauthnTestAuthenticator{makeCredentialUvNotRequired: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	if _, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("first ListCredentials: %v", err)
	}

	if _, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("cached ListCredentials: %v", err)
	}

	if got := a.metadataCalls; got != 2 {
		t.Fatalf("metadata calls before mutation = %d, want 2", got)
	}

	op := sampleMakeCredentialOperation(false)
	if _, err := session.MakeCredential(context.Background(), op, session.operationOptions()...); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	if _, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("post-mutation ListCredentials: %v", err)
	}

	if got := a.metadataCalls; got != 3 {
		t.Fatalf("metadata calls after mutation = %d, want 3", got)
	}
}

func TestGetAssertionReturnsAllAssertionsInOrder(t *testing.T) {
	a := &webauthnTestAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	op := sampleGetAssertionOperation()
	op.AllowList = []credential.PublicKeyCredentialDescriptor{{ID: []byte{0xc0, 0x5e}}}
	output, err := session.GetAssertion(context.Background(), op, session.operationOptions()...)
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	result := output.Result
	if len(result.Assertions) != 2 {
		t.Fatalf("assertions = %#v, want 2", result.Assertions)
	}

	if !bytes.Equal(result.Assertions[0].Credential.ID, []byte{0xc0, 0x5e}) ||
		!bytes.Equal(result.Assertions[1].Credential.ID, []byte{0xb0, 0xb0}) {
		t.Fatalf("assertion order = %#v", result.Assertions)
	}

	if result.Assertions[0].SignatureHex != "aabb" ||
		!bytes.Equal(result.Assertions[1].User.ID, []byte("user-2")) {
		t.Fatalf("assertion mapping = %#v", result.Assertions)
	}

	if result.Assertions[1].NumberOfCredentials != 0 {
		t.Fatalf("numberOfCredentials = %#v, want 0", result.Assertions[1].NumberOfCredentials)
	}

	if result.Assertions[0].UserSelected {
		t.Fatalf("userSelected = %#v, want false", result.Assertions[0].UserSelected)
	}

	if !bytes.Equal(a.getAssertionClientData, []byte(`{"type":"webauthn.get"}`)) {
		t.Fatalf("getAssertion clientDataJSON = %q", a.getAssertionClientData)
	}

	if len(a.tokenRPIDs) != 0 {
		t.Fatalf("token rpIDs = %v, want none without UV option", a.tokenRPIDs)
	}
}

func TestGetAssertionWorkflowReturnsZeroAfterMidstreamFailure(t *testing.T) {
	cause := errors.New("assertion enumeration failed")
	a := &webauthnTestAuthenticator{
		getAssertionErr:           cause,
		getAssertionErrAfterFirst: true,
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.GetAssertion(
		context.Background(),
		sampleGetAssertionOperation(),
	)
	if !errors.Is(err, cause) {
		t.Fatalf("GetAssertion error = %v, want %v", err, cause)
	}
	requireZero(t, output)
}

func TestGetAssertionUsesBuiltInUVWhenRequested(t *testing.T) {
	a := &webauthnTestAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	op := sampleGetAssertionOperation()
	op.Options.UserVerification = new(true)
	_, err := session.GetAssertion(
		context.Background(),
		op,
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if len(a.tokenRPIDs) != 0 {
		t.Fatalf("token rpIDs = %v, want built-in UV without a token", a.tokenRPIDs)
	}

	if len(a.getAssertionToken) != 0 {
		t.Fatalf("GetAssertion token = %q, want none", a.getAssertionToken)
	}

	if !a.getAssertionOptions[protocol.OptionUserVerification] {
		t.Fatalf("GetAssertion options = %#v, want built-in uv", a.getAssertionOptions)
	}
}

func TestGetAssertionAcquiresScopedTokenWhenCTAPRequiresIt(t *testing.T) {
	a := &webauthnTestAuthenticator{getAssertionRequiresToken: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	_, err := session.GetAssertion(
		context.Background(),
		sampleGetAssertionOperation(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if !slices.Equal(a.tokenRPIDs, []string{"example.com"}) {
		t.Fatalf("token rpIDs = %v, want scoped RP ID", a.tokenRPIDs)
	}

	if string(a.getAssertionToken) != "token:example.com" {
		t.Fatalf("GetAssertion token = %q, want scoped token", a.getAssertionToken)
	}

	if a.getAssertionCalls != 2 {
		t.Fatalf("GetAssertion calls = %d, want preflight plus authorized retry", a.getAssertionCalls)
	}
}

func TestGetAssertionAcquiresScopedTokenWhenCTAPRequiresBuiltInUV(t *testing.T) {
	a := &webauthnTestAuthenticator{getAssertionRequiresBuiltInUV: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	_, err := session.GetAssertion(
		context.Background(),
		sampleGetAssertionOperation(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if !slices.Equal(a.tokenRPIDs, []string{"example.com"}) {
		t.Fatalf("token rpIDs = %v, want scoped RP ID", a.tokenRPIDs)
	}

	if a.getAssertionCalls != 2 {
		t.Fatalf("GetAssertion calls = %d, want preflight plus authorized retry", a.getAssertionCalls)
	}
}

func TestWebAuthnDelegatesPRFRoutingToCTAP(t *testing.T) {
	a := &webauthnTestAuthenticator{makeCredentialUvNotRequired: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	makeOperation := sampleMakeCredentialOperation(false)
	makeOperation.Extensions = &webauthn.CreateAuthenticationExtensionsClientInputs{
		PRFInputs: &webauthn.PRFInputs{PRF: webauthn.AuthenticationExtensionsPRFInputs{
			Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("make")},
		}},
	}

	if _, err := session.MakeCredential(
		context.Background(),
		makeOperation,
		session.operationOptions()...,
	); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	if a.makeCredentialExtensions == nil || a.makeCredentialExtensions.PRFInputs == nil ||
		string(a.makeCredentialExtensions.PRF.Eval.First) != "make" {
		t.Fatalf("MakeCredential extensions = %#v, want unmodified PRF input", a.makeCredentialExtensions)
	}

	getOperation := sampleGetAssertionOperation()
	getOperation.Extensions = &webauthn.GetAuthenticationExtensionsClientInputs{
		PRFInputs: &webauthn.PRFInputs{PRF: webauthn.AuthenticationExtensionsPRFInputs{
			Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("get")},
		}},
	}
	if _, err := session.GetAssertion(
		context.Background(),
		getOperation,
		session.operationOptions()...,
	); err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if a.getAssertionExtensions == nil || a.getAssertionExtensions.PRFInputs == nil ||
		string(a.getAssertionExtensions.PRF.Eval.First) != "get" {
		t.Fatalf("GetAssertion extensions = %#v, want unmodified PRF input", a.getAssertionExtensions)
	}
}

func TestWebAuthnDelegatesPreviewSignToCTAP(t *testing.T) {
	a := &webauthnTestAuthenticator{
		makeCredentialUvNotRequired: true,
		extensions:                  []extension.ExtensionIdentifier{extension.ExtensionIdentifierPreviewSign},
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	makeOperation := sampleMakeCredentialOperation(false)
	makeOperation.Extensions = &webauthn.CreateAuthenticationExtensionsClientInputs{
		PreviewSignInputs: &webauthn.PreviewSignInputs{
			PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
				GenerateKey: &webauthn.PreviewSignGenerateKeyInputs{
					Algorithms: []cose.Algorithm{cose.AlgorithmES256},
				},
			},
		},
	}
	if _, err := session.MakeCredential(
		context.Background(),
		makeOperation,
		session.operationOptions()...,
	); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	if a.makeCredentialExtensions == nil || a.makeCredentialExtensions.PreviewSignInputs == nil ||
		a.makeCredentialExtensions.PreviewSign.GenerateKey == nil ||
		!slices.Equal(a.makeCredentialExtensions.PreviewSign.GenerateKey.Algorithms, []cose.Algorithm{cose.AlgorithmES256}) {
		t.Fatalf("MakeCredential previewSign extensions = %#v", a.makeCredentialExtensions)
	}

	getOperation := sampleGetAssertionOperation()
	getOperation.AllowList = []credential.PublicKeyCredentialDescriptor{{ID: []byte{0xc0, 0x5e}}}
	getOperation.Extensions = &webauthn.GetAuthenticationExtensionsClientInputs{
		PreviewSignInputs: &webauthn.PreviewSignInputs{
			PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
				SignByCredential: map[string]webauthn.PreviewSignSignInputs{
					"wF4": {
						KeyHandle:  []byte{0x01, 0x02},
						ToBeSigned: []byte("message"),
					},
				},
			},
		},
	}
	if _, err := session.GetAssertion(
		context.Background(),
		getOperation,
		session.operationOptions()...,
	); err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if a.getAssertionExtensions == nil || a.getAssertionExtensions.PreviewSignInputs == nil ||
		string(a.getAssertionExtensions.PreviewSign.SignByCredential["wF4"].ToBeSigned) != "message" {
		t.Fatalf("GetAssertion previewSign extensions = %#v", a.getAssertionExtensions)
	}
}

func TestMakeCredentialAcquiresTokenForRegistrationPRFEvaluation(t *testing.T) {
	a := &webauthnTestAuthenticator{
		makeCredentialUvNotRequired: true,
		extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	operation := sampleMakeCredentialOperation(false)
	operation.Extensions = &webauthn.CreateAuthenticationExtensionsClientInputs{
		PRFInputs: &webauthn.PRFInputs{PRF: webauthn.AuthenticationExtensionsPRFInputs{
			Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte{}},
		}},
	}

	if _, err := session.MakeCredential(
		context.Background(),
		operation,
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	if !slices.Equal(a.tokenRPIDs, []string{"example.com"}) {
		t.Fatalf("token rpIDs = %v, want scoped RP ID", a.tokenRPIDs)
	}
	if string(a.makeCredentialToken) != "token:example.com" {
		t.Fatalf("MakeCredential token = %q, want scoped token", a.makeCredentialToken)
	}
	if a.makeCredentialCalls != 1 {
		t.Fatalf("MakeCredential calls = %d, want one authorized call", a.makeCredentialCalls)
	}
}

func TestWebAuthnCTAPStatusMapsCodes(t *testing.T) {
	tests := []struct {
		name     string
		invoke   func(context.Context, *contractAuthenticatorHandle) error
		setupErr func(*webauthnTestAuthenticator)
		want     failure.Code
	}{
		{
			name: "make credential excluded",
			invoke: func(ctx context.Context, session *contractAuthenticatorHandle) error {
				_, err := session.MakeCredential(
					ctx,
					appwebauthn.MakeCredentialOperation{
						MakeCredentialInput: sampleMakeCredentialOperation(false).MakeCredentialInput,
					},
					session.operationOptions()...,
				)

				return err
			},
			setupErr: func(a *webauthnTestAuthenticator) {
				a.makeCredentialErr = &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorMakeCredential,
					StatusCode: ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED,
				}
			},
			want: failure.CodeCredentialExcluded,
		},
		{
			name: "get assertion no credentials",
			invoke: func(ctx context.Context, session *contractAuthenticatorHandle) error {
				_, err := session.GetAssertion(
					ctx,
					sampleGetAssertionOperation(),
					session.operationOptions()...,
				)

				return err
			},
			setupErr: func(a *webauthnTestAuthenticator) {
				a.getAssertionErr = &ctaptransport.CTAPError{
					Command:    protocol.AuthenticatorGetAssertion,
					StatusCode: ctaptransport.CTAP2_ERR_NO_CREDENTIALS,
				}
			},
			want: failure.CodeCredentialNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &webauthnTestAuthenticator{makeCredentialUvNotRequired: true}
			tt.setupErr(a)
			session := openContractAuthenticator(t, nil, a)
			defer func() { _ = session.Close() }()

			err := tt.invoke(context.Background(), session)
			requireFailureCode(t, err, tt.want)
		})
	}
}

func TestWebAuthnOutputsDoNotMarshalTokens(t *testing.T) {
	output := appwebauthn.GetAssertionOutput{
		Result: &appwebauthn.GetAssertionResult{
			Assertions: []appwebauthn.Assertion{
				{SignatureHex: "746f6b656e"},
			},
		},
	}

	raw, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if bytes.Contains(raw, []byte("pinUvAuthToken")) {
		t.Fatalf("WebAuthn output leaked token marker: %s", raw)
	}
}

func sampleMakeCredentialOperation(dryRun bool) appwebauthn.MakeCredentialOperation {
	return appwebauthn.MakeCredentialOperation{
		MakeCredentialInput: appwebauthn.MakeCredentialInput{
			RP: credential.PublicKeyCredentialRpEntity{
				ID:   "example.com",
				Name: "Example",
			},
			User: credential.PublicKeyCredentialUserEntity{
				ID:          []byte{0x01, 0x02},
				Name:        "alice@example.com",
				DisplayName: "Alice",
			},
			ClientDataJSON: []byte(`{"type":"webauthn.create"}`),
			PubKeyCredParams: []credential.PublicKeyCredentialParameters{
				{Algorithm: -7},
			},
		},
		DryRun: dryRun,
	}
}

func sampleGetAssertionOperation() appwebauthn.GetAssertionOperation {
	return appwebauthn.GetAssertionOperation{
		GetAssertionInput: appwebauthn.GetAssertionInput{
			RPID:           "example.com",
			ClientDataJSON: []byte(`{"type":"webauthn.get"}`),
		},
	}
}

type webauthnTestAuthenticator struct {
	contractAuthenticator
	makeCredentialUvNotRequired   bool
	alwaysUV                      bool
	extensions                    []extension.ExtensionIdentifier
	makeCredentialRequiresToken   bool
	getAssertionRequiresToken     bool
	getAssertionRequiresBuiltInUV bool
	tokenRPIDs                    []string

	makeCredentialCalls                 int
	makeCredentialErr                   error
	returnMakeCredentialResponseOnError bool
	makeCredentialToken                 []byte
	makeCredentialClientData            []byte
	makeCredentialRP                    credential.PublicKeyCredentialRpEntity
	makeCredentialUser                  credential.PublicKeyCredentialUserEntity
	makeCredentialParams                []credential.PublicKeyCredentialParameters
	makeCredentialExcludeList           []credential.PublicKeyCredentialDescriptor
	makeCredentialExtensions            *webauthn.CreateAuthenticationExtensionsClientInputs
	makeCredentialOptions               map[protocol.Option]bool
	makeCredentialEnterpriseAttestation uint
	makeCredentialAttestationFormats    []attestation.AttestationStatementFormatIdentifier

	getAssertionErr           error
	getAssertionErrAfterFirst bool
	getAssertionCalls         int
	tokenErr                  error
	getAssertionToken         []byte
	getAssertionClientData    []byte
	getAssertionExtensions    *webauthn.GetAuthenticationExtensionsClientInputs
	getAssertionOptions       map[protocol.Option]bool

	metadataCalls int
}

func (a *webauthnTestAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Extensions: a.extensions,
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagement:        true,
			protocol.OptionPinUvAuthToken:              true,
			protocol.OptionUserVerification:            true,
			protocol.OptionMakeCredentialUvNotRequired: a.makeCredentialUvNotRequired,
			protocol.OptionAlwaysUv:                    a.alwaysUV,
		},
	}, true
}

func (a *webauthnTestAuthenticator) GetPinUvAuthTokenUsingUV(
	_ context.Context,
	_ protocol.Permission,
	rpID string,
) ([]byte, error) {
	a.tokenRPIDs = append(a.tokenRPIDs, rpID)

	if a.tokenErr != nil {
		return nil, a.tokenErr
	}

	return []byte("token:" + rpID), nil
}

func (a *webauthnTestAuthenticator) MakeCredential(
	_ context.Context,
	pinUvAuthToken []byte,
	clientData []byte,
	rp credential.PublicKeyCredentialRpEntity,
	user credential.PublicKeyCredentialUserEntity,
	pubKeyCredParams []credential.PublicKeyCredentialParameters,
	excludeList []credential.PublicKeyCredentialDescriptor,
	extensions *webauthn.CreateAuthenticationExtensionsClientInputs,
	options map[protocol.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []attestation.AttestationStatementFormatIdentifier,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	a.makeCredentialCalls++
	a.makeCredentialToken = slices.Clone(pinUvAuthToken)
	a.makeCredentialClientData = clientData
	a.makeCredentialRP = rp
	a.makeCredentialUser = user
	a.makeCredentialParams = pubKeyCredParams
	a.makeCredentialExcludeList = excludeList
	a.makeCredentialExtensions = extensions
	if options != nil {
		a.makeCredentialOptions = lo.Assign(options)
	}

	a.makeCredentialEnterpriseAttestation = enterpriseAttestation
	a.makeCredentialAttestationFormats = attestationFormatsPreference

	if pinUvAuthToken == nil && a.makeCredentialRequiresToken {
		return protocol.AuthenticatorMakeCredentialResponse{}, ctapdevice.ErrPinUvAuthTokenRequired
	}

	if a.makeCredentialErr != nil {
		if a.returnMakeCredentialResponseOnError {
			return sampleMakeCredentialResponse(), a.makeCredentialErr
		}

		return protocol.AuthenticatorMakeCredentialResponse{}, a.makeCredentialErr
	}

	return sampleMakeCredentialResponse(), nil
}

func (a *webauthnTestAuthenticator) GetAssertion(
	_ context.Context,
	pinUvAuthToken []byte,
	_ string,
	clientData []byte,
	_ []credential.PublicKeyCredentialDescriptor,
	extensions *webauthn.GetAuthenticationExtensionsClientInputs,
	options map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {
		a.getAssertionCalls++
		a.getAssertionToken = slices.Clone(pinUvAuthToken)
		a.getAssertionClientData = clientData
		a.getAssertionExtensions = extensions
		a.getAssertionOptions = maps.Clone(options)

		if pinUvAuthToken == nil && a.getAssertionRequiresBuiltInUV {
			yield(protocol.AuthenticatorGetAssertionResponse{}, ctapdevice.ErrBuiltInUVRequired)

			return
		}

		if pinUvAuthToken == nil && a.getAssertionRequiresToken {
			yield(protocol.AuthenticatorGetAssertionResponse{}, ctapdevice.ErrPinUvAuthTokenRequired)

			return
		}

		if a.getAssertionErr != nil && !a.getAssertionErrAfterFirst {
			yield(protocol.AuthenticatorGetAssertionResponse{}, a.getAssertionErr)

			return
		}

		if !yield(sampleAssertionResponse([]byte{0xc0, 0x5e}, []byte{0xaa, 0xbb}, []byte("user-1"), 2), nil) {
			return
		}

		if a.getAssertionErr != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, a.getAssertionErr)

			return
		}

		yield(sampleAssertionResponse([]byte{0xb0, 0xb0}, []byte{0xcc, 0xdd}, []byte("user-2"), 0), nil)
	}
}

func (a *webauthnTestAuthenticator) GetCredsMetadata(
	context.Context,
	[]byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	a.metadataCalls++

	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(1)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(8)),
	}, nil
}

func (a *webauthnTestAuthenticator) EnumerateRPs(
	context.Context,
	[]byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{
			RP:       credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
			RPIDHash: []byte("rp-hash"),
			TotalRPs: 1,
		}, nil)
	}
}

func (a *webauthnTestAuthenticator) EnumerateCredentials(
	context.Context,
	[]byte,
	[]byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(protocol.AuthenticatorCredentialManagementResponse{
			User: credential.PublicKeyCredentialUserEntity{
				ID:          []byte("user"),
				Name:        "alice@example.com",
				DisplayName: "Alice",
			},
			CredentialID: credential.PublicKeyCredentialDescriptor{
				Type: credential.PublicKeyCredentialTypePublicKey,
				ID:   []byte{0xc0, 0x5e},
			},
			TotalCredentials:  1,
			CredProtect:       0,
			ThirdPartyPayment: new(false),
		}, nil)
	}
}

func sampleMakeCredentialResponse() protocol.AuthenticatorMakeCredentialResponse {
	return protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: []byte{0x01, 0x02, 0x03},
		AuthData: &protocol.MakeCredentialAuthData{
			Flags:     protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagUserVerified,
			SignCount: 7,
			AttestedCredentialData: &protocol.AttestedCredentialData{
				AAGUID:       uuid.Must(uuid.Parse("00112233-4455-6677-8899-aabbccddeeff")),
				CredentialID: []byte{0xc0, 0x5e},
				CredentialPublicKey: cose.Key{
					cose.KeyParameterKty:    cose.KeyTypeEC2,
					cose.KeyParameterAlg:    cose.AlgorithmES256,
					cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
					cose.EC2KeyParameterX:   []byte{0x01},
					cose.EC2KeyParameterY:   []byte{0x02},
				},
			},
		},
		AttestationStatement: map[string]any{
			"alg": int64(-7),
			"sig": []byte{0x99},
		},
	}
}

func sampleAssertionResponse(
	credentialID []byte,
	signature []byte,
	userID []byte,
	numberOfCredentials uint,
) protocol.AuthenticatorGetAssertionResponse {
	return protocol.AuthenticatorGetAssertionResponse{
		Credential: credential.PublicKeyCredentialDescriptor{
			Type:       credential.PublicKeyCredentialTypePublicKey,
			ID:         credentialID,
			Transports: []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB},
		},
		AuthDataRaw: []byte{0x05, 0x06},
		AuthData: &protocol.GetAssertionAuthData{
			Flags:     protocol.AuthDataFlagUserPresent,
			SignCount: 9,
		},
		Signature:           signature,
		User:                &credential.PublicKeyCredentialUserEntity{ID: userID, Name: string(userID)},
		NumberOfCredentials: numberOfCredentials,
		UserSelected:        false,
	}
}
