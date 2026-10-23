package webauthn

import (
	"bytes"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/kit/model/failure"
	. "github.com/telesma-app/kit/model/webauthn"
)

func TestNormalizeMakeCredentialInputRequiresCoreFields(t *testing.T) {
	userPresenceFalse := false
	base := validMakeCredentialInput(nil)

	tests := []struct {
		name     string
		change   func(*MakeCredentialInput)
		wantCode failure.Code
	}{
		{
			name:     "rp id",
			wantCode: failure.CodeRelyingPartyIDRequired,
			change: func(input *MakeCredentialInput) {
				input.RP.ID = ""
			},
		},
		{
			name:     "user id",
			wantCode: failure.CodeUserIDRequired,
			change: func(input *MakeCredentialInput) {
				input.User.ID = nil
			},
		},
		{
			name:     "client data",
			wantCode: failure.CodeClientDataJSONRequired,
			change: func(input *MakeCredentialInput) {
				input.ClientDataJSON = nil
			},
		},
		{
			name:     "params",
			wantCode: failure.CodePublicKeyCredentialParametersRequired,
			change: func(input *MakeCredentialInput) {
				input.PubKeyCredParams = nil
			},
		},
		{
			name:     "algorithm",
			wantCode: failure.CodePublicKeyCredentialAlgorithmRequired,
			change: func(input *MakeCredentialInput) {
				input.PubKeyCredParams = []credential.PublicKeyCredentialParameters{{}}
			},
		},
		{
			name:     "user id length",
			wantCode: failure.CodeCTAPLengthInvalid,
			change: func(input *MakeCredentialInput) {
				input.User.ID = bytes.Repeat([]byte{0x01}, 65)
			},
		},
		{
			name:     "duplicate parameter",
			wantCode: failure.CodeCTAPParameterInvalid,
			change: func(input *MakeCredentialInput) {
				input.PubKeyCredParams = []credential.PublicKeyCredentialParameters{
					{Algorithm: -7},
					{Algorithm: -7},
				}
			},
		},
		{
			name:     "false user presence",
			wantCode: failure.CodeCTAPOptionInvalid,
			change: func(input *MakeCredentialInput) {
				input.Options = AuthenticatorOptions{UserPresence: &userPresenceFalse}
			},
		},
		{
			name:     "enterprise attestation",
			wantCode: failure.CodeCTAPOptionInvalid,
			change: func(input *MakeCredentialInput) {
				input.EnterpriseAttestation = 3
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := base
			tt.change(&input)

			_, err := NormalizeMakeCredentialInput(input)
			assertValidationFailure(t, err, tt.wantCode)
		})
	}
}

func TestNormalizeMakeCredentialInputPreservesCallerAttestationFormats(t *testing.T) {
	tests := []struct {
		name   string
		second attestation.AttestationStatementFormatIdentifier
	}{
		{name: "success", second: attestation.AttestationStatementFormatIdentifierNone},
		{name: "validation failure", second: " "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formats := []attestation.AttestationStatementFormatIdentifier{" packed ", tt.second}
			input := validMakeCredentialInput(nil)
			input.AttestationFormatsPreference = formats

			normalized, err := NormalizeMakeCredentialInput(input)

			if tt.second == " " {
				assertValidationFailure(t, err, failure.CodeCTAPParameterInvalid)
			} else {
				if err != nil {
					t.Fatalf("NormalizeMakeCredentialInput: %v", err)
				}

				want := []attestation.AttestationStatementFormatIdentifier{attestation.AttestationStatementFormatIdentifierPacked, tt.second}
				if !slices.Equal(normalized.AttestationFormatsPreference, want) {
					t.Errorf("normalized formats = %v, want %v", normalized.AttestationFormatsPreference, want)
				}
			}

			want := []attestation.AttestationStatementFormatIdentifier{" packed ", tt.second}
			if !slices.Equal(formats, want) {
				t.Errorf("caller formats = %v, want %v", formats, want)
			}
		})
	}
}

func TestNormalizeInputsTrimAndDefaultCredentialTypes(t *testing.T) {
	userID := []byte{0x0a, 0x0b}
	credentialID := []byte{0xc0, 0x5e}
	formats := []attestation.AttestationStatementFormatIdentifier{
		attestation.AttestationStatementFormatIdentifierPacked,
		attestation.AttestationStatementFormatIdentifierPacked,
		attestation.AttestationStatementFormatIdentifierNone,
	}

	input, err := NormalizeMakeCredentialInput(MakeCredentialInput{
		RP:             credential.PublicKeyCredentialRpEntity{ID: " example.com "},
		User:           credential.PublicKeyCredentialUserEntity{ID: userID},
		ClientDataJSON: []byte("client-data"),
		PubKeyCredParams: []credential.PublicKeyCredentialParameters{
			{Algorithm: -7},
			{Type: "future-key", Algorithm: -7},
		},
		ExcludeList: []credential.PublicKeyCredentialDescriptor{
			{ID: credentialID},
		},
		AttestationFormatsPreference: formats,
	})
	if err != nil {
		t.Fatalf("NormalizeMakeCredentialInput: %v", err)
	}

	if input.RP.ID != "example.com" {
		t.Fatalf("RP.ID = %q, want trimmed", input.RP.ID)
	}

	if !bytes.Equal(input.User.ID, userID) {
		t.Fatalf("User.ID = %#v, want original user id", input.User.ID)
	}

	if input.PubKeyCredParams[0].Type != PublicKeyCredentialTypePublicKey {
		t.Fatalf("param type = %q, want public-key", input.PubKeyCredParams[0].Type)
	}

	if input.PubKeyCredParams[1].Type != "future-key" {
		t.Fatalf("param type = %q, want future-key", input.PubKeyCredParams[1].Type)
	}

	if input.ExcludeList[0].Type != PublicKeyCredentialTypePublicKey ||
		!bytes.Equal(input.ExcludeList[0].ID, credentialID) {
		t.Fatalf("exclude descriptor = %#v, want default public-key with original id", input.ExcludeList[0])
	}

	if !slices.Equal(input.AttestationFormatsPreference, formats) {
		t.Fatalf("attestation formats = %#v, want original formats", input.AttestationFormatsPreference)
	}
}

func TestNormalizeGetAssertionInputValidatesAllowListID(t *testing.T) {
	_, err := NormalizeGetAssertionInput(GetAssertionInput{
		RPID:           "example.com",
		ClientDataJSON: []byte("client-data"),
		AllowList: []credential.PublicKeyCredentialDescriptor{
			{},
		},
	})
	assertValidationFailure(t, err, failure.CodeCredentialIDRequired)
}

func TestNormalizeGetAssertionInputRequiresCoreFields(t *testing.T) {
	tests := []struct {
		name     string
		input    GetAssertionInput
		wantCode failure.Code
	}{
		{
			name: "rp id",
			input: GetAssertionInput{
				ClientDataJSON: []byte("client-data"),
			},
			wantCode: failure.CodeRelyingPartyIDRequired,
		},
		{
			name: "client data",
			input: GetAssertionInput{
				RPID: "example.com",
			},
			wantCode: failure.CodeClientDataJSONRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeGetAssertionInput(tt.input)
			assertValidationFailure(t, err, tt.wantCode)
		})
	}
}

func assertValidationFailure(t *testing.T, err error, wantCode failure.Code) {
	t.Helper()

	if !failure.IsCode(err, wantCode) {
		t.Fatalf("error = %v, want %s", err, wantCode)
	}

	if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
		t.Fatalf("failure phase = %q, want %q", got, failure.PhaseValidation)
	}
}
