package workflow

import (
	"testing"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/protocol"
	ctapwebauthn "github.com/telesma-app/ctap/webauthn"
	appwebauthn "github.com/telesma-app/kit/model/webauthn"
)

func TestMakeCredentialShouldTryWithoutTokenForPRFEvaluation(t *testing.T) {
	prfEvaluation := func() appwebauthn.MakeCredentialInput {
		return appwebauthn.MakeCredentialInput{
			Extensions: &ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
				PRFInputs: &ctapwebauthn.PRFInputs{PRF: ctapwebauthn.AuthenticationExtensionsPRFInputs{
					Eval: ctapwebauthn.AuthenticationExtensionsPRFValues{First: []byte{}},
				}},
			},
		}
	}
	prfSupported := []extension.ExtensionIdentifier{
		extension.ExtensionIdentifierHMACSecret,
		extension.ExtensionIdentifierHMACSecretMC,
	}

	tests := []struct {
		name  string
		info  protocol.AuthenticatorGetInfoResponse
		input appwebauthn.MakeCredentialInput
		want  bool
	}{
		{
			name: "UV token",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: prfSupported,
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
					protocol.OptionPinUvAuthToken:   true,
				},
			},
			input: prfEvaluation(),
			want:  false,
		},
		{
			name: "PIN token",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: prfSupported,
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			input: prfEvaluation(),
			want:  false,
		},
		{
			name: "hmac-secret-mc absent",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
				Options:    map[protocol.Option]bool{protocol.OptionClientPIN: true},
			},
			input: prfEvaluation(),
			want:  true,
		},
		{
			name: "PIN not configured",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: prfSupported,
				Options:    map[protocol.Option]bool{protocol.OptionClientPIN: false},
			},
			input: prfEvaluation(),
			want:  true,
		},
		{
			name: "PIN token lacks MakeCredential permission",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: prfSupported,
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                      true,
					protocol.OptionNoMcGaPermissionsWithClientPin: true,
				},
			},
			input: prfEvaluation(),
			want:  true,
		},
		{
			name: "eval absent",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: prfSupported,
				Options:    map[protocol.Option]bool{protocol.OptionClientPIN: true},
			},
			input: appwebauthn.MakeCredentialInput{
				Extensions: &ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
					PRFInputs: &ctapwebauthn.PRFInputs{},
				},
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := makeCredentialShouldTryWithoutToken(test.info, test.input); got != test.want {
				t.Fatalf("makeCredentialShouldTryWithoutToken() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestMakeCredentialExtensionResultsKeepRawOutputsAndMapLevel3Results(t *testing.T) {
	residentKey := false
	response := protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			CreateCredentialPropertiesOutputs: &ctapwebauthn.CreateCredentialPropertiesOutputs{
				CredentialProperties: ctapwebauthn.CredentialPropertiesOutput{ResidentKey: &residentKey},
			},
			CreateCredentialBlobOutputs: &ctapwebauthn.CreateCredentialBlobOutputs{CredBlob: true},
			CreateHMACSecretOutputs:     &ctapwebauthn.CreateHMACSecretOutputs{HMACCreateSecret: true},
			CreatePRFOutputs: &ctapwebauthn.CreatePRFOutputs{PRF: ctapwebauthn.CreateAuthenticationExtensionsPRFOutputs{
				Enabled: true,
				Results: ctapwebauthn.AuthenticationExtensionsPRFValues{
					First:  []byte{0x01, 0x02},
					Second: []byte{0x03, 0x04},
				},
			}},
		},
		AuthData: &protocol.MakeCredentialAuthData{Extensions: &protocol.CreateExtensionOutputs{
			CreateCredProtectOutput:  protocol.CreateCredProtectOutput{CredProtect: 0x03},
			CreateMinPinLengthOutput: protocol.CreateMinPinLengthOutput{MinPinLength: 8},
			CreatePinComplexityPolicyOutput: &protocol.CreatePinComplexityPolicyOutput{
				PinComplexityPolicy: true,
			},
		}},
	}

	got := makeCredentialExtensionResults(nil, response)
	if got == nil || got.Client == nil || got.Authenticator == nil {
		t.Fatalf("extension results = %#v, want client and authenticator sections", got)
	}

	if got.Client.CredentialProperties == nil || got.Client.CredentialProperties.ResidentKey == nil ||
		*got.Client.CredentialProperties.ResidentKey || got.Client.CredentialBlob == nil ||
		!got.Client.CredentialBlob.Accepted || got.Client.HMACSecret == nil ||
		!got.Client.HMACSecret.Enabled {
		t.Fatalf("client raw/credProps results = %#v", got.Client)
	}

	if got.Client.PRF == nil || !got.Client.PRF.Enabled ||
		len(got.Client.PRF.Results.First) != 2 || len(got.Client.PRF.Results.Second) != 2 {
		t.Fatalf("PRF result = %#v", got.Client.PRF)
	}

	if got.Authenticator.CredentialProtection == nil ||
		got.Authenticator.CredentialProtection.Policy != extension.CredentialProtectionPolicyUserVerificationRequired ||
		got.Authenticator.MinPINLength == nil || got.Authenticator.MinPINLength.Value != 8 ||
		got.Authenticator.PINComplexityPolicy == nil || !got.Authenticator.PINComplexityPolicy.Enabled {
		t.Fatalf("authenticator extension results = %#v", got.Authenticator)
	}
}

func TestMakeCredentialPRFUsesCTAPClientOutput(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "unsupported"},
		{name: "available", enabled: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := makeCredentialExtensionResults(nil, makeCredentialPRFResponse(test.enabled, nil, nil))
			if got == nil || got.Client == nil || got.Client.PRF == nil ||
				got.Client.PRF.Enabled != test.enabled || !got.Client.PRF.Results.IsZero() {
				t.Fatalf("PRF result = %#v, want enabled=%t without results", got, test.enabled)
			}
		})
	}
}

func TestMakeCredentialExtensionResultsStillRoutesRawHMACMC(t *testing.T) {
	raw := makeCredentialExtensionResults(&ctapwebauthn.CreateAuthenticationExtensionsClientInputs{
		CreateHMACSecretMCInputs: &ctapwebauthn.CreateHMACSecretMCInputs{},
	}, makeCredentialPRFResponse(true, []byte{0xaa}, []byte{0xbb}))
	if raw == nil || raw.Client == nil || raw.Client.HMACSecretMC == nil ||
		raw.Client.HMACSecretMC.Output1Hex != "aa" || raw.Client.HMACSecretMC.Output2Hex != "bb" ||
		raw.Client.PRF != nil {
		t.Fatalf("raw HMAC MC result = %#v", raw)
	}
}

func TestGetAssertionExtensionResultsUseLevel3PRFOutputWithoutEnabled(t *testing.T) {
	got := getAssertionExtensionResults(getAssertionPRFResponse([]byte{0x07, 0x08}, nil))
	if got == nil || got.Client == nil || got.Client.PRF == nil ||
		len(got.Client.PRF.Results.First) != 2 {
		t.Fatalf("GetAssertion PRF result = %#v", got)
	}

	empty := getAssertionExtensionResults(getAssertionPRFResponse(nil, nil))
	if empty == nil || empty.Client == nil || empty.Client.PRF == nil || !empty.Client.PRF.Results.IsZero() {
		t.Fatalf("empty PRF result = %#v, want {prf:{}}", empty)
	}
}

func TestGetAssertionExtensionResultsKeepRawOutputs(t *testing.T) {
	got := getAssertionExtensionResults(protocol.AuthenticatorGetAssertionResponse{ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
		GetCredentialBlobOutputs: &ctapwebauthn.GetCredentialBlobOutputs{GetCredBlob: []byte{0x01, 0x02}},
		GetHMACSecretOutputs: &ctapwebauthn.GetHMACSecretOutputs{HMACGetSecret: ctapwebauthn.HMACGetSecretOutput{
			Output1: []byte{0x03, 0x04},
			Output2: []byte{0x05, 0x06},
		}},
	}})
	if got == nil || got.Client == nil || got.Client.CredentialBlob == nil ||
		got.Client.CredentialBlob.ValueHex != "0102" || got.Client.HMACSecret == nil ||
		got.Client.HMACSecret.Output1Hex != "0304" || got.Client.HMACSecret.Output2Hex != "0506" {
		t.Fatalf("raw GetAssertion extension results = %#v", got)
	}
}

func TestPreviewSignExtensionResultsUseHexArtifacts(t *testing.T) {
	makeResult := makeCredentialExtensionResults(nil, protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			PreviewSignOutputs: &ctapwebauthn.PreviewSignOutputs{
				PreviewSign: ctapwebauthn.AuthenticationExtensionsPreviewSignOutputs{
					GeneratedKey: &ctapwebauthn.PreviewSignGeneratedKey{
						KeyHandle:         []byte{0x01, 0x02},
						PublicKey:         []byte{0xa5, 0x01},
						Algorithm:         cose.AlgorithmES256,
						AttestationObject: []byte{0xa3, 0x01},
					},
				},
			},
		},
	})
	if makeResult == nil || makeResult.Client == nil || makeResult.Client.PreviewSign == nil ||
		makeResult.Client.PreviewSign.GeneratedKey == nil {
		t.Fatalf("MakeCredential previewSign result = %#v", makeResult)
	}

	generatedKey := makeResult.Client.PreviewSign.GeneratedKey
	if generatedKey.KeyHandleHex != "0102" || generatedKey.PublicKeyCOSEHex != "a501" ||
		generatedKey.Algorithm != cose.AlgorithmES256 || generatedKey.AttestationObjectCBORHex != "a301" {
		t.Fatalf("previewSign generated key = %#v", generatedKey)
	}

	getResult := getAssertionExtensionResults(protocol.AuthenticatorGetAssertionResponse{
		ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
			PreviewSignOutputs: &ctapwebauthn.PreviewSignOutputs{
				PreviewSign: ctapwebauthn.AuthenticationExtensionsPreviewSignOutputs{
					Signature: []byte{0x03, 0x04},
				},
			},
		},
	})
	if getResult == nil || getResult.Client == nil || getResult.Client.PreviewSign == nil ||
		getResult.Client.PreviewSign.SignatureHex != "0304" {
		t.Fatalf("GetAssertion previewSign result = %#v", getResult)
	}

	emptySignature := getAssertionExtensionResults(protocol.AuthenticatorGetAssertionResponse{
		ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
			PreviewSignOutputs: &ctapwebauthn.PreviewSignOutputs{
				PreviewSign: ctapwebauthn.AuthenticationExtensionsPreviewSignOutputs{
					Signature: []byte{},
				},
			},
		},
	})
	if emptySignature == nil || emptySignature.Client == nil || emptySignature.Client.PreviewSign == nil ||
		emptySignature.Client.PreviewSign.SignatureHex != "" {
		t.Fatalf("present-empty previewSign signature = %#v", emptySignature)
	}
}

func TestWebAuthnLargeBlobOutputsPreserveOptionalPresence(t *testing.T) {
	unsupported := false
	makeResult := makeCredentialExtensionResults(nil, protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			LargeBlobOutputs: &ctapwebauthn.LargeBlobOutputs{LargeBlob: ctapwebauthn.AuthenticationExtensionsLargeBlobOutputs{
				Supported: &unsupported,
			}},
		},
	})
	if makeResult == nil || makeResult.Client == nil || makeResult.Client.LargeBlob == nil ||
		makeResult.Client.LargeBlob.Supported {
		t.Fatalf("make largeBlob output = %#v, want explicit false", makeResult)
	}

	written := false
	getResult := getAssertionExtensionResults(protocol.AuthenticatorGetAssertionResponse{
		ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
			LargeBlobOutputs: &ctapwebauthn.LargeBlobOutputs{LargeBlob: ctapwebauthn.AuthenticationExtensionsLargeBlobOutputs{
				Blob:    []byte{},
				Written: &written,
			}},
		},
		AuthData: &protocol.GetAssertionAuthData{Extensions: &protocol.GetExtensionOutputs{
			GetThirdPartyPaymentOutput: &protocol.GetThirdPartyPaymentOutput{ThirdPartyPayment: false},
		}},
	})
	if getResult == nil || getResult.Client == nil || getResult.Client.LargeBlob == nil ||
		getResult.Client.LargeBlob.BlobHex == nil || *getResult.Client.LargeBlob.BlobHex != "" ||
		getResult.Client.LargeBlob.Written == nil || *getResult.Client.LargeBlob.Written ||
		getResult.Authenticator == nil || getResult.Authenticator.ThirdPartyPayment == nil ||
		*getResult.Authenticator.ThirdPartyPayment {
		t.Fatalf("get extension output = %#v, want present-empty blob and explicit false outputs", getResult)
	}
}

func makeCredentialPRFResponse(enabled bool, first, second []byte) protocol.AuthenticatorMakeCredentialResponse {
	return protocol.AuthenticatorMakeCredentialResponse{
		ExtensionOutputs: &ctapwebauthn.CreateAuthenticationExtensionsClientOutputs{
			CreatePRFOutputs: &ctapwebauthn.CreatePRFOutputs{
				PRF: ctapwebauthn.CreateAuthenticationExtensionsPRFOutputs{
					Enabled: enabled,
					Results: ctapwebauthn.AuthenticationExtensionsPRFValues{
						First:  first,
						Second: second,
					},
				},
			},
		},
	}
}

func getAssertionPRFResponse(first, second []byte) protocol.AuthenticatorGetAssertionResponse {
	return protocol.AuthenticatorGetAssertionResponse{
		ExtensionOutputs: &ctapwebauthn.GetAuthenticationExtensionsClientOutputs{
			GetPRFOutputs: &ctapwebauthn.GetPRFOutputs{
				PRF: ctapwebauthn.GetAuthenticationExtensionsPRFOutputs{
					Results: ctapwebauthn.AuthenticationExtensionsPRFValues{
						First:  first,
						Second: second,
					},
				},
			},
		},
	}
}
