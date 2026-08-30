package ctapkit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	rtinspect "github.com/telesma-app/kit/internal/inspect"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/largeblobs"
	"github.com/telesma-app/kit/model/report"
	webauthn2 "github.com/telesma-app/kit/model/webauthn"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/token2"
)

func TestOperationEventStagesHaveCountsWithoutPercent(t *testing.T) {
	completed := uint64(1)
	total := uint64(3)
	assertJSON(t, model.OperationEvent{
		Stage:     model.OperationStageEnumeratingRPs,
		Completed: &completed,
		Total:     &total,
	}, `{"stage":"enumerating-rps","completed":1,"total":3}`)
}

func TestOperationEventIncludesStateStages(t *testing.T) {
	assertJSON(t, model.OperationEvent{
		Stage: model.OperationStageCapturingBioSample,
	}, `{"stage":"capturing-bio-sample"}`)
}

func TestUserVerificationInteractionJSON(t *testing.T) {
	modality := protocol.UserVerifyFingerprintInternal
	assertJSON(t, model.InteractionRequest{
		Kind:       model.InteractionKindUserVerification,
		Permission: "credentialManagement",
		UVModality: &modality,
	}, `{"kind":"user-verification","permission":"credentialManagement","uvModality":2}`)
	assertJSON(t, VerificationFlowPIN, `"pin"`)
}

func TestPINInteractionJSON(t *testing.T) {
	powerCycleState := false
	tests := []struct {
		name  string
		state model.PINInteractionState
		want  string
	}{
		{
			name: "initial state",
			state: model.PINInteractionState{
				RetriesRemaining: new(uint(7)),
				PowerCycleState:  &powerCycleState,
			},
			want: `{"kind":"pin","permission":"credentialManagement","pinState":{"retriesRemaining":7,"powerCycleState":false}}`,
		},
		{
			name: "retry state",
			state: model.PINInteractionState{
				PreviousAttemptInvalid: true,
				RetriesRemaining:       new(uint(6)),
				PowerCycleState:        &powerCycleState,
			},
			want: `{"kind":"pin","permission":"credentialManagement","pinState":{"previousAttemptInvalid":true,"retriesRemaining":6,"powerCycleState":false}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertJSON(t, model.InteractionRequest{
				Kind:       model.InteractionKindPIN,
				Permission: "credentialManagement",
				PINState:   &tt.state,
			}, tt.want)
		})
	}
}

func TestInteractionRequestJSONIncludesPreviewAndResponseOmitsPIN(t *testing.T) {
	request := model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Factory reset fingerprint-1?",
		Destructive: true,
		Preview: map[string]any{
			"attachmentId": "fingerprint-1",
			"warnings":     []string{"factory reset erases authenticator state"},
		},
	}

	assertJSON(t, request, `{"kind":"touch","message":"Factory reset fingerprint-1?","destructive":true,"preview":{"attachmentId":"fingerprint-1","warnings":["factory reset erases authenticator state"]}}`)
	assertJSON(t, model.InteractionResponse{
		PIN: []byte("123456"),
	}, `{}`)
}

func TestPublicDTOJSONContractsUseCTAP23Spellings(t *testing.T) {
	// This audit test keeps public input/output names aligned with CTAP 2.3 spellings.
	tests := []struct {
		name  string
		value any
		want  []string
	}{
		{
			name: "inspect mirrors authenticator get info",
			value: rtinspect.BuildResult(report.DeviceReport{}, protocol.AuthenticatorGetInfoResponse{
				ForcePINChange:                true,
				MinPINLength:                  4,
				MaxCredentialIdLength:         32,
				MaxRPIDsForSetMinPINLength:    new(uint(3)),
				Algorithms:                    []credential.PublicKeyCredentialParameters{{Type: credential.PublicKeyCredentialTypePublicKey, Algorithm: -7}},
				Transports:                    []credential.AuthenticatorTransport{credential.AuthenticatorTransportUSB},
				AttestationFormats:            []attestation.AttestationStatementFormatIdentifier{attestation.AttestationStatementFormatIdentifierPacked},
				VendorPrototypeConfigCommands: []protocol.VendorCommandID{0x1_0000_0000},
				PinComplexityPolicy:           new(true),
				PinComplexityPolicyURL:        []byte("https://policy.example"),
				MaxPINLength:                  64,
				EncCredStoreState:             []byte("encrypted-store-state"),
				AuthenticatorConfigCommands:   []protocol.ConfigSubCommand{1, 4},
				UvModality:                    new(protocol.UserVerifyFingerprintInternal),
			}),
			want: []string{
				`"forcePINChange":true`,
				`"minPINLength":4`,
				`"maxCredentialIdLength":32`,
				`"maxRPIDsForSetMinPINLength":3`,
				`"algorithms":[{"type":"public-key","alg":-7}]`,
				`"transports":["usb"]`,
				`"attestationFormats":["packed"]`,
				`"vendorPrototypeConfigCommands":[4294967296]`,
				`"pinComplexityPolicyURL":"aHR0cHM6Ly9wb2xpY3kuZXhhbXBsZQ=="`,
				`"maxPINLength":64`,
				`"encCredStoreState":"ZW5jcnlwdGVkLXN0b3JlLXN0YXRl"`,
				`"authenticatorConfigCommands":[1,4]`,
				`"uvModality":2`,
				`"uvModalityLabel":"fingerprint_internal"`,
				`"assessment":{"facts":[`,
			},
		},
		{
			name: "credential inventory uses WebAuthn acronym spellings",
			value: credentials.InventoryReport{
				Summary: credentials.InventorySummary{TotalRPs: 1},
				Groups: []credentials.CredentialGroup{
					{
						RPID:        "example.com",
						RPIDHashHex: "abcd",
						Credentials: []credentials.CredentialRecord{
							{
								CredentialIDHex:   "beef",
								UserIDHex:         "0102",
								LargeBlobKeyState: "available",
							},
						},
					},
				},
			},
			want: []string{
				`"totalRPs":1`,
				`"rpID":"example.com"`,
				`"rpIDHashHex":"abcd"`,
				`"credentialIDHex":"beef"`,
				`"userIDHex":"0102"`,
				`"largeBlobKeyState":"available"`,
			},
		},
		{
			name: "credential operation inputs use ID spellings",
			value: credentials.UpdateUserOperation{
				Target:       credentials.CredentialTarget{},
				Name:         "updated",
				NameProvided: true,
			},
			want: []string{
				`"name":"updated"`,
				`"nameProvided":true`,
			},
		},
		{
			name:  "credential delete input uses ID spelling",
			value: credentials.DeleteOperation{CredentialIDHex: "beef"},
			want:  []string{`"credentialIDHex":"beef"`},
		},
		{
			name: "credential mutation outputs use lower-case wrappers",
			value: credentials.DeleteOutput{
				Preview: credentials.DeletePreview{
					CredentialIDHex: "beef",
					RPID:            "example.com",
					UserIDHex:       "0102",
				},
				Result: &credentials.DeleteResult{
					AttachmentID:    "fingerprint-1",
					CredentialIDHex: "beef",
					RPID:            "example.com",
					UserIDHex:       "0102",
				},
			},
			want: []string{
				`"preview"`,
				`"result"`,
				`"attachmentId":"fingerprint-1"`,
				`"credentialIDHex":"beef"`,
				`"rpID":"example.com"`,
				`"userIDHex":"0102"`,
			},
		},
		{
			name: "credential update outputs preserve previous and current identities",
			value: credentials.UpdateUserOutput{
				Preview: credentials.UpdateUserPreview{
					CredentialIDHex: "beef",
					RPID:            "example.com",
					Current:         credentials.UserIdentity{UserIDHex: "0102"},
					Proposed:        credentials.UserIdentity{UserIDHex: "0304"},
				},
				Result: &credentials.UpdateUserResult{
					AttachmentID:    "fingerprint-1",
					CredentialIDHex: "beef",
					RPID:            "example.com",
					Previous:        credentials.UserIdentity{UserIDHex: "0102"},
					Current:         credentials.UserIdentity{UserIDHex: "0304"},
				},
			},
			want: []string{
				`"attachmentId":"fingerprint-1"`,
				`"credentialIDHex":"beef"`,
				`"rpID":"example.com"`,
				`"userIDHex":"0304"`,
			},
		},
		{
			name: "WebAuthn operation kinds and inputs use acronym spellings",
			value: webauthn2.MakeCredentialOperation{
				MakeCredentialInput: webauthn2.MakeCredentialInput{
					RP:             credential.PublicKeyCredentialRpEntity{ID: "example.com"},
					User:           credential.PublicKeyCredentialUserEntity{ID: []byte{0x01, 0x02}},
					ClientDataJSON: []byte("client-data"),
					PubKeyCredParams: []credential.PublicKeyCredentialParameters{
						{Algorithm: -7},
					},
					ExcludeList: []credential.PublicKeyCredentialDescriptor{
						{ID: []byte{0xbe, 0xef}},
					},
				},
			},
			want: []string{
				`"rp"`,
				`"clientDataJSON"`,
				`"id":"AQI="`,
				`"pubKeyCredParams"`,
				`"id":"vu8="`,
			},
		},
		{
			name: "WebAuthn outputs include CTAP artifact spellings",
			value: webauthn2.MakeCredentialOutput{
				Result: &webauthn2.MakeCredentialResult{
					AttachmentID:             "fingerprint-1",
					RPID:                     "example.com",
					Format:                   "packed",
					CredentialIDHex:          "beef",
					PublicKeyCOSEHex:         "a50102",
					AuthenticatorDataHex:     "0102",
					AttestationObjectCBORHex: "a30102",
				},
			},
			want: []string{
				`"attachmentId":"fingerprint-1"`,
				`"rpID":"example.com"`,
				`"credentialIDHex":"beef"`,
				`"publicKeyCOSEHex":"a50102"`,
				`"authenticatorDataHex":"0102"`,
				`"attestationObjectCBORHex":"a30102"`,
			},
		},
		{
			name: "config status uses CTAP get info spellings",
			value: config.StatusReport{
				PIN: config.PINStatus{
					State:               config.StateConfigured,
					Supported:           true,
					Configured:          new(true),
					MinPINLength:        4,
					MaxPINLength:        64,
					ForcePINChange:      true,
					PinComplexityURL:    "https://policy.example",
					PinComplexityPolicy: new(true),
					Retries: config.RetryState{
						State:           config.StateSupported,
						Remaining:       new(uint(5)),
						PowerCycleState: new(true),
					},
				},
				Bio: config.BioStatus{
					UVBioEnroll:     config.CapabilityState{Supported: true},
					UVModality:      new(uint(2)),
					UVModalityLabel: "fingerprint_internal",
				},
				AuthenticatorConfig: config.AuthenticatorConfigStatus{
					UVAcfg: config.CapabilityState{Supported: true},
				},
				Limits: config.LimitsStatus{
					MaxRPIDsForSetMinPINLength: new(uint(3)),
				},
			},
			want: []string{
				`"minPINLength":4`,
				`"maxPINLength":64`,
				`"forcePINChange":true`,
				`"pinComplexityPolicyURL":"https://policy.example"`,
				`"uvBioEnroll"`,
				`"uvModality":2`,
				`"uvModalityLabel":"fingerprint_internal"`,
				`"uvAcfg"`,
				`"maxRPIDsForSetMinPINLength":3`,
				`"powerCycleState":true`,
			},
		},
		{
			name: "bio sensor output uses spec-named string enums",
			value: config.BioSensorReport{
				Supported:                          true,
				Modality:                           config.BioModalityFingerprint,
				FingerprintKind:                    config.FingerprintKindTouch,
				MaxCaptureSamplesRequiredForEnroll: new(uint(4)),
				MaxTemplateFriendlyName:            new(uint(64)),
			},
			want: []string{
				`"supported":true`,
				`"modality":"fingerprint"`,
				`"fingerprintKind":"touch"`,
				`"maxCaptureSamplesRequiredForEnroll":4`,
				`"maxTemplateFriendlyName":64`,
			},
		},
		{
			name: "authenticator config output names set min PIN length result",
			value: config.AuthenticatorConfigOutput{
				Preview: config.AuthenticatorConfigPreview{
					Operation:           config.AuthenticatorConfigMinPINLength,
					CurrentMinPINLength: 4,
					NewMinPINLength:     new(uint(8)),
					MaxPINLength:        64,
					MinPINLengthRPIDs:   []string{"example.com"},
					Authenticator: config.AuthenticatorConfigStatus{
						SetMinPINLength: config.CapabilityState{Supported: true},
					},
				},
				Result: &config.AuthenticatorConfigResult{
					Operation:       config.AuthenticatorConfigMinPINLength,
					NewMinPINLength: new(uint(8)),
					State:           config.StateSupported,
				},
			},
			want: []string{
				`"operation":"setMinPINLength"`,
				`"currentMinPINLength":4`,
				`"newMinPINLength":8`,
				`"maxPINLength":64`,
				`"minPinLengthRPIDs":["example.com"]`,
				`"setMinPINLength"`,
				`"newMinPINLength":8`,
			},
		},
		{
			name: "set min PIN length operation uses CTAP subcommand parameter names",
			value: config.SetMinPINLengthOperation{
				NewMinPINLength:     new(uint(8)),
				MinPINLengthRPIDs:   []string{"example.com"},
				ForceChangePIN:      true,
				PINComplexityPolicy: true,
			},
			want: []string{
				`"newMinPINLength":8`,
				`"minPinLengthRPIDs":["example.com"]`,
				`"forceChangePin":true`,
				`"pinComplexityPolicy":true`,
			},
		},
		{
			name: "bio operation input uses template ID spelling",
			value: []any{
				config.BioRenameOperation{TemplateIDHex: "abcd"},
				config.BioRemoveOperation{TemplateIDHex: "dcba"},
			},
			want: []string{
				`"templateIDHex":"abcd"`,
				`"templateIDHex":"dcba"`,
			},
		},
		{
			name: "bio outputs use template ID and enrollment sample names",
			value: config.BioEnrollOutput{
				Result: &config.BioEnrollResult{
					TemplateIDHex:          "abcd",
					LastEnrollSampleStatus: "good",
				},
			},
			want: []string{
				`"templateIDHex":"abcd"`,
				`"lastEnrollSampleStatus":"good"`,
			},
		},
		{
			name: "bio list records use template ID spelling",
			value: config.BioListReport{
				Enrollments: []config.BioEnrollmentRecord{
					{TemplateIDHex: "abcd"},
				},
			},
			want: []string{
				`"templateIDHex":"abcd"`,
			},
		},
		{
			name: "large blob read output uses credential target spellings",
			value: largeblobs.ReadReport{
				State: largeblobs.ReadStatePresent,
				Target: largeblobs.BlobTarget{
					CredentialIDHex: "beef",
					RP:              credentials.RelyingParty{ID: "example.com", IDHashHex: "abcd"},
					User:            credentials.UserIdentity{UserIDHex: "0102"},
				},
			},
			want: []string{
				`"credentialIDHex":"beef"`,
				`"idHashHex":"abcd"`,
				`"userIDHex":"0102"`,
			},
		},
		{
			name: "large blob operation input uses credential ID spelling",
			value: []any{
				largeblobs.ReadOperation{CredentialIDHex: "beef"},
				largeblobs.WriteOperation{CredentialIDHex: "cafe"},
				largeblobs.DeleteOperation{CredentialIDHex: "fade"},
			},
			want: []string{
				`"credentialIDHex":"beef"`,
				`"credentialIDHex":"cafe"`,
				`"credentialIDHex":"fade"`,
			},
		},
		{
			name: "large blob list output uses credential ID spelling",
			value: largeblobs.ListReport{
				Array: largeblobs.ListArraySummary{NonconformingBlobCount: 1},
				Entries: []largeblobs.ArrayEntry{
					{
						State: largeblobs.EntryStateMatched,
						Target: &largeblobs.BlobTarget{
							CredentialIDHex: "beef",
							User:            credentials.UserIdentity{UserIDHex: "0102"},
						},
					},
				},
			},
			want: []string{
				`"credentialIDHex":"beef"`,
				`"userIDHex":"0102"`,
				`"nonconformingBlobCount":1`,
			},
		},
		{
			name: "large blob mutation output names serialized array size",
			value: largeblobs.MutationOutput{
				Preview: largeblobs.MutationPreview{
					Target:                             largeblobs.BlobTarget{CredentialIDHex: "beef"},
					LargeBlobKeyState:                  largeblobs.LargeBlobKeyAvailable,
					SerializedLargeBlobArraySizeBefore: 10,
					SerializedLargeBlobArraySizeAfter:  20,
				},
				Result: &largeblobs.MutationResult{
					CredentialIDHex:                    "beef",
					RPID:                               "example.com",
					UserIDHex:                          "0102",
					SerializedLargeBlobArraySizeBefore: 10,
					SerializedLargeBlobArraySizeAfter:  20,
				},
			},
			want: []string{
				`"serializedLargeBlobArraySizeBefore":10`,
				`"serializedLargeBlobArraySizeAfter":20`,
				`"credentialIDHex":"beef"`,
				`"rpID":"example.com"`,
				`"userIDHex":"0102"`,
				`"largeBlobKeyState":"available"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("marshal output: %v", err)
			}

			text := string(raw)
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Fatalf("JSON missing %s: %s", want, text)
				}
			}

		})
	}
}

func TestPreviewSignResultJSONUsesArtifactSpellings(t *testing.T) {
	assertJSON(t, webauthn2.MakeCredentialClientExtensionResults{
		PreviewSign: &webauthn2.MakeCredentialPreviewSignOutput{
			GeneratedKey: &webauthn2.PreviewSignGeneratedKey{
				KeyHandleHex:             "0102",
				PublicKeyCOSEHex:         "a501",
				Algorithm:                -7,
				AttestationObjectCBORHex: "a301",
			},
		},
	}, `{"previewSign":{"generatedKey":{"keyHandleHex":"0102","publicKeyCOSEHex":"a501","algorithm":-7,"attestationObjectCBORHex":"a301"}}}`)

	assertJSON(t, webauthn2.GetAssertionClientExtensionResults{
		PreviewSign: &webauthn2.GetAssertionPreviewSignOutput{},
	}, `{"previewSign":{"signatureHex":""}}`)
}

func TestDeviceReportSmartCardInterfaceJSON(t *testing.T) {
	value := report.DeviceReport{
		Attachment: report.AttachmentReport{
			ID:        "attachment-1",
			Transport: transport.ModeSmartCard,
			SmartCard: &report.SmartCardReport{
				Reader:    "reader-one",
				ATR:       "3b80800101",
				Interface: transport.SmartCardInterfaceContactless,
			},
		},
	}

	assertJSON(t, value, `{"attachment":{"id":"attachment-1","transport":"smart-card","smartCard":{"reader":"reader-one","atr":"3b80800101","interface":"contactless"}}}`)
}

func TestDeviceReportIdentityJSON(t *testing.T) {
	value := report.DeviceReport{
		Attachment: report.AttachmentReport{
			ID:        "hid:one",
			Transport: transport.ModeHID,
		},
		Identity: &report.DeviceIdentityReport{
			Vendor:       report.DeviceVendorToken2,
			Name:         "Token2 USB-C NFC",
			SerialNumber: "86104012345678",
		},
	}

	assertJSON(t, value, `{"attachment":{"id":"hid:one","transport":"hid"},"identity":{"vendor":"token2","name":"Token2 USB-C NFC","serialNumber":"86104012345678"}}`)
}

func TestDeviceReportUsesToken2ProviderTypesJSON(t *testing.T) {
	value := report.DeviceReport{
		Attachment: report.AttachmentReport{
			ID:        "hid:token2",
			Transport: transport.ModeHID,
		},
		VendorMetadata: &report.DeviceVendorMetadata{
			Token2: &token2.DeviceInfo{
				SerialNumber: "72103654095303",
				Release:      "R3.2",
				FormFactor:   "Bio3 Dual A+C PIN+",
				Branding:     "Token2",
			},
		},
	}

	assertJSON(t, value, `{"attachment":{"id":"hid:token2","transport":"hid"},"vendorMetadata":{"token2":{"serialNumber":"72103654095303","release":"R3.2","formFactor":"Bio3 Dual A+C PIN+","branding":"Token2","interfaceStateKnown":false,"fidoEnabled":false,"hotpKeystrokeEnabled":false,"ccidEnabled":false,"capabilitiesKnown":false,"fidoPINSet":false,"fidoPINLocked":false,"supportsHOTP":false,"supportsTOTP":false,"supportsNFC":false,"supportsCCID":false,"supportsFIDO21":false,"hasFingerprintSensor":false,"supportsFingerprintRegistration":false,"supportsMandatoryFingerprint":false,"otpRequiresFingerprint":false,"supportsButtonHOTP":false,"buttonHOTPConfigured":false,"buttonHOTPSendsEnter":false,"buttonHOTPRequiresLongPress":false,"buttonHOTPUsesNumericKeypad":false}}}`)
}

func TestCTAP23JSONPresenceContracts(t *testing.T) {
	setMinPINLength := config.SetMinPINLengthOperation{
		NewMinPINLength: new(uint(0)),
	}

	assertJSON(t, setMinPINLength, `{"newMinPINLength":0}`)
	assertJSON(t, config.SetMinPINLengthOperation{}, `{}`)

	emptyBlob := ""
	written := false
	thirdPartyPayment := false
	extensions := webauthn2.GetAssertionExtensionResults{
		Client: &webauthn2.GetAssertionClientExtensionResults{
			LargeBlob: &webauthn2.LargeBlobGetOutput{BlobHex: &emptyBlob, Written: &written},
		},
		Authenticator: &webauthn2.GetAssertionAuthenticatorExtensionOutputs{
			ThirdPartyPayment: &thirdPartyPayment,
		},
	}

	assertJSON(t, extensions, `{"client":{"largeBlob":{"blobHex":"","written":false}},"authenticator":{"thirdPartyPayment":false}}`)
	assertJSON(t, credentials.StoreStateResult{
		AuthenticatorIdentifierHex: "00",
		CredentialStoreStateHex:    "11",
	}, `{"authenticatorIdentifierHex":"00","credentialStoreStateHex":"11"}`)
}

func assertJSON(t *testing.T, value any, want string) {
	t.Helper()

	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T): %v", value, err)
	}

	if string(raw) != want {
		t.Fatalf("json.Marshal(%T) = %s, want %s", value, raw, want)
	}
}
