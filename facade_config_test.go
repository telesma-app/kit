package ctapkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/model"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
)

func TestConfigMutationCallerInputIsValidatedBeforeDeviceState(t *testing.T) {
	session := openContractAuthenticator(t, nil, nil)
	defer func() { _ = session.Close() }()

	_, err := session.SetAlwaysUV(t.Context(), appconfig.SetAlwaysUVOperation{
		Target: appconfig.AlwaysUVTarget("invalid"),
	})
	requireFailureCode(t, err, failure.CodeCTAPParameterInvalid)

	_, err = session.BioRename(t.Context(), appconfig.BioRenameOperation{
		TemplateIDHex: "not-hex",
		FriendlyName:  "finger",
	})
	requireFailureCode(t, err, failure.CodeBioTemplateIDInvalid)
}

func TestBioRenameUsesCanonicalTemplateIDAcrossPreviewCommandAndResult(t *testing.T) {
	a := &bioMutationAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.BioRename(t.Context(), appconfig.BioRenameOperation{
		TemplateIDHex: " 0A0B ",
		FriendlyName:  "finger",
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("BioRename: %v", err)
	}
	if output.Result == nil {
		t.Fatal("result = nil")
	}
	if output.Preview.TemplateIDHex != "0a0b" || output.Result.TemplateIDHex != "0a0b" {
		t.Fatalf("template IDs = %q/%q, want canonical 0a0b", output.Preview.TemplateIDHex, output.Result.TemplateIDHex)
	}
	if !bytes.Equal(a.templateID, []byte{0x0a, 0x0b}) {
		t.Fatalf("command template ID = %x, want 0a0b", a.templateID)
	}
}

func TestBioSensorInfoReportsSpecNamedEnums(t *testing.T) {
	tests := []struct {
		name string
		kind uint
		want appconfig.FingerprintKind
	}{
		{
			name: "touch",
			kind: 1,
			want: appconfig.FingerprintKindTouch,
		},
		{
			name: "swipe",
			kind: 2,
			want: appconfig.FingerprintKindSwipe,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &bioSensorAuthenticator{
				modality:        protocol.BioModalityFingerprint,
				fingerprintKind: tt.kind,
			}
			session := openContractAuthenticator(t, nil, a)
			defer func() { _ = session.Close() }()

			output, err := session.BioSensorInfo(context.Background(), session.operationOptions()...)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			if output.Modality != appconfig.BioModalityFingerprint {
				t.Fatalf("modality = %#v, want fingerprint", output.Modality)
			}

			if output.FingerprintKind != tt.want {
				t.Fatalf("fingerprintKind = %#v, want %s", output.FingerprintKind, tt.want)
			}

			raw, err := json.Marshal(output)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			text := string(raw)
			if !strings.Contains(text, `"modality":"fingerprint"`) {
				t.Fatalf("JSON = %s, want string modality", text)
			}

			if !strings.Contains(text, `"fingerprintKind":"`+string(tt.want)+`"`) {
				t.Fatalf("JSON = %s, want string fingerprint kind", text)
			}
		})
	}
}

func TestBioSensorInfoOmitsUnknownSpecValues(t *testing.T) {
	tests := []struct {
		name            string
		modality        protocol.BioModality
		fingerprintKind uint
	}{
		{
			name: "zero",
		},
		{
			name:            "unknown",
			modality:        protocol.BioModality(99),
			fingerprintKind: 99,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &bioSensorAuthenticator{
				modality:        tt.modality,
				fingerprintKind: tt.fingerprintKind,
			}
			session := openContractAuthenticator(t, nil, a)
			defer func() { _ = session.Close() }()

			output, err := session.BioSensorInfo(context.Background(), session.operationOptions()...)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			if output.Modality != "" {
				t.Fatalf("modality = %#v, want empty", output.Modality)
			}

			if output.FingerprintKind != "" {
				t.Fatalf("fingerprintKind = %#v, want empty", output.FingerprintKind)
			}

			raw, err := json.Marshal(output)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			text := string(raw)
			if strings.Contains(text, `"modality"`) || strings.Contains(text, `"fingerprintKind"`) {
				t.Fatalf("JSON = %s, want modality and fingerprintKind omitted", text)
			}
		})
	}
}

func TestResetRequestsTouchInteractionBeforeReset(t *testing.T) {
	events := &recordingEventSink{}
	a := &resetCountingAuthenticator{events: events}
	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindTouch {
			t.Fatalf("interaction kind = %s, want touch", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	_, err := session.ResetFactory(
		context.Background(),
		appconfig.ResetFactoryOperation{},
		session.operationOptions(WithInteractionHandler(handler))...,
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := a.resetCount.Load(); got != 1 {
		t.Fatalf("Reset count = %d, want 1", got)
	}

	if !a.touchSeenBeforeReset.Load() {
		t.Fatal("touch interaction was not emitted before reset")
	}
}

func TestResetStatusNormalization(t *testing.T) {
	tests := []struct {
		name    string
		command protocol.Command
		status  ctaptransport.StatusCode
		want    failure.Code
	}{
		{
			name:    "reset window expired",
			command: protocol.AuthenticatorReset,
			status:  ctaptransport.CTAP2_ERR_NOT_ALLOWED,
			want:    failure.CodeResetWindowExpired,
		},
		{
			name:    "user action timeout",
			command: protocol.AuthenticatorReset,
			status:  ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT,
			want:    failure.CodeResetTouchTimeout,
		},
		{
			name:    "action timeout",
			command: protocol.AuthenticatorReset,
			status:  ctaptransport.CTAP2_ERR_ACTION_TIMEOUT,
			want:    failure.CodeResetTouchTimeout,
		},
		{
			name:    "not allowed for another command",
			command: protocol.AuthenticatorMakeCredential,
			status:  ctaptransport.CTAP2_ERR_NOT_ALLOWED,
			want:    failure.CodeAuthenticatorOperationNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runConfirmedResetWithError(t, &ctaptransport.CTAPError{
				Command:    tt.command,
				StatusCode: tt.status,
			})

			requireFailureCode(t, err, tt.want)

			if _, ok := errors.AsType[*ctaptransport.CTAPError](err); !ok {
				t.Fatalf("Run error = %v, want original CTAPError in chain", err)
			}
		})
	}
}

func TestRunContextReachesTokenAndAuthenticatorCommand(t *testing.T) {
	type contextKey struct{}

	a := &contextRecordingConfigAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	marker := new(int)
	ctx := context.WithValue(context.Background(), contextKey{}, marker)
	if _, err := session.SetAlwaysUV(
		ctx,
		appconfig.SetAlwaysUVOperation{Target: appconfig.AlwaysUVTargetEnable},
		WithInteractionHandler(userVerificationHandler(t)),
	); err != nil {
		t.Fatalf("SetAlwaysUV: %v", err)
	}

	if got := a.tokenCtx.Value(contextKey{}); got != marker {
		t.Fatalf("token context value = %v, want marker", got)
	}

	if got := a.commandCtx.Value(contextKey{}); got != marker {
		t.Fatalf("command context value = %v, want marker", got)
	}
}

func TestBioEnrollmentCleanupUsesBoundedIndependentContext(t *testing.T) {
	type contextKey struct{}

	operationErr := errors.New("capture failed")
	cleanupErr := context.DeadlineExceeded
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "marker"))
	a := &bioCleanupAuthenticator{
		cancelOperation: cancel,
		captureErr:      operationErr,
		cleanupErr:      cleanupErr,
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	result, err := session.BioEnroll(
		ctx,
		appconfig.BioEnrollOperation{},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if !errors.Is(err, operationErr) {
		t.Fatalf("Run error = %v, want original capture error", err)
	}

	requireZero(t, result)

	if a.cleanupCtx == nil {
		t.Fatal("cleanup context was not recorded")
	}

	if err := a.cleanupContextErr; err != nil {
		t.Fatalf("cleanup context was already canceled during command: %v", err)
	}

	if got := a.cleanupCtx.Value(contextKey{}); got != "marker" {
		t.Fatalf("cleanup context value = %v, want marker", got)
	}

	deadline, ok := a.cleanupCtx.Deadline()
	if !ok {
		t.Fatal("cleanup context has no deadline")
	}

	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 2*time.Second {
		t.Fatalf("cleanup deadline remaining = %v, want within two seconds", remaining)
	}
}

func runConfirmedResetWithError(t *testing.T, resetErr error) error {
	t.Helper()

	events := &recordingEventSink{}
	a := &resetCountingAuthenticator{events: events, resetErr: resetErr}
	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindTouch {
			t.Fatalf("interaction kind = %s, want touch", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	_, err := session.ResetFactory(
		context.Background(),
		appconfig.ResetFactoryOperation{},
		session.operationOptions(WithInteractionHandler(handler))...,
	)
	if err == nil {
		t.Fatal("Run error = nil, want error")
	}

	return err
}

type contextRecordingConfigAuthenticator struct {
	contractAuthenticator
	contractConfigManager
	tokenCtx   context.Context
	commandCtx context.Context
}

type bioMutationAuthenticator struct {
	contractAuthenticator
	templateID []byte
}

func (a *bioMutationAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionBioEnroll:        true,
		protocol.OptionUvBioEnroll:      true,
		protocol.OptionPinUvAuthToken:   true,
		protocol.OptionUserVerification: true,
	}}, true
}

func (a *bioMutationAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *bioMutationAuthenticator) SetFriendlyName(_ context.Context, _ []byte, templateID []byte, _ string) error {
	a.templateID = templateID

	return nil
}

func (a *contextRecordingConfigAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionAuthenticatorConfig: true,
		protocol.OptionPinUvAuthToken:      true,
		protocol.OptionUserVerification:    true,
		protocol.OptionUvAcfg:              true,
		protocol.OptionAlwaysUv:            false,
	}}, true
}

func (a *contextRecordingConfigAuthenticator) GetPinUvAuthTokenUsingUV(
	ctx context.Context,
	_ protocol.Permission,
	_ string,
) ([]byte, error) {
	a.tokenCtx = ctx

	return []byte("token"), nil
}

func (a *contextRecordingConfigAuthenticator) ToggleAlwaysUV(ctx context.Context, token []byte) error {
	if token == nil {
		return ctapdevice.ErrPinUvAuthTokenRequired
	}

	a.commandCtx = ctx

	return nil
}

type bioCleanupAuthenticator struct {
	contractAuthenticator
	contractBioEnrollmentManager
	cancelOperation   context.CancelFunc
	captureErr        error
	cleanupErr        error
	cleanupCtx        context.Context
	cleanupContextErr error
}

func (a *bioCleanupAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionBioEnroll:        true,
		protocol.OptionUvBioEnroll:      true,
		protocol.OptionPinUvAuthToken:   true,
		protocol.OptionUserVerification: true,
	}}, true
}

func (a *bioCleanupAuthenticator) GetPinUvAuthTokenUsingUV(context.Context, protocol.Permission, string) ([]byte, error) {
	return []byte("token"), nil
}

func (a *bioCleanupAuthenticator) EnrollBegin(context.Context, []byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	remaining := uint(1)
	status := protocol.LastEnrollSampleStatusFingerprintGood

	return protocol.AuthenticatorBioEnrollmentResponse{
		TemplateID:             []byte("template"),
		LastEnrollSampleStatus: &status,
		RemainingSamples:       &remaining,
	}, nil
}

func (a *bioCleanupAuthenticator) EnrollCaptureNextSample(context.Context, []byte, []byte, uint) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	if a.cancelOperation != nil {
		a.cancelOperation()
	}

	return protocol.AuthenticatorBioEnrollmentResponse{}, a.captureErr
}

func (a *bioCleanupAuthenticator) CancelCurrentEnrollment(ctx context.Context) error {
	a.cleanupCtx = ctx
	a.cleanupContextErr = ctx.Err()

	return a.cleanupErr
}

type bioSensorAuthenticator struct {
	contractAuthenticator
	contractBioEnrollmentManager
	modality        protocol.BioModality
	fingerprintKind uint
}

func (a *bioSensorAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionBioEnroll: true,
		},
	}, true
}

func (a *bioSensorAuthenticator) GetBioModality(context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{Modality: a.modality}, nil
}

func (a *bioSensorAuthenticator) GetFingerprintSensorInfo(context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	return protocol.AuthenticatorBioEnrollmentResponse{FingerprintKind: a.fingerprintKind}, nil
}

func TestPINMutationsRejectEmptyPINAtSessionRun(t *testing.T) {
	tests := []struct {
		name   string
		set    *appconfig.SetPINOperation
		change *appconfig.ChangePINOperation
	}{
		{
			name: "set empty new PIN",
			set:  &appconfig.SetPINOperation{},
		},
		{
			name:   "change empty current PIN",
			change: &appconfig.ChangePINOperation{NewPIN: "5678"},
		},
		{
			name:   "change empty new PIN",
			change: &appconfig.ChangePINOperation{CurrentPIN: "1234"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &pinMutationCountingAuthenticator{configured: tt.change != nil}
			session := openContractAuthenticator(t, nil, a)
			defer func() { _ = session.Close() }()

			var result appconfig.PINOutput
			var err error
			if tt.set != nil {
				result, err = session.SetPIN(context.Background(), *tt.set, session.operationOptions()...)
			} else {
				result, err = session.ChangePIN(context.Background(), *tt.change, session.operationOptions()...)
			}
			requireZero(t, result)

			requireFailureCode(t, err, failure.CodePINRequired)

			if got := a.setCalls.Load(); got != 0 {
				t.Fatalf("SetPIN calls = %d, want 0", got)
			}

			if got := a.changeCalls.Load(); got != 0 {
				t.Fatalf("ChangePIN calls = %d, want 0", got)
			}
		})
	}
}

func TestUVTokenAcquisitionRequestsUserVerificationInteraction(t *testing.T) {
	events := &recordingEventSink{}
	a := &uvTokenAuthenticator{events: events}
	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindUserVerification {
			t.Fatalf("interaction kind = %s, want user-verification", req.Kind)
		}

		return model.InteractionResponse{}, nil
	})

	result, err := session.SetAlwaysUV(context.Background(), appconfig.SetAlwaysUVOperation{
		Target: appconfig.AlwaysUVTargetEnable,
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Result == nil {
		t.Fatal("result.Result = nil, want execution result")
	}

	if !a.uvCalled.Load() {
		t.Fatal("GetPinUvAuthTokenUsingUV was not called")
	}

	if !a.userVerificationSeen.Load() {
		t.Fatal("user-verification interaction was not emitted before UV token acquisition")
	}
}
