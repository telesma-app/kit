package workflow

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/conformance/ctap23"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	apptransport "github.com/telesma-app/kit/transport"
)

func TestConformanceTransportMapsRuntimeAttachments(t *testing.T) {
	tests := []struct {
		mode        apptransport.Mode
		environment ConformanceEnvironment
		want        ctap23.AuthenticatorTransport
	}{
		{mode: apptransport.ModeHID, want: ctap23.AuthenticatorTransportHID},
		{mode: apptransport.ModeWindowsProxy, want: ctap23.AuthenticatorTransportHID},
		{mode: apptransport.ModeSmartCard, want: ctap23.AuthenticatorTransportNFC},
		{
			mode: apptransport.ModeHID,
			environment: ConformanceEnvironment{
				BLESessionProvider: func(context.Context, func(context.Context, ctap23.BLESession) error) error { return nil },
			},
			want: ctap23.AuthenticatorTransportBLE,
		},
	}

	for _, test := range tests {
		if got := conformanceTransport(test.mode, test.environment); got != test.want {
			t.Fatalf("conformanceTransport(%q) = %q, want %q", test.mode, got, test.want)
		}
	}
}

func TestSelectPinUvAuthProtocol(t *testing.T) {
	tests := []struct {
		name      string
		info      protocol.AuthenticatorGetInfoResponse
		want      protocol.PinUvAuthProtocol
		wantError bool
	}{
		{
			name: "first supported advertised protocol",
			info: protocol.AuthenticatorGetInfoResponse{PinUvAuthProtocols: []protocol.PinUvAuthProtocol{
				99,
				protocol.PinUvAuthProtocolTwo,
				protocol.PinUvAuthProtocolOne,
			}},
			want: protocol.PinUvAuthProtocolTwo,
		},
		{
			name: "preview UV token defaults to protocol one",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options:  map[protocol.Option]bool{protocol.OptionUvToken: true},
			},
			want: protocol.PinUvAuthProtocolOne,
		},
		{
			name:      "no supported protocol",
			info:      protocol.AuthenticatorGetInfoResponse{},
			wantError: true,
		},
		{
			name: "unknown advertised protocol",
			info: protocol.AuthenticatorGetInfoResponse{
				PinUvAuthProtocols: []protocol.PinUvAuthProtocol{99},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectPinUvAuthProtocol(tt.info)
			if tt.wantError {
				if !failure.IsCode(err, failure.CodeVerificationFlowUnsupported) {
					t.Fatalf("error = %v, want verification-flow unsupported", err)
				}
				if got != 0 {
					t.Fatalf("protocol = %d, want zero", got)
				}

				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("protocol = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestConformanceConfigResolvesCurrentGenerationForEveryCallback(t *testing.T) {
	firstConfig := &conformanceConfigDeviceStub{}
	secondConfig := &conformanceConfigDeviceStub{}
	firstTokens := &conformanceTokenProviderStub{info: protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
	}}
	secondTokens := &conformanceTokenProviderStub{info: protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
	}}

	currentConfig := ConfigDevice(firstConfig)
	currentTokens := rtauthenticator.TokenProvider(firstTokens)
	currentCalls := 0
	tokenService := &conformanceTokenServiceStub{token: make([]byte, 32)}
	interactions := &conformanceInteractionStub{}
	runner := NewRunner(Environment{
		Selected:     report.DeviceReport{Attachment: report.AttachmentReport{ID: "current-generation"}},
		Interactions: interactions,
		Tokens:       tokenService,
		Effects:      rtruntime.NewStateEffects(),
	})
	config := runner.conformanceConfig(ConformanceEnvironment{
		Current: func() (ConfigDevice, rtauthenticator.TokenProvider, error) {
			currentCalls++

			return currentConfig, currentTokens, nil
		},
	}, ctap23.RunRequest{})

	if err := config.Resetter(t.Context(), nil); err != nil {
		t.Fatalf("first reset: %v", err)
	}
	currentConfig = secondConfig
	currentTokens = secondTokens
	if err := config.Resetter(t.Context(), nil); err != nil {
		t.Fatalf("second reset: %v", err)
	}
	if firstConfig.resetCalls != 1 || secondConfig.resetCalls != 1 {
		t.Fatalf("reset calls = first %d, second %d; want one each", firstConfig.resetCalls, secondConfig.resetCalls)
	}

	currentConfig = firstConfig
	currentTokens = firstTokens
	first, err := config.TokenProvider(t.Context(), nil, ctap23.PinUvAuthTokenRequest{})
	if err != nil {
		t.Fatalf("first token: %v", err)
	}
	currentConfig = secondConfig
	currentTokens = secondTokens
	second, err := config.TokenProvider(t.Context(), nil, ctap23.PinUvAuthTokenRequest{})
	if err != nil {
		t.Fatalf("second token: %v", err)
	}
	if first.Protocol != protocol.PinUvAuthProtocolOne || second.Protocol != protocol.PinUvAuthProtocolTwo {
		t.Fatalf("token protocols = %d, %d; want 1, 2", first.Protocol, second.Protocol)
	}
	if currentCalls != 4 {
		t.Fatalf("Current calls = %d, want 4", currentCalls)
	}
	// Current selects the protocol and fallback provider for each generation;
	// ordinary token acquisition remains the Runner TokenService's job.
	if tokenService.useCalls != 2 {
		t.Fatalf("Runner token-service uses = %d, want 2", tokenService.useCalls)
	}
	if interactions.calls != 2 {
		t.Fatalf("interaction calls = %d, want two reset touches", interactions.calls)
	}
}

func TestConformanceConfigPropagatesCurrentErrorBeforeUsingCapabilities(t *testing.T) {
	cause := errors.New("connection generation is detached")
	currentCalls := 0
	tokenService := &conformanceTokenServiceStub{token: make([]byte, 32)}
	interactions := &conformanceInteractionStub{}
	runner := NewRunner(Environment{
		Interactions: interactions,
		Tokens:       tokenService,
		Effects:      rtruntime.NewStateEffects(),
	})
	config := runner.conformanceConfig(ConformanceEnvironment{
		Current: func() (ConfigDevice, rtauthenticator.TokenProvider, error) {
			currentCalls++

			return nil, nil, cause
		},
	}, ctap23.RunRequest{})

	if _, err := config.TokenProvider(t.Context(), nil, ctap23.PinUvAuthTokenRequest{}); !errors.Is(err, cause) {
		t.Fatalf("token error = %v, want %v", err, cause)
	}
	if err := config.Resetter(t.Context(), nil); !errors.Is(err, cause) {
		t.Fatalf("reset error = %v, want %v", err, cause)
	}
	if currentCalls != 2 {
		t.Fatalf("Current calls = %d, want 2", currentCalls)
	}
	if tokenService.useCalls != 0 || tokenService.invalidations != 0 || interactions.calls != 0 {
		t.Fatalf(
			"side effects = token uses %d, invalidations %d, interactions %d; want zero",
			tokenService.useCalls,
			tokenService.invalidations,
			interactions.calls,
		)
	}
}

func TestConformanceConfigPowerCycleBoundary(t *testing.T) {
	t.Run("absent boundary stays nil", func(t *testing.T) {
		runner := NewRunner(Environment{})
		config := runner.conformanceConfig(ConformanceEnvironment{}, ctap23.RunRequest{})
		if config.PowerCycler != nil {
			t.Fatal("PowerCycler is non-nil without a runtime boundary")
		}
	})

	t.Run("success invalidates after generation change", func(t *testing.T) {
		var order []string
		tokenService := &conformanceTokenServiceStub{order: &order}
		interactions := &conformanceInteractionStub{order: &order}
		runner := NewRunner(Environment{
			Selected:     report.DeviceReport{Attachment: report.AttachmentReport{ID: "cycle-target"}},
			Interactions: interactions,
			Tokens:       tokenService,
		})
		key := conformanceContextKey{}
		ctx := context.WithValue(t.Context(), key, "cycle-context")
		config := runner.conformanceConfig(ConformanceEnvironment{
			PowerCycle: func(callbackCtx context.Context, action func(context.Context) error) error {
				if got := callbackCtx.Value(key); got != "cycle-context" {
					t.Fatalf("power-cycle context value = %v", got)
				}
				order = append(order, "boundary-enter")
				if err := action(callbackCtx); err != nil {
					return err
				}
				order = append(order, "boundary-exit")

				return nil
			},
		}, ctap23.RunRequest{})

		if err := config.PowerCycler(ctx); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(order, []string{"boundary-enter", "interaction", "boundary-exit", "invalidate"}) {
			t.Fatalf("order = %v, want armed boundary, interaction, rebind, invalidation", order)
		}
		if len(interactions.requests) != 1 {
			t.Fatalf("interaction requests = %d, want 1", len(interactions.requests))
		}
		request := interactions.requests[0]
		if request.Kind != model.InteractionKindPowerCycle || !request.Destructive {
			t.Fatalf("power-cycle interaction = %#v", request)
		}
		if request.Message != "Physically power-cycle authenticator cycle-target and wait for it to reconnect." {
			t.Fatalf("power-cycle message = %q", request.Message)
		}
	})

	t.Run("error preserves cause and retained tokens", func(t *testing.T) {
		cause := errors.New("rebind failed")
		tokenService := &conformanceTokenServiceStub{}
		runner := NewRunner(Environment{Tokens: tokenService})
		config := runner.conformanceConfig(ConformanceEnvironment{
			PowerCycle: func(context.Context, func(context.Context) error) error {
				return cause
			},
		}, ctap23.RunRequest{})

		if err := config.PowerCycler(t.Context()); !errors.Is(err, cause) {
			t.Fatalf("error = %v, want %v", err, cause)
		}
		if tokenService.invalidations != 0 {
			t.Fatalf("invalidations = %d, want zero", tokenService.invalidations)
		}
	})

	t.Run("cancellation is propagated without invalidation", func(t *testing.T) {
		tokenService := &conformanceTokenServiceStub{}
		runner := NewRunner(Environment{Tokens: tokenService})
		config := runner.conformanceConfig(ConformanceEnvironment{
			PowerCycle: func(ctx context.Context, _ func(context.Context) error) error {
				return ctx.Err()
			},
		}, ctap23.RunRequest{})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if err := config.PowerCycler(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", err)
		}
		if tokenService.invalidations != 0 {
			t.Fatalf("invalidations = %d, want zero", tokenService.invalidations)
		}
	})

	t.Run("interaction error crosses boundary without invalidation", func(t *testing.T) {
		cause := errors.New("power-cycle interaction failed")
		interactions := &conformanceInteractionStub{err: cause}
		tokenService := &conformanceTokenServiceStub{}
		runner := NewRunner(Environment{
			Interactions: interactions,
			Tokens:       tokenService,
		})
		config := runner.conformanceConfig(ConformanceEnvironment{
			PowerCycle: func(ctx context.Context, action func(context.Context) error) error {
				return action(ctx)
			},
		}, ctap23.RunRequest{})

		if err := config.PowerCycler(t.Context()); !errors.Is(err, cause) {
			t.Fatalf("error = %v, want %v", err, cause)
		}
		if tokenService.invalidations != 0 {
			t.Fatalf("invalidations = %d, want zero", tokenService.invalidations)
		}
	})
}

func TestConformanceConfigPreservesEnvironmentDeclarations(t *testing.T) {
	enabled := true
	runner := NewRunner(Environment{})
	config := runner.conformanceConfig(ConformanceEnvironment{}, ctap23.RunRequest{
		LargeBlobEnabledByDefault: &enabled,
		AccountSelectionDisplay:   ctap23.AccountSelectionDisplayPresent,
		SecurityProfile:           ctap23.SecurityProfileEnterprise,
	})

	if config.LargeBlobEnabledByDefault != &enabled {
		t.Fatal("large-blob default policy declaration was not preserved")
	}
	if config.AccountSelectionDisplay != ctap23.AccountSelectionDisplayPresent {
		t.Fatalf("account-selection display = %q", config.AccountSelectionDisplay)
	}
	if config.SecurityProfile != ctap23.SecurityProfileEnterprise {
		t.Fatalf("security profile = %q", config.SecurityProfile)
	}
}

func TestConformanceConfigTemporaryPINAndUVInteractions(t *testing.T) {
	pin := []byte("123456")
	interactions := &conformanceInteractionStub{response: model.InteractionResponse{PIN: pin}}
	runner := NewRunner(Environment{
		Selected:     report.DeviceReport{Attachment: report.AttachmentReport{ID: "interaction-target"}},
		Interactions: interactions,
	})
	config := runner.conformanceConfig(ConformanceEnvironment{}, ctap23.RunRequest{})
	pinRequest := ctap23.TemporaryPINRequest{MinCodePoints: 6, MaxCodePoints: 63}

	gotPIN, err := config.TemporaryPINProvider(t.Context(), pinRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotPIN) == 0 || &gotPIN[0] != &pin[0] {
		t.Fatal("temporary PIN ownership was not transferred directly to the suite")
	}
	borrowedPIN := slices.Clone(gotPIN)
	if err := config.UVConfigurator(t.Context(), borrowedPIN); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(borrowedPIN, gotPIN) {
		t.Fatal("UV configuration modified the borrowed PIN")
	}
	if len(interactions.requests) != 2 {
		t.Fatalf("interaction requests = %d, want 2", len(interactions.requests))
	}
	temporaryPINInteraction := interactions.requests[0]
	if temporaryPINInteraction.Kind != model.InteractionKindPIN || !temporaryPINInteraction.Destructive {
		t.Fatalf("temporary PIN interaction = %#v", temporaryPINInteraction)
	}
	if temporaryPINInteraction.Message != "Provide a temporary PIN for destructive CTAP 2.3 conformance testing on authenticator interaction-target." {
		t.Fatalf("temporary PIN message = %q", temporaryPINInteraction.Message)
	}
	if temporaryPINInteraction.Preview != pinRequest {
		t.Fatalf("temporary PIN preview = %#v, want %#v", temporaryPINInteraction.Preview, pinRequest)
	}
	uvInteraction := interactions.requests[1]
	if uvInteraction.Kind != model.InteractionKindUserVerificationConfiguration || !uvInteraction.Destructive {
		t.Fatalf("UV configuration interaction = %#v", uvInteraction)
	}
	if uvInteraction.Message != "Configure built-in user verification on authenticator interaction-target for CTAP 2.3 conformance testing." {
		t.Fatalf("UV configuration message = %q", uvInteraction.Message)
	}
}

func TestConformanceConfigTemporaryPINAndUVInteractionErrors(t *testing.T) {
	cause := errors.New("interaction failed")
	interactions := &conformanceInteractionStub{err: cause}
	runner := NewRunner(Environment{Interactions: interactions})
	config := runner.conformanceConfig(ConformanceEnvironment{}, ctap23.RunRequest{})

	gotPIN, err := config.TemporaryPINProvider(t.Context(), ctap23.TemporaryPINRequest{})
	if !errors.Is(err, cause) || gotPIN != nil {
		t.Fatalf("temporary PIN result = %q, %v; want nil, %v", gotPIN, err, cause)
	}
	if err := config.UVConfigurator(t.Context(), []byte("borrowed")); !errors.Is(err, cause) {
		t.Fatalf("UV configuration error = %v, want %v", err, cause)
	}
	if err := config.BiometricSampleProvider(t.Context()); !errors.Is(err, cause) {
		t.Fatalf("biometric sample interaction error = %v, want %v", err, cause)
	}
	if err := config.PrepareAccountSelection(t.Context(), ctap23.AccountSelectionRequest{}); !errors.Is(err, cause) {
		t.Fatalf("account-selection interaction error = %v, want %v", err, cause)
	}
}

func TestConformanceConfigBiometricSampleInteraction(t *testing.T) {
	interactions := &conformanceInteractionStub{}
	runner := NewRunner(Environment{
		Selected:     report.DeviceReport{Attachment: report.AttachmentReport{ID: "biometric-target"}},
		Interactions: interactions,
	})
	config := runner.conformanceConfig(ConformanceEnvironment{}, ctap23.RunRequest{})

	if err := config.BiometricSampleProvider(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(interactions.requests) != 1 {
		t.Fatalf("interaction requests = %d, want 1", len(interactions.requests))
	}
	request := interactions.requests[0]
	if request.Kind != model.InteractionKindUserVerification || !request.Destructive {
		t.Fatalf("biometric sample interaction = %#v", request)
	}
	if request.Message != "Present the requested fingerprint sample to authenticator biometric-target." {
		t.Fatalf("biometric sample message = %q", request.Message)
	}
	if request.UVModality == nil || *request.UVModality != protocol.UserVerifyFingerprintInternal {
		t.Fatalf("biometric sample modality = %#v", request.UVModality)
	}
}

func TestConformanceConfigAccountSelectionInteraction(t *testing.T) {
	interactions := &conformanceInteractionStub{}
	runner := NewRunner(Environment{
		Selected:     report.DeviceReport{Attachment: report.AttachmentReport{ID: "selection-target"}},
		Interactions: interactions,
	})
	config := runner.conformanceConfig(ConformanceEnvironment{}, ctap23.RunRequest{})
	request := ctap23.AccountSelectionRequest{
		RPID:        "selection.example",
		UserID:      []byte{1, 2, 3},
		Name:        "account",
		DisplayName: "Account",
	}

	if err := config.PrepareAccountSelection(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if len(interactions.requests) != 1 {
		t.Fatalf("interaction requests = %d, want 1", len(interactions.requests))
	}
	interaction := interactions.requests[0]
	if interaction.Kind != model.InteractionKindAccountSelection || !interaction.Destructive {
		t.Fatalf("account-selection interaction = %#v", interaction)
	}
	if interaction.Message != "Select the requested account on authenticator selection-target." {
		t.Fatalf("account-selection message = %q", interaction.Message)
	}
	preview, ok := interaction.Preview.(ctap23.AccountSelectionRequest)
	if !ok || preview.RPID != request.RPID ||
		!slices.Equal(preview.UserID, request.UserID) ||
		preview.Name != request.Name || preview.DisplayName != request.DisplayName {
		t.Fatalf("account-selection preview = %#v, want %#v", interaction.Preview, request)
	}
}

func TestRunCTAP23ConformanceBindsRunnerToEnvironmentCBOR(t *testing.T) {
	currentCalls := 0
	runner := NewRunner(Environment{})
	_, err := runner.RunCTAP23Conformance(t.Context(), ConformanceEnvironment{
		Current: func() (ConfigDevice, rtauthenticator.TokenProvider, error) {
			currentCalls++

			return nil, nil, nil
		},
	}, ctap23.RunRequest{})
	if !errors.Is(err, client.ErrTransportNotConfigured) {
		t.Fatalf("error = %v, want unconfigured stable CBOR boundary", err)
	}
	if currentCalls != 0 {
		t.Fatalf("Current calls before suite execution = %d, want zero", currentCalls)
	}
}

type conformanceConfigDeviceStub struct {
	ConfigDevice
	resetCalls int
	resetErr   error
}

func (d *conformanceConfigDeviceStub) Reset(context.Context) error {
	d.resetCalls++

	return d.resetErr
}

type conformanceTokenProviderStub struct {
	rtauthenticator.TokenProvider
	info protocol.AuthenticatorGetInfoResponse
}

func (d *conformanceTokenProviderStub) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	return d.info, nil
}

func (d *conformanceTokenProviderStub) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return d.info, true
}

type conformanceTokenServiceStub struct {
	token         []byte
	useErr        error
	useCalls      int
	invalidations int
	order         *[]string
}

func (s *conformanceTokenServiceStub) Use(
	_ context.Context,
	_ rtruntime.TokenUse,
	use func([]byte) error,
) error {
	s.useCalls++
	if s.useErr != nil {
		return s.useErr
	}

	return use(s.token)
}

func (s *conformanceTokenServiceStub) Invalidate() {
	s.invalidations++
	if s.order != nil {
		*s.order = append(*s.order, "invalidate")
	}
}

func (*conformanceTokenServiceStub) InvalidateUnlessPermission(protocol.Permission) {}

type conformanceInteractionStub struct {
	response model.InteractionResponse
	err      error
	calls    int
	requests []model.InteractionRequest
	order    *[]string
}

func (s *conformanceInteractionStub) RequestInteraction(
	_ context.Context,
	request model.InteractionRequest,
) (model.InteractionResponse, error) {
	s.calls++
	s.requests = append(s.requests, request)
	if s.order != nil {
		*s.order = append(*s.order, "interaction")
	}

	return s.response, s.err
}

type conformanceContextKey struct{}
