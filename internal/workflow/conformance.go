package workflow

import (
	"context"
	"slices"

	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
	"github.com/telesma-app/kit/conformance/ctap23"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
	apptransport "github.com/telesma-app/kit/transport"
)

// ConformanceEnvironment binds one CTAP 2.3 run to the owning runtime's
// replaceable authenticator connection.
type ConformanceEnvironment struct {
	CBOR ctaptransport.CBOR
	// Raw transport providers temporarily detach the normal CTAP connection,
	// lend one exclusive observation session, and rebind before returning.
	HIDSessionProvider ctap23.HIDSessionProvider
	NFCCardProvider    ctap23.NFCCardProvider
	BLESessionProvider ctap23.BLESessionProvider
	// Current returns capabilities from one currently installed authenticator
	// connection generation. Rebindable runtimes resolve it for every callback
	// so reset and token-provider fallback operations never retain a superseded
	// device. The Runner's TokenService must separately use a stable dynamic
	// TokenProvider because cached-token acquisition does not call Current.
	Current func() (ConfigDevice, rtauthenticator.TokenProvider, error)
	// PowerCycle arms the owning runtime's rebind boundary before invoking
	// action for a physical HID or BLE cycle. An NFC implementation resets and
	// rebinds its card session without invoking action. A nil callback means the
	// owning runtime cannot satisfy physical power-cycle tests.
	PowerCycle func(context.Context, func(context.Context) error) error
}

// RunCTAP23Conformance executes the selected CTAP 2.3 tests over the opened
// authenticator's raw command boundary while routing tokens and resets through
// the owning runtime.
func (r Runner) RunCTAP23Conformance(
	ctx context.Context,
	environment ConformanceEnvironment,
	request ctap23.RunRequest,
) (conformance.SuiteResult, error) {
	suite, err := ctap23.SuiteFor(request.Mode, r.conformanceConfig(environment, request))
	if err != nil {
		return conformance.SuiteResult{}, err
	}

	runner, err := conformance.NewRunner(environment.CBOR)
	if err != nil {
		return conformance.SuiteResult{}, err
	}

	return runner.Run(ctx, suite)
}

func (r Runner) conformanceConfig(
	environment ConformanceEnvironment,
	request ctap23.RunRequest,
) ctap23.Config {
	config := ctap23.Config{
		Metadata:                  request.Metadata,
		Transport:                 conformanceTransport(r.env.Selected.Attachment.Transport, environment),
		Featureful:                request.Featureful,
		AccountSelectionDisplay:   request.AccountSelectionDisplay,
		SecurityProfile:           request.SecurityProfile,
		LargeBlobEnabledByDefault: request.LargeBlobEnabledByDefault,
		HIDSessionProvider:        environment.HIDSessionProvider,
		NFCCardProvider:           environment.NFCCardProvider,
		BLESessionProvider:        environment.BLESessionProvider,
		TokenProvider: func(
			ctx context.Context,
			_ *client.Client,
			request ctap23.PinUvAuthTokenRequest,
		) (ctap23.PinUvAuthToken, error) {
			device, tokenDevice, err := environment.Current()
			if err != nil {
				return ctap23.PinUvAuthToken{}, err
			}

			return r.conformanceToken(ctx, device, tokenDevice, request)
		},
		Resetter: func(ctx context.Context, _ *client.Client) error {
			device, _, err := environment.Current()
			if err != nil {
				return err
			}

			return r.conformanceReset(ctx, device)
		},
		TemporaryPINProvider: r.conformanceTemporaryPIN,
		UVConfigurator:       r.conformanceUVConfigurator,
		BiometricSampleProvider: func(ctx context.Context) error {
			modality := protocol.UserVerifyFingerprintInternal
			_, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
				Kind:        model.InteractionKindUserVerification,
				Message:     "Present the requested fingerprint sample to authenticator " + string(r.env.Selected.Attachment.ID) + ".",
				Destructive: true,
				UVModality:  &modality,
			})

			return err
		},
		PrepareAccountSelection: func(ctx context.Context, request ctap23.AccountSelectionRequest) error {
			_, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
				Kind:        model.InteractionKindAccountSelection,
				Message:     "Select the requested account on authenticator " + string(r.env.Selected.Attachment.ID) + ".",
				Destructive: true,
				Preview:     request,
			})

			return err
		},
	}
	if environment.PowerCycle != nil {
		config.PowerCycler = func(ctx context.Context) error {
			action := func(actionCtx context.Context) error {
				_, err := r.env.Interactions.RequestInteraction(actionCtx, model.InteractionRequest{
					Kind:        model.InteractionKindPowerCycle,
					Message:     "Physically power-cycle authenticator " + string(r.env.Selected.Attachment.ID) + " and wait for it to reconnect.",
					Destructive: true,
				})

				return err
			}
			if err := environment.PowerCycle(ctx, action); err != nil {
				return err
			}

			r.env.Tokens.Invalidate()

			return nil
		}
	}

	return config
}

func (r Runner) conformanceTemporaryPIN(
	ctx context.Context,
	request ctap23.TemporaryPINRequest,
) ([]byte, error) {
	response, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindPIN,
		Message:     "Provide a temporary PIN for destructive CTAP 2.3 conformance testing on authenticator " + string(r.env.Selected.Attachment.ID) + ".",
		Destructive: true,
		Preview:     request,
	})
	if err != nil {
		return nil, err
	}

	// Ownership transfers from the interaction broker to the suite, which
	// wipes the buffer when the current test ends.
	return response.PIN, nil
}

func (r Runner) conformanceUVConfigurator(ctx context.Context, _ []byte) error {
	_, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindUserVerificationConfiguration,
		Message:     "Configure built-in user verification on authenticator " + string(r.env.Selected.Attachment.ID) + " for CTAP 2.3 conformance testing.",
		Destructive: true,
	})

	return err
}

func conformanceTransport(
	mode apptransport.Mode,
	environment ConformanceEnvironment,
) ctap23.AuthenticatorTransport {
	if environment.BLESessionProvider != nil {
		return ctap23.AuthenticatorTransportBLE
	}
	if environment.NFCCardProvider != nil {
		return ctap23.AuthenticatorTransportNFC
	}
	if environment.HIDSessionProvider != nil {
		return ctap23.AuthenticatorTransportHID
	}
	if mode == apptransport.ModeSmartCard {
		return ctap23.AuthenticatorTransportNFC
	}

	return ctap23.AuthenticatorTransportHID
}

func (r Runner) conformanceToken(
	ctx context.Context,
	device ConfigDevice,
	tokenDevice rtauthenticator.TokenProvider,
	request ctap23.PinUvAuthTokenRequest,
) (ctap23.PinUvAuthToken, error) {
	info, err := rtauthenticator.ResolveInfo(ctx, tokenDevice)
	if err != nil {
		return ctap23.PinUvAuthToken{}, err
	}
	selectedProtocol, err := selectPinUvAuthProtocol(info)
	if err != nil {
		return ctap23.PinUvAuthToken{}, err
	}

	token, err := r.acquireConformanceToken(ctx, request)
	if !failure.IsCode(err, failure.CodePINNotConfigured) {
		return ctap23.PinUvAuthToken{Protocol: selectedProtocol, Value: token}, err
	}

	response, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:       model.InteractionKindPIN,
		Message:    "Create a temporary PIN for CTAP 2.3 conformance testing.",
		Permission: request.Permission.String(),
	})
	if err != nil {
		return ctap23.PinUvAuthToken{}, err
	}
	defer secret.Zero(response.PIN)

	err = device.SetPIN(ctx, string(response.PIN))
	r.env.Tokens.Invalidate()
	if err != nil {
		return ctap23.PinUvAuthToken{}, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.ClientPINSubCommandSetPIN,
		))
	}

	token, err = tokenDevice.GetPinUvAuthTokenUsingPIN(
		ctx,
		string(response.PIN),
		request.Permission,
		request.RPID,
	)
	if err != nil {
		return ctap23.PinUvAuthToken{}, errornorm.Annotate(err, errornorm.WithClientPINSubCommand(
			failure.PhaseTokenAcquisition,
			protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		))
	}

	return ctap23.PinUvAuthToken{Protocol: selectedProtocol, Value: token}, nil
}

func selectPinUvAuthProtocol(info protocol.AuthenticatorGetInfoResponse) (protocol.PinUvAuthProtocol, error) {
	for _, candidate := range info.PinUvAuthProtocols {
		switch candidate {
		case protocol.PinUvAuthProtocolOne, protocol.PinUvAuthProtocolTwo:
			return candidate, nil
		}
	}

	if len(info.PinUvAuthProtocols) == 0 &&
		info.Versions.IsPreviewOnly() && info.Options[protocol.OptionUvToken] {
		return protocol.PinUvAuthProtocolOne, nil
	}

	return 0, failure.New(
		failure.CodeVerificationFlowUnsupported,
		failure.WithPhase(failure.PhaseTokenAcquisition),
	)
}

func (r Runner) acquireConformanceToken(
	ctx context.Context,
	request ctap23.PinUvAuthTokenRequest,
) ([]byte, error) {
	var token []byte
	err := r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: request.Permission,
		RPID:       request.RPID,
	}, func(value []byte) error {
		token = slices.Clone(value)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (r Runner) conformanceReset(ctx context.Context, device ConfigDevice) error {
	if _, err := r.env.Interactions.RequestInteraction(ctx, model.InteractionRequest{
		Kind:        model.InteractionKindTouch,
		Message:     "Touch authenticator " + string(r.env.Selected.Attachment.ID) + " to continue the destructive conformance reset.",
		Destructive: true,
	}); err != nil {
		return err
	}

	r.recordStateEffect(rtruntime.StateEffectAuthenticatorReset)
	err := device.Reset(ctx)
	r.env.Tokens.Invalidate()
	if err != nil {
		return errornorm.Annotate(err, errornorm.WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorReset,
		))
	}

	return nil
}
