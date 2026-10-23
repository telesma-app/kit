package authenticator

import (
	"context"
	"errors"
	"io/fs"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	directhid "github.com/telesma-app/ctap/backend/hid"
	"github.com/telesma-app/ctap/backend/hidproxy"
	"github.com/telesma-app/ctap/options"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	kitlog "github.com/telesma-app/kit/internal/logging"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
)

func Open(ctx context.Context, mode transport.Mode, path string) (*Opened, error) {
	var (
		deviceTransport ctaptransport.Device
		smartCard       *SmartCard
		err             error
	)

	switch mode {
	case transport.ModeHID:
		deviceTransport, err = directhid.Open(ctx, path)
	case transport.ModeWindowsProxy:
		deviceTransport, err = hidproxy.Open(ctx, path)
	case transport.ModeSmartCard:
		var card *pcsc.Card

		card, err = pcsc.Open(path, pcsc.WithShareMode(pcsc.ShareModeShared), pcsc.WithDisconnectDisposition(pcsc.DispositionResetCard))
		if err == nil {
			smartCard = &SmartCard{Card: card, Interface: card.Interface()}
			deviceTransport = smartCard
		}
	default:
		panic("authenticator: invalid transport mode: " + string(mode))
	}

	if err != nil {
		return nil, openFailure(mode, err)
	}

	opened := &Opened{Lifecycle: deviceTransport, Card: smartCard}
	if hid, ok := deviceTransport.(*ctaphid.Transport); ok {
		opened.Vendor = hid
		opened.HIDInit = new(hid.InitResponse())
	}

	var opts []options.Option
	if recorder := kitlog.RecorderFrom(ctx); recorder != nil {
		opts = append(opts, options.WithDiagnosticSink(kitlog.NewCTAPSink(recorder)))
	}

	device, err := ctapdevice.New(ctx, deviceTransport, opts...)
	if err == nil {
		opened.Lifecycle = device
		opened.Info = device
		opened.Tokens = device
		opened.CredentialInventory = device
		opened.Credentials = device
		opened.WebAuthn = device
		opened.LargeBlobs = device
		opened.ConfigStatus = device
		opened.Config = device
		opened.Bio = device
	}

	if smartCard != nil {
		err = errors.Join(err, smartCard.EndFIDO(ctx))
	}

	if err != nil {
		return opened, openFailure(mode, err)
	}

	return opened, nil
}

func openFailure(mode transport.Mode, err error) error {
	code := failure.CodeTransportFailure

	switch {
	case errors.Is(err, context.Canceled):
		code = failure.CodeOperationCanceled
	case errors.Is(err, context.DeadlineExceeded):
		code = failure.CodeOperationTimeout
	case errors.Is(err, fs.ErrPermission), errors.Is(err, pcsc.ErrNoAccess):
		code = failure.CodeTransportPermissionDenied
	case mode == transport.ModeWindowsProxy:
		code = failure.CodeTransportProxyUnavailable
	}

	return failure.Wrap(
		code,
		err,
		failure.WithPhase(failure.PhaseAuthenticator),
	)
}
