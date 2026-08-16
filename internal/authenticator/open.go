package authenticator

import (
	"context"
	"errors"
	"io/fs"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	directhid "github.com/telesma-app/ctap/backend/hid"
	"github.com/telesma-app/ctap/backend/hidproxy"
	ctappcsc "github.com/telesma-app/ctap/backend/pcsc"
	"github.com/telesma-app/ctap/options"
	ctaptransport "github.com/telesma-app/ctap/transport"
	kitlog "github.com/telesma-app/kit/internal/logging"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
)

// Open opens the private CTAP authenticator implementation for a transport path.
func Open(ctx context.Context, mode transport.Mode, path string) (*Opened, error) {
	var (
		deviceTransport ctaptransport.Device
		err             error
	)
	switch mode {
	case transport.ModeHID:
		deviceTransport, err = directhid.Open(ctx, path)
	case transport.ModeWindowsProxy:
		deviceTransport, err = hidproxy.Open(ctx, path)
	case transport.ModeSmartCard:
		deviceTransport, err = ctappcsc.Open(ctx, path)
	default:
		panic("authenticator: invalid transport mode: " + string(mode))
	}

	var opts []options.Option
	if recorder := kitlog.RecorderFrom(ctx); recorder != nil {
		opts = append(opts, options.WithDiagnosticSink(kitlog.NewCTAPSink(recorder)))
	}

	if err == nil {
		device, newErr := ctapdevice.New(ctx, deviceTransport, opts...)
		if newErr != nil {
			err = errors.Join(newErr, deviceTransport.Close())
		} else {
			return &Opened{
				Lifecycle:           device,
				Info:                device,
				Vendor:              device,
				Tokens:              device,
				CredentialInventory: device,
				Credentials:         device,
				WebAuthn:            device,
				LargeBlobs:          device,
				ConfigStatus:        device,
				Config:              device,
				Bio:                 device,
			}, nil
		}
	}

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

	return nil, failure.Wrap(
		code,
		err,
		failure.WithPhase(failure.PhaseAuthenticator),
	)
}
