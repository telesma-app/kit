package ctapkit

import (
	"context"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/internal/authenticator"
)

// authenticatorConnectionTokenProvider keeps the runtime token service bound
// to the current transport generation across a conformance power cycle.
type authenticatorConnectionTokenProvider struct {
	connection *authenticatorConnection
}

func (p authenticatorConnectionTokenProvider) GetInfo(
	ctx context.Context,
) (protocol.AuthenticatorGetInfoResponse, error) {
	provider, err := p.current()
	if err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	return provider.GetInfo(ctx)
}

func (p authenticatorConnectionTokenProvider) GetInfoCached() (
	protocol.AuthenticatorGetInfoResponse,
	bool,
) {
	opened, _, ok := p.connection.Current()
	if !ok {
		return protocol.AuthenticatorGetInfoResponse{}, false
	}

	return opened.Tokens.GetInfoCached()
}

func (p authenticatorConnectionTokenProvider) GetPinUvAuthTokenUsingPIN(
	ctx context.Context,
	pin string,
	permission protocol.Permission,
	rpID string,
) ([]byte, error) {
	provider, err := p.current()
	if err != nil {
		return nil, err
	}

	return provider.GetPinUvAuthTokenUsingPIN(ctx, pin, permission, rpID)
}

func (p authenticatorConnectionTokenProvider) GetPinUvAuthTokenUsingUV(
	ctx context.Context,
	permission protocol.Permission,
	rpID string,
) ([]byte, error) {
	provider, err := p.current()
	if err != nil {
		return nil, err
	}

	return provider.GetPinUvAuthTokenUsingUV(ctx, permission, rpID)
}

func (p authenticatorConnectionTokenProvider) GetPINRetries(
	ctx context.Context,
) (uint, *bool, error) {
	provider, err := p.current()
	if err != nil {
		return 0, nil, err
	}

	return provider.GetPINRetries(ctx)
}

func (p authenticatorConnectionTokenProvider) current() (
	authenticator.TokenProvider,
	error,
) {
	opened, _, ok := p.connection.Current()
	if !ok {
		return nil, &ctaptransport.DeviceInvalidatedError{
			Err: p.connection.unavailableError(),
		}
	}

	return opened.Tokens, nil
}

var _ authenticator.TokenProvider = authenticatorConnectionTokenProvider{}
