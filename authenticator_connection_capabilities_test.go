package ctapkit

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/internal/workflow"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	apptransport "github.com/telesma-app/kit/transport"
)

func TestOpenAuthenticatorHandleTokenProviderSwitchesGeneration(t *testing.T) {
	first := &authenticatorConnectionCapabilitiesDevice{marker: 10, cached: true}
	handle, err := openAuthenticatorHandle(
		t.Context(),
		newContractDevice(),
		func(context.Context, apptransport.Mode, string) (*authenticator.Opened, error) {
			return contractOpened(first), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	assertAuthenticatorConnectionTokenProvider(t, handle.tokenProvider, first)

	second := &authenticatorConnectionCapabilitiesDevice{marker: 20, cached: true}
	generation, err := handle.installConnection(
		1,
		authenticatorConnectionCapabilitiesReport("second"),
		contractOpened(second),
	)
	if err != nil || generation != 2 {
		t.Fatalf("installConnection() = (%d, %v), want (2, nil)", generation, err)
	}

	assertAuthenticatorConnectionTokenProvider(t, handle.tokenProvider, second)
	assertAuthenticatorConnectionCapabilitiesCalls(t, first, 1)
	assertAuthenticatorConnectionCapabilitiesCalls(t, second, 1)

	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatorConnectionTokenProviderGetInfoCachedSemantics(t *testing.T) {
	first := &authenticatorConnectionCapabilitiesDevice{marker: 10}
	connection := newAuthenticatorConnection(contractOpened(first))
	provider := authenticatorConnectionTokenProvider{connection: connection}

	info, valid := provider.GetInfoCached()
	if info.MaxMsgSize != first.cachedMarker() || valid {
		t.Fatalf("invalid first cache = (%#v, %t), want marker %d and false", info, valid, first.cachedMarker())
	}

	second := &authenticatorConnectionCapabilitiesDevice{marker: 20, cached: true}
	generation, err := connection.Install(1, contractOpened(second))
	if err != nil {
		t.Fatal(err)
	}
	info, valid = provider.GetInfoCached()
	if info.MaxMsgSize != second.cachedMarker() || !valid {
		t.Fatalf("valid second cache = (%#v, %t), want marker %d and true", info, valid, second.cachedMarker())
	}

	detachedGeneration, err := connection.Detach(generation)
	if err != nil {
		t.Fatal(err)
	}
	info, valid = provider.GetInfoCached()
	if !reflect.DeepEqual(info, protocol.AuthenticatorGetInfoResponse{}) || valid {
		t.Fatalf("detached cache = (%#v, %t), want zero and false", info, valid)
	}

	third := &authenticatorConnectionCapabilitiesDevice{marker: 30, cached: true}
	if _, err := connection.Install(detachedGeneration, contractOpened(third)); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	info, valid = provider.GetInfoCached()
	if !reflect.DeepEqual(info, protocol.AuthenticatorGetInfoResponse{}) || valid {
		t.Fatalf("closed cache = (%#v, %t), want zero and false", info, valid)
	}
}

func TestAuthenticatorConnectionTokenProviderUnavailableIsDeviceInvalidated(t *testing.T) {
	tests := []struct {
		name       string
		transition func(*testing.T, *authenticatorConnection)
		code       failure.Code
	}{
		{
			name: "detached",
			transition: func(t *testing.T, connection *authenticatorConnection) {
				t.Helper()
				if _, err := connection.Detach(1); err != nil {
					t.Fatal(err)
				}
			},
			code: failure.CodeTransportFailure,
		},
		{
			name: "closed",
			transition: func(t *testing.T, connection *authenticatorConnection) {
				t.Helper()
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
			},
			code: failure.CodeAuthenticatorClosed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			device := &authenticatorConnectionCapabilitiesDevice{marker: 10, cached: true}
			connection := newAuthenticatorConnection(contractOpened(device))
			provider := authenticatorConnectionTokenProvider{connection: connection}
			test.transition(t, connection)

			info, valid := provider.GetInfoCached()
			if !reflect.DeepEqual(info, protocol.AuthenticatorGetInfoResponse{}) || valid {
				t.Fatalf("GetInfoCached() = (%#v, %t), want zero and false", info, valid)
			}

			operations := []struct {
				name string
				run  func() error
			}{
				{name: "GetInfo", run: func() error { _, err := provider.GetInfo(t.Context()); return err }},
				{name: "GetPinUvAuthTokenUsingPIN", run: func() error {
					_, err := provider.GetPinUvAuthTokenUsingPIN(t.Context(), "1234", protocol.PermissionMakeCredential, "example.com")
					return err
				}},
				{name: "GetPinUvAuthTokenUsingUV", run: func() error {
					_, err := provider.GetPinUvAuthTokenUsingUV(t.Context(), protocol.PermissionGetAssertion, "example.com")
					return err
				}},
				{name: "GetPINRetries", run: func() error { _, _, err := provider.GetPINRetries(t.Context()); return err }},
			}
			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					assertAuthenticatorConnectionInvalidated(t, operation.run(), test.code)
				})
			}

			assertAuthenticatorConnectionCapabilitiesCalls(t, device, 0)
			if test.name == "detached" {
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAuthenticatorCurrentConformanceCapabilitiesSwitchGeneration(t *testing.T) {
	first := &authenticatorConnectionCapabilitiesDevice{marker: 10}
	connection := newAuthenticatorConnection(contractOpened(first))
	handle := &Authenticator{connection: connection}

	config, tokens, err := handle.currentConformanceCapabilities()
	if err != nil || config != first || tokens != first {
		t.Fatalf("first Current() = (%T, %T, %v), want first capabilities", config, tokens, err)
	}

	second := &authenticatorConnectionCapabilitiesDevice{marker: 20}
	generation, err := connection.Install(1, contractOpened(second))
	if err != nil {
		t.Fatal(err)
	}
	config, tokens, err = handle.currentConformanceCapabilities()
	if err != nil || config != second || tokens != second {
		t.Fatalf("second Current() = (%T, %T, %v), want second capabilities", config, tokens, err)
	}

	if _, err := connection.Detach(generation); err != nil {
		t.Fatal(err)
	}
	config, tokens, err = handle.currentConformanceCapabilities()
	if config != nil || tokens != nil {
		t.Fatalf("detached capabilities = (%T, %T), want nil", config, tokens)
	}
	assertAuthenticatorConnectionInvalidated(t, err, failure.CodeTransportFailure)

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	config, tokens, err = handle.currentConformanceCapabilities()
	if config != nil || tokens != nil {
		t.Fatalf("closed capabilities = (%T, %T), want nil", config, tokens)
	}
	assertAuthenticatorConnectionInvalidated(t, err, failure.CodeAuthenticatorClosed)
}

func TestAuthenticatorInstallConnectionPublishesCapabilitiesAndInvalidatesTokenOnDisplacedCloseError(t *testing.T) {
	closeError := errors.New("old close failed")
	first := &authenticatorConnectionCapabilitiesDevice{marker: 10, closeErr: closeError}
	handle := newAuthenticatorConnectionCapabilitiesHandle(first, "first")
	tokenKey, tokenHandle := cacheAuthenticatorConnectionToken(handle)

	second := &authenticatorConnectionCapabilitiesDevice{marker: 20}
	secondOpened := contractOpened(second)
	secondReport := authenticatorConnectionCapabilitiesReport("second")
	generation, err := handle.installConnection(1, secondReport, secondOpened)
	if generation != 2 || !errors.Is(err, closeError) {
		t.Fatalf("Install() = (%d, %v), want (2, displaced close error)", generation, err)
	}

	current, currentGeneration, ok := handle.connection.Current()
	if current != secondOpened || currentGeneration != generation || !ok {
		t.Fatalf("Current() = (%p, %d, %t), want (%p, 2, true)", current, currentGeneration, ok, secondOpened)
	}
	assertAuthenticatorConnectionCapabilitiesInstalled(t, handle, second, secondReport)
	if _, ok := handle.tokens.GetToken(tokenKey); ok {
		t.Fatal("superseded generation token remains cached")
	}
	if _, err := tokenHandle.Bytes(); !errors.Is(err, secret.ErrInvalidated) {
		t.Fatalf("superseded token error = %v, want ErrInvalidated", err)
	}

	if err := handle.connection.Close(); !errors.Is(err, closeError) {
		t.Fatalf("Close() = %v, want accumulated displaced close error", err)
	}
}

func TestAuthenticatorInstallConnectionRejectsStaleGenerationWithoutChangingCapabilitiesOrToken(t *testing.T) {
	first := &authenticatorConnectionCapabilitiesDevice{marker: 10}
	handle := newAuthenticatorConnectionCapabilitiesHandle(first, "first")
	tokenKey, tokenHandle := cacheAuthenticatorConnectionToken(handle)

	rejected := &authenticatorConnectionCapabilitiesDevice{marker: 20}
	rejectedReport := authenticatorConnectionCapabilitiesReport("rejected")
	generation, err := handle.installConnection(0, rejectedReport, contractOpened(rejected))
	if generation != 1 || !failure.IsCode(err, failure.CodeTransportFailure) {
		t.Fatalf("stale Install() = (%d, %v), want generation 1 transport failure", generation, err)
	}

	assertAuthenticatorConnectionCapabilitiesInstalled(
		t,
		handle,
		first,
		authenticatorConnectionCapabilitiesReport("first"),
	)
	if rejected.closeCalls.Load() != 1 {
		t.Fatalf("rejected owner close calls = %d, want 1", rejected.closeCalls.Load())
	}
	if token, ok := handle.tokens.GetToken(tokenKey); !ok || string(token) != "first-token" {
		t.Fatalf("current generation token = (%q, %t), want retained first token", token, ok)
	}
	if _, err := tokenHandle.Bytes(); err != nil {
		t.Fatalf("current generation token was invalidated: %v", err)
	}

	if err := handle.connection.Close(); err != nil {
		t.Fatal(err)
	}
}

type authenticatorConnectionCapabilitiesDevice struct {
	contractAuthenticator

	marker     uint
	cached     bool
	closeErr   error
	closeCalls atomic.Int32
	infoCalls  atomic.Int32
	cacheCalls atomic.Int32
	pinCalls   atomic.Int32
	uvCalls    atomic.Int32
	retryCalls atomic.Int32
}

func (d *authenticatorConnectionCapabilitiesDevice) Close() error {
	d.closeCalls.Add(1)

	return d.closeErr
}

func (d *authenticatorConnectionCapabilitiesDevice) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	d.infoCalls.Add(1)

	return protocol.AuthenticatorGetInfoResponse{MaxMsgSize: d.marker}, nil
}

func (d *authenticatorConnectionCapabilitiesDevice) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	d.cacheCalls.Add(1)

	return protocol.AuthenticatorGetInfoResponse{MaxMsgSize: d.cachedMarker()}, d.cached
}

func (d *authenticatorConnectionCapabilitiesDevice) GetPinUvAuthTokenUsingPIN(
	context.Context,
	string,
	protocol.Permission,
	string,
) ([]byte, error) {
	d.pinCalls.Add(1)

	return []byte{byte(d.marker)}, nil
}

func (d *authenticatorConnectionCapabilitiesDevice) GetPinUvAuthTokenUsingUV(
	context.Context,
	protocol.Permission,
	string,
) ([]byte, error) {
	d.uvCalls.Add(1)

	return []byte{byte(d.marker + 1)}, nil
}

func (d *authenticatorConnectionCapabilitiesDevice) GetPINRetries(context.Context) (uint, *bool, error) {
	d.retryCalls.Add(1)
	powerCycle := d.marker%2 == 0

	return d.marker, &powerCycle, nil
}

func (d *authenticatorConnectionCapabilitiesDevice) cachedMarker() uint {
	return d.marker + 1
}

func assertAuthenticatorConnectionTokenProvider(
	t *testing.T,
	provider authenticator.TokenProvider,
	want *authenticatorConnectionCapabilitiesDevice,
) {
	t.Helper()

	info, err := provider.GetInfo(t.Context())
	if err != nil || info.MaxMsgSize != want.marker {
		t.Fatalf("GetInfo() = (%#v, %v), want marker %d", info, err, want.marker)
	}
	info, valid := provider.GetInfoCached()
	if info.MaxMsgSize != want.cachedMarker() || valid != want.cached {
		t.Fatalf("GetInfoCached() = (%#v, %t), want marker %d and %t", info, valid, want.cachedMarker(), want.cached)
	}
	pinToken, err := provider.GetPinUvAuthTokenUsingPIN(
		t.Context(),
		"1234",
		protocol.PermissionMakeCredential,
		"example.com",
	)
	if err != nil || !reflect.DeepEqual(pinToken, []byte{byte(want.marker)}) {
		t.Fatalf("GetPinUvAuthTokenUsingPIN() = (%v, %v)", pinToken, err)
	}
	uvToken, err := provider.GetPinUvAuthTokenUsingUV(
		t.Context(),
		protocol.PermissionGetAssertion,
		"example.com",
	)
	if err != nil || !reflect.DeepEqual(uvToken, []byte{byte(want.marker + 1)}) {
		t.Fatalf("GetPinUvAuthTokenUsingUV() = (%v, %v)", uvToken, err)
	}
	retries, powerCycle, err := provider.GetPINRetries(t.Context())
	if err != nil || retries != want.marker || powerCycle == nil || !*powerCycle {
		t.Fatalf("GetPINRetries() = (%d, %v, %v), want (%d, true, nil)", retries, powerCycle, err, want.marker)
	}
}

func assertAuthenticatorConnectionCapabilitiesCalls(
	t *testing.T,
	device *authenticatorConnectionCapabilitiesDevice,
	want int32,
) {
	t.Helper()

	if device.infoCalls.Load() != want ||
		device.cacheCalls.Load() != want ||
		device.pinCalls.Load() != want ||
		device.uvCalls.Load() != want ||
		device.retryCalls.Load() != want {
		t.Fatalf(
			"provider calls = info:%d cache:%d PIN:%d UV:%d retries:%d, want %d each",
			device.infoCalls.Load(),
			device.cacheCalls.Load(),
			device.pinCalls.Load(),
			device.uvCalls.Load(),
			device.retryCalls.Load(),
			want,
		)
	}
}

func newAuthenticatorConnectionCapabilitiesHandle(
	device *authenticatorConnectionCapabilitiesDevice,
	id string,
) *Authenticator {
	opened := contractOpened(device)
	connection := newAuthenticatorConnection(opened)

	return &Authenticator{
		selected:            authenticatorConnectionCapabilitiesReport(id),
		connection:          connection,
		cbor:                connection,
		lifecycle:           connection,
		vendor:              device,
		info:                device,
		tokenProvider:       authenticatorConnectionTokenProvider{connection: connection},
		credentialInventory: device,
		credentials:         device,
		webAuthn:            device,
		largeBlobs:          device,
		configStatus:        device,
		config:              device,
		bio:                 device,
		tokens:              rtruntime.NewTokenStore(),
		largeBlobState:      workflow.NewLargeBlobState(),
	}
}

func cacheAuthenticatorConnectionToken(
	handle *Authenticator,
) (rtruntime.TokenKey, *secret.Handle) {
	key := rtruntime.TokenKey{
		Permission: protocol.PermissionMakeCredential,
		RPID:       "example.com",
	}
	token := secret.New([]byte("first-token"))
	handle.tokens.SetToken(key, token)

	return key, token
}

func assertAuthenticatorConnectionCapabilitiesInstalled(
	t *testing.T,
	handle *Authenticator,
	want *authenticatorConnectionCapabilitiesDevice,
	wantReport report.DeviceReport,
) {
	t.Helper()

	if !reflect.DeepEqual(handle.Device(), wantReport) ||
		handle.vendor != want ||
		handle.info != want ||
		handle.credentialInventory != want ||
		handle.credentials != want ||
		handle.webAuthn != want ||
		handle.largeBlobs != want ||
		handle.configStatus != want ||
		handle.config != want ||
		handle.bio != want {
		t.Fatalf("installed facade capabilities do not all belong to marker %d", want.marker)
	}
}

func authenticatorConnectionCapabilitiesReport(id string) report.DeviceReport {
	return report.DeviceReport{Attachment: report.AttachmentReport{ID: report.AttachmentID(id)}}
}

var _ authenticator.TokenProvider = (*authenticatorConnectionCapabilitiesDevice)(nil)
