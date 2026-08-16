package ctapkit

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/model"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/operation"
)

type closeCountingAuthenticator struct {
	contractAuthenticator
	closeStarted chan struct{}
	releaseClose chan struct{}
	closeCount   atomic.Int32
}

func (a *closeCountingAuthenticator) Close() error {
	if a.closeCount.Add(1) == 1 {
		close(a.closeStarted)
		<-a.releaseClose
	}

	return nil
}

type cancelablePINConfigAuthenticator struct {
	contractAuthenticator
	contractConfigManager
	closeStarted chan struct{}
	closeCount   atomic.Int32
}

func (a *cancelablePINConfigAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionAuthenticatorConfig: true,
		protocol.OptionClientPIN:           true,
		protocol.OptionPinUvAuthToken:      true,
		protocol.OptionAlwaysUv:            false,
	}}, true
}

func (a *cancelablePINConfigAuthenticator) ToggleAlwaysUV(context.Context, []byte) error {
	return ctapdevice.ErrPinUvAuthTokenRequired
}

func (a *cancelablePINConfigAuthenticator) Close() error {
	if a.closeCount.Add(1) == 1 {
		close(a.closeStarted)
	}

	return nil
}

type contextualInteractionHandlerFunc func(context.Context, model.InteractionRequest) (model.InteractionResponse, error)

func (f contextualInteractionHandlerFunc) RequestInteraction(
	ctx context.Context,
	req model.InteractionRequest,
) (model.InteractionResponse, error) {
	return f(ctx, req)
}

type blockingConfigAuthenticator struct {
	contractAuthenticator
	contractConfigManager
	commandEntered chan struct{}
}

func (a *blockingConfigAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionAuthenticatorConfig: true,
		protocol.OptionPinUvAuthToken:      true,
		protocol.OptionUserVerification:    true,
		protocol.OptionUvAcfg:              true,
		protocol.OptionAlwaysUv:            false,
	}}, true
}

func (a *blockingConfigAuthenticator) GetPinUvAuthTokenUsingUV(
	context.Context,
	protocol.Permission,
	string,
) ([]byte, error) {
	return []byte("token"), nil
}

func (a *blockingConfigAuthenticator) ToggleAlwaysUV(ctx context.Context, token []byte) error {
	if token == nil {
		return ctapdevice.ErrPinUvAuthTokenRequired
	}

	close(a.commandEntered)
	<-ctx.Done()

	return ctx.Err()
}

type closeReleasedConfigAuthenticator struct {
	blockingConfigAuthenticator
	commandReleased chan struct{}
	closeCount      atomic.Int32
}

func (a *closeReleasedConfigAuthenticator) ToggleAlwaysUV(ctx context.Context, token []byte) error {
	if token == nil {
		return ctapdevice.ErrPinUvAuthTokenRequired
	}

	close(a.commandEntered)
	<-a.commandReleased

	return ctx.Err()
}

func (a *closeReleasedConfigAuthenticator) Close() error {
	if a.closeCount.Add(1) == 1 {
		close(a.commandReleased)
	}

	return nil
}

func TestAuthenticatorTypedOperationContract(t *testing.T) {
	opened := openContractAuthenticator(t, nil, nil)
	defer func() { _ = opened.Close() }()

	output, err := opened.ConfigStatus(context.Background(), WithInteractionHandler(nil))
	if err != nil {
		t.Fatalf("ConfigStatus: %v", err)
	}

	if output.Device.Attachment.ID == "" {
		t.Fatalf("unexpected output: %#v", output)
	}
}

func TestAuthenticatorPreCompletedContextHasAuthenticatorPhase(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	deadline, deadlineCancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
	defer deadlineCancel()

	tests := []struct {
		name string
		ctx  context.Context
		code failure.Code
	}{
		{name: "canceled", ctx: canceled, code: failure.CodeOperationCanceled},
		{name: "deadline", ctx: deadline, code: failure.CodeOperationTimeout},
	}

	opened := openContractAuthenticator(t, nil, nil)
	defer func() { _ = opened.Close() }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := opened.ConfigStatus(tt.ctx)
			requireFailureCode(t, err, tt.code)

			snapshot := failure.Snapshot(err)
			if snapshot.Operation != string(operation.ConfigStatus) {
				t.Fatalf("operation = %q, want %q", snapshot.Operation, operation.ConfigStatus)
			}

			if snapshot.Phase != failure.PhaseAuthenticator {
				t.Fatalf("phase = %q, want %q", snapshot.Phase, failure.PhaseAuthenticator)
			}
		})
	}
}

func TestAuthenticatorCloseClosesAuthenticatorOnce(t *testing.T) {
	a := &closeCountingAuthenticator{
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
	opened := openContractAuthenticator(t, nil, a)
	defer func() { _ = opened.Close() }()

	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)

	go func() {
		firstErr <- opened.Close()
	}()

	<-a.closeStarted

	go func() {
		secondErr <- opened.Close()
	}()

	close(a.releaseClose)

	for _, err := range []error{<-firstErr, <-secondErr} {
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	if got := a.closeCount.Load(); got != 1 {
		t.Fatalf("authenticator close count = %d, want 1", got)
	}
}

func TestAuthenticatorCloseCancelsActiveRunAndClosesAuthenticatorOnce(t *testing.T) {
	a := &cancelablePINConfigAuthenticator{
		closeStarted: make(chan struct{}),
	}
	opened := openContractAuthenticator(t, nil, a)

	interactionEntered := make(chan struct{})
	runDone := make(chan error, 1)
	handler := contextualInteractionHandlerFunc(func(ctx context.Context, _ model.InteractionRequest) (model.InteractionResponse, error) {
		close(interactionEntered)
		<-ctx.Done()

		return model.InteractionResponse{}, ctx.Err()
	})

	go func() {
		_, err := opened.SetAlwaysUV(
			context.Background(),
			appconfig.SetAlwaysUVOperation{Target: appconfig.AlwaysUVTargetEnable},
			opened.operationOptions(WithInteractionHandler(handler))...,
		)
		runDone <- err
	}()

	select {
	case <-interactionEntered:
	case err := <-runDone:
		t.Fatalf("Run returned before PIN interaction: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Run did not reach PIN interaction")
	}

	closeDone := make(chan error, 2)

	go func() { closeDone <- opened.Close() }()

	select {
	case <-a.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Authenticator.Close did not close authenticator")
	}

	go func() { closeDone <- opened.Close() }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Authenticator.Close: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Authenticator.Close did not return")
		}
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("Run was not canceled by Authenticator.Close")
	}

	if got := a.closeCount.Load(); got != 1 {
		t.Fatalf("authenticator close count = %d, want 1", got)
	}
}

func TestAuthenticatorCloseCancelsBlockedAuthenticatorCommand(t *testing.T) {
	a := &blockingConfigAuthenticator{commandEntered: make(chan struct{})}
	opened := openContractAuthenticator(t, nil, a)
	defer func() { _ = opened.Close() }()

	runDone := make(chan error, 1)
	go func() {
		_, err := opened.SetAlwaysUV(
			context.Background(),
			appconfig.SetAlwaysUVOperation{Target: appconfig.AlwaysUVTargetEnable},
			opened.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
		)
		runDone <- err
	}()

	select {
	case <-a.commandEntered:
	case <-time.After(time.Second):
		t.Fatal("Run did not reach authenticator command")
	}

	if err := opened.Close(); err != nil {
		t.Fatalf("Authenticator.Close: %v", err)
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("blocked authenticator command did not observe cancellation")
	}
}

func TestAuthenticatorCloseReleasesTransportBeforeWaitingForBlockedCommand(t *testing.T) {
	a := &closeReleasedConfigAuthenticator{
		blockingConfigAuthenticator: blockingConfigAuthenticator{
			commandEntered: make(chan struct{}),
		},
		commandReleased: make(chan struct{}),
	}
	opened := openContractAuthenticator(t, nil, a)

	runDone := make(chan error, 1)
	go func() {
		_, err := opened.SetAlwaysUV(
			context.Background(),
			appconfig.SetAlwaysUVOperation{Target: appconfig.AlwaysUVTargetEnable},
			opened.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
		)
		runDone <- err
	}()

	select {
	case <-a.commandEntered:
	case <-time.After(time.Second):
		t.Fatal("Run did not reach authenticator command")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- opened.Close() }()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Authenticator.Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Authenticator.Close did not release the blocked transport command")
	}

	select {
	case err := <-runDone:
		requireFailureCode(t, err, failure.CodeOperationCanceled)
	case <-time.After(time.Second):
		t.Fatal("blocked authenticator command did not return after transport close")
	}

	if got := a.closeCount.Load(); got != 1 {
		t.Fatalf("authenticator close count = %d, want 1", got)
	}
}

func TestRunAfterAuthenticatorCloseIsRejected(t *testing.T) {
	opened := openContractAuthenticator(t, nil, nil)

	if err := opened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	result, err := opened.ConfigStatus(context.Background(), opened.operationOptions()...)
	requireFailureCode(t, err, failure.CodeAuthenticatorClosed)
	requireZero(t, result)
}

func TestTransportConnectionFailureClosesAuthenticator(t *testing.T) {
	tests := []ctaptransport.IOOperation{
		ctaptransport.IORead,
		ctaptransport.IOWrite,
		ctaptransport.IOTransmit,
	}

	for _, ioOperation := range tests {
		t.Run(string(ioOperation), func(t *testing.T) {
			a := &transportFailureAuthenticator{
				operation:   ioOperation,
				invalidated: true,
			}
			opened := openContractAuthenticator(t, nil, a)

			_, err := opened.SetPIN(context.Background(), appconfig.SetPINOperation{
				NewPIN: "1234",
			}, opened.operationOptions()...)
			requireFailureCode(t, err, failure.CodeTransportFailure)

			if !opened.Closed() {
				t.Fatal("opened remained open after transport connection failure")
			}

			if got := a.closeCount.Load(); got != 1 {
				t.Fatalf("authenticator close count = %d, want 1", got)
			}

			_, err = opened.ConfigStatus(context.Background(), opened.operationOptions()...)
			requireFailureCode(t, err, failure.CodeAuthenticatorClosed)

			if err := opened.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			if got := a.closeCount.Load(); got != 1 {
				t.Fatalf("authenticator close count after duplicate Close = %d, want 1", got)
			}
		})
	}
}

func TestTransportFailureWithoutDeviceInvalidationKeepsAuthenticatorOpen(t *testing.T) {
	tests := []ctaptransport.IOOperation{
		ctaptransport.IORead,
		ctaptransport.IOWrite,
		ctaptransport.IOTransmit,
	}

	for _, ioOperation := range tests {
		t.Run(string(ioOperation), func(t *testing.T) {
			a := &transportFailureAuthenticator{operation: ioOperation}
			opened := openContractAuthenticator(t, nil, a)

			_, err := opened.SetPIN(context.Background(), appconfig.SetPINOperation{
				NewPIN: "1234",
			}, opened.operationOptions()...)
			requireFailureCode(t, err, failure.CodeTransportFailure)

			if opened.Closed() {
				t.Fatal("opened closed without device invalidation")
			}

			if got := a.closeCount.Load(); got != 0 {
				t.Fatalf("authenticator close count = %d, want 0", got)
			}

			if err := opened.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			if got := a.closeCount.Load(); got != 1 {
				t.Fatalf("authenticator close count after Close = %d, want 1", got)
			}
		})
	}
}

func TestCanceledTransmitWithoutDeviceInvalidationKeepsAuthenticatorOpen(t *testing.T) {
	a := &transportFailureAuthenticator{
		operation: ctaptransport.IOTransmit,
		cause:     context.Canceled,
	}
	opened := openContractAuthenticator(t, nil, a)
	defer func() { _ = opened.Close() }()

	_, err := opened.SetPIN(context.Background(), appconfig.SetPINOperation{
		NewPIN: "1234",
	}, opened.operationOptions()...)
	requireFailureCode(t, err, failure.CodeOperationCanceled)

	if opened.Closed() {
		t.Fatal("opened closed after a canceled transmit without device invalidation")
	}

	if got := a.closeCount.Load(); got != 0 {
		t.Fatalf("authenticator close count = %d, want 0", got)
	}
}

type transportFailureAuthenticator struct {
	contractAuthenticator
	contractConfigManager
	operation   ctaptransport.IOOperation
	cause       error
	invalidated bool
	closeCount  atomic.Int32
}

func (a *transportFailureAuthenticator) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: false,
		},
	}, true
}

func (a *transportFailureAuthenticator) SetPIN(context.Context, string) error {
	cause := a.cause
	if cause == nil {
		cause = io.ErrClosedPipe
	}
	err := &ctaptransport.IOError{
		Operation: a.operation,
		Err:       cause,
	}

	if a.invalidated {
		return &ctaptransport.DeviceInvalidatedError{Err: err}
	}

	return err
}

func (a *transportFailureAuthenticator) Close() error {
	a.closeCount.Add(1)

	return nil
}

func TestAuthenticatorEventSinksAreScopedToRun(t *testing.T) {
	firstEvents := &recordingEventSink{}
	secondEvents := &recordingEventSink{}

	opened := openContractAuthenticator(t, nil, &progressCredentialAuthenticator{})
	defer func() { _ = opened.Close() }()

	if _, err := opened.Authenticator.ListCredentials(
		context.Background(),
		WithInteractionHandler(userVerificationHandler(t)),
		WithEventSink(firstEvents),
	); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	firstEventCount := len(firstEvents.Events())
	if firstEventCount == 0 {
		t.Fatal("first opened emitted no events")
	}

	if got := len(secondEvents.Events()); got != 0 {
		t.Fatalf("second sink events before second run = %d, want 0", got)
	}

	if _, err := opened.Authenticator.ListCredentials(
		context.Background(),
		WithInteractionHandler(userVerificationHandler(t)),
		WithEventSink(secondEvents),
	); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	if got := len(firstEvents.Events()); got != firstEventCount {
		t.Fatalf("first sink events after second run = %d, want %d", got, firstEventCount)
	}

	if got := len(secondEvents.Events()); got == 0 {
		t.Fatal("second run emitted no events")
	}
}
