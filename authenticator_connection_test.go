package ctapkit

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/model/failure"
)

func TestAuthenticatorConnectionCurrentAndCBOR(t *testing.T) {
	endpoint := newAuthenticatorConnectionEndpoint()
	endpoint.response = ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       []byte{0xa1, 0x01, 0x02},
	}
	opened := authenticatorConnectionOpened(endpoint)
	connection := newAuthenticatorConnection(opened)

	current, generation, ok := connection.Current()
	if current != opened || generation != 1 || !ok {
		t.Fatalf("Current() = (%p, %d, %t), want (%p, 1, true)", current, generation, ok, opened)
	}

	request := []byte{0x04}
	response, err := connection.CBOR(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != endpoint.response.StatusCode || !bytes.Equal(response.Data, endpoint.response.Data) {
		t.Fatalf("response = %#v, want %#v", response, endpoint.response)
	}
	requests := endpoint.Requests()
	if len(requests) != 1 || !bytes.Equal(requests[0], request) {
		t.Fatalf("requests = %x, want [%x]", requests, request)
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatorConnectionCBORUsesOneUnlockedGenerationSnapshot(t *testing.T) {
	oldEndpoint := newAuthenticatorConnectionEndpoint()
	oldEndpoint.response = ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: []byte("old")}
	oldEndpoint.cborRelease = make(chan struct{})
	connection := newAuthenticatorConnection(authenticatorConnectionOpened(oldEndpoint))

	type cborResult struct {
		response ctaptransport.CBORResponse
		err      error
	}
	cborResultChannel := make(chan cborResult, 1)
	go func() {
		response, err := connection.CBOR(t.Context(), []byte{0x04})
		cborResultChannel <- cborResult{response: response, err: err}
	}()
	authenticatorConnectionReceive(t, oldEndpoint.cborStarted)

	nextEndpoint := newAuthenticatorConnectionEndpoint()
	nextEndpoint.response = ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: []byte("next")}
	next := authenticatorConnectionOpened(nextEndpoint)
	generation, err := connection.Install(1, next)
	if err != nil || generation != 2 {
		t.Fatalf("Install() = (%d, %v), want (2, nil)", generation, err)
	}
	current, currentGeneration, ok := connection.Current()
	if current != next || currentGeneration != 2 || !ok {
		t.Fatalf("Current() = (%p, %d, %t), want (%p, 2, true)", current, currentGeneration, ok, next)
	}

	close(oldEndpoint.cborRelease)
	result := authenticatorConnectionReceive(t, cborResultChannel)
	if result.err != nil || string(result.response.Data) != "old" {
		t.Fatalf("in-flight CBOR = (%#v, %v), want old generation result", result.response, result.err)
	}

	response, err := connection.CBOR(t.Context(), []byte{0x04})
	if err != nil || string(response.Data) != "next" {
		t.Fatalf("next CBOR = (%#v, %v)", response, err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatorConnectionDetachPublishesBeforeClosing(t *testing.T) {
	oldEndpoint := newAuthenticatorConnectionEndpoint()
	oldEndpoint.closeRelease = make(chan struct{})
	connection := newAuthenticatorConnection(authenticatorConnectionOpened(oldEndpoint))

	type transitionResult struct {
		generation uint64
		err        error
	}
	detachResult := make(chan transitionResult, 1)
	go func() {
		generation, err := connection.Detach(1)
		detachResult <- transitionResult{generation: generation, err: err}
	}()
	authenticatorConnectionReceive(t, oldEndpoint.closeStarted)

	current, generation, ok := connection.Current()
	if current != nil || generation != 2 || ok {
		t.Fatalf("detached Current() = (%p, %d, %t), want (nil, 2, false)", current, generation, ok)
	}

	nextEndpoint := newAuthenticatorConnectionEndpoint()
	next := authenticatorConnectionOpened(nextEndpoint)
	installedGeneration, err := connection.Install(2, next)
	if err != nil || installedGeneration != 3 {
		t.Fatalf("Install while old close is blocked = (%d, %v), want (3, nil)", installedGeneration, err)
	}

	close(oldEndpoint.closeRelease)
	result := authenticatorConnectionReceive(t, detachResult)
	if result.generation != 2 || result.err != nil {
		t.Fatalf("Detach() = (%d, %v), want (2, nil)", result.generation, result.err)
	}
	if oldEndpoint.CloseCalls() != 1 {
		t.Fatalf("old close calls = %d, want 1", oldEndpoint.CloseCalls())
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatorConnectionInstallPublishesBeforeClosingDisplaced(t *testing.T) {
	oldEndpoint := newAuthenticatorConnectionEndpoint()
	oldEndpoint.closeRelease = make(chan struct{})
	connection := newAuthenticatorConnection(authenticatorConnectionOpened(oldEndpoint))

	nextEndpoint := newAuthenticatorConnectionEndpoint()
	nextEndpoint.response = ctaptransport.CBORResponse{StatusCode: ctaptransport.CTAP2_OK, Data: []byte("next")}
	next := authenticatorConnectionOpened(nextEndpoint)
	installResult := make(chan error, 1)
	go func() {
		_, err := connection.Install(1, next)
		installResult <- err
	}()
	authenticatorConnectionReceive(t, oldEndpoint.closeStarted)

	current, generation, ok := connection.Current()
	if current != next || generation != 2 || !ok {
		t.Fatalf("Current() = (%p, %d, %t), want (%p, 2, true)", current, generation, ok, next)
	}
	response, err := connection.CBOR(t.Context(), []byte{0x04})
	if err != nil || string(response.Data) != "next" {
		t.Fatalf("CBOR during displaced close = (%#v, %v)", response, err)
	}

	close(oldEndpoint.closeRelease)
	if err := authenticatorConnectionReceive(t, installResult); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatorConnectionRejectsStaleTransitions(t *testing.T) {
	endpoint := newAuthenticatorConnectionEndpoint()
	opened := authenticatorConnectionOpened(endpoint)
	connection := newAuthenticatorConnection(opened)

	generation, err := connection.Detach(0)
	if generation != 1 || !failure.IsCode(err, failure.CodeTransportFailure) {
		t.Fatalf("stale Detach() = (%d, %v)", generation, err)
	}
	current, currentGeneration, ok := connection.Current()
	if current != opened || currentGeneration != 1 || !ok || endpoint.CloseCalls() != 0 {
		t.Fatalf("stale Detach changed state: current=%p generation=%d ok=%t closes=%d", current, currentGeneration, ok, endpoint.CloseCalls())
	}

	rejectedCloseError := errors.New("rejected close")
	rejectedEndpoint := newAuthenticatorConnectionEndpoint()
	rejectedEndpoint.closeErr = rejectedCloseError
	generation, err = connection.Install(0, authenticatorConnectionOpened(rejectedEndpoint))
	if generation != 1 || !failure.IsCode(err, failure.CodeTransportFailure) || !errors.Is(err, rejectedCloseError) {
		t.Fatalf("stale Install() = (%d, %v)", generation, err)
	}
	if rejectedEndpoint.CloseCalls() != 1 {
		t.Fatalf("rejected close calls = %d, want 1", rejectedEndpoint.CloseCalls())
	}
	current, currentGeneration, ok = connection.Current()
	if current != opened || currentGeneration != 1 || !ok {
		t.Fatalf("stale Install changed state: current=%p generation=%d ok=%t", current, currentGeneration, ok)
	}

	detachedGeneration, err := connection.Detach(1)
	if err != nil || detachedGeneration != 2 {
		t.Fatalf("Detach() = (%d, %v), want (2, nil)", detachedGeneration, err)
	}
	generation, err = connection.Detach(2)
	if generation != 2 || !failure.IsCode(err, failure.CodeTransportFailure) {
		t.Fatalf("already-detached Detach() = (%d, %v)", generation, err)
	}
	if err := connection.Close(); !errors.Is(err, rejectedCloseError) {
		t.Fatalf("Close error = %v, want rejected owner close error", err)
	}
}

func TestAuthenticatorConnectionCBORUnavailableIsDeviceInvalidated(t *testing.T) {
	connection := newAuthenticatorConnection(authenticatorConnectionOpened(newAuthenticatorConnectionEndpoint()))
	detachedGeneration, err := connection.Detach(1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = connection.CBOR(t.Context(), []byte{0x04})
	assertAuthenticatorConnectionInvalidated(t, err, failure.CodeTransportFailure)

	next := authenticatorConnectionOpened(newAuthenticatorConnectionEndpoint())
	installedGeneration, err := connection.Install(detachedGeneration, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = connection.CBOR(t.Context(), []byte{0x04})
	assertAuthenticatorConnectionInvalidated(t, err, failure.CodeAuthenticatorClosed)

	current, generation, ok := connection.Current()
	if current != nil || generation != installedGeneration+1 || ok {
		t.Fatalf("closed Current() = (%p, %d, %t)", current, generation, ok)
	}
}

func TestAuthenticatorConnectionConcurrentCloseSharesErrorAndDoesNotHoldMutex(t *testing.T) {
	closeError := errors.New("close failed")
	endpoint := newAuthenticatorConnectionEndpoint()
	endpoint.closeErr = closeError
	endpoint.closeRelease = make(chan struct{})
	connection := newAuthenticatorConnection(authenticatorConnectionOpened(endpoint))

	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- connection.Close() }()
	authenticatorConnectionReceive(t, endpoint.closeStarted)

	current, generation, ok := connection.Current()
	if current != nil || generation != 2 || ok {
		t.Fatalf("Current during Close = (%p, %d, %t), want (nil, 2, false)", current, generation, ok)
	}
	go func() { second <- connection.Close() }()
	authenticatorConnectionAssertBlocked(t, first)
	authenticatorConnectionAssertBlocked(t, second)

	close(endpoint.closeRelease)
	if err := authenticatorConnectionReceive(t, first); !errors.Is(err, closeError) {
		t.Fatalf("first Close error = %v", err)
	}
	if err := authenticatorConnectionReceive(t, second); !errors.Is(err, closeError) {
		t.Fatalf("second Close error = %v", err)
	}
	if err := connection.Close(); !errors.Is(err, closeError) {
		t.Fatalf("later Close error = %v", err)
	}
	if endpoint.CloseCalls() != 1 {
		t.Fatalf("close calls = %d, want 1", endpoint.CloseCalls())
	}
}

func TestAuthenticatorConnectionInstallAfterCloseClosesNewOwner(t *testing.T) {
	connection := newAuthenticatorConnection(authenticatorConnectionOpened(newAuthenticatorConnectionEndpoint()))
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	closeError := errors.New("new owner close failed")
	nextEndpoint := newAuthenticatorConnectionEndpoint()
	nextEndpoint.closeErr = closeError
	generation, err := connection.Install(2, authenticatorConnectionOpened(nextEndpoint))
	if generation != 2 || !failure.IsCode(err, failure.CodeAuthenticatorClosed) || !errors.Is(err, closeError) {
		t.Fatalf("Install after Close = (%d, %v)", generation, err)
	}
	if nextEndpoint.CloseCalls() != 1 {
		t.Fatalf("new owner close calls = %d, want 1", nextEndpoint.CloseCalls())
	}
}

func TestAuthenticatorConnectionInstallThenCloseRaceClosesBothGenerations(t *testing.T) {
	oldCloseError := errors.New("old close failed")
	oldEndpoint := newAuthenticatorConnectionEndpoint()
	oldEndpoint.closeErr = oldCloseError
	oldEndpoint.closeRelease = make(chan struct{})
	connection := newAuthenticatorConnection(authenticatorConnectionOpened(oldEndpoint))

	nextCloseError := errors.New("next close failed")
	nextEndpoint := newAuthenticatorConnectionEndpoint()
	nextEndpoint.closeErr = nextCloseError
	installResult := make(chan error, 1)
	go func() {
		_, err := connection.Install(1, authenticatorConnectionOpened(nextEndpoint))
		installResult <- err
	}()
	authenticatorConnectionReceive(t, oldEndpoint.closeStarted)

	closeResult := make(chan error, 1)
	go func() { closeResult <- connection.Close() }()
	authenticatorConnectionReceive(t, nextEndpoint.closeStarted)
	authenticatorConnectionAssertBlocked(t, closeResult)

	close(oldEndpoint.closeRelease)
	if err := authenticatorConnectionReceive(t, installResult); !errors.Is(err, oldCloseError) {
		t.Fatalf("Install error = %v", err)
	}
	err := authenticatorConnectionReceive(t, closeResult)
	if !errors.Is(err, oldCloseError) || !errors.Is(err, nextCloseError) {
		t.Fatalf("Close error = %v, want both generation errors", err)
	}
	if oldEndpoint.CloseCalls() != 1 || nextEndpoint.CloseCalls() != 1 {
		t.Fatalf("close calls = old %d next %d, want 1/1", oldEndpoint.CloseCalls(), nextEndpoint.CloseCalls())
	}
	_, generation, ok := connection.Current()
	if generation != 3 || ok {
		t.Fatalf("closed generation = %d, ok = %t, want 3/false", generation, ok)
	}
}

func TestAuthenticatorConnectionCloseThenInstallRaceRejectsAndClosesNewOwner(t *testing.T) {
	oldEndpoint := newAuthenticatorConnectionEndpoint()
	oldEndpoint.closeRelease = make(chan struct{})
	connection := newAuthenticatorConnection(authenticatorConnectionOpened(oldEndpoint))

	closeResult := make(chan error, 1)
	go func() { closeResult <- connection.Close() }()
	authenticatorConnectionReceive(t, oldEndpoint.closeStarted)

	nextCloseError := errors.New("next close failed")
	nextEndpoint := newAuthenticatorConnectionEndpoint()
	nextEndpoint.closeErr = nextCloseError
	generation, err := connection.Install(1, authenticatorConnectionOpened(nextEndpoint))
	if generation != 2 || !failure.IsCode(err, failure.CodeAuthenticatorClosed) || !errors.Is(err, nextCloseError) {
		t.Fatalf("racing Install = (%d, %v)", generation, err)
	}
	if nextEndpoint.CloseCalls() != 1 {
		t.Fatalf("next close calls = %d, want 1", nextEndpoint.CloseCalls())
	}

	close(oldEndpoint.closeRelease)
	if err := authenticatorConnectionReceive(t, closeResult); !errors.Is(err, nextCloseError) {
		t.Fatalf("Close error = %v, want rejected owner close error", err)
	}
}

func TestAuthenticatorConnectionDetachAndCloseRacesCloseOneOwner(t *testing.T) {
	t.Run("Detach linearizes first", func(t *testing.T) {
		closeError := errors.New("detached close failed")
		endpoint := newAuthenticatorConnectionEndpoint()
		endpoint.closeErr = closeError
		endpoint.closeRelease = make(chan struct{})
		connection := newAuthenticatorConnection(authenticatorConnectionOpened(endpoint))

		detachResult := make(chan error, 1)
		go func() {
			_, err := connection.Detach(1)
			detachResult <- err
		}()
		authenticatorConnectionReceive(t, endpoint.closeStarted)

		closeResult := make(chan error, 1)
		go func() { closeResult <- connection.Close() }()
		authenticatorConnectionAssertBlocked(t, closeResult)

		close(endpoint.closeRelease)
		if err := authenticatorConnectionReceive(t, detachResult); !errors.Is(err, closeError) {
			t.Fatalf("Detach error = %v", err)
		}
		if err := authenticatorConnectionReceive(t, closeResult); !errors.Is(err, closeError) {
			t.Fatalf("Close error = %v", err)
		}
		if endpoint.CloseCalls() != 1 {
			t.Fatalf("close calls = %d, want 1", endpoint.CloseCalls())
		}
	})

	t.Run("Close linearizes first", func(t *testing.T) {
		endpoint := newAuthenticatorConnectionEndpoint()
		endpoint.closeRelease = make(chan struct{})
		connection := newAuthenticatorConnection(authenticatorConnectionOpened(endpoint))

		closeResult := make(chan error, 1)
		go func() { closeResult <- connection.Close() }()
		authenticatorConnectionReceive(t, endpoint.closeStarted)

		generation, err := connection.Detach(1)
		if generation != 2 || !failure.IsCode(err, failure.CodeAuthenticatorClosed) {
			t.Fatalf("racing Detach = (%d, %v)", generation, err)
		}
		close(endpoint.closeRelease)
		if err := authenticatorConnectionReceive(t, closeResult); err != nil {
			t.Fatal(err)
		}
		if endpoint.CloseCalls() != 1 {
			t.Fatalf("close calls = %d, want 1", endpoint.CloseCalls())
		}
	})
}

func assertAuthenticatorConnectionInvalidated(t *testing.T, err error, code failure.Code) {
	t.Helper()

	var invalidated *ctaptransport.DeviceInvalidatedError
	if !errors.As(err, &invalidated) || !failure.IsCode(err, code) {
		t.Fatalf("error = %v, want DeviceInvalidatedError with %s", err, code)
	}
}

func authenticatorConnectionOpened(endpoint *authenticatorConnectionEndpoint) *authenticator.Opened {
	return &authenticator.Opened{CBOR: endpoint, Lifecycle: endpoint}
}

type authenticatorConnectionEndpoint struct {
	mu sync.Mutex

	response     ctaptransport.CBORResponse
	cborErr      error
	closeErr     error
	cborStarted  chan struct{}
	cborRelease  chan struct{}
	closeStarted chan struct{}
	closeRelease chan struct{}
	cborStart    sync.Once
	closeStart   sync.Once
	requests     [][]byte
	closeCalls   int
}

func newAuthenticatorConnectionEndpoint() *authenticatorConnectionEndpoint {
	return &authenticatorConnectionEndpoint{
		cborStarted:  make(chan struct{}),
		closeStarted: make(chan struct{}),
	}
}

func (e *authenticatorConnectionEndpoint) CBOR(
	ctx context.Context,
	data []byte,
) (ctaptransport.CBORResponse, error) {
	e.mu.Lock()
	e.requests = append(e.requests, slices.Clone(data))
	release := e.cborRelease
	response := e.response
	err := e.cborErr
	e.mu.Unlock()
	e.cborStart.Do(func() { close(e.cborStarted) })

	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctaptransport.CBORResponse{}, ctx.Err()
		}
	}

	return response, err
}

func (e *authenticatorConnectionEndpoint) Close() error {
	e.mu.Lock()
	e.closeCalls++
	release := e.closeRelease
	err := e.closeErr
	e.mu.Unlock()
	e.closeStart.Do(func() { close(e.closeStarted) })

	if release != nil {
		<-release
	}

	return err
}

func (e *authenticatorConnectionEndpoint) Requests() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()

	return slices.Clone(e.requests)
}

func (e *authenticatorConnectionEndpoint) CloseCalls() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.closeCalls
}

func authenticatorConnectionReceive[T any](t *testing.T, channel <-chan T) T {
	t.Helper()

	select {
	case value := <-channel:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for authenticator connection event")
		var zero T

		return zero
	}
}

func authenticatorConnectionAssertBlocked[T any](t *testing.T, channel <-chan T) {
	t.Helper()

	select {
	case value := <-channel:
		t.Fatalf("operation unexpectedly completed with %#v", value)
	default:
	}
}
