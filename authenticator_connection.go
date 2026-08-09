package ctapkit

import (
	"context"
	"errors"
	"sync"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/model/failure"
)

// authenticatorConnection is a stable CBOR endpoint whose owned authenticator
// connection can be replaced between commands.
type authenticatorConnection struct {
	mu sync.Mutex

	opened     *authenticator.Opened
	generation uint64
	closed     bool

	pendingCloses int
	closeErr      error
	closeDone     chan struct{}
	closeDoneSet  bool
}

func newAuthenticatorConnection(opened *authenticator.Opened) *authenticatorConnection {
	return &authenticatorConnection{
		opened:     opened,
		generation: 1,
		closeDone:  make(chan struct{}),
	}
}

// Current returns a borrowed snapshot of the installed authenticator and its
// generation. The connection retains ownership of the returned Opened.
func (c *authenticatorConnection) Current() (*authenticator.Opened, uint64, bool) {
	opened, generation, closed := c.snapshot()

	return opened, generation, !closed && opened != nil
}

// Detach removes and closes the authenticator at expectedGeneration. A stale
// generation never changes the installed authenticator.
func (c *authenticatorConnection) Detach(expectedGeneration uint64) (uint64, error) {
	c.mu.Lock()
	switch {
	case c.closed:
		generation := c.generation
		c.mu.Unlock()

		return generation, authenticatorConnectionClosedError()
	case expectedGeneration != c.generation, c.opened == nil:
		generation := c.generation
		c.mu.Unlock()

		return generation, authenticatorConnectionStateError()
	}

	opened := c.opened
	c.opened = nil
	c.generation++
	generation := c.generation
	c.pendingCloses++
	c.mu.Unlock()

	err := opened.Lifecycle.Close()
	c.finishClose(err)

	return generation, err
}

// Install atomically installs next at expectedGeneration. Ownership of next
// transfers to the connection at method entry. A displaced authenticator, or
// a rejected next authenticator, is closed before Install returns.
func (c *authenticatorConnection) Install(
	expectedGeneration uint64,
	next *authenticator.Opened,
) (uint64, error) {
	c.mu.Lock()
	if c.closed {
		generation := c.generation
		trackClose := !c.closeDoneSet
		if trackClose {
			c.pendingCloses++
		}
		c.mu.Unlock()

		closeErr := next.Lifecycle.Close()
		if trackClose {
			c.finishClose(closeErr)
		}

		return generation, errors.Join(authenticatorConnectionClosedError(), closeErr)
	}
	if expectedGeneration != c.generation {
		generation := c.generation
		c.pendingCloses++
		c.mu.Unlock()

		closeErr := next.Lifecycle.Close()
		c.finishClose(closeErr)

		return generation, errors.Join(authenticatorConnectionStateError(), closeErr)
	}

	displaced := c.opened
	c.opened = next
	c.generation++
	generation := c.generation
	if displaced != nil {
		c.pendingCloses++
	}
	c.mu.Unlock()

	if displaced == nil {
		return generation, nil
	}

	err := displaced.Lifecycle.Close()
	c.finishClose(err)

	return generation, err
}

func (c *authenticatorConnection) CBOR(
	ctx context.Context,
	data []byte,
) (ctaptransport.CBORResponse, error) {
	opened, _, closed := c.snapshot()
	if opened == nil {
		err := authenticatorConnectionStateError()
		if closed {
			err = authenticatorConnectionClosedError()
		}

		return ctaptransport.CBORResponse{}, &ctaptransport.DeviceInvalidatedError{Err: err}
	}

	return opened.CBOR.CBOR(ctx, data)
}

func (c *authenticatorConnection) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.generation++

		opened := c.opened
		c.opened = nil
		if opened != nil {
			c.pendingCloses++
		}
		c.completeCloseLocked()
		closeDone := c.closeDone
		c.mu.Unlock()

		if opened != nil {
			err := opened.Lifecycle.Close()
			c.finishClose(err)
		}

		<-closeDone

		c.mu.Lock()
		err := c.closeErr
		c.mu.Unlock()

		return err
	}

	closeDone := c.closeDone
	c.mu.Unlock()
	<-closeDone

	c.mu.Lock()
	err := c.closeErr
	c.mu.Unlock()

	return err
}

func (c *authenticatorConnection) snapshot() (*authenticator.Opened, uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.opened, c.generation, c.closed
}

func (c *authenticatorConnection) unavailableError() error {
	_, _, closed := c.snapshot()
	if closed {
		return authenticatorConnectionClosedError()
	}

	return authenticatorConnectionStateError()
}

func (c *authenticatorConnection) finishClose(err error) {
	c.mu.Lock()
	c.closeErr = errors.Join(c.closeErr, err)
	c.pendingCloses--
	c.completeCloseLocked()
	c.mu.Unlock()
}

func (c *authenticatorConnection) completeCloseLocked() {
	if c.closed && c.pendingCloses == 0 && !c.closeDoneSet {
		close(c.closeDone)
		c.closeDoneSet = true
	}
}

func authenticatorConnectionClosedError() error {
	return failure.New(
		failure.CodeAuthenticatorClosed,
		failure.WithPhase(failure.PhaseAuthenticator),
	)
}

func authenticatorConnectionStateError() error {
	return failure.New(
		failure.CodeTransportFailure,
		failure.WithPhase(failure.PhaseAuthenticator),
	)
}

var _ ctaptransport.CBOR = (*authenticatorConnection)(nil)
