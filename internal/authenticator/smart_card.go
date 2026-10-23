package authenticator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	ctaptransport "github.com/telesma-app/ctap/transport"
	ctapiso7816 "github.com/telesma-app/ctap/transport/iso7816"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/pcsc"
)

type smartCardConnection interface {
	iso7816.Card
	Lifecycle
	BeginTransaction(context.Context) error
	EndTransaction(pcsc.Disposition) error
	Status() (*pcsc.CardStatus, error)
}

// SmartCard owns one PC/SC connection. The runtime operation gate protects its
// borrowed FIDO session; Close only touches the connection and can interrupt I/O.
type SmartCard struct {
	Card          smartCardConnection
	Interface     pcsc.CardInterface
	FIDOSelectErr error

	fidoSelected bool
	closed       atomic.Bool
	closeOnce    sync.Once
	closeErr     error
}

func (c *SmartCard) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	if !c.fidoSelected {
		if err := c.BeginTransaction(ctx); err != nil {
			c.FIDOSelectErr = err
			return ctaptransport.CBORResponse{}, err
		}

		_, err := ctapiso7816.Select(ctx, c.Card)

		c.FIDOSelectErr = err
		if err != nil {
			return ctaptransport.CBORResponse{}, errors.Join(c.sessionError(ctx, err), c.EndTransaction(pcsc.DispositionLeaveCard))
		}

		c.fidoSelected = true
	}

	response, err := ctapiso7816.CBOR(ctx, c.Card, data)

	return response, c.sessionError(ctx, err)
}

// EndFIDO releases the FIDO session and transaction before a prompt or applet change.
func (c *SmartCard) EndFIDO(ctx context.Context) error {
	selected := c.fidoSelected

	c.fidoSelected = false
	if !selected || c.closed.Load() {
		return nil
	}

	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()

	err := errors.Join(ctapiso7816.Deselect(cleanup, c.Card), c.EndTransaction(pcsc.DispositionLeaveCard))
	if err != nil {
		return c.invalidate(err)
	}

	return nil
}

// BeginTransaction switches from any completed FIDO series to management.
func (c *SmartCard) BeginTransaction(ctx context.Context) error {
	if err := c.EndFIDO(ctx); err != nil {
		return err
	}

	if err := c.Card.BeginTransaction(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return err
		}

		return c.invalidate(err)
	}

	return nil
}

func (c *SmartCard) EndTransaction(disposition pcsc.Disposition) error {
	if c.closed.Load() {
		return nil
	}

	if err := c.Card.EndTransaction(disposition); err != nil {
		return c.invalidate(err)
	}

	return nil
}

func (c *SmartCard) Transmit(ctx context.Context, command []byte) ([]byte, error) {
	response, err := c.Card.Transmit(ctx, command)
	if err != nil {
		return response, c.invalidate(&ctaptransport.IOError{Operation: ctaptransport.IOTransmit, Err: err})
	}

	return response, nil
}

func (c *SmartCard) Status() (*pcsc.CardStatus, error) {
	status, err := c.Card.Status()
	if err != nil {
		return status, c.invalidate(err)
	}

	return status, nil
}

func (c *SmartCard) sessionError(ctx context.Context, err error) error {
	if _, invalid := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); invalid {
		return errors.Join(err, c.Close())
	}

	if _, ioFailure := errors.AsType[*ctaptransport.IOError](err); ioFailure {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return err
		}

		return c.invalidate(err)
	}

	return err
}

func (c *SmartCard) invalidate(err error) error {
	return &ctaptransport.DeviceInvalidatedError{Err: errors.Join(err, c.Close())}
}

func (c *SmartCard) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)

		if err := c.Card.Close(); err != nil {
			c.closeErr = &ctaptransport.IOError{Operation: ctaptransport.IOClose, Err: err}
		}
	})

	return c.closeErr
}
