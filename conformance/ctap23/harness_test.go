package ctap23

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

type scriptedCBORExchange struct {
	request  []byte
	response ctaptransport.CBORResponse
	err      error
}

type scriptedCBORTransport struct {
	exchanges []scriptedCBORExchange
	next      int
	failure   error
}

func newScriptedCBORTransport(t testing.TB, exchanges ...scriptedCBORExchange) *scriptedCBORTransport {
	t.Helper()

	transport := &scriptedCBORTransport{exchanges: exchanges}
	t.Cleanup(func() {
		transport.assertExhausted(t)
	})

	return transport
}

func (s *scriptedCBORTransport) CBOR(ctx context.Context, request []byte) (ctaptransport.CBORResponse, error) {
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if s.failure != nil {
		return ctaptransport.CBORResponse{}, s.failure
	}
	if s.next == len(s.exchanges) {
		s.failure = fmt.Errorf("scripted CBOR: unexpected exchange %d", s.next+1)

		return ctaptransport.CBORResponse{}, s.failure
	}

	exchange := s.exchanges[s.next]
	if !bytes.Equal(request, exchange.request) {
		s.failure = fmt.Errorf("scripted CBOR: request mismatch at exchange %d", s.next+1)

		return ctaptransport.CBORResponse{}, s.failure
	}
	s.next++

	if exchange.err != nil {
		return ctaptransport.CBORResponse{}, exchange.err
	}

	return ctaptransport.ValidateCBORResponse(protocol.Command(request[0]), exchange.response)
}

func (s *scriptedCBORTransport) assertExhausted(t testing.TB) {
	t.Helper()

	if s.failure != nil {
		t.Fatal(s.failure)
	}
	if s.next != len(s.exchanges) {
		t.Fatalf("scripted CBOR: %d exchanges remain", len(s.exchanges)-s.next)
	}
}

func TestScriptedCBORTransportReplaysResponsesAndErrors(t *testing.T) {
	transportFailure := errors.New("device disconnected")
	transport := newScriptedCBORTransport(t,
		scriptedCBORExchange{
			request: []byte{byte(protocol.AuthenticatorGetInfo)},
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_OK,
				Data:       []byte{0xa0},
			},
		},
		scriptedCBORExchange{
			request: []byte{byte(protocol.AuthenticatorMakeCredential), 0xa0},
			response: ctaptransport.CBORResponse{
				StatusCode: ctaptransport.CTAP2_ERR_MISSING_PARAMETER,
			},
		},
		scriptedCBORExchange{
			request: []byte{byte(protocol.AuthenticatorReset)},
			err:     transportFailure,
		},
	)

	response, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != ctaptransport.CTAP2_OK || !bytes.Equal(response.Data, []byte{0xa0}) {
		t.Fatalf("response = %#v", response)
	}

	_, err = transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorMakeCredential), 0xa0})
	var ctapErr *ctaptransport.CTAPError
	if !errors.As(err, &ctapErr) {
		t.Fatalf("error = %v, want CTAPError", err)
	}
	if ctapErr.Command != protocol.AuthenticatorMakeCredential || ctapErr.StatusCode != ctaptransport.CTAP2_ERR_MISSING_PARAMETER {
		t.Fatalf("CTAP error = %#v", ctapErr)
	}

	_, err = transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorReset)})
	if !errors.Is(err, transportFailure) {
		t.Fatalf("error = %v, want %v", err, transportFailure)
	}
}

func TestScriptedCBORTransportRejectsOutOfOrderAndExtraRequests(t *testing.T) {
	transport := &scriptedCBORTransport{exchanges: []scriptedCBORExchange{
		{request: []byte{byte(protocol.AuthenticatorGetInfo)}},
	}}

	_, mismatch := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorReset)})
	if mismatch == nil || mismatch.Error() != "scripted CBOR: request mismatch at exchange 1" {
		t.Fatalf("mismatch error = %v", mismatch)
	}
	if transport.next != 0 {
		t.Fatalf("next exchange = %d, want 0", transport.next)
	}

	_, sticky := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if sticky != mismatch {
		t.Fatalf("sticky error = %v, want %v", sticky, mismatch)
	}

	exhausted := &scriptedCBORTransport{}
	_, unexpected := exhausted.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)})
	if unexpected == nil || unexpected.Error() != "scripted CBOR: unexpected exchange 1" {
		t.Fatalf("unexpected error = %v", unexpected)
	}
}

func TestScriptedCBORTransportDoesNotConsumeCanceledExchange(t *testing.T) {
	transport := newScriptedCBORTransport(t, scriptedCBORExchange{
		request: []byte{byte(protocol.AuthenticatorGetInfo)},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if transport.next != 0 {
		t.Fatalf("next exchange = %d, want 0", transport.next)
	}

	if _, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorGetInfo)}); err != nil {
		t.Fatal(err)
	}
}
