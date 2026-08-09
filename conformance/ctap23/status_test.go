package ctap23

import (
	"errors"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/conformance"
)

func TestExpectCTAPStatusAcceptsExpectedAuthenticatorStatus(t *testing.T) {
	err := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorMakeCredential,
		StatusCode: ctaptransport.CTAP2_ERR_MISSING_PARAMETER,
	}

	if got := expectCTAPStatus(err, ctaptransport.CTAP2_ERR_MISSING_PARAMETER); got != nil {
		t.Fatal(got)
	}
	if got := expectCTAPStatus(err, ctaptransport.CTAP2_ERR_INVALID_CBOR, ctaptransport.CTAP2_ERR_MISSING_PARAMETER); got != nil {
		t.Fatal(got)
	}
}

func TestExpectCTAPStatusClassifiesWrongOrMissingStatusAsFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "success"},
		{
			name: "wrong status",
			err: &ctaptransport.CTAPError{
				Command:    protocol.AuthenticatorMakeCredential,
				StatusCode: ctaptransport.CTAP2_ERR_INVALID_CBOR,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := expectCTAPStatus(test.err, ctaptransport.CTAP2_ERR_MISSING_PARAMETER)
			var assertion *conformance.AssertionError
			if !errors.As(err, &assertion) {
				t.Fatalf("error = %v, want AssertionError", err)
			}
			if strings.Contains(err.Error(), "request") {
				t.Fatalf("error leaked request data: %q", err)
			}
		})
	}
}

func TestExpectCTAPStatusPreservesTransportFailure(t *testing.T) {
	disconnected := errors.New("device disconnected")
	if got := expectCTAPStatus(disconnected, ctaptransport.CTAP2_ERR_MISSING_PARAMETER); !errors.Is(got, disconnected) {
		t.Fatalf("error = %v, want transport failure", got)
	}
}
