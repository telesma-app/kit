package ctap23

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
)

func TestExchangeCTAP2ClearsOwnedCommandData(t *testing.T) {
	transportError := errors.New("transport unavailable")
	tests := []struct {
		name           string
		transportError error
	}{
		{name: "success"},
		{name: "transport error", transportError: transportError},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			secret := []byte("suite-owned direct large blob")
			defer clear(secret)
			wantSecret := bytes.Clone(secret)
			defer clear(wantSecret)
			device := &retainingCTAP2WireDevice{err: testCase.transportError}

			_, err := exchangeCTAP2(
				context.Background(),
				device,
				protocol.AuthenticatorGetAssertion,
				map[uint64]any{4: map[string]any{"largeBlob": map[string]any{"write": secret}}},
			)
			if !errors.Is(err, testCase.transportError) {
				t.Fatalf("exchange error = %v, want %v", err, testCase.transportError)
			}
			if len(device.request) == 0 {
				t.Fatal("transport did not retain the command buffer")
			}
			if !allZeroCTAP2Wire(device.request) {
				t.Fatalf("owned command buffer was not cleared: %x", device.request)
			}
			if !bytes.Equal(secret, wantSecret) {
				t.Fatalf("caller-owned request value was mutated: %x", secret)
			}
		})
	}
}

func TestExchangeCTAP2ClearsErrorResponseDataWithoutMutatingCallerRequest(t *testing.T) {
	tests := []struct {
		name   string
		status ctaptransport.StatusCode
		err    error
	}{
		{
			name: "transport error",
			err:  errors.New("transport unavailable"),
		},
		{
			name:   "non-OK status",
			status: ctaptransport.CTAP2_ERR_INVALID_CBOR,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			secret := []byte("caller-owned direct large blob")
			defer clear(secret)
			wantSecret := bytes.Clone(secret)
			defer clear(wantSecret)
			responseData := []byte("retained error response")
			device := &retainingCTAP2WireDevice{
				status:       testCase.status,
				responseData: responseData,
				err:          testCase.err,
			}

			_, err := exchangeCTAP2(
				context.Background(),
				device,
				protocol.AuthenticatorGetAssertion,
				map[uint64]any{4: map[string]any{"largeBlob": map[string]any{"write": secret}}},
			)
			if err == nil {
				t.Fatal("error response was accepted")
			}
			if !allZeroCTAP2Wire(responseData) {
				t.Fatalf("error response data was not cleared: %x", responseData)
			}
			if !allZeroCTAP2Wire(device.request) {
				t.Fatalf("owned command buffer was not cleared: %x", device.request)
			}
			if !bytes.Equal(secret, wantSecret) {
				t.Fatalf("caller-owned request value was mutated: %x", secret)
			}
		})
	}
}

type retainingCTAP2WireDevice struct {
	request      []byte
	status       ctaptransport.StatusCode
	responseData []byte
	err          error
}

func (device *retainingCTAP2WireDevice) CBOR(
	_ context.Context,
	request []byte,
) (ctaptransport.CBORResponse, error) {
	device.request = request

	return ctaptransport.CBORResponse{
		StatusCode: device.status,
		Data:       device.responseData,
	}, device.err
}

func allZeroCTAP2Wire(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}

	return true
}
