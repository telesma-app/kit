package ctapkit

import (
	"testing"

	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/largeblobs"
)

func TestDecodeLargeBlobReturnsZeroResultOnError(t *testing.T) {
	result, err := DecodeLargeBlob([]byte(`{"broken"`), largeblobs.DecodeModeJSON)
	if !failure.IsCode(err, failure.CodeLargeBlobJSONInvalid) {
		t.Fatalf("DecodeLargeBlob error = %v, want %s", err, failure.CodeLargeBlobJSONInvalid)
	}
	if result.Mode != "" || result.Text != "" || result.Value != nil {
		t.Fatalf("DecodeLargeBlob result = %#v, want zero", result)
	}
}
