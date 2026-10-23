package workflow

import (
	"fmt"
	"testing"

	ctapauthenticator "github.com/telesma-app/ctap/authenticator"
)

func TestReadLargeBlobArrayTreatsChecksumFailureAsInitialArray(t *testing.T) {
	device := &largeBlobReadDeviceStub{
		err: fmt.Errorf("torn write: %w", ctapauthenticator.ErrLargeBlobsIntegrityCheck),
	}

	blobs, err := (Runner{}).readLargeBlobArray(t.Context(), device)
	if err != nil {
		t.Fatalf("readLargeBlobArray: %v", err)
	}

	if blobs == nil || len(blobs) != 0 {
		t.Fatalf("blobs = %#v, want non-nil initial empty array", blobs)
	}
}
