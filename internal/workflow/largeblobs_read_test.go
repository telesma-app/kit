package workflow

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func TestReadLargeBlobFollowsPerCredentialReadAlgorithm(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	present := encryptedWorkflowLargeBlob(t, key, []byte("payload"))
	corrupt := authenticatedCorruptWorkflowLargeBlob(t, key, []byte("not-deflate"), 7)
	nonconforming := protocol.LargeBlob{
		Ciphertext: []byte("ciphertext"),
		Nonce:      []byte("short"),
		OrigSize:   7,
	}

	tests := []struct {
		name        string
		key         []byte
		blobs       []protocol.LargeBlob
		wantState   applargeblobs.ReadState
		wantPayload []byte
		wantFailure failure.Code
		wantReads   int
	}{
		{
			name:      "key missing means blob missing",
			wantState: applargeblobs.ReadStateMissing,
		},
		{
			name:      "blob missing",
			key:       key,
			wantState: applargeblobs.ReadStateMissing,
			wantReads: 1,
		},
		{
			name:      "nonconforming entry skipped",
			key:       key,
			blobs:     []protocol.LargeBlob{nonconforming},
			wantState: applargeblobs.ReadStateMissing,
			wantReads: 1,
		},
		{
			name:        "blob present",
			key:         key,
			blobs:       []protocol.LargeBlob{present},
			wantState:   applargeblobs.ReadStatePresent,
			wantPayload: []byte("payload"),
			wantReads:   1,
		},
		{
			name:        "authenticated blob with corrupt compressed data",
			key:         key,
			blobs:       []protocol.LargeBlob{corrupt},
			wantFailure: failure.CodeLargeBlobIntegrityFailure,
			wantReads:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := &largeBlobReadDeviceStub{
				blobs: tt.blobs,
			}
			report, err := (Runner{}).readLargeBlobFromInventory(
				t.Context(),
				device,
				"c05e",
				workflowLargeBlobInventory(tt.key, tt.blobs),
			)
			if device.reads != tt.wantReads {
				t.Fatalf("large-blob array reads = %d, want %d", device.reads, tt.wantReads)
			}
			if tt.wantFailure != "" {
				if !failure.IsCode(err, tt.wantFailure) {
					t.Fatalf("error = %v, want code %q", err, tt.wantFailure)
				}
				if !jsonValuesEqual(t, report, applargeblobs.ReadReport{}) {
					t.Fatalf("report = %#v, want zero value", report)
				}

				return
			}
			if err != nil {
				t.Fatalf("ReadLargeBlob: %v", err)
			}
			if report.State != tt.wantState {
				t.Fatalf("state = %q, want %q", report.State, tt.wantState)
			}
			if !((report.RawBytes == nil) == (tt.wantPayload == nil) && bytes.Equal(report.RawBytes, tt.wantPayload)) {
				t.Fatalf("raw bytes = %x, want %x", report.RawBytes, tt.wantPayload)
			}
		})
	}
}

type largeBlobReadDeviceStub struct {
	inspectDeviceStub
	blobs []protocol.LargeBlob
	err   error
	reads int
}

func (s *largeBlobReadDeviceStub) GetLargeBlobs(context.Context) ([]protocol.LargeBlob, error) {
	s.reads++

	return s.blobs, s.err
}

func workflowLargeBlobInventory(key []byte, blobs []protocol.LargeBlob) *largeBlobInventory {
	keys := make(largeBlobKeyStore)
	if key != nil {
		keys.add("rp-hash", "c05e", key)
	}

	return &largeBlobInventory{
		support: applargeblobs.SupportReport{
			LargeBlobs:            true,
			LargeBlobKeyExtension: true,
		},
		credentials: appcredentials.InventoryReport{
			Summary: appcredentials.InventorySummary{TotalCredentials: 1},
			Groups: []appcredentials.CredentialGroup{{
				RPID:        "example.com",
				RPIDHashHex: "rp-hash",
				Credentials: []appcredentials.CredentialRecord{{
					CredentialIDHex: "c05e",
				}},
			}},
		},
		keys:  keys,
		blobs: blobs,
	}
}

func encryptedWorkflowLargeBlob(
	t *testing.T,
	key []byte,
	payload []byte,
) protocol.LargeBlob {
	t.Helper()

	blob, err := crypto.EncryptLargeBlob(key, payload)
	if err != nil {
		t.Fatalf("EncryptLargeBlob: %v", err)
	}

	return blob
}

func authenticatedCorruptWorkflowLargeBlob(
	t *testing.T,
	key []byte,
	compressed []byte,
	originalSize uint,
) protocol.LargeBlob {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	originalSizeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(originalSizeBytes, uint64(originalSize))
	additionalData := append([]byte("blob"), originalSizeBytes...)

	return protocol.LargeBlob{
		Ciphertext: gcm.Seal(nil, nonce, compressed, additionalData),
		Nonce:      nonce,
		OrigSize:   originalSize,
	}
}
