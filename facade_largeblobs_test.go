package ctapkit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/model"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func TestCredentialInventoryDoesNotExposeLargeBlobKey(t *testing.T) {
	if _, ok := reflect.TypeFor[appcredentials.CredentialRecord]().FieldByName("LargeBlobKey"); ok {
		t.Fatal("public CredentialRecord exposes LargeBlobKey")
	}

	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.ListCredentials(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}

	raw, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if bytes.Contains(raw, []byte(`"largeBlobKey":`)) ||
		bytes.Contains(raw, []byte("largeBlobKeyHex")) ||
		bytes.Contains(raw, []byte("01010101010101010101010101010101")) {
		t.Fatalf("credential inventory leaked largeBlobKey: %s", raw)
	}

	if !bytes.Contains(raw, []byte(`"largeBlobKeyState":"available"`)) {
		t.Fatalf("credential inventory omitted largeBlobKey availability: %s", raw)
	}

	if !bytes.Equal(a.lastEnumeratedLargeBlobKey, make([]byte, len(a.lastEnumeratedLargeBlobKey))) {
		t.Fatal("ListCredentials retained largeBlobKey after building the public report")
	}
}

func TestLargeBlobWriteEventsFollowInteractionAndInventoryOrder(t *testing.T) {
	events := &recordingEventSink{}
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	result, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Result == nil {
		t.Fatal("result.Result = nil, want execution result")
	}

	want := []model.OperationStage{
		model.OperationStageInteractionRequired,
		model.OperationStageEnumeratingRPs,
		model.OperationStageEnumeratingCredentials,
	}

	got := eventStages(events.Events())
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}

	if got := a.largeBlobReads.Load(); got != 1 {
		t.Fatalf("large blob reads = %d, want 1", got)
	}

	if got := a.largeBlobWrites.Load(); got != 1 {
		t.Fatalf("large blob writes = %d, want 1", got)
	}
}

func TestLargeBlobWriteUsesSeparateGrantForReadOnlyInventory(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{credentialManagementReadOnly: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	_, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("WriteLargeBlob: %v", err)
	}

	if got := a.tokenCalls.Load(); got != 2 {
		t.Fatalf("token calls = %d, want 2", got)
	}
	wantPermissions := []protocol.Permission{
		protocol.PermissionPersistentCredentialManagementReadOnly,
		protocol.PermissionLargeBlobWrite,
	}

	if !slices.Equal(a.tokenPermissions, wantPermissions) {
		t.Fatalf("token permissions = %#v, want %#v", a.tokenPermissions, wantPermissions)
	}
}

func TestLargeBlobWriteCapacityErrorReturnsNoPartialPreview(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{maxSerializedLargeBlobArray: 16}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		DryRun:          true,
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	requireFailureCode(t, err, failure.CodeLargeBlobArrayTooLarge)

	requireZero(t, output)
}

func TestLargeBlobWriteZeroCapacityMeansUnknownLimit(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		DryRun:          true,
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("WriteLargeBlob dry run: %v", err)
	}

	if output.Preview.SerializedLargeBlobArrayLimit != 0 {
		t.Fatalf("preview limit = %#v, want unknown", output.Preview.SerializedLargeBlobArrayLimit)
	}
}

func TestLargeBlobEditUsesOneInventoryReadBeforeRefresh(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	if _, err := session.ListLargeBlobs(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("list large blobs: %v", err)
	}

	if _, err := session.ReadLargeBlob(context.Background(), applargeblobs.ReadOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("read large blob: %v", err)
	}

	operation := applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
		DryRun:          true,
	}
	if _, err := session.WriteLargeBlob(
		context.Background(),
		operation,
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("preview write large blob: %v", err)
	}

	operation.DryRun = false
	if _, err := session.WriteLargeBlob(
		context.Background(),
		operation,
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("write large blob: %v", err)
	}

	if got := a.rpEnumerations.Load(); got != 1 {
		t.Fatalf("RP enumerations before refresh = %d, want 1", got)
	}

	if got := a.credentialEnumerations.Load(); got != 1 {
		t.Fatalf("credential enumerations before refresh = %d, want 1", got)
	}

	if got := a.largeBlobReads.Load(); got != 1 {
		t.Fatalf("large blob reads before refresh = %d, want 1", got)
	}

	if got := a.largeBlobWrites.Load(); got != 1 {
		t.Fatalf("large blob writes = %d, want 1", got)
	}

	if _, err := session.ListLargeBlobs(
		context.Background(),
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	); err != nil {
		t.Fatalf("refresh large blobs: %v", err)
	}

	if got := a.rpEnumerations.Load(); got != 2 {
		t.Fatalf("RP enumerations after refresh = %d, want 2", got)
	}

	if got := a.credentialEnumerations.Load(); got != 2 {
		t.Fatalf("credential enumerations after refresh = %d, want 2", got)
	}

	if got := a.largeBlobReads.Load(); got != 2 {
		t.Fatalf("large blob reads after refresh = %d, want 2", got)
	}
}

func TestLargeBlobReadWithMissingKeyDoesNotFetchSharedArray(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{omitLargeBlobKey: true}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	report, err := session.ReadLargeBlob(
		t.Context(),
		applargeblobs.ReadOperation{CredentialIDHex: "c05e"},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("ReadLargeBlob: %v", err)
	}
	if report.State != applargeblobs.ReadStateMissing {
		t.Fatalf("state = %q, want %q", report.State, applargeblobs.ReadStateMissing)
	}
	if got := a.largeBlobReads.Load(); got != 0 {
		t.Fatalf("large-blob array reads = %d, want 0", got)
	}
}

func TestLargeBlobListReadsFreshReport(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	if _, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("list large blobs: %v", err)
	}

	if _, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("list large blobs again: %v", err)
	}

	if got := a.rpEnumerations.Load(); got != 2 {
		t.Fatalf("RP enumerations = %d, want 2", got)
	}

	if got := a.credentialEnumerations.Load(); got != 2 {
		t.Fatalf("credential enumerations = %d, want 2", got)
	}

	if got := a.largeBlobReads.Load(); got != 2 {
		t.Fatalf("large blob reads = %d, want 2", got)
	}
}

func TestLargeBlobListAlwaysObservesCurrentAuthenticatorState(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	if _, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...); err != nil {
		t.Fatalf("first ListLargeBlobs: %v", err)
	}

	added, err := crypto.EncryptLargeBlob(bytes.Repeat([]byte{0x01}, 32), []byte("refreshed"))
	if err != nil {
		t.Fatalf("encrypt refreshed blob: %v", err)
	}
	a.largeBlobs = []protocol.LargeBlob{added}

	output, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("refreshed ListLargeBlobs: %v", err)
	}

	if len(output.Entries) != 1 || output.Entries[0].State != applargeblobs.EntryStateMatched {
		t.Fatalf("refreshed large blob output = %#v, want one present credential blob", output)
	}

	cachedOutput, err := session.ListLargeBlobs(context.Background(), session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("cached ListLargeBlobs after refresh: %v", err)
	}

	if len(cachedOutput.Entries) != 1 || cachedOutput.Entries[0].State != applargeblobs.EntryStateMatched {
		t.Fatalf("cached large blob output = %#v, want refreshed report", cachedOutput)
	}

	if got := a.rpEnumerations.Load(); got != 3 {
		t.Fatalf("RP enumerations = %d, want 3", got)
	}

	if got := a.credentialEnumerations.Load(); got != 3 {
		t.Fatalf("credential enumerations = %d, want 3", got)
	}

	if got := a.tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}

	if got := a.largeBlobReads.Load(); got != 3 {
		t.Fatalf("large blob reads = %d, want 3", got)
	}
}

func TestLargeBlobDeleteLastBlobWritesEmptyArray(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{
		largeBlobs: []protocol.LargeBlob{encryptedLargeBlob(t, 0x01, "current")},
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.DeleteLargeBlob(context.Background(), applargeblobs.DeleteOperation{
		CredentialIDHex: "c05e",
	}, session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...)
	if err != nil {
		t.Fatalf("delete large blob: %v", err)
	}

	if output.Result == nil {
		t.Fatal("delete result = nil")
	}

	if output.Result.Operation != applargeblobs.MutationDelete {
		t.Fatalf("operation = %s, want delete", output.Result.Operation)
	}

	if output.Result.BlobCountAfter != 0 {
		t.Fatalf("blob count after = %d, want 0", output.Result.BlobCountAfter)
	}

	if got := a.largeBlobWrites.Load(); got != 1 {
		t.Fatalf("large blob writes = %d, want 1", got)
	}

	if a.lastSetLargeBlobs == nil {
		t.Fatal("replacement blobs = nil, want empty slice")
	}

	if got := len(a.lastSetLargeBlobs); got != 0 {
		t.Fatalf("replacement blob count = %d, want 0", got)
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("CBOR enc mode: %v", err)
	}

	raw, err := encMode.Marshal(a.lastSetLargeBlobs)
	if err != nil {
		t.Fatalf("marshal replacement blobs: %v", err)
	}

	if !bytes.Equal(raw, []byte{0x80}) {
		t.Fatalf("replacement CBOR = %x, want 80 empty array", raw)
	}
}

func TestLargeBlobWriteReplacesAuthenticatedEntryWithCorruptCompressedData(t *testing.T) {
	a := &largeBlobWriteEventAuthenticator{
		largeBlobs: []protocol.LargeBlob{
			authenticatedCorruptLargeBlob(t, 0x01, []byte("not-deflate"), 7),
		},
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	output, err := session.WriteLargeBlob(
		t.Context(),
		applargeblobs.WriteOperation{
			CredentialIDHex: "c05e",
			Payload:         []byte("replacement"),
		},
		session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
	)
	if err != nil {
		t.Fatalf("WriteLargeBlob: %v", err)
	}
	if output.Result == nil {
		t.Fatal("result = nil")
	}
	if output.Result.Operation != applargeblobs.MutationReplace ||
		output.Result.CurrentByteCount != 7 ||
		output.Result.BlobCountAfter != 1 {
		t.Fatalf("result = %#v, want one replaced entry with declared previous size 7", output.Result)
	}
	if output.Preview.Operation != output.Result.Operation ||
		output.Preview.ProposedByteCount != output.Result.ProposedByteCount ||
		output.Preview.SerializedLargeBlobArraySizeAfter != output.Result.SerializedLargeBlobArraySizeAfter ||
		output.Preview.BlobCountAfter != output.Result.BlobCountAfter {
		t.Fatalf("preview/result diverged: %#v / %#v", output.Preview, output.Result)
	}
	if len(a.lastSetLargeBlobs) != 1 {
		t.Fatalf("written blobs = %d, want 1", len(a.lastSetLargeBlobs))
	}

	raw, err := crypto.DecryptLargeBlob(bytes.Repeat([]byte{0x01}, 32), a.lastSetLargeBlobs[0])
	if err != nil {
		t.Fatalf("DecryptLargeBlob replacement: %v", err)
	}
	if !bytes.Equal(raw, []byte("replacement")) {
		t.Fatalf("replacement payload = %q", raw)
	}
}

func TestLargeBlobGarbageCollectResults(t *testing.T) {
	nonConforming := protocol.LargeBlob{
		Ciphertext: []byte("not-a-gcm-ciphertext"),
		Nonce:      []byte("short"),
		OrigSize:   4,
	}
	tests := []struct {
		name              string
		blobs             []protocol.LargeBlob
		omitLargeBlobKey  bool
		wantNoop          bool
		wantDeleted       int
		wantAfter         int
		wantMatched       int
		wantOrphaned      int
		wantNonconforming int
		wantWrites        int32
	}{
		{
			name:        "matched blob is a noop",
			blobs:       []protocol.LargeBlob{encryptedLargeBlob(t, 0x01, "current")},
			wantNoop:    true,
			wantAfter:   1,
			wantMatched: 1,
		},
		{
			name:              "non-conforming blob is preserved",
			blobs:             []protocol.LargeBlob{nonConforming},
			wantNoop:          true,
			wantAfter:         1,
			wantNonconforming: 1,
		},
		{
			name:        "authenticated corrupt blob is preserved",
			blobs:       []protocol.LargeBlob{authenticatedCorruptLargeBlob(t, 0x01, []byte("not-deflate"), 7)},
			wantNoop:    true,
			wantAfter:   1,
			wantMatched: 1,
		},
		{
			name:             "missing enumerated key does not defer orphan collection",
			blobs:            []protocol.LargeBlob{encryptedLargeBlob(t, 0x01, "orphaned")},
			omitLargeBlobKey: true,
			wantDeleted:      1,
			wantOrphaned:     1,
			wantWrites:       1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &largeBlobWriteEventAuthenticator{
				largeBlobs:       tt.blobs,
				omitLargeBlobKey: tt.omitLargeBlobKey,
			}
			session := openContractAuthenticator(t, nil, a)
			t.Cleanup(func() { _ = session.Close() })

			output, err := session.GarbageCollectLargeBlobs(
				t.Context(),
				applargeblobs.GarbageCollectOperation{},
				session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
			)
			if err != nil {
				t.Fatalf("GarbageCollectLargeBlobs: %v", err)
			}
			if output.Result == nil {
				t.Fatal("result = nil")
			}

			result := output.Result
			if result.Noop != tt.wantNoop ||
				result.DeletedBlobCount != tt.wantDeleted ||
				result.BlobCountAfter != tt.wantAfter ||
				result.MatchedBlobCount != tt.wantMatched ||
				result.OrphanedBlobCount != tt.wantOrphaned ||
				result.NonconformingBlobCount != tt.wantNonconforming {
				t.Fatalf(
					"result = {noop:%t deleted:%d after:%d matched:%d orphaned:%d nonconforming:%d}, want {noop:%t deleted:%d after:%d matched:%d orphaned:%d nonconforming:%d}",
					result.Noop,
					result.DeletedBlobCount,
					result.BlobCountAfter,
					result.MatchedBlobCount,
					result.OrphanedBlobCount,
					result.NonconformingBlobCount,
					tt.wantNoop,
					tt.wantDeleted,
					tt.wantAfter,
					tt.wantMatched,
					tt.wantOrphaned,
					tt.wantNonconforming,
				)
			}
			if got := a.largeBlobWrites.Load(); got != tt.wantWrites {
				t.Fatalf("large blob writes = %d, want %d", got, tt.wantWrites)
			}
			if got := len(a.lastSetLargeBlobs); got != tt.wantAfter && tt.wantWrites != 0 {
				t.Fatalf("replacement blob count = %d, want %d", got, tt.wantAfter)
			}
			if got := a.rpEnumerations.Load(); got != 1 {
				t.Fatalf("RP enumerations = %d, want 1", got)
			}
			if got := a.credentialEnumerations.Load(); got != 1 {
				t.Fatalf("credential enumerations = %d, want 1", got)
			}
			if got := a.largeBlobReads.Load(); got != 1 {
				t.Fatalf("large blob reads = %d, want 1", got)
			}
		})
	}
}

func TestLargeBlobGarbageCollectWireMutation(t *testing.T) {
	tests := []struct {
		name      string
		blobs     []protocol.LargeBlob
		wantAfter int
		checkWire func(*testing.T, []protocol.LargeBlob)
	}{
		{
			name: "preserves matched blob",
			blobs: []protocol.LargeBlob{
				encryptedLargeBlob(t, 0x01, "current"),
				encryptedLargeBlob(t, 0x02, "orphan"),
			},
			wantAfter: 1,
			checkWire: func(t *testing.T, blobs []protocol.LargeBlob) {
				if _, err := crypto.DecryptLargeBlob(bytes.Repeat([]byte{0x01}, 32), blobs[0]); err != nil {
					t.Fatalf("replacement blob is not decryptable by known largeBlobKey: %v", err)
				}
			},
		},
		{
			name:  "writes empty array when all blobs are unmatched",
			blobs: []protocol.LargeBlob{encryptedLargeBlob(t, 0x02, "orphan")},
			checkWire: func(t *testing.T, blobs []protocol.LargeBlob) {
				if blobs == nil {
					t.Fatal("replacement blobs = nil, want empty slice")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &largeBlobWriteEventAuthenticator{largeBlobs: tt.blobs}
			session := openContractAuthenticator(t, nil, a)
			t.Cleanup(func() { _ = session.Close() })

			output, err := session.GarbageCollectLargeBlobs(
				t.Context(),
				applargeblobs.GarbageCollectOperation{},
				session.operationOptions(WithInteractionHandler(userVerificationHandler(t)))...,
			)
			if err != nil {
				t.Fatalf("GarbageCollectLargeBlobs: %v", err)
			}
			if output.Result == nil {
				t.Fatal("result = nil")
			}
			if output.Result.Noop || output.Result.DeletedBlobCount != 1 || output.Result.BlobCountAfter != tt.wantAfter {
				t.Fatalf(
					"result = {noop:%t deleted:%d after:%d}, want {noop:false deleted:1 after:%d}",
					output.Result.Noop,
					output.Result.DeletedBlobCount,
					output.Result.BlobCountAfter,
					tt.wantAfter,
				)
			}
			if got := a.largeBlobWrites.Load(); got != 1 {
				t.Fatalf("large blob writes = %d, want 1", got)
			}
			if got := len(a.lastSetLargeBlobs); got != tt.wantAfter {
				t.Fatalf("replacement blob count = %d, want %d", got, tt.wantAfter)
			}

			tt.checkWire(t, a.lastSetLargeBlobs)
		})
	}
}

func encryptedLargeBlob(t *testing.T, keyByte byte, payload string) protocol.LargeBlob {
	t.Helper()

	blob, err := crypto.EncryptLargeBlob(bytes.Repeat([]byte{keyByte}, 32), []byte(payload))
	if err != nil {
		t.Fatalf("EncryptLargeBlob: %v", err)
	}

	return blob
}

func authenticatedCorruptLargeBlob(
	t *testing.T,
	keyByte byte,
	compressed []byte,
	originalSize uint,
) protocol.LargeBlob {
	t.Helper()

	block, err := aes.NewCipher(bytes.Repeat([]byte{keyByte}, 32))
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

func TestLargeBlobWritePINOnlyFlowDoesNotRequestUserVerification(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		return model.InteractionResponse{
			PIN: []byte("1234"),
		}, nil
	})

	result, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Result == nil {
		t.Fatal("result.Result = nil, want execution result")
	}

	if got := a.pinCalls.Load(); got != 1 {
		t.Fatalf("PIN token calls = %d, want 1", got)
	}

	if got := a.uvCalls.Load(); got != 0 {
		t.Fatalf("UV token calls = %d, want 0", got)
	}

	want := []model.OperationStage{
		model.OperationStageInteractionRequired,
		model.OperationStageEnumeratingRPs,
		model.OperationStageEnumeratingCredentials,
	}

	got := eventStages(events.Events())
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}

	if got := a.largeBlobReads.Load(); got != 1 {
		t.Fatalf("large blob reads = %d, want 1", got)
	}

	for _, event := range events.Events() {
		if event.Kind == model.InteractionKindUserVerification {
			t.Fatal("user-verification interaction emitted for PIN-only authenticator")
		}
	}
}

func TestLargeBlobWritePreparedRefreshRequestsPINOnce(t *testing.T) {
	a := &pinOnlyLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractAuthenticator(t, nil, a)
	defer func() { _ = session.Close() }()

	var requests []model.InteractionRequest
	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		requests = append(requests, req)

		return model.InteractionResponse{PIN: []byte("1234")}, nil
	})

	_, err := session.WriteLargeBlob(context.Background(), applargeblobs.WriteOperation{
		CredentialIDHex: "c05e",
		Payload:         []byte("test"),
	}, session.operationOptions(WithInteractionHandler(handler))...)
	if err != nil {
		t.Fatalf("WriteLargeBlob: %v", err)
	}

	if _, err := session.ListLargeBlobs(
		context.Background(),
		session.operationOptions(WithInteractionHandler(handler))...,
	); err != nil {
		t.Fatalf("ListLargeBlobs refresh: %v", err)
	}

	if got := a.pinCalls.Load(); got != 1 {
		t.Fatalf("PIN token calls = %d, want 1", got)
	}

	if len(requests) != 1 {
		t.Fatalf("PIN requests = %d, want 1", len(requests))
	}

	if got, want := requests[0].Permission, "credentialManagement,largeBlobWrite"; got != want {
		t.Fatalf("PIN permission = %q, want %q", got, want)
	}
}

func TestLargeBlobWritePINVerificationFlowSkipsUVForUVCapableAuthenticator(t *testing.T) {
	events := &recordingEventSink{}
	a := &pinPreferredLargeBlobWriteEventAuthenticator{
		largeBlobWriteEventAuthenticator: largeBlobWriteEventAuthenticator{},
	}
	session := openContractAuthenticator(t, events, a)
	defer func() { _ = session.Close() }()

	handler := interactionHandlerFunc(func(req model.InteractionRequest) (model.InteractionResponse, error) {
		if req.Kind != model.InteractionKindPIN {
			t.Fatalf("interaction kind = %s, want PIN", req.Kind)
		}

		return model.InteractionResponse{PIN: []byte("1234")}, nil
	})

	result, err := session.WriteLargeBlob(
		context.Background(),
		applargeblobs.WriteOperation{
			CredentialIDHex: "c05e",
			Payload:         []byte("test"),
		},
		session.operationOptions(WithVerificationFlow(VerificationFlowPIN), WithInteractionHandler(handler))...,
	)
	if err != nil {
		t.Fatalf("WriteLargeBlob: %v", err)
	}

	if result.Result == nil {
		t.Fatal("mutation result = nil, want output")
	}

	if got := a.pinCalls.Load(); got != 1 {
		t.Fatalf("PIN token calls = %d, want 1", got)
	}

	if got := a.uvCalls.Load(); got != 0 {
		t.Fatalf("UV token calls = %d, want 0", got)
	}

	for _, event := range events.Events() {
		if event.Kind == model.InteractionKindUserVerification {
			t.Fatal("user-verification interaction emitted for PIN verification flow")
		}
	}
}
