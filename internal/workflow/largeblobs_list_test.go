package workflow

import (
	"testing"

	"github.com/telesma-app/ctap/protocol"
	applargeblobs "github.com/telesma-app/kit/model/largeblobs"
)

func TestListLargeBlobsClassifiesEveryArrayEntry(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	otherKey := make([]byte, 32)
	otherKey[0] = 2
	blobs := []protocol.LargeBlob{
		encryptedWorkflowLargeBlob(t, key, []byte("matched")),
		encryptedWorkflowLargeBlob(t, otherKey, []byte("orphaned")),
		{Ciphertext: []byte("short"), Nonce: []byte("short"), OrigSize: 1},
		authenticatedCorruptWorkflowLargeBlob(t, key, []byte("not-deflate"), 7),
	}

	report := (Runner{}).listLargeBlobsFromInventory(workflowLargeBlobInventory(key, blobs))

	wantStates := []applargeblobs.EntryState{
		applargeblobs.EntryStateMatched,
		applargeblobs.EntryStateOrphaned,
		applargeblobs.EntryStateNonconforming,
		applargeblobs.EntryStateCorrupt,
	}
	if len(report.Entries) != len(wantStates) {
		t.Fatalf("entries = %d, want %d", len(report.Entries), len(wantStates))
	}
	for index, want := range wantStates {
		if report.Entries[index].Index != index || report.Entries[index].State != want {
			t.Fatalf("entry %d = %#v, want state %q", index, report.Entries[index], want)
		}
	}
	if report.Entries[0].Target == nil || report.Entries[0].Target.CredentialIDHex != "c05e" {
		t.Fatalf("matched target = %#v", report.Entries[0].Target)
	}
	if report.Entries[3].Target == nil || report.Entries[3].Target.CredentialIDHex != "c05e" {
		t.Fatalf("corrupt target = %#v", report.Entries[3].Target)
	}

	summary := report.Array
	if !summary.Read ||
		summary.BlobCount != 4 ||
		summary.MatchedBlobCount != 1 ||
		summary.OrphanedBlobCount != 1 ||
		summary.NonconformingBlobCount != 1 ||
		summary.CorruptBlobCount != 1 {
		t.Fatalf("array summary = %#v", summary)
	}
}

func TestListLargeBlobsIgnoresMissingCredentialKeysWhenClassifyingOrphans(t *testing.T) {
	otherKey := make([]byte, 32)
	otherKey[0] = 2
	blob := encryptedWorkflowLargeBlob(t, otherKey, []byte("unknown"))

	report := (Runner{}).listLargeBlobsFromInventory(workflowLargeBlobInventory(nil, []protocol.LargeBlob{blob}))

	if len(report.Entries) != 1 || report.Entries[0].State != applargeblobs.EntryStateOrphaned {
		t.Fatalf("entries = %#v, want orphaned", report.Entries)
	}
	if report.Array.OrphanedBlobCount != 1 {
		t.Fatalf("array summary = %#v", report.Array)
	}
}
