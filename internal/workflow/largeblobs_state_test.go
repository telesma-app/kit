package workflow

import (
	"bytes"
	"testing"

	"github.com/telesma-app/ctap/protocol"
)

func TestLargeBlobStateRetainsInventory(t *testing.T) {
	blobs := []protocol.LargeBlob{{Ciphertext: []byte{0x01}}}
	inventory := &largeBlobInventory{blobs: blobs}
	state := &LargeBlobState{}
	state.replaceInventory(inventory)

	loaded, ok := state.currentInventory()
	if !ok {
		t.Fatal("large blob inventory missing")
	}
	if loaded != inventory {
		t.Fatal("large blob inventory was copied")
	}
	if &loaded.blobs[0] != &blobs[0] {
		t.Fatal("large blob array was copied")
	}

	replacement := []protocol.LargeBlob{{Ciphertext: []byte{0x02}}}
	state.replaceBlobs(replacement)
	if &state.current.blobs[0] != &replacement[0] {
		t.Fatal("replacement large blob array was copied")
	}
}

func TestLargeBlobStateClearZerosOwnedKeys(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	state := &LargeBlobState{}
	state.replaceInventory(&largeBlobInventory{
		keys: largeBlobKeyStore{
			{rpIDHashHex: "rp", credentialIDHex: "credential"}: key,
		},
	})

	state.Clear()

	if state.current != nil {
		t.Fatal("large blob inventory retained after clear")
	}
	if !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("largeBlobKey was not zeroed")
	}
}

func TestLargeBlobKeyStoreScopesKeysByRP(t *testing.T) {
	first := bytes.Repeat([]byte{0x11}, 32)
	second := bytes.Repeat([]byte{0x22}, 32)
	keys := make(largeBlobKeyStore)
	defer keys.zero()
	keys.add("first-rp", "credential", first)
	keys.add("second-rp", "credential", second)

	if got := keys.get("first-rp", "credential"); !bytes.Equal(got, first) {
		t.Fatalf("first RP key = %x, want %x", got, first)
	}
	if got := keys.get("second-rp", "credential"); !bytes.Equal(got, second) {
		t.Fatalf("second RP key = %x, want %x", got, second)
	}
}
