package largeblobs

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/kit/model/failure"
	. "github.com/telesma-app/kit/model/largeblobs"
)

func TestDecodeLargeBlob(t *testing.T) {
	cborPayload, err := cbor.Marshal(map[string]any{"ok": true, "count": uint64(2)})
	if err != nil {
		t.Fatalf("Marshal(cbor): %v", err)
	}

	tests := []struct {
		name        string
		raw         []byte
		mode        DecodeMode
		wantText    string
		wantValue   any
		wantFailure failure.Code
	}{
		{name: "utf8", raw: []byte("hello"), mode: DecodeModeUTF8, wantText: "hello"},
		{name: "empty utf8", mode: DecodeModeUTF8},
		{name: "json", raw: []byte(`{"ok":true}`), mode: DecodeModeJSON, wantValue: map[string]any{"ok": true}},
		{name: "cbor", raw: cborPayload, mode: DecodeModeCBOR, wantValue: map[string]any{"ok": true, "count": uint64(2)}},
		{name: "malformed utf8", raw: []byte{0xff}, mode: DecodeModeUTF8, wantFailure: failure.CodeLargeBlobUTF8Invalid},
		{name: "malformed json", raw: []byte(`{"ok"`), mode: DecodeModeJSON, wantFailure: failure.CodeLargeBlobJSONInvalid},
		{name: "malformed cbor", raw: []byte{0xff}, mode: DecodeModeCBOR, wantFailure: failure.CodeLargeBlobCBORInvalid},
		{name: "empty mode", raw: []byte("opaque"), wantFailure: failure.CodeLargeBlobDecodeModeUnsupported},
		{name: "unsupported", raw: []byte("opaque"), mode: DecodeMode("future"), wantFailure: failure.CodeLargeBlobDecodeModeUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Decode(tt.raw, tt.mode)
			if tt.wantFailure != "" {
				if !failure.IsCode(err, tt.wantFailure) {
					t.Fatalf("Decode error = %v, want %s", err, tt.wantFailure)
				}
				if result.Mode != "" || result.Text != "" || result.Value != nil {
					t.Fatalf("Decode result = %#v, want zero", result)
				}

				snapshot := failure.Snapshot(err)
				if snapshot == nil || snapshot.Phase != failure.PhaseDecode {
					t.Fatalf("failure = %#v, want decode phase", snapshot)
				}

				return
			}

			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if result.Mode != tt.mode {
				t.Fatalf("Mode = %q, want %q", result.Mode, tt.mode)
			}
			if result.Text != tt.wantText {
				t.Fatalf("Text = %q, want %q", result.Text, tt.wantText)
			}
			if !jsonValuesEqual(t, result.Value, tt.wantValue) {
				t.Fatalf("Value = %#v, want %#v", result.Value, tt.wantValue)
			}
		})
	}
}

func jsonValuesEqual(t testing.TB, got, want any) bool {
	t.Helper()

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("encode actual JSON value: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("encode expected JSON value: %v", err)
	}

	return bytes.Equal(gotJSON, wantJSON)
}
