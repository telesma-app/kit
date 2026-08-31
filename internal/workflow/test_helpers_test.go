package workflow

import (
	"bytes"
	"encoding/json"
	"testing"
)

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
