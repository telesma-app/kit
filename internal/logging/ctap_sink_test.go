package logging

import (
	"context"
	"testing"
	"time"

	"github.com/telesma-app/ctap/diagnostic"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/operation"
)

func TestCTAPSinkAppendsOperationExchange(t *testing.T) {
	recorder := &sinkRecorder{}
	ctx := WithOperation(t.Context(), operation.ListCredentials)
	NewCTAPSink(recorder)(ctx, diagnostic.Exchange{
		StartedAt:  time.Now(),
		Duration:   10 * time.Millisecond,
		Command:    protocol.AuthenticatorClientPIN,
		SubCommand: uint64(protocol.ClientPINSubCommandGetPINRetries),
		Request: diagnostic.Message{
			Notation:       `{1: 1, 2: 1, 4: '[REDACTED]'}`,
			Bytes:          4,
			RedactedFields: []string{"PinUvAuthParam"},
		},
		Response: diagnostic.Message{Notation: `{3: 8}`, Bytes: 3},
	})

	if len(recorder.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(recorder.entries))
	}

	entry := recorder.entries[0]
	if entry.OperationKind != operation.ListCredentials {
		t.Fatalf("operation kind = %q", entry.OperationKind)
	}

	if entry.CommandCode != uint8(protocol.AuthenticatorClientPIN) ||
		entry.SubCommandCode == nil || *entry.SubCommandCode != uint64(protocol.ClientPINSubCommandGetPINRetries) {
		t.Fatalf("command = %#v", entry)
	}

	if entry.Request == nil || entry.Request.CBORDiagnostic != `{1: 1, 2: 1, 4: '[REDACTED]'}` ||
		entry.Request.OriginalBytes != 4 || entry.Response == nil || entry.Response.CBORDiagnostic != `{3: 8}` {
		t.Fatalf("payloads = request %#v, response %#v", entry.Request, entry.Response)
	}

	if len(entry.RedactedFields) != 1 || entry.RedactedFields[0] != "request.PinUvAuthParam" {
		t.Fatalf("redacted fields = %v", entry.RedactedFields)
	}

	if entry.Outcome != model.LogOutcomeSucceeded || entry.DurationMilliseconds != 10 {
		t.Fatalf("completion = %#v", entry)
	}
}

func TestCTAPSinkNormalizesCancellation(t *testing.T) {
	recorder := &sinkRecorder{}
	NewCTAPSink(recorder)(t.Context(), diagnostic.Exchange{
		Command: protocol.AuthenticatorReset,
		Err:     context.Canceled,
	})

	if len(recorder.entries) != 1 || recorder.entries[0].Outcome != model.LogOutcomeCanceled {
		t.Fatalf("entries = %#v", recorder.entries)
	}
}

func TestCBORDiagnosticPayloadIsBounded(t *testing.T) {
	payload := CBORDiagnosticPayload(diagnostic.Message{
		Notation: string(make([]byte, MaxPayloadBytes+1)),
		Bytes:    100_000,
	})
	if !payload.Truncated || payload.OriginalBytes != 100_000 ||
		payload.StoredBytes > MaxPayloadBytes || len(payload.CBORDiagnostic) != payload.StoredBytes {
		t.Fatalf("payload = %#v", payload)
	}
}

type sinkRecorder struct {
	entries []model.LogEntry
}

func (r *sinkRecorder) Append(entry model.LogEntry) {
	r.entries = append(r.entries, entry)
}
