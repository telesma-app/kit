package logging

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/telesma-app/ctap/diagnostic"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/operation"
)

const (
	MaxPayloadBytes = 64 * 1024
	previewBytes    = 4 * 1024
)

type operationKey struct{}
type recorderKey struct{}

func WithOperation(ctx context.Context, kind operation.Kind) context.Context {
	return context.WithValue(ctx, operationKey{}, kind)
}

func OperationFrom(ctx context.Context) operation.Kind {
	kind, _ := ctx.Value(operationKey{}).(operation.Kind)

	return kind
}

type Recorder interface {
	Append(model.LogEntry)
}

func WithRecorder(ctx context.Context, recorder Recorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, recorder)
}

func RecorderFrom(ctx context.Context) Recorder {
	recorder, _ := ctx.Value(recorderKey{}).(Recorder)

	return recorder
}

func CBORDiagnosticPayload(message diagnostic.Message) *model.LogPayload {
	stored := message.Notation
	truncated := len(stored) > MaxPayloadBytes
	if truncated {
		stored = safePreview([]byte(stored), previewBytes)
	}
	return &model.LogPayload{
		CBORDiagnostic:  stored,
		DiagnosticError: safePreview([]byte(message.Error), previewBytes),
		OriginalBytes:   message.Bytes,
		StoredBytes:     len(stored),
		Truncated:       truncated,
	}
}

func safePreview(raw []byte, limit int) string {
	if len(raw) <= limit {
		return string(raw)
	}

	preview := raw[:limit]
	for len(preview) > 0 && !utf8.Valid(preview) {
		preview = preview[:len(preview)-1]
	}

	return string(preview)
}

func FinishElapsed(entry model.LogEntry, duration time.Duration, err error) model.LogEntry {
	entry.ErrorMessage = transportErrorMessage(err)
	entry.DurationMilliseconds = duration.Milliseconds()

	return finishOutcome(entry, failure.Snapshot(err))
}

func transportErrorMessage(err error) string {
	code, ok := failure.CodeOf(err)
	if !ok || code != failure.CodeTransportFailure &&
		code != failure.CodeTransportPermissionDenied &&
		code != failure.CodeTransportProxyUnavailable {
		return ""
	}

	typed, ok := errors.AsType[*failure.Error](err)
	if !ok || typed.Unwrap() == nil {
		return ""
	}

	return safePreview([]byte(typed.Unwrap().Error()), previewBytes)
}

func finishOutcome(entry model.LogEntry, snapshot *failure.Failure) model.LogEntry {
	entry.Error = snapshot
	if entry.Error == nil {
		entry.Outcome = model.LogOutcomeSucceeded

		return entry
	}

	if entry.Error.Category == failure.CategoryCanceled {
		entry.Outcome = model.LogOutcomeCanceled

		return entry
	}

	entry.Outcome = model.LogOutcomeFailed

	return entry
}
