package errornorm

import (
	"context"
	"errors"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/model/failure"
)

// Normalize converts every non-nil error into a stable failure.Error. The
// requested public operation is supplied only at this boundary; annotations
// carry the lower-level phase and actual authenticator command instead.
func Normalize(err error, operation string) *failure.Error {
	annotation := errorAnnotation(err)
	if existing, ok := errors.AsType[*failure.Error](err); ok {
		if operation != "" {
			existing.Operation = operation
		}

		if existing.Phase == "" {
			existing.Phase = annotation.phase
		}

		return existing
	}

	if errors.Is(err, context.Canceled) {
		return failure.Wrap(
			failure.CodeOperationCanceled,
			err,
			failureOptions(operation, annotation.phase, nil)...,
		)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return failure.Wrap(
			failure.CodeOperationTimeout,
			err,
			failureOptions(operation, annotation.phase, nil)...,
		)
	}

	if ctapErr, ok := errors.AsType[*ctaptransport.CTAPError](err); ok {
		return normalizeCTAP(err, ctapErr, operation, annotation)
	}

	if code, ok := upstreamCode(err, annotation); ok {
		return failure.Wrap(code, err, failureOptions(operation, annotation.phase, nil)...)
	}

	if code, ok := transportCode(err); ok {
		return failure.Wrap(code, err, failureOptions(operation, annotation.phase, nil)...)
	}

	return failure.Wrap(
		failure.CodeInternalError,
		err,
		failureOptions(operation, annotation.phase, nil)...,
	)
}

func normalizeCTAP(
	err error,
	ctapErr *ctaptransport.CTAPError,
	operation string,
	annotation Annotation,
) *failure.Error {
	annotation.command = ctapErr.Command
	if annotation.phase == "" {
		annotation.phase = failure.PhaseAuthenticatorCommand
	}

	if annotation.command == protocol.AuthenticatorGetNextAssertion {
		annotation.phase = failure.PhaseAssertionContinuation
	}

	return failure.Wrap(
		codeForCTAP(ctapErr.StatusCode, annotation),
		err,
		failureOptions(operation, annotation.phase, ctapDetail(ctapErr, annotation))...,
	)
}

func ctapDetail(ctapErr *ctaptransport.CTAPError, annotation Annotation) *failure.CTAPDetail {
	detail := &failure.CTAPDetail{
		CommandCode: uint8(annotation.command),
		StatusCode:  uint8(ctapErr.StatusCode),
	}

	if annotation.subCommand != 0 {
		detail.SubCommandCode = new(annotation.subCommand)
	}

	return detail
}

func failureOptions(operation string, phase failure.Phase, detail *failure.CTAPDetail) []failure.Option {
	return []failure.Option{
		failure.WithOperation(operation),
		failure.WithPhase(phase),
		failure.WithCTAP(detail),
	}
}

func errorAnnotation(err error) Annotation {
	if annotated, ok := errors.AsType[*annotatedError](err); ok {
		return annotated.annotation
	}

	return Annotation{}
}
