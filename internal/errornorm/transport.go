package errornorm

import (
	"errors"

	ctapclient "github.com/telesma-app/ctap/client"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	ctapiso7816 "github.com/telesma-app/ctap/transport/iso7816"
	ctaptoken2 "github.com/telesma-app/ctap/transport/token2"
	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/pcsc"
)

func transportCode(err error) (failure.Code, bool) {
	if _, ok := errors.AsType[*ctaphid.ErrorResponse](err); ok {
		return failure.CodeTransportFailure, true
	}

	if _, ok := errors.AsType[*ctaptransport.IOError](err); ok {
		return failure.CodeTransportFailure, true
	}

	if _, ok := errors.AsType[*pcsc.Error](err); ok {
		return failure.CodeTransportFailure, true
	}

	if _, ok := errors.AsType[*ctaptoken2.APDUError](err); ok {
		return failure.CodeTransportFailure, true
	}

	if _, ok := errors.AsType[*baseiso7816.APDUError](err); ok {
		return failure.CodeTransportFailure, true
	}

	if errors.Is(err, ctapclient.ErrTransportNotConfigured) ||
		errors.Is(err, ctaphid.ErrMessageTooLarge) ||
		errors.Is(err, ctaphid.ErrInvalidRequestMessage) ||
		errors.Is(err, ctaphid.ErrUnexpectedCommand) ||
		errors.Is(err, ctaphid.ErrInvalidResponseMessage) ||
		errors.Is(err, baseiso7816.ErrInvalidResponse) ||
		errors.Is(err, ctapiso7816.ErrCommandTooLarge) ||
		errors.Is(err, ctapiso7816.ErrUnsupportedVersion) ||
		errors.Is(err, ctaptoken2.ErrInvalidResponse) ||
		errors.Is(err, ctaptoken2.ErrCommandTooLarge) {
		return failure.CodeTransportFailure, true
	}

	return "", false
}
