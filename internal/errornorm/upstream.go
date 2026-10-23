package errornorm

import (
	"errors"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/mds"
)

func upstreamCode(err error, annotation Annotation) (failure.Code, bool) {
	switch {
	case errors.Is(err, ctapdevice.ErrPinUvAuthTokenRequired):
		return failure.CodePINUVAuthTokenRequired, true
	case errors.Is(err, ctapdevice.ErrPinNotSet):
		return failure.CodePINNotConfigured, true
	case errors.Is(err, ctapdevice.ErrPinAlreadySet):
		return failure.CodePINAlreadyConfigured, true
	case errors.Is(err, ctapdevice.ErrPinChangeRequired):
		return failure.CodePINChangeRequired, true
	case errors.Is(err, ctapdevice.ErrBuiltInUVRequired),
		errors.Is(err, ctapdevice.ErrUvNotConfigured):
		return failure.CodeVerificationFlowUnsupported, true
	case errors.Is(err, ctapdevice.ErrLargeBlobsIntegrityCheck):
		return failure.CodeLargeBlobIntegrityFailure, true
	case errors.Is(err, ctapdevice.ErrLargeBlobsTooBig):
		return failure.CodeLargeBlobArrayTooLarge, true
	case errors.Is(err, ctapdevice.SyntaxError) && annotation.command == protocol.AuthenticatorLargeBlobs:
		return failure.CodeLargeBlobArrayInvalid, true
	case errors.Is(err, ctapdevice.ErrInvalidSaltSize), errors.Is(err, ctapdevice.SyntaxError):
		return failure.CodeCTAPParameterInvalid, true
	case errors.Is(err, ctapdevice.ErrSpecViolation):
		return failure.CodeCTAPSpecViolation, true
	case errors.Is(err, ctapdevice.ErrPingPongMismatch):
		return failure.CodeTransportFailure, true
	case errors.Is(err, ctapdevice.ErrNotSupported):
		return unsupportedCode(annotation), true
	default:
		return "", false
	}
}

func unsupportedCode(annotation Annotation) failure.Code {
	switch annotation.command {
	case protocol.AuthenticatorGetInfo:
		return failure.CodeGetInfoUnsupported
	case protocol.AuthenticatorClientPIN:
		return failure.CodePINUnsupported
	case protocol.AuthenticatorBioEnrollment,
		protocol.PrototypeAuthenticatorBioEnrollment:
		return failure.CodeBioUnsupported
	case protocol.AuthenticatorCredentialManagement,
		protocol.PrototypeAuthenticatorCredentialManagement:
		return failure.CodeCredentialManagementUnsupported
	case protocol.AuthenticatorLargeBlobs:
		return failure.CodeLargeBlobUnsupported
	case protocol.AuthenticatorConfig:
		return failure.CodeAuthenticatorConfigUnsupported
	default:
		return failure.CodeOperationUnsupported
	}
}

func metadataCode(err error) (failure.Code, bool) {
	switch {
	case errors.Is(err, mds.ErrInvalidAAGUID):
		return failure.CodeMDSAAGUIDInvalid, true
	case errors.Is(err, mds.ErrVerify):
		return failure.CodeMDSVerificationFailed, true
	case errors.Is(err, mds.ErrFetch):
		return failure.CodeMDSFetchFailed, true
	default:
		return "", false
	}
}
