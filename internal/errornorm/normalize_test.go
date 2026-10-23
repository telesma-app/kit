package errornorm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	ctaptoken2 "github.com/telesma-app/ctap/transport/token2"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/mds"
	"github.com/telesma-app/pcsc"
)

func TestDefaultCode(t *testing.T) {
	tests := []struct {
		name   string
		status ctaptransport.StatusCode
		code   failure.Code
	}{
		{"invalid command", ctaptransport.CTAP1_ERR_INVALID_COMMAND, failure.CodeCTAPCommandInvalid},
		{"invalid parameter", ctaptransport.CTAP1_ERR_INVALID_PARAMETER, failure.CodeCTAPParameterInvalid},
		{"invalid length", ctaptransport.CTAP1_ERR_INVALID_LENGTH, failure.CodeCTAPLengthInvalid},
		{"invalid sequence", ctaptransport.CTAP1_ERR_INVALID_SEQ, failure.CodeCTAPSequenceInvalid},
		{"timeout", ctaptransport.CTAP1_ERR_TIMEOUT, failure.CodeAuthenticatorTimeout},
		{"channel busy", ctaptransport.CTAP1_ERR_CHANNEL_BUSY, failure.CodeAuthenticatorBusy},
		{"lock required", ctaptransport.CTAP1_ERR_LOCK_REQUIRED, failure.CodeCTAPLockRequired},
		{"invalid channel", ctaptransport.CTAP1_ERR_INVALID_CHANNEL, failure.CodeCTAPChannelInvalid},
		{"unexpected CBOR type", ctaptransport.CTAP2_ERR_CBOR_UNEXPECTED_TYPE, failure.CodeCTAPCBORTypeInvalid},
		{"invalid CBOR", ctaptransport.CTAP2_ERR_INVALID_CBOR, failure.CodeCTAPCBORInvalid},
		{"missing parameter", ctaptransport.CTAP2_ERR_MISSING_PARAMETER, failure.CodeCTAPParameterMissing},
		{"limit exceeded", ctaptransport.CTAP2_ERR_LIMIT_EXCEEDED, failure.CodeCTAPLimitExceeded},
		{"fingerprint database full", ctaptransport.CTAP2_ERR_FP_DATABASE_FULL, failure.CodeBioDatabaseFull},
		{"large blob storage full", ctaptransport.CTAP2_ERR_LARGE_BLOB_STORAGE_FULL, failure.CodeLargeBlobStorageFull},
		{"credential excluded", ctaptransport.CTAP2_ERR_CREDENTIAL_EXCLUDED, failure.CodeCredentialExcluded},
		{"processing", ctaptransport.CTAP2_ERR_PROCESSING, failure.CodeAuthenticatorProcessing},
		{"invalid credential", ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL, failure.CodeCredentialInvalid},
		{"user action pending", ctaptransport.CTAP2_ERR_USER_ACTION_PENDING, failure.CodeUserActionPending},
		{"operation pending", ctaptransport.CTAP2_ERR_OPERATION_PENDING, failure.CodeAuthenticatorOperationPending},
		{"no operations", ctaptransport.CTAP2_ERR_NO_OPERATIONS, failure.CodeAuthenticatorNoOperations},
		{"unsupported algorithm", ctaptransport.CTAP2_ERR_UNSUPPORTED_ALGORITHM, failure.CodeAlgorithmUnsupported},
		{"operation denied", ctaptransport.CTAP2_ERR_OPERATION_DENIED, failure.CodeAuthenticatorOperationDenied},
		{"key store full", ctaptransport.CTAP2_ERR_KEY_STORE_FULL, failure.CodeCredentialStoreFull},
		{"unsupported option", ctaptransport.CTAP2_ERR_UNSUPPORTED_OPTION, failure.CodeCTAPOptionUnsupported},
		{"invalid option", ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeCTAPOptionInvalid},
		{"keepalive cancel", ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL, failure.CodeAuthenticatorOperationCanceled},
		{"no credentials", ctaptransport.CTAP2_ERR_NO_CREDENTIALS, failure.CodeCredentialNotFound},
		{"user action timeout", ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, failure.CodeUserActionTimeout},
		{"not allowed", ctaptransport.CTAP2_ERR_NOT_ALLOWED, failure.CodeAuthenticatorOperationNotAllowed},
		{"PIN invalid", ctaptransport.CTAP2_ERR_PIN_INVALID, failure.CodePINInvalid},
		{"PIN blocked", ctaptransport.CTAP2_ERR_PIN_BLOCKED, failure.CodePINBlocked},
		{"PIN auth invalid", ctaptransport.CTAP2_ERR_PIN_AUTH_INVALID, failure.CodePINUVAuthInvalid},
		{"PIN auth blocked", ctaptransport.CTAP2_ERR_PIN_AUTH_BLOCKED, failure.CodePINUVAuthBlocked},
		{"PIN not set", ctaptransport.CTAP2_ERR_PIN_NOT_SET, failure.CodePINNotConfigured},
		{"PIN UV auth token required", ctaptransport.CTAP2_ERR_PUAT_REQUIRED, failure.CodePINUVAuthTokenRequired},
		{"PIN policy violation", ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION, failure.CodePINPolicyViolation},
		{"reserved status", ctaptransport.RESERVED_FOR_FUTURE_USE, failure.CodeCTAPReservedStatus},
		{"request too large", ctaptransport.CTAP2_ERR_REQUEST_TOO_LARGE, failure.CodeCTAPRequestTooLarge},
		{"action timeout", ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, failure.CodeAuthenticatorActionTimeout},
		{"user presence required", ctaptransport.CTAP2_ERR_UP_REQUIRED, failure.CodeUserPresenceRequired},
		{"user verification blocked", ctaptransport.CTAP2_ERR_UV_BLOCKED, failure.CodeUserVerificationBlocked},
		{"integrity failure", ctaptransport.CTAP2_ERR_INTEGRITY_FAILURE, failure.CodeCTAPIntegrityFailure},
		{"invalid subcommand", ctaptransport.CTAP2_ERR_INVALID_SUBCOMMAND, failure.CodeCTAPSubcommandInvalid},
		{"user verification invalid", ctaptransport.CTAP2_ERR_UV_INVALID, failure.CodeUserVerificationInvalid},
		{"unauthorized permission", ctaptransport.CTAP2_ERR_UNAUTHORIZED_PERMISSION, failure.CodePINUVPermissionUnauthorized},
		{"other", ctaptransport.CTAP1_ERR_OTHER, failure.CodeCTAPOtherError},
		{"unassigned", 0x41, failure.CodeCTAPReservedStatus},
		{"extension", 0xe1, failure.CodeCTAPExtensionError},
		{"vendor", 0xf1, failure.CodeCTAPVendorError},
		{"success is not an error", ctaptransport.CTAP2_OK, failure.CodeInternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultCode(tt.status); got != tt.code {
				t.Errorf("defaultCode(0x%02x) = %s, want %s", uint8(tt.status), got, tt.code)
			}
		})
	}
}

func TestNormalizeCTAPProvenance(t *testing.T) {
	raw := &ctaptransport.CTAPError{
		Command:    protocol.Command(0x7e),
		StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
	}
	err := Normalize(raw, "getInfo")
	assertFailure(t, err, failure.CodePINInvalid, "getInfo", failure.PhaseAuthenticatorCommand)

	detail := err.CTAP
	if detail == nil {
		t.Fatal("CTAP detail = nil")
	}

	if detail.Command != "" || detail.CommandCode != 0x7e {
		t.Fatalf("command = %#v, want unknown command byte 0x7e", detail)
	}

	if detail.Status != "CTAP2_ERR_PIN_INVALID" || detail.StatusCode != uint8(ctaptransport.CTAP2_ERR_PIN_INVALID) {
		t.Fatalf("status = %#v, want CTAP2_ERR_PIN_INVALID", detail)
	}

	var gotRaw *ctaptransport.CTAPError
	if !errors.As(err, &gotRaw) || !errors.Is(gotRaw, raw) {
		t.Fatalf("errors.As CTAPError = %p, want %p", gotRaw, raw)
	}
}

func TestNormalizeCTAPHIDErrorResponse(t *testing.T) {
	raw := &ctaphid.ErrorResponse{ErrorCode: ctaphid.ERR_OTHER}
	err := Normalize(Annotate(raw, commandContext(
		protocol.AuthenticatorGetAssertion,
	)), "webauthn.getAssertion")
	assertFailure(
		t,
		err,
		failure.CodeTransportFailure,
		"webauthn.getAssertion",
		failure.PhaseAuthenticatorCommand,
	)

	if err.CTAP != nil {
		t.Fatalf("CTAPHID error acquired CBOR CTAP detail: %#v", err.CTAP)
	}

	var gotRaw *ctaphid.ErrorResponse
	if !errors.As(err, &gotRaw) || !errors.Is(gotRaw, raw) {
		t.Fatalf("errors.As ErrorResponse = %p, want %p", gotRaw, raw)
	}
}

func TestNormalizeTransportIOError(t *testing.T) {
	rawCause := io.ErrClosedPipe
	raw := &ctaptransport.IOError{Operation: ctaptransport.IOWrite, Err: rawCause}

	err := Normalize(Annotate(raw, WithCommand(
		failure.PhaseAuthenticatorCommand,
		protocol.AuthenticatorGetAssertion,
	)), "webauthn.getAssertion")
	assertFailure(
		t,
		err,
		failure.CodeTransportFailure,
		"webauthn.getAssertion",
		failure.PhaseAuthenticatorCommand,
	)

	if err.CTAP != nil {
		t.Fatalf("device I/O error acquired CTAP detail: %#v", err.CTAP)
	}

	var gotIOErr *ctaptransport.IOError
	if !errors.As(err, &gotIOErr) || !errors.Is(gotIOErr, raw) {
		t.Fatalf("errors.As IOError = %p, want %p", gotIOErr, raw)
	}

	if !errors.Is(err, rawCause) {
		t.Fatal("device I/O cause not preserved")
	}
}

func TestNormalizePCSCTransportErrors(t *testing.T) {
	for _, operation := range []string{"SCardBeginTransaction", "SCardEndTransaction", "SCardStatus"} {
		t.Run(operation, func(t *testing.T) {
			raw := &pcsc.Error{Operation: operation, Code: 0x80100069}
			invalidated := &ctaptransport.DeviceInvalidatedError{Err: raw}

			for _, cause := range []error{raw, invalidated} {
				err := Normalize(Annotate(cause, WithPhase(failure.PhaseAuthenticatorCommand)), "getInfo")
				assertFailure(t, err, failure.CodeTransportFailure, "getInfo", failure.PhaseAuthenticatorCommand)

				if err.Category != failure.CategoryTransportFailure || err.CTAP != nil {
					t.Fatalf("PC/SC failure = %#v", err.Failure)
				}

				if !errors.Is(err, cause) || !errors.Is(err, pcsc.ErrCardRemoved) {
					t.Fatalf("PC/SC causes lost: %v", err)
				}

				if got, ok := errors.AsType[*pcsc.Error](err); !ok || got != raw {
					t.Fatalf("PC/SC error = %v, want %v", got, raw)
				}
			}
		})
	}
}

func TestNormalizePCSCErrorPreservesSpecificClassification(t *testing.T) {
	raw := &pcsc.Error{Operation: "SCardBeginTransaction", Code: 0x80100069}
	for _, test := range []struct {
		name  string
		cause error
		code  failure.Code
	}{
		{"canceled", errors.Join(raw, context.Canceled), failure.CodeOperationCanceled},
		{"timeout", errors.Join(raw, context.DeadlineExceeded), failure.CodeOperationTimeout},
		{"coded", failure.Wrap(failure.CodeTransportPermissionDenied, raw), failure.CodeTransportPermissionDenied},
		{"CTAP", errors.Join(raw, &ctaptransport.CTAPError{
			Command:    protocol.AuthenticatorClientPIN,
			StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
		}), failure.CodePINInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalidated := &ctaptransport.DeviceInvalidatedError{Err: test.cause}
			err := Normalize(invalidated, "getInfo")
			if err.Code != test.code || !errors.Is(err, invalidated) || !errors.Is(err, raw) {
				t.Fatalf("normalized PC/SC error = %#v", err.Failure)
			}
		})
	}
}

func TestNormalizeToken2TransportErrors(t *testing.T) {
	t.Run("APDU status", func(t *testing.T) {
		raw := &ctaptoken2.APDUError{SW1: 0x6a, SW2: 0x82}
		err := Normalize(Annotate(raw, WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorGetAssertion,
		)), "webauthn.getAssertion")
		assertFailure(
			t,
			err,
			failure.CodeTransportFailure,
			"webauthn.getAssertion",
			failure.PhaseAuthenticatorCommand,
		)

		if err.CTAP != nil {
			t.Fatalf("APDU error acquired CTAP detail: %#v", err.CTAP)
		}

		var got *ctaptoken2.APDUError
		if !errors.As(err, &got) || !errors.Is(got, raw) {
			t.Fatalf("errors.As APDUError = %p, want %p", got, raw)
		}
	})

	for _, sentinel := range []error{
		ctaptoken2.ErrInvalidResponse,
		ctaptoken2.ErrCommandTooLarge,
	} {
		err := Normalize(sentinel, "getInfo")
		assertFailure(t, err, failure.CodeTransportFailure, "getInfo", "")

		if !errors.Is(err, sentinel) {
			t.Fatalf("transport sentinel %v not preserved", sentinel)
		}
	}
}

func TestNormalizeCommandOverrides(t *testing.T) {
	tests := []struct {
		name       string
		annotation Annotation
		status     ctaptransport.StatusCode
		code       failure.Code
	}{
		{"make credential denied", commandContext(protocol.AuthenticatorMakeCredential), ctaptransport.CTAP2_ERR_OPERATION_DENIED, failure.CodeCredentialCreationDenied},
		{"assertion invalid credential", commandContext(protocol.AuthenticatorGetAssertion), ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL, failure.CodeCredentialNotFound},
		{"assertion denied", commandContext(protocol.AuthenticatorGetAssertion), ctaptransport.CTAP2_ERR_OPERATION_DENIED, failure.CodeAssertionDenied},
		{"assertion not allowed", commandContext(protocol.AuthenticatorGetAssertion), ctaptransport.CTAP2_ERR_NOT_ALLOWED, failure.CodeAssertionNotAllowed},
		{"next assertion not allowed", commandContext(protocol.AuthenticatorGetNextAssertion), ctaptransport.CTAP2_ERR_NOT_ALLOWED, failure.CodeAssertionContinuationUnavailable},
		{"get info invalid command", commandContext(protocol.AuthenticatorGetInfo), ctaptransport.CTAP1_ERR_INVALID_COMMAND, failure.CodeGetInfoUnsupported},
		{"reset not allowed", commandContext(protocol.AuthenticatorReset), ctaptransport.CTAP2_ERR_NOT_ALLOWED, failure.CodeResetWindowExpired},
		{"reset user timeout", commandContext(protocol.AuthenticatorReset), ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, failure.CodeResetTouchTimeout},
		{"reset action timeout", commandContext(protocol.AuthenticatorReset), ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, failure.CodeResetTouchTimeout},
		{"bio enumerate invalid option", bioContext(protocol.BioEnrollmentSubCommandEnumerateEnrollments), ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeBioNoEnrollments},
		{"bio rename invalid option", bioContext(protocol.BioEnrollmentSubCommandSetFriendlyName), ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeBioEnrollmentNotFound},
		{"bio remove invalid option", bioContext(protocol.BioEnrollmentSubCommandRemoveEnrollment), ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeBioEnrollmentNotFound},
		{"bio enroll invalid option", bioContext(protocol.BioEnrollmentSubCommandEnrollBegin), ctaptransport.CTAP2_ERR_INVALID_OPTION, failure.CodeCTAPOptionInvalid},
		{"bio enroll user timeout", bioContext(protocol.BioEnrollmentSubCommandEnrollBegin), ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, failure.CodeBioInteractionTimeout},
		{"bio enroll action timeout", bioContext(protocol.BioEnrollmentSubCommandEnrollBegin), ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, failure.CodeBioInteractionTimeout},
		{"credential delete invalid credential", credentialContext(protocol.CredentialManagementSubCommandDeleteCredential), ctaptransport.CTAP2_ERR_INVALID_CREDENTIAL, failure.CodeCredentialNotFound},
		{"selection canceled", commandContext(protocol.AuthenticatorSelection), ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL, failure.CodeAuthenticatorSelectionCanceled},
		{"selection user timeout", commandContext(protocol.AuthenticatorSelection), ctaptransport.CTAP2_ERR_USER_ACTION_TIMEOUT, failure.CodeAuthenticatorSelectionTimeout},
		{"selection action timeout", commandContext(protocol.AuthenticatorSelection), ctaptransport.CTAP2_ERR_ACTION_TIMEOUT, failure.CodeAuthenticatorSelectionTimeout},
		{"large blob invalid sequence", commandContext(protocol.AuthenticatorLargeBlobs), ctaptransport.CTAP1_ERR_INVALID_SEQ, failure.CodeLargeBlobWriteSequenceInvalid},
		{"large blob integrity", commandContext(protocol.AuthenticatorLargeBlobs), ctaptransport.CTAP2_ERR_INTEGRITY_FAILURE, failure.CodeLargeBlobIntegrityFailure},
		{"config storage full", configContext(protocol.ConfigSubCommandSetMinPINLength), ctaptransport.CTAP2_ERR_KEY_STORE_FULL, failure.CodeAuthenticatorConfigStorageFull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := codeForCTAP(tt.status, tt.annotation); got != tt.code {
				t.Errorf("codeForCTAP(0x%02x, command 0x%02x) = %s, want %s", uint8(tt.status), uint8(tt.annotation.command), got, tt.code)
			}
		})
	}
}

func TestNormalizeCommandOverrideProvenance(t *testing.T) {
	raw := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorGetNextAssertion,
		StatusCode: ctaptransport.CTAP2_ERR_NOT_ALLOWED,
	}
	err := Normalize(Annotate(raw, commandContext(
		protocol.AuthenticatorGetAssertion,
	)), "webauthn.getAssertion")
	assertFailure(
		t,
		err,
		failure.CodeAssertionContinuationUnavailable,
		"webauthn.getAssertion",
		failure.PhaseAssertionContinuation,
	)

	detail := err.CTAP
	if detail == nil || detail.CommandCode != uint8(protocol.AuthenticatorGetNextAssertion) {
		t.Fatalf("CTAP detail = %#v, want getNextAssertion command", detail)
	}

	var gotRaw *ctaptransport.CTAPError
	if !errors.As(err, &gotRaw) || !errors.Is(gotRaw, raw) {
		t.Fatalf("raw CTAP error not preserved: %v", err)
	}
}

func TestNormalizeGeneralErrors(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		wrapped := fmt.Errorf("upstream canceled: %w", context.Canceled)
		err := Normalize(wrapped, "getInfo")
		assertFailure(t, err, failure.CodeOperationCanceled, "getInfo", "")

		if !errors.Is(err, context.Canceled) {
			t.Fatal("context.Canceled not preserved")
		}
	})

	t.Run("deadline", func(t *testing.T) {
		wrapped := fmt.Errorf("upstream deadline: %w", context.DeadlineExceeded)
		err := Normalize(wrapped, "getInfo")
		assertFailure(t, err, failure.CodeOperationTimeout, "getInfo", "")

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("context.DeadlineExceeded not preserved")
		}
	})

	t.Run("command annotated plain error is internal", func(t *testing.T) {
		raw := errors.New("opaque command failure")
		err := Normalize(Annotate(raw, WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorGetAssertion,
		)), "webauthn.getAssertion")
		assertFailure(
			t,
			err,
			failure.CodeInternalError,
			"webauthn.getAssertion",
			failure.PhaseAuthenticatorCommand,
		)

		if err.CTAP != nil {
			t.Fatalf("plain command error acquired CTAP detail: %#v", err.CTAP)
		}

		if !errors.Is(err, raw) {
			t.Fatal("plain command cause not preserved")
		}
	})

	t.Run("typed CTAPHID framing error is transport", func(t *testing.T) {
		err := Normalize(Annotate(ctaphid.ErrInvalidResponseMessage, WithCommand(
			failure.PhaseAuthenticatorCommand,
			protocol.AuthenticatorGetAssertion,
		)), "webauthn.getAssertion")
		assertFailure(
			t,
			err,
			failure.CodeTransportFailure,
			"webauthn.getAssertion",
			failure.PhaseAuthenticatorCommand,
		)

		if !errors.Is(err, ctaphid.ErrInvalidResponseMessage) {
			t.Fatal("CTAPHID framing sentinel not preserved")
		}
	})

	t.Run("unannotated internal error", func(t *testing.T) {
		raw := errors.New("opaque")
		err := Normalize(raw, "getInfo")
		assertFailure(t, err, failure.CodeInternalError, "getInfo", "")

		if !errors.Is(err, raw) {
			t.Fatal("opaque cause not preserved")
		}
	})

	t.Run("typed failure enrichment", func(t *testing.T) {
		raw := errors.New("invalid")
		typed := failure.Wrap(
			failure.CodeBioTemplateIDInvalid,
			raw,
			failure.WithPhase(failure.PhaseValidation),
		)
		err := Normalize(typed, "credentials.delete")
		assertFailure(t, err, failure.CodeBioTemplateIDInvalid, "credentials.delete", failure.PhaseValidation)

		if !errors.Is(err, raw) {
			t.Fatal("typed failure cause not preserved")
		}
	})

	t.Run("normalized failure cause does not override its code", func(t *testing.T) {
		existing := failure.Wrap(
			failure.CodeBioTemplateIDInvalid,
			context.Canceled,
			failure.WithOperation("credentials.delete"),
			failure.WithPhase(failure.PhaseValidation),
		)

		got := Normalize(existing, "credentials.delete")
		assertFailure(
			t,
			got,
			failure.CodeBioTemplateIDInvalid,
			"credentials.delete",
			failure.PhaseValidation,
		)

		if !errors.Is(got, context.Canceled) {
			t.Fatal("typed failure cause not preserved")
		}
	})
}

func TestUpstreamCode(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		annotation Annotation
		code       failure.Code
	}{
		{"PIN UV auth token required", ctapdevice.ErrPinUvAuthTokenRequired, commandContext(protocol.AuthenticatorMakeCredential), failure.CodePINUVAuthTokenRequired},
		{"PIN not set", ctapdevice.ErrPinNotSet, tokenContext(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions), failure.CodePINNotConfigured},
		{"PIN already set", ctapdevice.ErrPinAlreadySet, WithClientPINSubCommand(failure.PhaseAuthenticatorCommand, protocol.ClientPINSubCommandSetPIN), failure.CodePINAlreadyConfigured},
		{"PIN change required", ctapdevice.ErrPinChangeRequired, commandContext(protocol.AuthenticatorMakeCredential), failure.CodePINChangeRequired},
		{"built-in UV required", ctapdevice.ErrBuiltInUVRequired, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeVerificationFlowUnsupported},
		{"UV not configured", ctapdevice.ErrUvNotConfigured, tokenContext(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions), failure.CodeVerificationFlowUnsupported},
		{"large blob integrity", ctapdevice.ErrLargeBlobsIntegrityCheck, commandContext(protocol.AuthenticatorLargeBlobs), failure.CodeLargeBlobIntegrityFailure},
		{"large blob syntax", ctapdevice.SyntaxError, commandContext(protocol.AuthenticatorLargeBlobs), failure.CodeLargeBlobArrayInvalid},
		{"large blob too big", ctapdevice.ErrLargeBlobsTooBig, commandContext(protocol.AuthenticatorLargeBlobs), failure.CodeLargeBlobArrayTooLarge},
		{"invalid salt", ctapdevice.ErrInvalidSaltSize, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeCTAPParameterInvalid},
		{"generic syntax", ctapdevice.SyntaxError, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeCTAPParameterInvalid},
		{"spec violation", ctapdevice.ErrSpecViolation, commandContext(protocol.AuthenticatorGetAssertion), failure.CodeCTAPSpecViolation},
		{"ping pong mismatch", ctapdevice.ErrPingPongMismatch, WithPhase(failure.PhaseAuthenticatorCommand), failure.CodeTransportFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := upstreamCode(tt.err, tt.annotation)
			if !ok || got != tt.code {
				t.Errorf("upstreamCode(%v, command 0x%02x) = %s, %t; want %s, true", tt.err, uint8(tt.annotation.command), got, ok, tt.code)
			}
		})
	}
}

func TestUpstreamUnsupportedCode(t *testing.T) {
	tests := []struct {
		name    string
		command protocol.Command
		code    failure.Code
	}{
		{"get info", protocol.AuthenticatorGetInfo, failure.CodeGetInfoUnsupported},
		{"client PIN", protocol.AuthenticatorClientPIN, failure.CodePINUnsupported},
		{"bio enrollment", protocol.AuthenticatorBioEnrollment, failure.CodeBioUnsupported},
		{"credential management", protocol.AuthenticatorCredentialManagement, failure.CodeCredentialManagementUnsupported},
		{"large blobs", protocol.AuthenticatorLargeBlobs, failure.CodeLargeBlobUnsupported},
		{"authenticator config", protocol.AuthenticatorConfig, failure.CodeAuthenticatorConfigUnsupported},
		{"other command", protocol.AuthenticatorGetAssertion, failure.CodeOperationUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := upstreamCode(ctapdevice.ErrNotSupported, commandContext(tt.command))
			if !ok || got != tt.code {
				t.Errorf("upstreamCode(ErrNotSupported, command 0x%02x) = %s, %t; want %s, true", uint8(tt.command), got, ok, tt.code)
			}
		})
	}
}

func TestNormalizeUpstreamSentinel(t *testing.T) {
	raw := &ctapdevice.ErrorWithMessage{
		Message: "upstream detail",
		Err:     ctapdevice.ErrPinUvAuthTokenRequired,
	}
	err := Normalize(Annotate(raw, commandContext(
		protocol.AuthenticatorMakeCredential,
	)), "webauthn.makeCredential")
	assertFailure(
		t,
		err,
		failure.CodePINUVAuthTokenRequired,
		"webauthn.makeCredential",
		failure.PhaseAuthenticatorCommand,
	)

	if !errors.Is(err, ctapdevice.ErrPinUvAuthTokenRequired) {
		t.Fatal("upstream sentinel not preserved")
	}
}

func commandContext(command protocol.Command) Annotation {
	return WithCommand(failure.PhaseAuthenticatorCommand, command)
}

func tokenContext(subCommand protocol.ClientPINSubCommand) Annotation {
	return WithClientPINSubCommand(failure.PhaseTokenAcquisition, subCommand)
}

func bioContext(subCommand protocol.BioEnrollmentSubCommand) Annotation {
	return WithBioEnrollmentSubCommand(
		failure.PhaseAuthenticatorCommand,
		protocol.AuthenticatorBioEnrollment,
		subCommand,
	)
}

func credentialContext(subCommand protocol.CredentialManagementSubCommand) Annotation {
	return WithCredentialManagementSubCommand(
		failure.PhaseAuthenticatorCommand,
		protocol.AuthenticatorCredentialManagement,
		subCommand,
	)
}

func configContext(subCommand protocol.ConfigSubCommand) Annotation {
	return WithConfigSubCommand(failure.PhaseAuthenticatorCommand, subCommand)
}

func assertFailure(
	t *testing.T,
	typed *failure.Error,
	code failure.Code,
	operation string,
	phase failure.Phase,
) {
	t.Helper()

	if typed.Code != code {
		t.Fatalf("failure code = %s, want %s", typed.Code, code)
	}

	wantCategory := failure.New(code).Category
	if typed.Category != wantCategory {
		t.Fatalf("failure category = %s, want %s", typed.Category, wantCategory)
	}

	if typed.Operation != operation {
		t.Fatalf("operation = %q, want %q", typed.Operation, operation)
	}

	if typed.Phase != phase {
		t.Fatalf("phase = %q, want %q", typed.Phase, phase)
	}
}

func TestMetadataErrorsPreserveClassificationAndCause(t *testing.T) {
	for _, test := range []struct {
		cause error
		code  failure.Code
	}{
		{mds.ErrInvalidAAGUID, failure.CodeMDSAAGUIDInvalid},
		{mds.ErrVerify, failure.CodeMDSVerificationFailed},
		{fmt.Errorf("%w: %w", mds.ErrFetch, context.DeadlineExceeded), failure.CodeMDSFetchFailed},
		{&mds.HTTPStatusError{StatusCode: 503}, failure.CodeMDSFetchFailed},
	} {
		result := Normalize(Annotate(fmt.Errorf("lookup: %w", test.cause), WithPhase(failure.PhaseMetadata)), "")
		if result.Code != test.code || result.Phase != failure.PhaseMetadata || !errors.Is(result, test.cause) {
			t.Fatalf("normalized error = %#v", result)
		}

		if _, ok := test.cause.(*mds.HTTPStatusError); ok && result.Params["httpStatus"] != "503" {
			t.Fatalf("HTTP status lost: %#v", result.Params)
		}
	}
}

func TestNormalizeRetainsJoinedCausesAndCodedCommandMetadata(t *testing.T) {
	commandErr := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorClientPIN,
		StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
	}
	primary := Normalize(Annotate(commandErr, WithClientPINSubCommand(
		failure.PhaseTokenAcquisition,
		protocol.ClientPINSubCommandGetPINRetries,
	)), "credentials.list")
	cleanupErr := errors.New("transaction cleanup failed")
	invalidated := &ctaptransport.DeviceInvalidatedError{Err: cleanupErr}
	outer := fmt.Errorf("workflow: %w", errors.Join(primary, invalidated))

	got := Normalize(Annotate(outer, WithPhase(failure.PhaseAuthenticator)), "credentials.delete")
	assertFailure(t, got, failure.CodePINInvalid, "credentials.delete", failure.PhaseTokenAcquisition)

	for _, cause := range []error{outer, primary, commandErr, cleanupErr} {
		if !errors.Is(got, cause) {
			t.Fatalf("normalization lost cause %v", cause)
		}
	}

	if retained, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](got); !ok || retained != invalidated {
		t.Fatalf("invalidation = %v, want %v", retained, invalidated)
	}

	detail := got.CTAP
	if detail == nil || detail.CommandCode != uint8(protocol.AuthenticatorClientPIN) ||
		detail.StatusCode != uint8(ctaptransport.CTAP2_ERR_PIN_INVALID) || detail.SubCommandCode == nil ||
		*detail.SubCommandCode != uint64(protocol.ClientPINSubCommandGetPINRetries) {
		t.Fatalf("command provenance = %#v", detail)
	}

	if primary.Operation != "credentials.list" || primary.Phase != failure.PhaseTokenAcquisition {
		t.Fatalf("source failure metadata changed: %#v", primary.Failure)
	}
}

func TestNormalizeEnrichesCodedErrorWithoutMutatingSource(t *testing.T) {
	cause := errors.New("HTTP request failed")
	primary := failure.Wrap(failure.CodeMDSFetchFailed, cause,
		failure.WithOperation("getInfo"),
		failure.WithParams(map[string]string{"httpStatus": "503"}),
	)
	outer := fmt.Errorf("lookup: %w", primary)

	got := Normalize(Annotate(outer, WithPhase(failure.PhaseMetadata)), "")
	assertFailure(t, got, failure.CodeMDSFetchFailed, "getInfo", failure.PhaseMetadata)

	if got.Params["httpStatus"] != "503" || !errors.Is(got, outer) || !errors.Is(got, cause) {
		t.Fatalf("normalization lost metadata or causes: %#v", got.Failure)
	}

	if primary.Phase != "" || primary.Operation != "getInfo" {
		t.Fatalf("source failure metadata changed: %#v", primary.Failure)
	}
}

func TestNormalizeSharedCodedError(t *testing.T) {
	primary := Normalize(&ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorGetInfo,
		StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
	}, "getInfo")

	for _, operation := range []string{"credentials.list", "credentials.delete"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()

			got := Normalize(primary, operation)
			assertFailure(t, got, failure.CodePINInvalid, operation, failure.PhaseAuthenticatorCommand)

			if primary.Operation != "getInfo" || primary.CTAP.CommandCode != uint8(protocol.AuthenticatorGetInfo) {
				t.Fatalf("shared failure metadata changed: %#v", primary.Failure)
			}
		})
	}
}
