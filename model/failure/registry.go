package failure

import (
	"strconv"
)

type paramValueRule string

const (
	paramValueField      paramValueRule = "field"
	paramValueUint       paramValueRule = "uint"
	paramValueHTTPStatus paramValueRule = "http-status"
)

var paramValueEnums = map[paramValueRule]map[string]struct{}{
	paramValueField: values(
		"pin",
		"currentPIN",
		"newPIN",
	),
}

type codeSpec struct {
	category Category
	params   map[string]paramValueRule
}

var codeRegistry = newCodeRegistry()

func newCodeRegistry() map[Code]codeSpec {
	registry := make(map[Code]codeSpec)
	register := func(category Category, codes ...Code) {
		for _, code := range codes {
			registry[code] = codeSpec{category: category}
		}
	}
	allow := func(code Code, rules map[string]paramValueRule) {
		spec := registry[code]
		spec.params = rules
		registry[code] = spec
	}

	register(CategoryInternal, CodeInternalError)
	register(CategoryUnsupported,
		CodeOperationUnsupported,
		CodeVerificationFlowUnsupported,
		CodeTransportModeUnsupported,
		CodeCredentialManagementUnsupported,
		CodePINUnsupported,
		CodeBioUnsupported,
		CodeAuthenticatorConfigUnsupported,
		CodeMinPINLengthUnsupported,
		CodeLargeBlobUnsupported,
		CodeLargeBlobDecodeModeUnsupported,
		CodeCTAPCommandInvalid,
		CodeAlgorithmUnsupported,
		CodeCTAPOptionUnsupported,
		CodeCTAPSubcommandInvalid,
		CodeGetInfoUnsupported,
	)
	register(CategoryPermissionDenied,
		CodeTransportPermissionDenied,
	)
	register(CategoryTransportFailure,
		CodeTransportProxyUnavailable,
		CodeTransportFailure,
		CodeMDSFetchFailed,
		CodeCTAPSequenceInvalid,
		CodeCTAPLockRequired,
		CodeCTAPChannelInvalid,
		CodeCTAPIntegrityFailure,
		CodeCTAPSpecViolation,
		CodeCTAPOtherError,
		CodeCTAPReservedStatus,
		CodeCTAPExtensionError,
		CodeCTAPVendorError,
	)
	register(CategoryTimeout,
		CodeOperationTimeout,
		CodeResetTouchTimeout,
		CodeAuthenticatorTimeout,
		CodeUserActionTimeout,
		CodeAuthenticatorActionTimeout,
		CodeAuthenticatorSelectionTimeout,
		CodeBioInteractionTimeout,
	)
	register(CategoryBusy,
		CodeAuthenticatorBusy,
		CodeAuthenticatorProcessing,
		CodeUserActionPending,
		CodeAuthenticatorOperationPending,
	)
	register(CategoryCanceled,
		CodeOperationCanceled,
		CodeInteractionCanceled,
		CodeAuthenticatorOperationCanceled,
		CodeAuthenticatorSelectionCanceled,
	)
	register(CategoryInvalidOperation,
		CodeInteractionHandlerRequired,
		CodeMDSAAGUIDInvalid,
		CodeRelyingPartyIDRequired,
		CodeUserIDRequired,
		CodeClientDataJSONRequired,
		CodePublicKeyCredentialParametersRequired,
		CodePublicKeyCredentialAlgorithmRequired,
		CodeCredentialIDRequired,
		CodeCredentialChangesRequired,
		CodeUserIDHexInvalid,
		CodePINRequired,
		CodeBioTemplateIDRequired,
		CodeBioTemplateIDInvalid,
		CodeLargeBlobArrayInvalid,
		CodeLargeBlobWriteSequenceInvalid,
		CodeCTAPParameterInvalid,
		CodeCTAPLengthInvalid,
		CodeCTAPCBORTypeInvalid,
		CodeCTAPCBORInvalid,
		CodeCTAPParameterMissing,
		CodeCTAPLimitExceeded,
		CodeCTAPOptionInvalid,
		CodeCTAPRequestTooLarge,
	)
	register(CategoryInvalidState,
		CodeAuthenticatorClosed,
		CodeDeviceNotFound,
		CodeMDSVerificationFailed,
		CodeCredentialNotFound,
		CodeCredentialExcluded,
		CodeCredentialStoreFull,
		CodeAttestedCredentialDataMissing,
		CodeCredentialCreationDenied,
		CodeAssertionDenied,
		CodeAssertionNotAllowed,
		CodeAssertionContinuationUnavailable,
		CodePINAlreadyConfigured,
		CodePINNotConfigured,
		CodePINInvalid,
		CodePINBlocked,
		CodePINUVAuthInvalid,
		CodePINUVAuthBlocked,
		CodePINPolicyViolation,
		CodePINChangeRequired,
		CodePINUVAuthTokenRequired,
		CodePINUVPermissionUnauthorized,
		CodeUserPresenceRequired,
		CodeUserVerificationBlocked,
		CodeUserVerificationInvalid,
		CodeBioNoEnrollments,
		CodeBioEnrollmentNotFound,
		CodeBioDatabaseFull,
		CodeAuthenticatorConfigStorageFull,
		CodeAuthenticatorOperationDenied,
		CodeAuthenticatorOperationNotAllowed,
		CodeAlwaysUVStateUnknown,
		CodeAlwaysUVAlreadyTarget,
		CodeMinPINLengthDecreaseNotAllowed,
		CodeResetWindowExpired,
		CodeLargeBlobKeyMissing,
		CodeLargeBlobKeyInvalid,
		CodeLargeBlobArrayTooLarge,
		CodeLargeBlobStorageFull,
		CodeLargeBlobIntegrityFailure,
		CodeLargeBlobUTF8Invalid,
		CodeLargeBlobJSONInvalid,
		CodeLargeBlobCBORInvalid,
		CodeCredentialInvalid,
		CodeAuthenticatorNoOperations,
	)

	allow(CodePINRequired, map[string]paramValueRule{
		"field": paramValueField,
	})
	allow(CodeMDSFetchFailed, map[string]paramValueRule{
		"httpStatus": paramValueHTTPStatus,
	})
	allow(CodeMinPINLengthDecreaseNotAllowed, map[string]paramValueRule{
		"current":   paramValueUint,
		"requested": paramValueUint,
	})
	allow(CodeLargeBlobArrayTooLarge, map[string]paramValueRule{
		"limit":     paramValueUint,
		"requested": paramValueUint,
	})

	return registry
}

func validParamValue(rule paramValueRule, value string) bool {
	if allowed, isEnum := paramValueEnums[rule]; isEnum {
		_, valid := allowed[value]
		return valid
	}

	switch rule {
	case paramValueUint:
		parsed, err := strconv.ParseUint(value, 10, 64)
		return err == nil && strconv.FormatUint(parsed, 10) == value
	case paramValueHTTPStatus:
		status, err := strconv.ParseUint(value, 10, 16)
		return err == nil && status >= 100 && status <= 599 && strconv.FormatUint(status, 10) == value
	default:
		return false
	}
}

func values(entries ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		result[entry] = struct{}{}
	}

	return result
}
