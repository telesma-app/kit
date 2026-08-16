package failure

import (
	"errors"
)

// CTAPDetail records the exact authenticator command and status associated with
// a failure. Numeric values remain authoritative for unknown extension and
// vendor values whose symbolic names are unavailable.
type CTAPDetail struct {
	Command          string  `json:"command,omitempty"`
	CommandCode      uint8   `json:"commandCode"`
	SubCommandFamily string  `json:"subCommandFamily,omitempty"`
	SubCommand       string  `json:"subCommand,omitempty"`
	SubCommandCode   *uint64 `json:"subCommandCode,omitempty"`
	Status           string  `json:"status,omitempty"`
	StatusCode       uint8   `json:"statusCode"`
}

// Failure is the transport-safe, machine-readable representation of one
// failure. It intentionally contains no human-readable message or Go cause.
type Failure struct {
	Code      Code              `json:"code"`
	Category  Category          `json:"category"`
	Params    map[string]string `json:"params,omitempty"`
	Operation string            `json:"operation,omitempty"`
	Phase     Phase             `json:"phase,omitempty"`
	CTAP      *CTAPDetail       `json:"ctap,omitempty"`
}

// Error is the Go error representation of a Failure. The wrapped cause is
// intentionally private and is never included in JSON.
type Error struct {
	Failure

	cause error
}

// Option configures a newly constructed Error.
type Option func(*Failure)

// New constructs a coded error without a wrapped Go cause.
func New(code Code, opts ...Option) *Error {
	return newError(code, nil, opts...)
}

// Wrap constructs a coded error that retains a private in-process cause.
func Wrap(code Code, cause error, opts ...Option) *Error {
	return newError(code, cause, opts...)
}

func newError(code Code, cause error, opts ...Option) *Error {
	snapshot := Failure{Code: code}
	for _, opt := range opts {
		opt(&snapshot)
	}
	snapshot = canonicalFailure(snapshot)

	return &Error{Failure: snapshot, cause: cause}
}

// WithParams records safe interpolation parameters. The code registry controls
// which names and values survive construction and snapshots.
func WithParams(params map[string]string) Option {
	return func(failure *Failure) {
		failure.Params = params
	}
}

// WithOperation records the public operation kind associated with a failure.
func WithOperation(operation string) Option {
	return func(failure *Failure) {
		failure.Operation = operation
	}
}

// WithPhase records the runtime phase in which a failure occurred.
func WithPhase(phase Phase) Option {
	return func(failure *Failure) {
		failure.Phase = phase
	}
}

// WithCTAP records exact CTAP provenance for an authenticator failure.
func WithCTAP(detail *CTAPDetail) Option {
	return func(failure *Failure) {
		failure.CTAP = detail
	}
}

func (e *Error) Error() string {
	return string(e.Code)
}

func (e *Error) Unwrap() error {
	return e.cause
}

// CodeOf returns the stable code for err. Every non-nil unrecognized error is
// represented as CodeInternalError.
func CodeOf(err error) (Code, bool) {
	snapshot := Snapshot(err)
	if snapshot == nil {
		return "", false
	}

	return snapshot.Code, true
}

// IsCode reports whether err resolves to code.
func IsCode(err error, code Code) bool {
	actual, ok := CodeOf(err)
	return ok && actual == code
}

// Snapshot returns the normalized, transport-safe failure stored by err. Nil
// errors have no snapshot; unknown errors become CodeInternalError.
func Snapshot(err error) *Failure {
	if err == nil {
		return nil
	}

	if typed, ok := errors.AsType[*Error](err); ok {
		return &typed.Failure
	}

	return new(canonicalFailure(Failure{Code: CodeInternalError}))
}

func canonicalFailure(failure Failure) Failure {
	spec, known := codeRegistry[failure.Code]
	if !known {
		failure.Code = CodeInternalError
		spec = codeRegistry[CodeInternalError]
	}

	failure.Category = spec.category
	failure.Params = allowedParams(failure.Params, spec.params)
	failure.Operation = canonicalOperation(failure.Operation)
	failure.Phase = canonicalPhase(failure.Phase)
	failure.CTAP = canonicalCTAP(failure.CTAP)

	return failure
}

func canonicalPhase(phase Phase) Phase {
	switch phase {
	case "",
		PhaseValidation,
		PhaseDiscovery,
		PhaseAuthenticator,
		PhaseInteraction,
		PhaseTokenAcquisition,
		PhaseAuthenticatorCommand,
		PhaseAssertionContinuation,
		PhaseMetadata,
		PhaseIdentity,
		PhaseDecode,
		PhaseCleanup:
		return phase
	default:
		return ""
	}
}

func allowedParams(params map[string]string, allowlist map[string]paramValueRule) map[string]string {
	if len(params) == 0 || len(allowlist) == 0 {
		return nil
	}

	filtered := make(map[string]string)
	for name, value := range params {
		if rule, allowed := allowlist[name]; allowed && validParamValue(rule, value) {
			filtered[name] = value
		}
	}

	if len(filtered) == 0 {
		return nil
	}

	return filtered
}
