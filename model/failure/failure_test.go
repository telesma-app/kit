package failure

import (
	"encoding/json"
	"errors"
	"testing"
)

var _ error = (*Error)(nil)

func TestNewConstructsSemanticErrorWithoutCause(t *testing.T) {
	err := New(
		CodePINRequired,
		WithParams(map[string]string{"field": "currentPIN"}),
		WithPhase(PhaseInteraction),
	)

	if cause := errors.Unwrap(err); cause != nil {
		t.Fatalf("Unwrap(New(...)) = %v, want nil", cause)
	}

	if err.Code != CodePINRequired || err.Category != CategoryInvalidOperation {
		t.Fatalf("failure = %#v, want PIN_REQUIRED/invalid-operation", err.Failure)
	}

	if len(err.Params) != 1 || err.Params["field"] != "currentPIN" {
		t.Fatalf("Params = %#v, want allowlisted parameter", err.Params)
	}

	if err.Phase != PhaseInteraction {
		t.Fatalf("Phase = %q, want %q", err.Phase, PhaseInteraction)
	}
}

func TestWrapBuildsCodedErrorAndRetainsCause(t *testing.T) {
	cause := errors.New("device response")
	subCommandCode := uint64(9)
	detail := &CTAPDetail{
		Command:          "authenticatorClientPIN",
		CommandCode:      6,
		SubCommandFamily: "clientPIN",
		SubCommand:       "getPinUvAuthTokenUsingPinWithPermissions",
		SubCommandCode:   &subCommandCode,
		Status:           "CTAP2_ERR_PIN_INVALID",
		StatusCode:       0x31,
	}
	params := map[string]string{
		"field": "currentPIN",
		"pin":   "must-not-survive",
	}
	err := Wrap(
		CodePINRequired,
		cause,
		WithParams(params),
		WithOperation("config.pin.change"),
		WithPhase(PhaseTokenAcquisition),
		WithCTAP(detail),
	)

	params["field"] = "newPIN"
	subCommandCode = 1
	detail.Status = "changed"

	if got := err.Error(); got != "PIN_REQUIRED" {
		t.Fatalf("Error() = %q, want PIN_REQUIRED", got)
	}

	if !errors.Is(err, cause) {
		t.Fatal("coded error does not unwrap to its cause")
	}

	if got, ok := CodeOf(err); !ok || got != CodePINRequired {
		t.Fatalf("CodeOf() = %q, %v, want %q, true", got, ok, CodePINRequired)
	}

	if !IsCode(err, CodePINRequired) {
		t.Fatal("IsCode() = false for the error's code")
	}

	if IsCode(err, CodePINInvalid) {
		t.Fatal("IsCode() = true for a different code")
	}

	if len(err.Params) != 1 || err.Params["field"] != "currentPIN" {
		t.Fatalf("Params = %#v, want only allowlisted parameter", err.Params)
	}

	if err.CTAP != detail || err.CTAP.Status != "changed" {
		t.Fatalf("CTAP = %#v, want aliased CTAP detail", err.CTAP)
	}

	if err.CTAP.SubCommandCode == nil || *err.CTAP.SubCommandCode != 1 {
		t.Fatalf("SubCommandCode = %#v, want aliased value 1", err.CTAP.SubCommandCode)
	}
}

func TestSnapshotAliasesStoredFailure(t *testing.T) {
	subCommandCode := uint64(1)
	err := Wrap(
		CodeLargeBlobArrayTooLarge,
		errors.New("too large"),
		WithParams(map[string]string{"requested": "100", "limit": "64"}),
		WithCTAP(&CTAPDetail{SubCommandCode: &subCommandCode, StatusCode: 0x15}),
	)

	first := Snapshot(err)
	first.Params["requested"] = "1"
	*first.CTAP.SubCommandCode = 2

	second := Snapshot(err)
	if second != first || second.Params["requested"] != "1" {
		t.Fatalf("snapshot did not alias stored params: %#v", second.Params)
	}

	if *second.CTAP.SubCommandCode != 2 {
		t.Fatalf("snapshot did not alias CTAP detail: %#v", second.CTAP)
	}
}

func TestFailureJSONWireShape(t *testing.T) {
	subCommandCode := uint64(9)
	err := Wrap(
		CodePINInvalid,
		errors.New("sensitive diagnostic"),
		WithOperation("webauthn.getAssertion"),
		WithPhase(PhaseTokenAcquisition),
		WithCTAP(&CTAPDetail{
			Command:          "authenticatorClientPIN",
			CommandCode:      6,
			SubCommandFamily: "clientPIN",
			SubCommand:       "getPinUvAuthTokenUsingPinWithPermissions",
			SubCommandCode:   &subCommandCode,
			Status:           "CTAP2_ERR_PIN_INVALID",
			StatusCode:       0x31,
		}),
	)

	raw, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal: %v", marshalErr)
	}

	want := `{"code":"PIN_INVALID","category":"invalid-state","operation":"webauthn.getAssertion","phase":"token-acquisition","ctap":{"command":"authenticatorClientPIN","commandCode":6,"subCommandFamily":"clientPIN","subCommand":"getPinUvAuthTokenUsingPinWithPermissions","subCommandCode":9,"status":"CTAP2_ERR_PIN_INVALID","statusCode":49}}`
	if string(raw) != want {
		t.Fatalf("Marshal = %s, want %s", raw, want)
	}
}

func TestUnknownCodeBecomesInternalError(t *testing.T) {
	const (
		unknownCode  Code  = "NOT_REGISTERED"
		unknownPhase Phase = "not-registered"
	)

	err := Wrap(
		unknownCode,
		errors.New("cause"),
		WithParams(map[string]string{"field": "value"}),
		WithPhase(unknownPhase),
	)

	if err.Code != CodeInternalError || err.Category != CategoryInternal {
		t.Fatalf("failure = %#v, want internal error", err.Failure)
	}

	if err.Params != nil {
		t.Fatalf("Params = %#v, want nil", err.Params)
	}

	if err.Phase != "" {
		t.Fatalf("Phase = %q, want empty", err.Phase)
	}

	if !IsCode(err, CodeInternalError) {
		t.Fatal("unknown code does not resolve to INTERNAL_ERROR")
	}

	if IsCode(err, unknownCode) {
		t.Fatal("IsCode accepted an unknown target code")
	}
}

func TestNilHelpers(t *testing.T) {
	if snapshot := Snapshot(nil); snapshot != nil {
		t.Fatalf("Snapshot(nil) = %#v, want nil", snapshot)
	}

	if code, ok := CodeOf(nil); ok || code != "" {
		t.Fatalf("CodeOf(nil) = %q, %v, want empty, false", code, ok)
	}

	if IsCode(nil, CodeInternalError) {
		t.Fatal("IsCode(nil) = true")
	}
}
