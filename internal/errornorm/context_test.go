package errornorm

import (
	"errors"
	"fmt"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/model/failure"
)

func TestAnnotatePreservesOuterErrorAndJoinedCauses(t *testing.T) {
	commandErr := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorClientPIN,
		StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
	}
	source := WithClientPINSubCommand(failure.PhaseTokenAcquisition, protocol.ClientPINSubCommandGetPINRetries)
	primary := Annotate(commandErr, source)
	cleanupErr := errors.New("transaction cleanup failed")
	invalidated := &ctaptransport.DeviceInvalidatedError{Err: cleanupErr}
	outer := fmt.Errorf("workflow: %w", errors.Join(primary, invalidated))

	got := Annotate(outer, WithPhase(failure.PhaseAuthenticator))
	if got != outer {
		t.Fatal("annotation replaced the outer error")
	}

	if !errors.Is(got, commandErr) || !errors.Is(got, cleanupErr) {
		t.Fatalf("annotation lost a joined cause: %v", got)
	}

	if retained, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](got); !ok || retained != invalidated {
		t.Fatalf("invalidation = %v, want %v", retained, invalidated)
	}

	if annotation := errorAnnotation(got); annotation != source {
		t.Fatalf("annotation = %#v, want %#v", annotation, source)
	}
}
