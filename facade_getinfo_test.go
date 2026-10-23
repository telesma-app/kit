package ctapkit

import (
	"context"
	"testing"
)

func TestGetInfoEmitsNoEventsWithoutProgressOrStateChanges(t *testing.T) {
	events := &recordingEventSink{}

	session := openContractAuthenticator(t, events, nil)
	defer func() { _ = session.Close() }()

	output, err := session.GetInfo(context.Background(), WithInteractionHandler(nil))
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}

	if len(output.Assessment.Facts) == 0 {
		t.Fatalf("unexpected output: %#v", output)
	}

	recorded := events.Events()
	if len(recorded) != 0 {
		t.Fatalf("events = %v, want none", recorded)
	}
}
