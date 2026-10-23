package workflow

import (
	"context"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/model/report"
)

type inspectDeviceStub struct {
	info protocol.AuthenticatorGetInfoResponse
}

func (s inspectDeviceStub) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return s.info, true
}

func (s inspectDeviceStub) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	return s.info, nil
}

func TestGetInfoAcceptsInfoCapabilityOnly(t *testing.T) {
	runner := Runner{
		Selected: report.EndpointReport{Attachment: report.AttachmentReport{ID: "inspect-capability"}},
	}

	result, err := runner.GetInfo(t.Context(), inspectDeviceStub{
		info: protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}},
	})
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}

	if len(result.Assessment.Facts) == 0 {
		t.Fatal("missing assessment")
	}
}
