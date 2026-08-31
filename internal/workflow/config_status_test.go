package workflow

import (
	"context"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/internal/errornorm"
	appconfig "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
)

type retryFailureDevice struct {
	info     protocol.AuthenticatorGetInfoResponse
	pinErr   error
	uvErr    error
	pinCalls *int
}

func (d retryFailureDevice) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	return d.info, nil
}

func (d retryFailureDevice) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return d.info, true
}

func (d retryFailureDevice) GetPINRetries(context.Context) (uint, *bool, error) {
	if d.pinCalls != nil {
		*d.pinCalls++
	}

	return 7, new(false), d.pinErr
}

func (d retryFailureDevice) GetUVRetries(context.Context) (uint, error) {
	return 5, d.uvErr
}

func TestConfigStatusRetryFailureReturnsZeroReport(t *testing.T) {
	raw := &ctaptransport.CTAPError{
		Command:    protocol.AuthenticatorClientPIN,
		StatusCode: ctaptransport.CTAP2_ERR_PIN_INVALID,
	}
	tests := []struct {
		name       string
		device     retryFailureDevice
		subCommand protocol.ClientPINSubCommand
	}{
		{
			name: "PIN retries",
			device: retryFailureDevice{
				info: protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				}},
				pinErr: raw,
			},
			subCommand: protocol.ClientPINSubCommandGetPINRetries,
		},
		{
			name: "UV retries",
			device: retryFailureDevice{
				info: protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				}},
				uvErr: raw,
			},
			subCommand: protocol.ClientPINSubCommandGetUVRetries,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := (Runner{}).ConfigStatus(t.Context(), tt.device)
			if err == nil {
				t.Fatal("ConfigStatus error = nil")
			}
			if !jsonValuesEqual(t, report, appconfig.StatusReport{}) {
				t.Fatalf("ConfigStatus report = %#v, want zero", report)
			}

			snapshot := failure.Snapshot(errornorm.Normalize(err, ""))
			if snapshot == nil || snapshot.Code != failure.CodePINInvalid {
				t.Fatalf("failure = %#v, want %s", snapshot, failure.CodePINInvalid)
			}
			if snapshot.Phase != failure.PhaseAuthenticatorCommand {
				t.Fatalf("failure phase = %q, want %q", snapshot.Phase, failure.PhaseAuthenticatorCommand)
			}
			if snapshot.CTAP == nil ||
				snapshot.CTAP.SubCommandCode == nil ||
				*snapshot.CTAP.SubCommandCode != uint64(tt.subCommand) {
				t.Fatalf("CTAP detail = %#v, want subcommand %d", snapshot.CTAP, tt.subCommand)
			}
		})
	}
}

func TestConfigStatusSkipsPINRetriesWhenPINIsNotConfigured(t *testing.T) {
	pinCalls := 0
	device := retryFailureDevice{
		info: protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: false,
		}},
		pinErr:   &ctaptransport.CTAPError{StatusCode: ctaptransport.CTAP2_ERR_PIN_NOT_SET},
		pinCalls: &pinCalls,
	}

	report, err := (Runner{}).ConfigStatus(t.Context(), device)
	if err != nil {
		t.Fatalf("ConfigStatus: %v", err)
	}
	if pinCalls != 0 {
		t.Fatalf("GetPINRetries calls = %d, want 0", pinCalls)
	}
	if !report.PIN.Supported || report.PIN.Configured == nil || *report.PIN.Configured {
		t.Fatalf("PIN status = %#v, want supported and not configured", report.PIN)
	}
	if report.PIN.Retries.State != appconfig.StateUnknown {
		t.Fatalf("PIN retry state = %q, want %q", report.PIN.Retries.State, appconfig.StateUnknown)
	}
}
