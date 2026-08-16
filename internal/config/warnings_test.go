package config

import (
	"strings"
	"testing"

	. "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/safety"
)

func TestPINWarningsDescribeCTAPEffects(t *testing.T) {
	status := StatusReport{PIN: PINStatus{Supported: true, Configured: new(false)}}

	preview, err := BuildPINPreview(status, PINMutationSet, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildPINPreview(set): %v", err)
	}

	if got := preview.Warnings[1].Message; !strings.Contains(got, "does not validate either PIN value") {
		t.Fatalf("dry-run warning = %q", got)
	}
	if got := preview.Warnings[0].Message; !strings.Contains(got, "removal requires authenticator reset") {
		t.Fatalf("set PIN warning = %q", got)
	}

	status.PIN.Configured = new(true)
	preview, err = BuildPINPreview(status, PINMutationChange, safety.PreviewModeExecute)
	if err != nil {
		t.Fatalf("BuildPINPreview(change): %v", err)
	}
	if got := preview.Warnings[0].Message; !strings.Contains(got, "incorrect current PIN consumes a retry") {
		t.Fatalf("change PIN warning = %q", got)
	}
}

func TestAuthenticatorConfigWarningsDescribeFieldSpecificEffects(t *testing.T) {
	status := StatusReport{
		PIN: PINStatus{MinPINLength: 4, MaxPINLength: 63},
		AuthenticatorConfig: AuthenticatorConfigStatus{
			Supported:       true,
			SetMinPINLength: CapabilityState{Supported: true},
		},
	}
	operation := SetMinPINLengthOperation{
		NewMinPINLength:     new(uint(8)),
		MinPINLengthRPIDs:   []string{"example.com"},
		ForceChangePIN:      true,
		PINComplexityPolicy: true,
	}

	preview, err := BuildMinPINLengthPreview(status, operation, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildMinPINLengthPreview: %v", err)
	}

	wantCodes := []string{
		warningMinPINLengthPolicy,
		warningMinPINLengthIrreversible,
		warningForcePINChange,
		warningPINComplexityPolicy,
		warningMinPINLengthRPIDs,
	}
	if len(preview.Warnings) != len(wantCodes) {
		t.Fatalf("warnings = %#v, want %d", preview.Warnings, len(wantCodes))
	}
	for index, want := range wantCodes {
		if got := preview.Warnings[index].Code; got != want {
			t.Fatalf("warning[%d].Code = %q, want %q", index, got, want)
		}
	}
}

func TestAlwaysUVWarningCodesDistinguishTargetState(t *testing.T) {
	configured := false
	status := StatusReport{AuthenticatorConfig: AuthenticatorConfigStatus{
		Supported: true,
		AlwaysUV: CapabilityState{
			Supported:  true,
			Configured: &configured,
			State:      StateNotConfigured,
		},
	}}

	enable, err := BuildAlwaysUVPreview(status, AlwaysUVTargetEnable, true, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildAlwaysUVPreview(enable): %v", err)
	}
	if got := enable.Warnings[0].Code; got != warningAlwaysUVEnable {
		t.Fatalf("enable warning code = %q, want %q", got, warningAlwaysUVEnable)
	}

	configured = true
	status.AuthenticatorConfig.AlwaysUV.State = StateConfigured
	disable, err := BuildAlwaysUVPreview(status, AlwaysUVTargetDisable, false, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildAlwaysUVPreview(disable): %v", err)
	}
	if got := disable.Warnings[0].Code; got != warningAlwaysUVDisable {
		t.Fatalf("disable warning code = %q, want %q", got, warningAlwaysUVDisable)
	}
	if enable.Warnings[0].Code == disable.Warnings[0].Code {
		t.Fatalf("enable and disable warnings share localization code %q", enable.Warnings[0].Code)
	}
}

func TestEnterpriseAttestationPreviewIsOneWayAndWarns(t *testing.T) {
	configured := false
	status := StatusReport{AuthenticatorConfig: AuthenticatorConfigStatus{
		Supported: true,
		EnterpriseAttestation: CapabilityState{
			Supported:  true,
			Configured: &configured,
			State:      StateNotConfigured,
		},
	}}

	preview, err := BuildEnableEnterpriseAttestationPreview(status, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildEnableEnterpriseAttestationPreview: %v", err)
	}
	if preview.Operation != AuthenticatorConfigEnterprise ||
		!preview.RequestedEnterpriseAttestation ||
		preview.CurrentEnterpriseAttestation == nil ||
		*preview.CurrentEnterpriseAttestation {
		t.Fatalf("preview = %#v", preview)
	}
	if got := preview.Warnings[0]; got.Code != warningEnterpriseAttestation ||
		!strings.Contains(got.Message, "no command to disable") {
		t.Fatalf("warning = %#v", got)
	}
}

func TestResetAndLongTouchWarningsStateNormativeTiming(t *testing.T) {
	reset := BuildResetFactoryPreview(StatusReport{})
	if got := reset.Warnings[2].Message; !strings.Contains(got, "displayless authenticator") ||
		!strings.Contains(got, "within 10 seconds of power-up") {
		t.Fatalf("reset timing warning = %q", got)
	}

	status := StatusReport{AuthenticatorConfig: AuthenticatorConfigStatus{
		Supported:         true,
		LongTouchForReset: CapabilityState{Supported: true, Configured: new(false)},
	}}
	preview, err := BuildEnableLongTouchForResetPreview(status, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildEnableLongTouchForResetPreview: %v", err)
	}
	if got := preview.Warnings[0].Message; !strings.Contains(got, "at least five seconds") {
		t.Fatalf("long-touch warning = %q", got)
	}
}
