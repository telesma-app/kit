package config

import (
	"testing"

	. "github.com/telesma-app/kit/model/config"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

func TestPINPreviewFailuresUseStableCodes(t *testing.T) {
	tests := []struct {
		name      string
		status    StatusReport
		operation PINMutationOperation
		wantCode  failure.Code
	}{
		{
			name:      "unsupported",
			operation: PINMutationSet,
			wantCode:  failure.CodePINUnsupported,
		},
		{
			name: "already configured",
			status: StatusReport{PIN: PINStatus{
				Supported:  true,
				Configured: new(true),
			}},
			operation: PINMutationSet,
			wantCode:  failure.CodePINAlreadyConfigured,
		},
		{
			name: "not configured",
			status: StatusReport{PIN: PINStatus{
				Supported:  true,
				Configured: new(false),
			}},
			operation: PINMutationChange,
			wantCode:  failure.CodePINNotConfigured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildPINPreview(tt.status, tt.operation, safety.PreviewModeDryRun)
			if !failure.IsCode(err, tt.wantCode) {
				t.Fatalf("BuildPINPreview error = %v, want %s", err, tt.wantCode)
			}

			if got := failure.Snapshot(err).Phase; got != failure.PhaseValidation {
				t.Fatalf("BuildPINPreview phase = %q, want %q", got, failure.PhaseValidation)
			}
		})
	}
}

func TestBioPreviewFailuresUseStableCodes(t *testing.T) {
	if _, err := BuildBioEnrollPreview(StatusReport{}, 0, safety.PreviewModeDryRun); !failure.IsCode(err, failure.CodeBioUnsupported) {
		t.Fatalf("BuildBioEnrollPreview error = %v, want %s", err, failure.CodeBioUnsupported)
	}

	if _, err := DecodeTemplateID(""); !failure.IsCode(err, failure.CodeBioTemplateIDRequired) {
		t.Fatalf("DecodeTemplateID(empty) error = %v, want %s", err, failure.CodeBioTemplateIDRequired)
	}

	if _, err := DecodeTemplateID("not-hex"); !failure.IsCode(err, failure.CodeBioTemplateIDInvalid) {
		t.Fatalf("DecodeTemplateID(invalid) error = %v, want %s", err, failure.CodeBioTemplateIDInvalid)
	}
}

func TestAuthenticatorConfigPreviewFailuresUseStableCodes(t *testing.T) {
	_, err := BuildAlwaysUVPreview(StatusReport{}, AlwaysUVTargetEnable, true, safety.PreviewModeDryRun)
	if !failure.IsCode(err, failure.CodeAuthenticatorConfigUnsupported) {
		t.Fatalf("BuildAlwaysUVPreview(unsupported) error = %v, want %s", err, failure.CodeAuthenticatorConfigUnsupported)
	}

	status := StatusReport{AuthenticatorConfig: AuthenticatorConfigStatus{
		Supported: true,
		AlwaysUV: CapabilityState{
			Supported: true,
			State:     StateUnknown,
		},
	}}
	_, err = BuildAlwaysUVPreview(status, AlwaysUVTargetEnable, true, safety.PreviewModeDryRun)
	if !failure.IsCode(err, failure.CodeAlwaysUVStateUnknown) {
		t.Fatalf("BuildAlwaysUVPreview(unknown) error = %v, want %s", err, failure.CodeAlwaysUVStateUnknown)
	}

	status.AuthenticatorConfig.AlwaysUV.State = StateConfigured
	status.AuthenticatorConfig.AlwaysUV.Configured = new(true)
	_, err = BuildAlwaysUVPreview(status, AlwaysUVTargetEnable, true, safety.PreviewModeDryRun)
	if !failure.IsCode(err, failure.CodeAlwaysUVAlreadyTarget) {
		t.Fatalf("BuildAlwaysUVPreview(already target) error = %v, want %s", err, failure.CodeAlwaysUVAlreadyTarget)
	}
}

func TestMinPINLengthDecreaseFailureKeepsApprovedParams(t *testing.T) {
	status := StatusReport{
		PIN: PINStatus{MinPINLength: 8},
		AuthenticatorConfig: AuthenticatorConfigStatus{
			Supported:       true,
			SetMinPINLength: CapabilityState{Supported: true},
		},
	}

	_, err := BuildMinPINLengthPreview(status, SetMinPINLengthOperation{NewMinPINLength: new(uint(4))}, safety.PreviewModeDryRun)
	if !failure.IsCode(err, failure.CodeMinPINLengthDecreaseNotAllowed) {
		t.Fatalf("BuildMinPINLengthPreview error = %v, want %s", err, failure.CodeMinPINLengthDecreaseNotAllowed)
	}

	snapshot := failure.Snapshot(err)
	if snapshot.Phase != failure.PhaseValidation {
		t.Fatalf("failure phase = %q, want %q", snapshot.Phase, failure.PhaseValidation)
	}

	if snapshot.Params["requested"] != "4" || snapshot.Params["current"] != "8" {
		t.Fatalf("failure params = %#v, want requested/current", snapshot.Params)
	}
}

func TestMinPINLengthPreviewUsesZeroValuesAsAbsent(t *testing.T) {
	status := StatusReport{
		PIN: PINStatus{MinPINLength: 4, MaxPINLength: 63},
		AuthenticatorConfig: AuthenticatorConfigStatus{
			Supported:       true,
			SetMinPINLength: CapabilityState{Supported: true},
		},
	}
	operation := SetMinPINLengthOperation{
		NewMinPINLength: new(uint(0)),
	}

	preview, err := BuildMinPINLengthPreview(status, operation, safety.PreviewModeDryRun)
	if !failure.IsCode(err, failure.CodeMinPINLengthDecreaseNotAllowed) {
		t.Fatalf("zero minimum error = %v, want decrease rejection", err)
	}

	operation.NewMinPINLength = nil
	preview, err = BuildMinPINLengthPreview(status, operation, safety.PreviewModeDryRun)
	if !failure.IsCode(err, failure.CodeCTAPParameterMissing) {
		t.Fatalf("zero-value request error = %v, want parameter missing", err)
	}

	operation.MinPINLengthRPIDs = []string{"example.com"}
	operation.ForceChangePIN = true
	operation.PINComplexityPolicy = true
	preview, err = BuildMinPINLengthPreview(status, operation, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildMinPINLengthPreview: %v", err)
	}

	if len(preview.MinPINLengthRPIDs) != 1 || !preview.ForceChangePIN || !preview.PINComplexityPolicy {
		t.Fatalf("preview = %#v", preview)
	}

}

func TestEnableLongTouchForResetPreviewValidation(t *testing.T) {
	base := StatusReport{AuthenticatorConfig: AuthenticatorConfigStatus{Supported: true}}
	if _, err := BuildEnableLongTouchForResetPreview(base, safety.PreviewModeDryRun); !failure.IsCode(err, failure.CodeAuthenticatorConfigUnsupported) {
		t.Fatalf("unsupported error = %v", err)
	}

	base.AuthenticatorConfig.LongTouchForReset = CapabilityState{Supported: true, Configured: new(true)}
	if _, err := BuildEnableLongTouchForResetPreview(base, safety.PreviewModeDryRun); !failure.IsCode(err, failure.CodeAuthenticatorOperationNotAllowed) {
		t.Fatalf("already enabled error = %v", err)
	}

	base.AuthenticatorConfig.LongTouchForReset.Configured = new(false)
	preview, err := BuildEnableLongTouchForResetPreview(base, safety.PreviewModeDryRun)
	if err != nil {
		t.Fatalf("BuildEnableLongTouchForResetPreview: %v", err)
	}

	if preview.CurrentLongTouch == nil || *preview.CurrentLongTouch ||
		!preview.RequestedLongTouch {
		t.Fatalf("preview = %#v", preview)
	}
}
