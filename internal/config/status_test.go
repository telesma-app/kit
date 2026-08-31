package config

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/getinfo"
	. "github.com/telesma-app/kit/model/config"
	appinspect "github.com/telesma-app/kit/model/inspect"
	"github.com/telesma-app/kit/model/report"
)

func TestBuildStatusReportMatchesCtaphidOptionSemantics(t *testing.T) {
	info := protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN:             false,
			protocol.OptionUserVerification:      false,
			protocol.OptionBioEnroll:             false,
			protocol.OptionUvBioEnroll:           false,
			protocol.OptionAuthenticatorConfig:   true,
			protocol.OptionUvAcfg:                false,
			protocol.OptionEnterpriseAttestation: false,
			protocol.OptionAlwaysUv:              false,
			protocol.OptionSetMinPINLength:       false,
		},
		LongTouchForReset: new(false),
		AuthenticatorConfigCommands: []protocol.ConfigSubCommand{
			protocol.ConfigSubCommandEnableLongTouchForReset,
		},
		VendorPrototypeConfigCommands: []protocol.VendorCommandID{7, 0x1_0000_0000},
	}

	r := BuildStatusReport(nilDevice(), info)

	if !r.PIN.Supported || r.PIN.Configured == nil || *r.PIN.Configured {
		t.Fatalf("clientPin false should mean supported but not configured: %#v", r.PIN)
	}

	if !r.UV.Supported || r.UV.Configured == nil || *r.UV.Configured {
		t.Fatalf("uv false should mean supported but not configured: %#v", r.UV)
	}

	if !r.Bio.Supported ||
		r.Bio.Configured == nil ||
		*r.Bio.Configured ||
		r.Bio.State != StateNotConfigured {
		t.Fatalf("bioEnroll false should mean supported but no enrollment provisioned: %#v", r.Bio)
	}

	if r.Bio.UVBioEnroll.Supported || r.Bio.UVBioEnroll.State != StateUnsupported {
		t.Fatalf("uvBioEnroll false should mean unsupported binding: %#v", r.Bio.UVBioEnroll)
	}

	if !r.AuthenticatorConfig.Supported || r.AuthenticatorConfig.State != StateSupported {
		t.Fatalf("authnrCfg true should mean supported: %#v", r.AuthenticatorConfig)
	}

	if r.AuthenticatorConfig.UVAcfg.Supported ||
		r.AuthenticatorConfig.UVAcfg.State != StateUnsupported {
		t.Fatalf("uvAcfg false should mean unsupported binding: %#v", r.AuthenticatorConfig.UVAcfg)
	}

	if !r.AuthenticatorConfig.AlwaysUV.Supported ||
		r.AuthenticatorConfig.AlwaysUV.Configured == nil ||
		*r.AuthenticatorConfig.AlwaysUV.Configured {
		t.Fatalf("alwaysUv false should mean supported but disabled: %#v", r.AuthenticatorConfig.AlwaysUV)
	}

	if !r.AuthenticatorConfig.EnterpriseAttestation.Supported ||
		r.AuthenticatorConfig.EnterpriseAttestation.Configured == nil ||
		*r.AuthenticatorConfig.EnterpriseAttestation.Configured {
		t.Fatalf("ep false should mean supported but disabled: %#v", r.AuthenticatorConfig.EnterpriseAttestation)
	}

	if !r.AuthenticatorConfig.VendorPrototype.Supported ||
		!slices.Equal(r.AuthenticatorConfig.VendorPrototypeConfigCommands, []string{"7", "4294967296"}) {
		t.Fatalf("vendor prototype inventory = %#v", r.AuthenticatorConfig)
	}

	if r.AuthenticatorConfig.SetMinPINLength.Supported ||
		r.AuthenticatorConfig.SetMinPINLength.State != StateUnsupported {
		t.Fatalf("setMinPINLength false should mean unsupported: %#v", r.AuthenticatorConfig.SetMinPINLength)
	}

	if r.ResetHints.LongTouchForReset != StateNotConfigured {
		t.Fatalf("longTouchForReset false should mean supported but disabled: %#v", r.ResetHints.LongTouchForReset)
	}
}

func TestBuildStatusReportLabelsUVModality(t *testing.T) {
	modality := protocol.UserVerifyFingerprintInternal |
		protocol.UserVerifyPasscodeExternal |
		protocol.UserVerify(0x2000)
	statusReport := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		UvModality: new(modality),
	})

	if statusReport.Bio.UVModality == nil || *statusReport.Bio.UVModality != uint(modality) {
		t.Fatalf("uv modality = %#v, want %#x", statusReport.Bio.UVModality, modality)
	}

	const want = "fingerprint_internal,passcode_external,unknown(0x2000)"
	if statusReport.Bio.UVModalityLabel != want {
		t.Fatalf("uv modality label = %q, want %q", statusReport.Bio.UVModalityLabel, want)
	}
}

func TestPreviewOnlyBioStatusReportsSupportWhenNoEnrollmentProvisioned(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Versions: []protocol.Version{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerificationMgmtPreview: false,
		},
	})
	if !statusReport.Bio.Supported ||
		!statusReport.Bio.PreviewOnly ||
		statusReport.Bio.Configured == nil ||
		*statusReport.Bio.Configured ||
		statusReport.Bio.State != StatePreviewOnly {
		t.Fatalf("preview bio false should mean preview-only support with no enrollment provisioned: %#v", statusReport.Bio)
	}

	statusReport = BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Versions: []protocol.Version{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerificationMgmtPreview: true,
		},
	})
	if !statusReport.Bio.Supported || statusReport.Bio.State != StatePreviewOnly {
		t.Fatalf("enabled preview bio option should be preview-only supported: %#v", statusReport.Bio)
	}
}

func TestBuildStatusReportAppliesEffectiveLimitsAndPreservesNullableZeros(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: false,
		},
		ForcePINChange:              false,
		MinPINLength:                0,
		MaxPINLength:                0,
		MaxRPIDsForSetMinPINLength:  new(uint(0)),
		PreferredPlatformUvAttempts: 0,
		UvCountSinceLastPinEntry:    new(uint(0)),
		PinComplexityPolicy:         new(false),
		PinComplexityPolicyURL:      []byte{},
	})

	if statusReport.PIN.MinPINLength != 4 {
		t.Fatalf("pin minPINLength = %#v, want effective 4", statusReport.PIN.MinPINLength)
	}

	if statusReport.PIN.MaxPINLength != 63 {
		t.Fatalf("pin maxPINLength = %#v, want effective 63", statusReport.PIN.MaxPINLength)
	}

	if statusReport.PIN.PinComplexityPolicy == nil || *statusReport.PIN.PinComplexityPolicy {
		t.Fatalf("pinComplexityPolicy = %#v, want explicit false", statusReport.PIN.PinComplexityPolicy)
	}

	if statusReport.Limits.MaxRPIDsForSetMinPINLength == nil || *statusReport.Limits.MaxRPIDsForSetMinPINLength != 0 {
		t.Fatalf("max RPIDs = %#v, want explicit 0", statusReport.Limits.MaxRPIDsForSetMinPINLength)
	}

	raw, err := json.Marshal(statusReport)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	text := string(raw)
	for _, want := range []string{
		`"minPINLength":4`,
		`"maxPINLength":63`,
		`"pinComplexityPolicy":false`,
		`"maxRPIDsForSetMinPINLength":0`,
		`"uvCountSinceLastPinEntry":0`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON missing %s: %s", want, text)
		}
	}

	for _, reject := range []string{"forcePINChange", "pinComplexityPolicyURL", "preferredPlatformUvAttempts"} {
		if strings.Contains(text, reject) {
			t.Fatalf("JSON included zero-value %s: %s", reject, text)
		}
	}
}

func TestBuildStatusReportUsesEffectivePINLimitsAndOmitsOtherAbsentNullableLimits(t *testing.T) {
	statusReport := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{})

	raw, err := json.Marshal(statusReport)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	text := string(raw)
	for _, reject := range []string{
		"forcePINChange",
		"pinComplexityPolicy",
		"pinComplexityPolicyURL",
		"maxRPIDsForSetMinPINLength",
		"preferredPlatformUvAttempts",
		"uvCountSinceLastPinEntry",
	} {
		if strings.Contains(text, reject) {
			t.Fatalf("JSON included absent %s: %s", reject, text)
		}
	}

	if !strings.Contains(text, `"maxPINLength":63`) {
		t.Fatalf("JSON omitted effective max PIN length: %s", text)
	}

	if !strings.Contains(text, `"minPINLength":4`) {
		t.Fatalf("JSON omitted effective minimum PIN length: %s", text)
	}
}

func TestBuildStatusReportUsesResolvedGetInfoFacts(t *testing.T) {
	info := protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN:             false,
			protocol.OptionUserVerification:      true,
			protocol.OptionBioEnroll:             false,
			protocol.OptionUvBioEnroll:           true,
			protocol.OptionAuthenticatorConfig:   true,
			protocol.OptionUvAcfg:                true,
			protocol.OptionEnterpriseAttestation: true,
			protocol.OptionAlwaysUv:              false,
			protocol.OptionSetMinPINLength:       true,
		},
		MinPINLength:      8,
		MaxPINLength:      64,
		LongTouchForReset: new(false),
		AuthenticatorConfigCommands: []protocol.ConfigSubCommand{
			protocol.ConfigSubCommandEnableLongTouchForReset,
		},
	}

	assessment := getinfo.Resolve(info)
	status := BuildStatusReport(nilDevice(), info)

	assertCapabilityMatchesFact(t, status.PIN.State, status.PIN.Supported, status.PIN.Configured, assessment, appinspect.FactIDClientPIN)
	assertCapabilityMatchesFact(t, status.UV.State, status.UV.Supported, status.UV.Configured, assessment, appinspect.FactIDUserVerification)
	assertCapabilityMatchesFact(t, status.Bio.State, status.Bio.Supported, status.Bio.Configured, assessment, appinspect.FactIDBioEnrollment)
	assertCapabilityMatchesFact(t, status.Bio.UVBioEnroll.State, status.Bio.UVBioEnroll.Supported, status.Bio.UVBioEnroll.Configured, assessment, appinspect.FactIDUvBioEnroll)
	assertCapabilityMatchesFact(t, status.AuthenticatorConfig.State, status.AuthenticatorConfig.Supported, status.AuthenticatorConfig.Configured, assessment, appinspect.FactIDAuthenticatorConfig)
	assertCapabilityMatchesFact(t, status.AuthenticatorConfig.UVAcfg.State, status.AuthenticatorConfig.UVAcfg.Supported, status.AuthenticatorConfig.UVAcfg.Configured, assessment, appinspect.FactIDUvAuthenticatorConfig)
	assertCapabilityMatchesFact(t, status.AuthenticatorConfig.EnterpriseAttestation.State, status.AuthenticatorConfig.EnterpriseAttestation.Supported, status.AuthenticatorConfig.EnterpriseAttestation.Configured, assessment, appinspect.FactIDEnterpriseAttestation)
	assertCapabilityMatchesFact(t, status.AuthenticatorConfig.AlwaysUV.State, status.AuthenticatorConfig.AlwaysUV.Supported, status.AuthenticatorConfig.AlwaysUV.Configured, assessment, appinspect.FactIDAlwaysUV)
	assertCapabilityMatchesFact(t, status.AuthenticatorConfig.SetMinPINLength.State, status.AuthenticatorConfig.SetMinPINLength.Supported, status.AuthenticatorConfig.SetMinPINLength.Configured, assessment, appinspect.FactIDSetMinPINLength)
	assertCapabilityMatchesFact(t, status.AuthenticatorConfig.LongTouchForReset.State, status.AuthenticatorConfig.LongTouchForReset.Supported, status.AuthenticatorConfig.LongTouchForReset.Configured, assessment, appinspect.FactIDLongTouchForReset)
	if status.ResetHints.LongTouchForReset != status.AuthenticatorConfig.LongTouchForReset.State {
		t.Fatalf("reset hint long-touch state = %s, authenticator config state = %s", status.ResetHints.LongTouchForReset, status.AuthenticatorConfig.LongTouchForReset.State)
	}

	if status.Limits.MinPINLength != 8 || status.Limits.MaxPINLength != 64 {
		t.Fatalf("effective limits = %#v, want 8/64", status.Limits)
	}
}

func TestBuildStatusReportKeepsCapabilitiesUnknownWhenOptionsAreAbsent(t *testing.T) {
	status := BuildStatusReport(nilDevice(), protocol.AuthenticatorGetInfoResponse{})

	for name, state := range map[string]StateValue{
		"PIN":                  status.PIN.State,
		"UV":                   status.UV.State,
		"bio":                  status.Bio.State,
		"authenticator config": status.AuthenticatorConfig.State,
		"always UV":            status.AuthenticatorConfig.AlwaysUV.State,
	} {
		if state != StateUnknown {
			t.Fatalf("%s state = %s, want unknown", name, state)
		}
	}
}

func assertCapabilityMatchesFact(t *testing.T, state StateValue, supported bool, configured *bool, assessment appinspect.Assessment, id appinspect.FactID) {
	t.Helper()

	fact, ok := getinfo.Find(assessment, id)
	if !ok {
		t.Fatalf("fact %q not found", id)
	}

	wantState := StateUnknown
	var wantConfigured *bool
	switch fact.State {
	case appinspect.FactStateSupported:
		wantState = StateSupported
	case appinspect.FactStateUnsupported:
		wantState = StateUnsupported
	case appinspect.FactStateConfigured, appinspect.FactStateEnabled:
		wantState = StateConfigured
		wantConfigured = new(true)
	case appinspect.FactStateNotConfigured, appinspect.FactStateDisabled:
		wantState = StateNotConfigured
		wantConfigured = new(false)
	}
	wantSupported := wantState == StateSupported || wantState == StateConfigured || wantState == StateNotConfigured

	if state != wantState || supported != wantSupported || !(configured == wantConfigured || configured != nil && wantConfigured != nil && *configured == *wantConfigured) {
		t.Fatalf("status for %q = state %s supported %t configured %#v; fact = %#v", id, state, supported, configured, fact)
	}
}

func nilDevice() report.DeviceReport {
	return report.DeviceReport{}
}
