package config

import (
	"strconv"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/getinfo"
	appconfig "github.com/telesma-app/kit/model/config"
	appinspect "github.com/telesma-app/kit/model/inspect"
	"github.com/telesma-app/kit/model/report"
)

func BuildStatusReport(device report.EndpointReport, info protocol.AuthenticatorGetInfoResponse) appconfig.StatusReport {
	assessment := getinfo.Resolve(info)
	r := appconfig.StatusReport{
		Device:              device,
		PIN:                 buildPINStatus(info, assessment),
		UV:                  buildUVStatus(factCapability(assessment, appinspect.FactIDUserVerification, false)),
		Bio:                 buildBioStatus(bioCapability(info, assessment)),
		AuthenticatorConfig: buildAuthenticatorConfigStatus(factCapability(assessment, appinspect.FactIDAuthenticatorConfig, false)),
		Limits:              buildLimitsStatus(info),
	}

	if info.UvModality != nil {
		r.Bio.UVModality = new(uint(*info.UvModality))
		r.Bio.UVModalityLabel = info.UvModality.String()
	}

	r.ResetHints.TransportsForReset = make([]string, len(info.TransportsForReset))
	for i, value := range info.TransportsForReset {
		r.ResetHints.TransportsForReset[i] = string(value)
	}

	r.Bio.UVBioEnroll = factCapability(assessment, appinspect.FactIDUvBioEnroll, false)
	r.AuthenticatorConfig.UVAcfg = factCapability(assessment, appinspect.FactIDUvAuthenticatorConfig, false)
	r.AuthenticatorConfig.EnterpriseAttestation = factCapability(assessment, appinspect.FactIDEnterpriseAttestation, false)
	r.AuthenticatorConfig.AlwaysUV = factCapability(assessment, appinspect.FactIDAlwaysUV, false)
	r.AuthenticatorConfig.SetMinPINLength = factCapability(assessment, appinspect.FactIDSetMinPINLength, false)
	longTouchForReset := factCapability(assessment, appinspect.FactIDLongTouchForReset, false)
	r.AuthenticatorConfig.LongTouchForReset = longTouchForReset
	r.AuthenticatorConfig.VendorPrototype = vendorPrototypeCapability(info)

	r.AuthenticatorConfig.VendorPrototypeConfigCommands = make([]string, len(info.VendorPrototypeConfigCommands))
	for i, value := range info.VendorPrototypeConfigCommands {
		r.AuthenticatorConfig.VendorPrototypeConfigCommands[i] = strconv.FormatUint(uint64(value), 10)
	}

	r.ResetHints.LongTouchForReset = longTouchForReset.State

	return r
}

func buildPINStatus(info protocol.AuthenticatorGetInfoResponse, assessment appinspect.Assessment) appconfig.PINStatus {
	capability := factCapability(assessment, appinspect.FactIDClientPIN, false)

	return appconfig.PINStatus{
		State:               capability.State,
		Supported:           capability.Supported,
		Configured:          capability.Configured,
		ProtocolSupported:   len(info.PinUvAuthProtocols) > 0,
		ForcePINChange:      info.ForcePINChange,
		PinComplexityPolicy: info.PinComplexityPolicy,
		PinComplexityURL:    info.PinComplexityPolicyURLString(),
		MinPINLength:        info.EffectiveMinPINLength(),
		MaxPINLength:        info.EffectiveMaxPINLength(),
		Retries:             appconfig.RetryState{State: appconfig.StateUnknown},
	}
}

func bioCapability(info protocol.AuthenticatorGetInfoResponse, assessment appinspect.Assessment) appconfig.CapabilityState {
	if info.Versions.IsPreviewOnly() {
		return factCapability(assessment, appinspect.FactIDBioEnrollmentPreview, true)
	}

	return factCapability(assessment, appinspect.FactIDBioEnrollment, false)
}

func buildUVStatus(capability appconfig.CapabilityState) appconfig.UVStatus {
	return appconfig.UVStatus{
		State:       capability.State,
		Supported:   capability.Supported,
		Configured:  capability.Configured,
		PreviewOnly: capability.PreviewOnly,
		Retries:     appconfig.RetryState{State: appconfig.StateUnknown},
	}
}

func buildBioStatus(capability appconfig.CapabilityState) appconfig.BioStatus {
	return appconfig.BioStatus{
		State:       capability.State,
		Supported:   capability.Supported,
		Configured:  capability.Configured,
		PreviewOnly: capability.PreviewOnly,
	}
}

func buildAuthenticatorConfigStatus(capability appconfig.CapabilityState) appconfig.AuthenticatorConfigStatus {
	return appconfig.AuthenticatorConfigStatus{
		State:       capability.State,
		Supported:   capability.Supported,
		Configured:  capability.Configured,
		PreviewOnly: capability.PreviewOnly,
	}
}

func vendorPrototypeCapability(info protocol.AuthenticatorGetInfoResponse) appconfig.CapabilityState {
	if info.VendorPrototypeConfigCommands == nil {
		return appconfig.CapabilityState{State: appconfig.StateUnsupported}
	}

	return appconfig.CapabilityState{
		State:     appconfig.StateSupported,
		Supported: true,
	}
}

func buildLimitsStatus(info protocol.AuthenticatorGetInfoResponse) appconfig.LimitsStatus {
	return appconfig.LimitsStatus{
		MinPINLength:                info.EffectiveMinPINLength(),
		MaxPINLength:                info.EffectiveMaxPINLength(),
		MaxRPIDsForSetMinPINLength:  info.MaxRPIDsForSetMinPINLength,
		PreferredPlatformUVAttempts: info.PreferredPlatformUvAttempts,
		UVCountSinceLastPINEntry:    info.UvCountSinceLastPinEntry,
	}
}

func factCapability(assessment appinspect.Assessment, id appinspect.FactID, previewOnly bool) appconfig.CapabilityState {
	fact, _ := getinfo.Find(assessment, id)

	state := appconfig.CapabilityState{PreviewOnly: previewOnly}

	switch fact.State {
	case appinspect.FactStateSupported:
		state.State = appconfig.StateSupported
		state.Supported = true
	case appinspect.FactStateConfigured, appinspect.FactStateEnabled:
		state.State = appconfig.StateConfigured
		state.Supported = true
		state.Configured = new(true)
	case appinspect.FactStateNotConfigured, appinspect.FactStateDisabled:
		state.State = appconfig.StateNotConfigured
		state.Supported = true
		state.Configured = new(false)
	case appinspect.FactStateUnsupported:
		state.State = appconfig.StateUnsupported
	case appinspect.FactStateUnknown:
		state.State = appconfig.StateUnknown
	default:
		panic("config: invalid fact state: " + string(fact.State))
	}

	if previewOnly && state.Supported {
		state.State = appconfig.StatePreviewOnly
	}

	return state
}
