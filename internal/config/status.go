package config

import (
	"strconv"

	"github.com/samber/lo"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/getinfo"
	appconfig "github.com/telesma-app/kit/model/config"
	appinspect "github.com/telesma-app/kit/model/inspect"
	"github.com/telesma-app/kit/model/report"
)

func BuildStatusReport(device report.DeviceReport, info protocol.AuthenticatorGetInfoResponse) appconfig.StatusReport {
	assessment := getinfo.Resolve(info)
	r := appconfig.StatusReport{
		Device: device,
		PIN: appconfig.PINStatus{
			State:   appconfig.StateUnknown,
			Retries: appconfig.RetryState{State: appconfig.StateUnknown},
		},
		UV: appconfig.UVStatus{
			State:   appconfig.StateUnknown,
			Retries: appconfig.RetryState{State: appconfig.StateUnknown},
		},
		Bio: appconfig.BioStatus{
			State:       appconfig.StateUnknown,
			UVBioEnroll: appconfig.CapabilityState{State: appconfig.StateUnknown},
		},
		AuthenticatorConfig: appconfig.AuthenticatorConfigStatus{
			State:                 appconfig.StateUnknown,
			UVAcfg:                appconfig.CapabilityState{State: appconfig.StateUnknown},
			EnterpriseAttestation: appconfig.CapabilityState{State: appconfig.StateUnknown},
			AlwaysUV:              appconfig.CapabilityState{State: appconfig.StateUnknown},
			SetMinPINLength:       appconfig.CapabilityState{State: appconfig.StateUnknown},
			LongTouchForReset:     appconfig.CapabilityState{State: appconfig.StateUnknown},
			VendorPrototype:       appconfig.CapabilityState{State: appconfig.StateUnknown},
		},
		ResetHints: appconfig.ResetHints{LongTouchForReset: appconfig.StateUnknown},
	}

	r.PIN = buildPINStatus(info, assessment)
	r.UV = buildUVStatus(factCapability(assessment, appinspect.FactIDUserVerification, false))
	r.Bio = buildBioStatus(bioCapability(info, assessment))
	if info.UvModality != nil {
		r.Bio.UVModality = new(uint(*info.UvModality))
		r.Bio.UVModalityLabel = info.UvModality.String()
	}
	r.ResetHints.TransportsForReset = lo.Map(info.TransportsForReset, func(value credential.AuthenticatorTransport, _ int) string {
		return string(value)
	})
	r.Bio.UVBioEnroll = factCapability(assessment, appinspect.FactIDUvBioEnroll, false)
	r.AuthenticatorConfig = buildAuthenticatorConfigStatus(factCapability(assessment, appinspect.FactIDAuthenticatorConfig, false))
	r.AuthenticatorConfig.UVAcfg = factCapability(assessment, appinspect.FactIDUvAuthenticatorConfig, false)
	r.AuthenticatorConfig.EnterpriseAttestation = factCapability(assessment, appinspect.FactIDEnterpriseAttestation, false)
	r.AuthenticatorConfig.AlwaysUV = factCapability(assessment, appinspect.FactIDAlwaysUV, false)
	r.AuthenticatorConfig.SetMinPINLength = factCapability(assessment, appinspect.FactIDSetMinPINLength, false)
	longTouchForReset := factCapability(assessment, appinspect.FactIDLongTouchForReset, false)
	r.AuthenticatorConfig.LongTouchForReset = longTouchForReset
	r.AuthenticatorConfig.VendorPrototype = vendorPrototypeCapability(info)
	r.AuthenticatorConfig.VendorPrototypeConfigCommands = lo.Map(info.VendorPrototypeConfigCommands, func(value protocol.VendorCommandID, _ int) string {
		return strconv.FormatUint(uint64(value), 10)
	})
	r.ResetHints.LongTouchForReset = longTouchForReset.State
	r.Limits = buildLimitsStatus(info, assessment)

	return r
}

func buildPINStatus(info protocol.AuthenticatorGetInfoResponse, assessment appinspect.Assessment) appconfig.PINStatus {
	status := appconfig.PINStatus{
		State:   appconfig.StateUnknown,
		Retries: appconfig.RetryState{State: appconfig.StateUnknown},
	}
	status.ProtocolSupported = len(info.PinUvAuthProtocols) > 0
	status.ForcePINChange = info.ForcePINChange
	status.PinComplexityPolicy = info.PinComplexityPolicy
	status.PinComplexityURL = info.PinComplexityPolicyURLString()
	status.MinPINLength = factUint(assessment, appinspect.FactIDEffectiveMinPINLength, info.EffectiveMinPINLength())
	status.MaxPINLength = factUint(assessment, appinspect.FactIDEffectiveMaxPINLength, info.EffectiveMaxPINLength())

	capability := factCapability(assessment, appinspect.FactIDClientPIN, false)
	status.State = capability.State
	status.Supported = capability.Supported
	status.Configured = capability.Configured

	return status
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
		UVBioEnroll: appconfig.CapabilityState{State: appconfig.StateUnknown},
	}
}

func buildAuthenticatorConfigStatus(capability appconfig.CapabilityState) appconfig.AuthenticatorConfigStatus {
	return appconfig.AuthenticatorConfigStatus{
		State:                 capability.State,
		Supported:             capability.Supported,
		Configured:            capability.Configured,
		PreviewOnly:           capability.PreviewOnly,
		UVAcfg:                appconfig.CapabilityState{State: appconfig.StateUnknown},
		EnterpriseAttestation: appconfig.CapabilityState{State: appconfig.StateUnknown},
		AlwaysUV:              appconfig.CapabilityState{State: appconfig.StateUnknown},
		SetMinPINLength:       appconfig.CapabilityState{State: appconfig.StateUnknown},
		LongTouchForReset:     appconfig.CapabilityState{State: appconfig.StateUnknown},
		VendorPrototype:       appconfig.CapabilityState{State: appconfig.StateUnknown},
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

func buildLimitsStatus(info protocol.AuthenticatorGetInfoResponse, assessment appinspect.Assessment) appconfig.LimitsStatus {
	return appconfig.LimitsStatus{
		MinPINLength:                factUint(assessment, appinspect.FactIDEffectiveMinPINLength, info.EffectiveMinPINLength()),
		MaxPINLength:                factUint(assessment, appinspect.FactIDEffectiveMaxPINLength, info.EffectiveMaxPINLength()),
		MaxRPIDsForSetMinPINLength:  info.MaxRPIDsForSetMinPINLength,
		PreferredPlatformUVAttempts: info.PreferredPlatformUvAttempts,
		UVCountSinceLastPINEntry:    info.UvCountSinceLastPinEntry,
	}
}

func factCapability(assessment appinspect.Assessment, id appinspect.FactID, previewOnly bool) appconfig.CapabilityState {
	fact, ok := getinfo.Find(assessment, id)
	if !ok {
		return appconfig.CapabilityState{State: appconfig.StateUnknown}
	}

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

func factUint(assessment appinspect.Assessment, id appinspect.FactID, fallback uint) uint {
	fact, ok := getinfo.Find(assessment, id)
	if !ok || fact.Value.Integer == nil {
		return fallback
	}

	return uint(*fact.Value.Integer)
}
