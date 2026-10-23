package config

import (
	"github.com/telesma-app/kit/model/report"
)

type StateValue string

const (
	StateSupported     StateValue = "supported"
	StateUnsupported   StateValue = "unsupported"
	StateUnknown       StateValue = "unknown"
	StateConfigured    StateValue = "configured"
	StateNotConfigured StateValue = "not_configured"
	StatePreviewOnly   StateValue = "preview_only"
)

type CapabilityState struct {
	State       StateValue `json:"state"`
	Supported   bool       `json:"supported"`
	Configured  *bool      `json:"configured,omitempty"`
	PreviewOnly bool       `json:"previewOnly,omitempty"`
}

type RetryState struct {
	State           StateValue `json:"state"`
	Remaining       *uint      `json:"remaining,omitempty"`
	PowerCycleState *bool      `json:"powerCycleState,omitempty"`
}

type UVStatus struct {
	State       StateValue `json:"state"`
	Supported   bool       `json:"supported"`
	Configured  *bool      `json:"configured,omitempty"`
	PreviewOnly bool       `json:"previewOnly,omitempty"`
	Retries     RetryState `json:"retries"`
}

type BioStatus struct {
	State           StateValue      `json:"state"`
	Supported       bool            `json:"supported"`
	Configured      *bool           `json:"configured,omitempty"`
	PreviewOnly     bool            `json:"previewOnly,omitempty"`
	UVBioEnroll     CapabilityState `json:"uvBioEnroll"`
	UVModality      *uint           `json:"uvModality,omitempty"`
	UVModalityLabel string          `json:"uvModalityLabel,omitempty"`
}

type ResetHints struct {
	LongTouchForReset  StateValue `json:"longTouchForReset"`
	TransportsForReset []string   `json:"transportsForReset,omitempty"`
}

type LimitsStatus struct {
	MinPINLength                uint  `json:"minPINLength"`
	MaxPINLength                uint  `json:"maxPINLength"`
	MaxRPIDsForSetMinPINLength  *uint `json:"maxRPIDsForSetMinPINLength,omitempty"`
	PreferredPlatformUVAttempts uint  `json:"preferredPlatformUvAttempts,omitempty"`
	UVCountSinceLastPINEntry    *uint `json:"uvCountSinceLastPinEntry,omitempty"`
}

type StatusReport struct {
	Device              report.EndpointReport     `json:"device"`
	PIN                 PINStatus                 `json:"pin"`
	UV                  UVStatus                  `json:"uv"`
	Bio                 BioStatus                 `json:"bio"`
	AuthenticatorConfig AuthenticatorConfigStatus `json:"authenticatorConfig"`
	ResetHints          ResetHints                `json:"resetHints"`
	Limits              LimitsStatus              `json:"limits"`
}
