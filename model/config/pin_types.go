package config

import (
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/model/safety"
)

type PINMutationOperation string

const (
	PINMutationSet    PINMutationOperation = "set"
	PINMutationChange PINMutationOperation = "change"
)

type PINStatus struct {
	State               StateValue `json:"state"`
	Supported           bool       `json:"supported"`
	Configured          *bool      `json:"configured,omitempty"`
	ProtocolSupported   bool       `json:"protocolSupported"`
	MinPINLength        uint       `json:"minPINLength"`
	MaxPINLength        uint       `json:"maxPINLength"`
	ForcePINChange      bool       `json:"forcePINChange,omitempty"`
	PinComplexityPolicy *bool      `json:"pinComplexityPolicy,omitempty"`
	PinComplexityURL    string     `json:"pinComplexityPolicyURL,omitempty"`
	Retries             RetryState `json:"retries"`
}

type PINMutationPreview struct {
	Operation PINMutationOperation  `json:"operation"`
	Device    report.EndpointReport `json:"device"`
	PIN       PINStatus             `json:"pin"`
	Mode      safety.PreviewMode    `json:"mode"`
	Warnings  []safety.Warning      `json:"warnings,omitempty"`
}

type PINMutationResult struct {
	Operation    PINMutationOperation `json:"operation"`
	AttachmentID report.AttachmentID  `json:"attachmentId"`
	PINState     StateValue           `json:"pinState"`
}
