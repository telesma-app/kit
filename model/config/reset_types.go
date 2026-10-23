package config

import (
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/model/safety"
)

type ResetPreview struct {
	Device     report.EndpointReport `json:"device"`
	ResetHints ResetHints            `json:"resetHints"`
	Mode       safety.PreviewMode    `json:"mode"`
	Warnings   []safety.Warning      `json:"warnings,omitempty"`
}

type ResetResult struct {
	AttachmentID report.AttachmentID `json:"attachmentId"`
	Reset        bool                `json:"reset"`
}
