package config

import (
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/model/safety"
)

type BioMutationOperation string

const (
	BioMutationRename BioMutationOperation = "rename"
	BioMutationRemove BioMutationOperation = "remove"
)

type BioModality string

const (
	BioModalityFingerprint BioModality = "fingerprint"
)

type FingerprintKind string

const (
	FingerprintKindTouch FingerprintKind = "touch"
	FingerprintKindSwipe FingerprintKind = "swipe"
)

type BioSensorReport struct {
	Device                             report.EndpointReport `json:"device"`
	Supported                          bool                  `json:"supported"`
	PreviewOnly                        bool                  `json:"previewOnly"`
	Modality                           BioModality           `json:"modality,omitempty"`
	FingerprintKind                    FingerprintKind       `json:"fingerprintKind,omitempty"`
	MaxCaptureSamplesRequiredForEnroll *uint                 `json:"maxCaptureSamplesRequiredForEnroll,omitempty"`
	MaxTemplateFriendlyName            *uint                 `json:"maxTemplateFriendlyName,omitempty"`
}

type BioListReport struct {
	Device      report.EndpointReport `json:"device"`
	Supported   bool                  `json:"supported"`
	PreviewOnly bool                  `json:"previewOnly"`
	Enrollments []BioEnrollmentRecord `json:"enrollments"`
}

type BioEnrollmentRecord struct {
	TemplateIDHex string `json:"templateIDHex"`
	FriendlyName  string `json:"friendlyName,omitempty"`
}

type BioEnrollRequest struct {
	TimeoutMilliseconds uint `json:"timeoutMilliseconds"`
}

type BioEnrollPreview struct {
	Device              report.EndpointReport `json:"device"`
	PreviewOnly         bool                  `json:"previewOnly"`
	TimeoutMilliseconds uint                  `json:"timeoutMilliseconds"`
	Mode                safety.PreviewMode    `json:"mode"`
	Warnings            []safety.Warning      `json:"warnings,omitempty"`
}

type BioEnrollSample struct {
	Status           string `json:"status"`
	RemainingSamples *uint  `json:"remainingSamples,omitempty"`
}

type BioEnrollResult struct {
	AttachmentID           report.AttachmentID `json:"attachmentId"`
	PreviewOnly            bool                `json:"previewOnly"`
	TemplateIDHex          string              `json:"templateIDHex"`
	Samples                []BioEnrollSample   `json:"samples,omitempty"`
	LastEnrollSampleStatus string              `json:"lastEnrollSampleStatus,omitempty"`
	RemainingSamples       *uint               `json:"remainingSamples,omitempty"`
}

type BioMutationPreview struct {
	Operation     BioMutationOperation  `json:"operation"`
	Device        report.EndpointReport `json:"device"`
	PreviewOnly   bool                  `json:"previewOnly"`
	TemplateIDHex string                `json:"templateIDHex"`
	FriendlyName  string                `json:"friendlyName,omitempty"`
	Mode          safety.PreviewMode    `json:"mode"`
	Warnings      []safety.Warning      `json:"warnings,omitempty"`
}

type BioMutationResult struct {
	Operation     BioMutationOperation `json:"operation"`
	AttachmentID  report.AttachmentID  `json:"attachmentId"`
	PreviewOnly   bool                 `json:"previewOnly"`
	TemplateIDHex string               `json:"templateIDHex"`
	FriendlyName  string               `json:"friendlyName,omitempty"`
}
