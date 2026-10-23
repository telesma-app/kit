package report

import (
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/inspect"
	mdsmodel "github.com/telesma-app/mds/model"
	"github.com/telesma-app/token2"
	"github.com/telesma-app/yubico"
)

type SourceState string

const (
	SourceNotRequested SourceState = "not-requested"
	SourceLoading      SourceState = "loading"
	SourceAvailable    SourceState = "available"
	SourcePartial      SourceState = "partial"
	SourceAbsent       SourceState = "absent"
	SourceUnavailable  SourceState = "unavailable"
	SourceUnsupported  SourceState = "unsupported"
	SourceFailed       SourceState = "failed"
)

type SourceReason string

const (
	ReasonTransport      SourceReason = "transport"
	ReasonAdapterMissing SourceReason = "adapter-missing"
	ReasonAAGUIDMissing  SourceReason = "aaguid-missing"
	ReasonVendorMismatch SourceReason = "vendor-mismatch"
	ReasonVendorUnknown  SourceReason = "vendor-unknown"
)

// Outcome records a source attempt; an error does not imply missing data.
type Outcome struct {
	State  SourceState      `json:"state"`
	Reason SourceReason     `json:"reason,omitempty"`
	Error  *failure.Failure `json:"error,omitempty"`
}

type HIDInitSource struct {
	Outcome
	Data *ctaphid.InitResponse `json:"data,omitempty"`
}

type GetInfoSource struct {
	Outcome
	Data *inspect.Info `json:"data,omitempty"`
}

type MDSSource struct {
	Outcome
	Data *mdsmodel.LookupResult `json:"data,omitempty"`
}

// YubicoSource includes a model name when the management response is recognized.
type YubicoSource struct {
	Outcome
	ModelName string             `json:"modelName,omitempty"`
	Data      *yubico.DeviceInfo `json:"data,omitempty"`
}

type Token2Source struct {
	Outcome
	Data *Token2Report `json:"data,omitempty"`
}

// SourceReading retains a value received before a read or cleanup failure.
// A nil Value with no Error means the interface did not provide a reading.
type SourceReading[T any] struct {
	Value *T               `json:"value"`
	Error *SourceReadError `json:"error,omitempty"`
}

// SourceReadError is diagnostic text from an independent metadata read.
type SourceReadError struct {
	Message string `json:"message"`
}

// Token2Report exposes independent vendor observations through the runtime's
// report boundary. The Token2 library retains Go errors in its descriptors.
type Token2Report struct {
	SerialNumber  SourceReading[string]               `json:"serialNumber"`
	ATR           SourceReading[token2.ATR]           `json:"atr"`
	Configuration SourceReading[token2.Configuration] `json:"configuration"`
	Model         *token2.Model                       `json:"model,omitempty"`
}

// Sources are independent observations, never a guessed physical identity.
type Sources struct {
	HIDInit HIDInitSource `json:"hidInit"`
	GetInfo GetInfoSource `json:"getInfo"`
	MDS     MDSSource     `json:"mds"`
	Yubico  YubicoSource  `json:"yubico"`
	Token2  Token2Source  `json:"token2"`
}
