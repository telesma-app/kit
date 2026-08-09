// Package inspect contains public authenticator inspection results.
package inspect

import (
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/model/report"
)

type Info struct {
	protocol.AuthenticatorGetInfoResponse
	UVModalityLabel string     `json:"uvModalityLabel,omitempty"`
	Assessment      Assessment `json:"assessment"`
}

type Result struct {
	Device report.DeviceReport `json:"device"`
	Info   Info                `json:"info"`
}
