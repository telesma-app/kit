// Package inspect contains public authenticator inspection results.
package inspect

import (
	"github.com/telesma-app/ctap/protocol"
)

type Info struct {
	protocol.AuthenticatorGetInfoResponse
	UVModalityLabel string     `json:"uvModalityLabel,omitempty"`
	Assessment      Assessment `json:"assessment"`
}
