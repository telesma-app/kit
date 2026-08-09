package model

import (
	"github.com/telesma-app/ctap/protocol"
)

type InteractionKind string

const (
	InteractionKindPIN                           InteractionKind = "pin"
	InteractionKindUserVerification              InteractionKind = "user-verification"
	InteractionKindUserVerificationConfiguration InteractionKind = "user-verification-configuration"
	InteractionKindPowerCycle                    InteractionKind = "power-cycle"
	InteractionKindTouch                         InteractionKind = "touch"
)

type InteractionRequest struct {
	Kind        InteractionKind      `json:"kind"`
	Message     string               `json:"message,omitempty"`
	Permission  string               `json:"permission,omitempty"`
	Destructive bool                 `json:"destructive,omitempty"`
	Preview     any                  `json:"preview,omitempty"`
	PINState    *PINInteractionState `json:"pinState,omitempty"`
	UVModality  *protocol.UserVerify `json:"uvModality,omitempty"`
}

type PINInteractionState struct {
	PreviousAttemptInvalid bool  `json:"previousAttemptInvalid,omitempty"`
	RetriesRemaining       *uint `json:"retriesRemaining,omitempty"`
	PowerCycleState        *bool `json:"powerCycleState,omitempty"`
}

type InteractionResponse struct {
	PIN      []byte `json:"-"`
	Canceled bool   `json:"canceled,omitempty"`
}
