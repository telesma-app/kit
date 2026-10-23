package errornorm

import (
	"errors"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/model/failure"
)

type Annotation struct {
	phase      failure.Phase
	command    protocol.Command
	subCommand uint64
}

func WithPhase(phase failure.Phase) Annotation {
	return Annotation{phase: phase}
}

func WithCommand(phase failure.Phase, command protocol.Command) Annotation {
	return Annotation{
		phase:   phase,
		command: command,
	}
}

func WithClientPINSubCommand(phase failure.Phase, subCommand protocol.ClientPINSubCommand) Annotation {
	return withSubCommand(
		phase,
		protocol.AuthenticatorClientPIN,
		uint64(subCommand),
	)
}

func WithBioEnrollmentSubCommand(
	phase failure.Phase,
	command protocol.Command,
	subCommand protocol.BioEnrollmentSubCommand,
) Annotation {
	return withSubCommand(phase, command, uint64(subCommand))
}

func WithCredentialManagementSubCommand(
	phase failure.Phase,
	command protocol.Command,
	subCommand protocol.CredentialManagementSubCommand,
) Annotation {
	return withSubCommand(phase, command, uint64(subCommand))
}

func WithConfigSubCommand(phase failure.Phase, subCommand protocol.ConfigSubCommand) Annotation {
	return withSubCommand(
		phase,
		protocol.AuthenticatorConfig,
		uint64(subCommand),
	)
}

func withSubCommand(
	phase failure.Phase,
	command protocol.Command,
	subCommand uint64,
) Annotation {
	return Annotation{
		phase:      phase,
		command:    command,
		subCommand: subCommand,
	}
}

type annotatedError struct {
	err        error
	annotation Annotation
}

func (e *annotatedError) Error() string {
	return e.err.Error()
}

func (e *annotatedError) Unwrap() error {
	return e.err
}

// Annotate records safe normalization metadata without changing the error identity.
// The annotation closest to the source wins over broader boundary metadata.
func Annotate(err error, annotation Annotation) error {
	if _, ok := errors.AsType[*annotatedError](err); ok {
		return err
	}

	return &annotatedError{err: err, annotation: annotation}
}
