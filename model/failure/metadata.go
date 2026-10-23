package failure

import (
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/kit/model/operation"
)

func canonicalOperation(value string) string {
	kind, ok := operation.Parse(value)
	if !ok {
		return ""
	}

	return string(kind)
}

func canonicalCTAP(detail *CTAPDetail) *CTAPDetail {
	if detail == nil {
		return nil
	}

	command := protocol.Command(detail.CommandCode)
	detail.Command, _ = command.Name()
	detail.Status, _ = ctaptransport.StatusCode(detail.StatusCode).Name()
	detail.SubCommandFamily = ""
	detail.SubCommand = ""

	if detail.SubCommandCode == nil {
		return detail
	}

	detail.SubCommandFamily, detail.SubCommand = canonicalSubCommand(
		command,
		*detail.SubCommandCode,
	)

	return detail
}

func canonicalSubCommand(command protocol.Command, value uint64) (string, string) {
	var family, name string

	switch command {
	case protocol.AuthenticatorClientPIN:
		family = "clientPIN"
		name, _ = protocol.ClientPINSubCommand(value).Name()
	case protocol.AuthenticatorBioEnrollment, protocol.PrototypeAuthenticatorBioEnrollment:
		family = "bioEnrollment"
		name, _ = protocol.BioEnrollmentSubCommand(value).Name()
	case protocol.AuthenticatorCredentialManagement, protocol.PrototypeAuthenticatorCredentialManagement:
		family = "credentialManagement"
		name, _ = protocol.CredentialManagementSubCommand(value).Name()
	case protocol.AuthenticatorConfig:
		family = "config"
		name, _ = protocol.ConfigSubCommand(value).Name()
	}

	return family, name
}
