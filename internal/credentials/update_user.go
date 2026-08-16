package credentials

import (
	"encoding/hex"
	"strings"

	"github.com/telesma-app/ctap/credential"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/safety"
)

type UpdateUserPlan struct {
	Preview    appcredentials.UpdateUserPreview
	Descriptor credential.PublicKeyCredentialDescriptor
	User       credential.PublicKeyCredentialUserEntity
}

func PrepareUpdateUser(operation appcredentials.UpdateUserOperation) (UpdateUserPlan, error) {
	target := operation.Target

	credentialID, credentialIDHex, err := ParseCredentialID(target.Record.CredentialIDHex)
	if err != nil {
		return UpdateUserPlan{}, err
	}
	target.Record.CredentialIDHex = credentialIDHex

	target.RP.ID = strings.TrimSpace(target.RP.ID)
	if target.RP.ID == "" {
		return UpdateUserPlan{}, failure.New(
			failure.CodeRelyingPartyIDRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	userID, err := hex.DecodeString(strings.TrimSpace(target.User.UserIDHex))
	if err != nil {
		return UpdateUserPlan{}, failure.Wrap(
			failure.CodeUserIDHexInvalid,
			err,
			failure.WithPhase(failure.PhaseValidation),
		)
	}
	target.User.UserIDHex = hex.EncodeToString(userID)
	operation.Target = target

	proposed, err := ResolveUpdatedUser(operation)
	if err != nil {
		return UpdateUserPlan{}, err
	}

	var transports []credential.AuthenticatorTransport
	for _, value := range target.Record.CredentialTransports {
		transports = append(transports, credential.AuthenticatorTransport(value))
	}

	return UpdateUserPlan{
		Preview: appcredentials.UpdateUserPreview{
			CredentialIDHex: target.Record.CredentialIDHex,
			RPID:            target.RP.ID,
			RPName:          target.RP.Name,
			Current:         target.User,
			Proposed:        proposed,
			Warnings: []safety.Warning{
				{
					Severity: safety.SeverityDestructive,
					Code:     "credential.update_user.mutation",
					Message:  "Changing the stored user information may prevent you from signing in with this passkey.",
				},
				{
					Severity: safety.SeverityInfo,
					Code:     "credential.update_user.scope",
					Message:  "CTAP requires user.id to remain identical and leaves the credential ID, key pair, and relying-party binding unchanged.",
				},
			},
		},
		Descriptor: credential.PublicKeyCredentialDescriptor{
			Type:       credential.PublicKeyCredentialType(target.Record.CredentialType),
			ID:         credentialID,
			Transports: transports,
		},
		User: credential.PublicKeyCredentialUserEntity{
			ID:          userID,
			Name:        proposed.Name,
			DisplayName: proposed.DisplayName,
		},
	}, nil
}

func ResolveUpdatedUser(operation appcredentials.UpdateUserOperation) (appcredentials.UserIdentity, error) {
	if !operation.NameProvided && !operation.DisplayProvided {
		return appcredentials.UserIdentity{}, failure.New(
			failure.CodeCredentialChangesRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	target := operation.Target
	proposed := target.User

	if operation.NameProvided {
		proposed.Name = strings.TrimSpace(operation.Name)
	}

	if operation.DisplayProvided {
		proposed.DisplayName = strings.TrimSpace(operation.DisplayName)
	}

	if proposed == target.User {
		return appcredentials.UserIdentity{}, failure.New(
			failure.CodeCredentialChangesRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	return proposed, nil
}
