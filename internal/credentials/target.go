package credentials

import (
	"encoding/hex"
	"strings"

	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
)

func ParseCredentialID(value string) ([]byte, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, "", failure.New(
			failure.CodeCredentialIDRequired,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	id, err := hex.DecodeString(value)
	if err != nil {
		return nil, "", failure.Wrap(
			failure.CodeCTAPParameterInvalid,
			err,
			failure.WithPhase(failure.PhaseValidation),
		)
	}

	return id, hex.EncodeToString(id), nil
}

func FindByCanonicalID(report appcredentials.InventoryReport, credentialIDHex string) (appcredentials.CredentialTarget, error) {
	for _, group := range report.Groups {
		for _, record := range group.Credentials {
			if record.CredentialIDHex != credentialIDHex {
				continue
			}

			return appcredentials.CredentialTarget{
				Record: record,
				RP: appcredentials.RelyingParty{
					ID:        group.RPID,
					Name:      group.RPName,
					IDHashHex: group.RPIDHashHex,
				},
				User: appcredentials.UserIdentity{
					UserIDHex:   record.UserIDHex,
					Name:        record.UserName,
					DisplayName: record.DisplayName,
				},
			}, nil
		}
	}

	return appcredentials.CredentialTarget{}, failure.New(
		failure.CodeCredentialNotFound,
		failure.WithPhase(failure.PhaseValidation),
	)
}
