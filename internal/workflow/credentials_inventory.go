package workflow

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/errornorm"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/internal/secret"
	"github.com/telesma-app/kit/model"
	appcredentials "github.com/telesma-app/kit/model/credentials"
	"github.com/telesma-app/kit/model/failure"
)

func (r Runner) ListCredentials(ctx context.Context, device authenticator.CredentialInventoryReader) (appcredentials.InventoryReport, error) {
	access, err := r.resolveCredentialAccess(ctx, device, protocol.PermissionNone)
	if err != nil {
		return appcredentials.InventoryReport{}, err
	}

	return r.credentialInventory(ctx, device, access, nil)
}

type credentialInventorySnapshot struct {
	metadata protocol.AuthenticatorCredentialManagementResponse
	groups   []credentialInventoryGroupSnapshot
}

type credentialInventoryGroupSnapshot struct {
	rp          protocol.AuthenticatorCredentialManagementResponse
	credentials []protocol.AuthenticatorCredentialManagementResponse
}

func (snapshot *credentialInventorySnapshot) zeroLargeBlobKeys() {
	for groupIndex := range snapshot.groups {
		for credentialIndex := range snapshot.groups[groupIndex].credentials {
			credential := &snapshot.groups[groupIndex].credentials[credentialIndex]
			secret.Zero(credential.LargeBlobKey)
			credential.LargeBlobKey = nil
		}
	}
}

func (r Runner) credentialInventory(
	ctx context.Context,
	device authenticator.CredentialInventoryReader,
	access credentialAccess,
	keys largeBlobKeyStore,
) (appcredentials.InventoryReport, error) {
	var snapshot credentialInventorySnapshot
	err := r.env.Tokens.Use(ctx, rtruntime.TokenUse{
		Permission: access.grantPermission,
		ReplaySafe: true,
	}, func(token []byte) error {
		current, err := r.readCredentialInventorySnapshot(ctx, device, token, access.command)
		if err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			current.zeroLargeBlobKeys()

			return errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseDiscovery))
		}

		snapshot = current

		return nil
	})
	if err != nil {
		snapshot.zeroLargeBlobKeys()
		keys.zero()

		return appcredentials.InventoryReport{}, err
	}

	return r.buildCredentialInventoryReport(snapshot, access, keys), nil
}

func (r Runner) readCredentialInventorySnapshot(
	ctx context.Context,
	device authenticator.CredentialInventoryReader,
	token []byte,
	command protocol.Command,
) (credentialInventorySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithPhase(failure.PhaseMetadata))
	}

	metadata, err := device.GetCredsMetadata(ctx, token)
	if err != nil {
		return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseMetadata,
			command,
			protocol.CredentialManagementSubCommandGetCredsMetadata,
		))
	}

	if err := ctx.Err(); err != nil {
		return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
			failure.PhaseMetadata,
			command,
			protocol.CredentialManagementSubCommandGetCredsMetadata,
		))
	}

	if metadata.ExistingResidentCredentialsCount == nil ||
		metadata.MaxPossibleRemainingResidentCredentialsCount == nil {
		return credentialInventorySnapshot{}, failure.New(
			failure.CodeCTAPSpecViolation,
			failure.WithPhase(failure.PhaseMetadata),
		)
	}

	snapshot := credentialInventorySnapshot{metadata: metadata}
	complete := false
	defer func() {
		if !complete {
			snapshot.zeroLargeBlobKeys()
		}
	}()

	if *metadata.ExistingResidentCredentialsCount == 0 {
		complete = true

		return snapshot, nil
	}

	var rpTotal uint64

	for rpResponse, err := range device.EnumerateRPs(ctx, token) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}

		if err != nil {
			subCommand := protocol.CredentialManagementSubCommandEnumerateRPsBegin
			if len(snapshot.groups) > 0 {
				subCommand = protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP
			}

			return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
				failure.PhaseDiscovery,
				command,
				subCommand,
			))
		}

		if len(snapshot.groups) == 0 {
			rpTotal = uint64(rpResponse.TotalRPs)
		}

		snapshot.groups = append(snapshot.groups, credentialInventoryGroupSnapshot{rp: rpResponse})

		r.env.Events.Emit(ctx, model.OperationEvent{
			Stage:     model.OperationStageEnumeratingRPs,
			Completed: new(uint64(len(snapshot.groups))),
			Total:     &rpTotal,
		})
	}

	credentialsTotal := uint64(*metadata.ExistingResidentCredentialsCount)
	var credentialsCompleted uint64
	seenLargeBlobKeys := make(map[largeBlobKeyID]struct{})

	for groupIndex := range snapshot.groups {
		group := &snapshot.groups[groupIndex]
		if err := ctx.Err(); err != nil {
			return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
				failure.PhaseDiscovery,
				command,
				protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
			))
		}

		for credentialResponse, err := range device.EnumerateCredentials(ctx, token, group.rp.RPIDHash) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}

			if err != nil {
				secret.Zero(credentialResponse.LargeBlobKey)

				subCommand := protocol.CredentialManagementSubCommandEnumerateCredentialsBegin
				if len(group.credentials) > 0 {
					subCommand = protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential
				}

				return credentialInventorySnapshot{}, errornorm.Annotate(err, errornorm.WithCredentialManagementSubCommand(
					failure.PhaseDiscovery,
					command,
					subCommand,
				))
			}

			if len(credentialResponse.LargeBlobKey) > 0 {
				if len(credentialResponse.LargeBlobKey) != 32 {
					secret.Zero(credentialResponse.LargeBlobKey)

					return credentialInventorySnapshot{}, failure.New(
						failure.CodeLargeBlobKeyInvalid,
						failure.WithPhase(failure.PhaseDiscovery),
					)
				}

				keyID := largeBlobKeyID{
					rpIDHashHex:     hex.EncodeToString(group.rp.RPIDHash),
					credentialIDHex: hex.EncodeToString(credentialResponse.CredentialID.ID),
				}
				if _, duplicate := seenLargeBlobKeys[keyID]; duplicate {
					secret.Zero(credentialResponse.LargeBlobKey)

					return credentialInventorySnapshot{}, failure.New(
						failure.CodeCTAPSpecViolation,
						failure.WithPhase(failure.PhaseDiscovery),
					)
				}
				seenLargeBlobKeys[keyID] = struct{}{}
			}

			group.credentials = append(group.credentials, credentialResponse)
			credentialsCompleted++

			r.env.Events.Emit(ctx, model.OperationEvent{
				Stage:     model.OperationStageEnumeratingCredentials,
				Completed: new(credentialsCompleted),
				Total:     &credentialsTotal,
			})
		}
	}

	complete = true

	return snapshot, nil
}

func (r Runner) buildCredentialInventoryReport(
	snapshot credentialInventorySnapshot,
	access credentialAccess,
	keys largeBlobKeyStore,
) appcredentials.InventoryReport {
	report := appcredentials.InventoryReport{
		Device: r.env.Selected,
		Support: appcredentials.SupportReport{
			CredentialManagement: true,
			PreviewOnly:          access.info.Versions.IsPreviewOnly(),
			ReadOnlyPermission:   access.inventoryPermission == protocol.PermissionPersistentCredentialManagementReadOnly,
		},
		Summary: appcredentials.InventorySummary{
			ExistingResidentCredentialsCount:             *snapshot.metadata.ExistingResidentCredentialsCount,
			MaxPossibleRemainingResidentCredentialsCount: *snapshot.metadata.MaxPossibleRemainingResidentCredentialsCount,
		},
		Groups: make([]appcredentials.CredentialGroup, 0, len(snapshot.groups)),
	}

	for _, rawGroup := range snapshot.groups {
		group := appcredentials.CredentialGroup{
			RPID:        strings.TrimSpace(rawGroup.rp.RP.ID),
			RPName:      strings.TrimSpace(rawGroup.rp.RP.Name),
			RPIDHashHex: hex.EncodeToString(rawGroup.rp.RPIDHash),
			Credentials: make([]appcredentials.CredentialRecord, 0, len(rawGroup.credentials)),
		}

		for _, response := range rawGroup.credentials {
			credentialIDHex := hex.EncodeToString(response.CredentialID.ID)
			var transports []string
			for _, transport := range response.CredentialID.Transports {
				transports = append(transports, string(transport))
			}
			record := appcredentials.CredentialRecord{
				CredentialIDHex:      credentialIDHex,
				CredentialType:       string(response.CredentialID.Type),
				CredentialTransports: transports,
				UserIDHex:            hex.EncodeToString(response.User.ID),
				UserName:             strings.TrimSpace(response.User.Name),
				DisplayName:          strings.TrimSpace(response.User.DisplayName),
				CredProtect:          response.CredProtect,
				ThirdPartyPayment:    response.ThirdPartyPayment,
				LargeBlobKeyState:    "missing",
			}

			if len(response.LargeBlobKey) > 0 {
				record.LargeBlobKeyState = "available"
				if keys == nil {
					secret.Zero(response.LargeBlobKey)
				} else {
					keys.add(group.RPIDHashHex, credentialIDHex, response.LargeBlobKey)
				}
			}

			group.Credentials = append(group.Credentials, record)
			report.Summary.TotalCredentials++
		}

		report.Groups = append(report.Groups, group)
	}

	sortInventoryGroups(report.Groups)
	report.Summary.TotalRPs = uint(len(report.Groups))

	return report
}

func inventoryPermission(info protocol.AuthenticatorGetInfoResponse) (protocol.Permission, error) {
	option := protocol.OptionCredentialManagement
	if info.Versions.IsPreviewOnly() {
		option = protocol.OptionCredentialManagementPreview
	}
	enabled, ok := info.Options[option]
	if !ok || !enabled {
		return 0, failure.New(failure.CodeCredentialManagementUnsupported,
			failure.WithPhase(failure.PhaseDiscovery),
		)
	}

	if info.Options[protocol.OptionPersistentCredentialManagementReadOnly] {
		return protocol.PermissionPersistentCredentialManagementReadOnly, nil
	}

	return protocol.PermissionCredentialManagement, nil
}
func sortInventoryGroups(groups []appcredentials.CredentialGroup) {
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].RPID != groups[j].RPID {
			return groups[i].RPID < groups[j].RPID
		}

		if groups[i].RPName != groups[j].RPName {
			return groups[i].RPName < groups[j].RPName
		}

		return groups[i].RPIDHashHex < groups[j].RPIDHashHex
	})

	for i := range groups {
		sort.Slice(groups[i].Credentials, func(left, right int) bool {
			return groups[i].Credentials[left].CredentialIDHex < groups[i].Credentials[right].CredentialIDHex
		})
	}
}
