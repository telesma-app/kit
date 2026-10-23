package credentials

import "github.com/telesma-app/kit/model/report"

// InventoryReport is the project-owned resident credential DTO shared by every output mode.
type InventoryReport struct {
	Device  report.EndpointReport `json:"device"`
	Support SupportReport         `json:"support"`
	Summary InventorySummary      `json:"summary"`
	Groups  []CredentialGroup     `json:"groups,omitempty"`
}

type SupportReport struct {
	CredentialManagement bool `json:"credentialManagement"`
	PreviewOnly          bool `json:"previewOnly"`
	ReadOnlyPermission   bool `json:"readOnlyPermission"`
}

type InventorySummary struct {
	ExistingResidentCredentialsCount             uint `json:"existingResidentCredentialsCount"`
	MaxPossibleRemainingResidentCredentialsCount uint `json:"maxPossibleRemainingResidentCredentialsCount"`
	TotalRPs                                     uint `json:"totalRPs"`
	TotalCredentials                             uint `json:"totalCredentials"`
}

type CredentialGroup struct {
	RPID        string             `json:"rpID"`
	RPName      string             `json:"rpName,omitempty"`
	RPIDHashHex string             `json:"rpIDHashHex,omitempty"`
	Credentials []CredentialRecord `json:"credentials,omitempty"`
}

type CredentialRecord struct {
	CredentialIDHex      string   `json:"credentialIDHex"`
	CredentialType       string   `json:"credentialType,omitempty"`
	CredentialTransports []string `json:"credentialTransports,omitempty"`
	UserIDHex            string   `json:"userIDHex,omitempty"`
	UserName             string   `json:"userName,omitempty"`
	DisplayName          string   `json:"displayName,omitempty"`
	CredProtect          uint     `json:"credProtect,omitempty"`
	LargeBlobKeyState    string   `json:"largeBlobKeyState,omitempty"`
	ThirdPartyPayment    *bool    `json:"thirdPartyPayment,omitempty"`
}
