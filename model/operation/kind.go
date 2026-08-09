package operation

// Kind identifies a typed public authenticator operation.
type Kind string

const (
	Inspect                     Kind = "inspect"
	ListCredentials             Kind = "credentials.list"
	CredentialStoreState        Kind = "credentials.storeState"
	DeleteCredential            Kind = "credentials.delete"
	UpdateCredentialUser        Kind = "credentials.updateUser"
	ReadLargeBlob               Kind = "largeBlobs.read"
	ListLargeBlobs              Kind = "largeBlobs.list"
	WriteLargeBlob              Kind = "largeBlobs.write"
	DeleteLargeBlob             Kind = "largeBlobs.delete"
	GarbageCollectLargeBlobs    Kind = "largeBlobs.garbageCollect"
	ConfigStatus                Kind = "config.status"
	BioSensorInfo               Kind = "config.bio.sensorInfo"
	BioList                     Kind = "config.bio.list"
	BioEnroll                   Kind = "config.bio.enroll"
	BioRename                   Kind = "config.bio.rename"
	BioRemove                   Kind = "config.bio.remove"
	ResetFactory                Kind = "config.reset.factory"
	SetPIN                      Kind = "config.pin.set"
	ChangePIN                   Kind = "config.pin.change"
	EnableEnterpriseAttestation Kind = "config.enterpriseAttestation.enable"
	SetAlwaysUV                 Kind = "config.alwaysUv.set"
	SetMinPINLength             Kind = "config.minPinLength.set"
	EnableLongTouchForReset     Kind = "config.longTouchForReset.enable"
	MakeCredential              Kind = "webauthn.makeCredential"
	GetAssertion                Kind = "webauthn.getAssertion"
)

// Parse returns the canonical operation kind represented by value.
func Parse(value string) (Kind, bool) {
	kind := Kind(value)
	switch kind {
	case Inspect,
		ListCredentials,
		CredentialStoreState,
		DeleteCredential,
		UpdateCredentialUser,
		ReadLargeBlob,
		ListLargeBlobs,
		WriteLargeBlob,
		DeleteLargeBlob,
		GarbageCollectLargeBlobs,
		ConfigStatus,
		BioSensorInfo,
		BioList,
		BioEnroll,
		BioRename,
		BioRemove,
		ResetFactory,
		SetPIN,
		ChangePIN,
		EnableEnterpriseAttestation,
		SetAlwaysUV,
		SetMinPINLength,
		EnableLongTouchForReset,
		MakeCredential,
		GetAssertion:
		return kind, true
	default:
		return "", false
	}
}
