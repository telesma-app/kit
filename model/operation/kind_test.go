package operation

import "testing"

func TestParseCanonicalKinds(t *testing.T) {
	tests := []struct {
		kind Kind
		wire string
	}{
		{Inspect, "inspect"},
		{ListCredentials, "credentials.list"},
		{CredentialStoreState, "credentials.storeState"},
		{DeleteCredential, "credentials.delete"},
		{UpdateCredentialUser, "credentials.updateUser"},
		{ReadLargeBlob, "largeBlobs.read"},
		{ListLargeBlobs, "largeBlobs.list"},
		{WriteLargeBlob, "largeBlobs.write"},
		{DeleteLargeBlob, "largeBlobs.delete"},
		{GarbageCollectLargeBlobs, "largeBlobs.garbageCollect"},
		{ConfigStatus, "config.status"},
		{BioSensorInfo, "config.bio.sensorInfo"},
		{BioList, "config.bio.list"},
		{BioEnroll, "config.bio.enroll"},
		{BioRename, "config.bio.rename"},
		{BioRemove, "config.bio.remove"},
		{ResetFactory, "config.reset.factory"},
		{SetPIN, "config.pin.set"},
		{ChangePIN, "config.pin.change"},
		{EnableEnterpriseAttestation, "config.enterpriseAttestation.enable"},
		{SetAlwaysUV, "config.alwaysUv.set"},
		{SetMinPINLength, "config.minPinLength.set"},
		{EnableLongTouchForReset, "config.longTouchForReset.enable"},
		{MakeCredential, "webauthn.makeCredential"},
		{GetAssertion, "webauthn.getAssertion"},
	}

	for _, tt := range tests {
		if string(tt.kind) != tt.wire {
			t.Errorf("%s = %q, want %q", tt.wire, tt.kind, tt.wire)
		}

		parsed, ok := Parse(tt.wire)
		if !ok || parsed != tt.kind {
			t.Errorf("Parse(%q) = %q, %v", tt.wire, parsed, ok)
		}
	}
}

func TestParseRejectsUnknownKind(t *testing.T) {
	if kind, ok := Parse("service.operation"); ok || kind != "" {
		t.Fatalf("Parse(service.operation) = %q, %v", kind, ok)
	}
}
