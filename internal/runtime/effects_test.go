package runtime

import "testing"

func TestStateEffectsInvalidateLargeBlobSnapshot(t *testing.T) {
	tests := []struct {
		name    string
		effects []StateEffect
		want    bool
	}{
		{name: "none", want: false},
		{
			name:    "credential inventory changed",
			effects: []StateEffect{StateEffectCredentialInventoryChanged},
			want:    true,
		},
		{
			name:    "large blob array changed",
			effects: []StateEffect{StateEffectLargeBlobArrayChanged},
			want:    true,
		},
		{
			name: "large blob snapshot synchronized",
			effects: []StateEffect{
				StateEffectLargeBlobArrayChanged,
				StateEffectLargeBlobSnapshotSynchronized,
			},
			want: false,
		},
		{
			name: "reset overrides synchronization",
			effects: []StateEffect{
				StateEffectAuthenticatorReset,
				StateEffectLargeBlobSnapshotSynchronized,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			effects := &StateEffects{}
			for _, effect := range tt.effects {
				effects.Record(effect)
			}

			if got := effects.InvalidatesLargeBlobSnapshot(); got != tt.want {
				t.Fatalf("InvalidatesLargeBlobSnapshot() = %t, want %t", got, tt.want)
			}
		})
	}
}
