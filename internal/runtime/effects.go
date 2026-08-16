package runtime

type StateEffect uint8

const (
	StateEffectCredentialInventoryChanged StateEffect = 1 << iota
	StateEffectLargeBlobArrayChanged
	StateEffectAuthenticatorReset
	StateEffectLargeBlobSnapshotSynchronized
)

// StateEffects records authenticator state that an operation may have changed.
// Effects are recorded before a mutating command because a command error does
// not prove that the authenticator left its state unchanged.
type StateEffects struct {
	recorded StateEffect
}

func (effects *StateEffects) Record(effect StateEffect) {
	effects.recorded |= effect
}

func (effects *StateEffects) Has(effect StateEffect) bool {
	return effects.recorded&effect != 0
}

// InvalidatesLargeBlobSnapshot reports whether the retained credential and
// large-blob inventory can no longer be trusted after the operation.
func (effects *StateEffects) InvalidatesLargeBlobSnapshot() bool {
	if effects.Has(StateEffectCredentialInventoryChanged) ||
		effects.Has(StateEffectAuthenticatorReset) {
		return true
	}

	return effects.Has(StateEffectLargeBlobArrayChanged) &&
		!effects.Has(StateEffectLargeBlobSnapshotSynchronized)
}
