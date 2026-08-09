# CTAP 2.3 porting handoff

Checkpoint date: 2026-08-09.

This file is the transient execution handoff for a fresh Codex session. Read
`AGENTS.md` and `conformance/PORTING_PLAYBOOK.md` first. The canonical task
states remain in `conformance/upstream/workplan.json`; the canonical integrated
case list remains in `conformance/upstream/manifest.json`.

## Objective

Complete the independent Go port of the pinned FIDO CTAP 2.3 authenticator
corpus, using deterministic no-hardware tests, precise current-spec references,
and existing Telesma components before adding local primitives. Keep the Go
implementation maintainable and stricter than the upstream JavaScript where the
current specification is more precise.

## Published sibling components

- `github.com/telesma-app/fido-registry` v0.2.0, signed commit `07463665`.
- `github.com/telesma-app/ctap` v0.46.0, signed commit `94fc372`.
- `github.com/telesma-app/mds` v0.4.0.
- `golang.org/x/text` v0.40.0.

The kit has no local `replace` directives for these modules.

## Integrated baseline

- Pinned corpus: 49 scripts / 295 cases.
- Manifest and suite: 152 integrated cases.
- Safe/full selections: 43 / 152.
- Workplan: 28 `merged`, 2 `review`, 1 `active`, 25 `blocked`.
- GetAssertion Resp-1 is independently approved and integrated. Its facade
  simulator now signs dynamic GetAssertion responses with the credential key.
- `fido-registry` COSE profiles and the shared MakeCredential/GetAssertion raw,
  canonical, typed, crypto, lifecycle, and token fixtures are already present.

Do not re-review or re-port `merged` rows merely because their diffs are large.

## Immediate parallel queue

Start three bounded agents in parallel, with the coordinator retaining suite,
manifest, facade, workplan, and integration ownership.

### A. Fix PIN-issued protocol-2 permissions

Workplan row:
`ctap23-authr-client-pin2-get-pin-uv-auth-token-using-pin-with-permissions`
(`review`).

Owned files:

- `conformance/ctap23/authr_client_pin2_get_pin_uv_auth_token_using_pin_with_permissions.go`
- `conformance/ctap23/authr_client_pin2_get_pin_uv_auth_token_using_pin_with_permissions_test.go`

Independent review findings:

1. Remove the pre-reset `requireExistingPIN`/initial `clientPin=true` gate from
   F-1. The case creates its own PIN after reset, so an initial false value is
   applicable, not a Skip.
2. Move P-1's zero advertised permission-mask Skip before power-cycle, reset,
   TemporaryPIN, and SetPIN. Its deterministic test must assert no mutation.
3. Add exact executed-step references:
   - CTAP 2.3 §6.5.5.7.2 for the subject PIN permission-token operation;
   - §6.5.7 `MUST` for the exact 32-byte protocol-2 token;
   - §6.8.2 for P-4 GetCredsMetadata/`pcmr` and no permissions RP ID, replacing
     the incorrect §6.8.3 enumerate-RPs reference;
   - §6.1.2 and §6.2.2 for the P-2/P-3 downstream UV assertions.
4. Add deterministic non-pass coverage for P-2/P-3 MakeCredential/GetAssertion
   CTAP failures and missing UV, P-3 no assertion, P-4 GetCredsMetadata failure,
   and F-1 authenticatorConfig failure.

After a separate fixer, use an independent rereviewer. Do not integrate while
any finding remains.

### B. Fix Reset-1

Workplan row: `ctap23-authr-reset-1` (`review`).

Owned files:

- `conformance/ctap23/authr_reset_1.go`
- `conformance/ctap23/authr_reset_1_test.go`

Independent review findings:

1. The post-reset GetAssertion must use a new clientDataHash, distinct from the
   pre-reset request, before refreshing the RP-scoped authorization/HMAC.
2. The fake must decode and retain both GetAssertion requests. Assert the exact
   RP ID and created credential ID, a changed post-reset hash, protocol 2, and a
   post-reset HMAC computed with the fresh third token over that new hash.

The rest of the flow is approved: exact `0x07`, reset-window and credential
invalidation references in CTAP 2.3 §6.6, pre-reset credential proof, exact
post-reset `CTAP2_ERR_NO_CREDENTIALS`, status/error classification, one cleanup,
and token wipes.

### C. Finish built-in-UV protocol-2 permissions

Workplan row:
`ctap23-authr-client-pin2-get-pin-uv-auth-token-using-uv-with-permissions`
(`active`).

Current file:

- `conformance/ctap23/authr_client_pin2_get_pin_uv_auth_token_using_uv_with_permissions.go`

The production draft is formatted and compile-only checked. It is not ready for
review because the test file does not exist. Add:

- `conformance/ctap23/authr_client_pin2_get_pin_uv_auth_token_using_uv_with_permissions_test.go`

Required deterministic coverage includes exact protocol-2 wire and crypto,
raw `uv`/profile gates, UVConfigurator false-to-true refresh, permission masks
and RP binding, independent P-2/P-3 credentials and token invalidation order,
P-4 `pcmr` proof, CTAP/transport/configuration classifications, cleanup, and
PIN/token wiping. Keep the row `active` until focused/full/race/vet/diff are
green, then move it to `review` for an independent review.

## Integration after approvals

Integrate in exact catalog/source order, one approved shard at a time:

1. PIN-issued permissions: +5 cases, full becomes 157; safe remains 43.
2. Reset-1: +1 case, full becomes 158.
3. UV-issued permissions: +4 cases, full becomes 162.

For each integration update `suite.go`, manifest rows, exact index-wise manifest
tests, facade simulator/status inventory/interactions, playbook counts, and the
workplan row atomically. Measure facade counts from actual execution; do not
guess. Re-run the full verification matrix after each integration.

## Agent framework state

The collaboration tree can retain old `pending_init` nodes after interruption.
Fresh `spawn_agent` may therefore fail with `agent thread limit reached` even
when execution slots are free. The proven fallback is `followup_task` on an
idle completed node with a self-contained prompt that says to ignore its old
task. This checkpoint successfully ran coordinator + reviewer + porter +
reviewer in all four slots that way.

Prefer a fresh node for each porter/reviewer/fixer when the tree permits it.
Under the node-limit fallback, reuse only the execution container, not its old
scope or assumptions. Never replace independent review with porter self-review.

## After the immediate wave

Re-audit stale blockers instead of accepting their old reasons. The runtime now
has stable power-cycle/rebind, reset, temporary PIN, UV configuration, generic
PIN/UV token, MakeCredential/GetAssertion, COSE profile, and raw CTAP2 fixtures
that did not exist when several rows were marked blocked.

Known current adjudications:

- `ctap23-resident-key` still needs an explicit authenticator-display
  capability; transaction-confirmation display metadata is not a proven
  substitute for account-selection display.
- AuthenticatorConfig and credential-management rows should be re-audited as
  soon as the permission shards merge; their generic token/reset blockers are
  likely stale.
- HID, NFC, and BLE raw-transport rows still require real transport-specific
  boundaries and must not be synthetic-passed through CBOR.

## Verification and repository hygiene

Before changing any `review` row to `merged`, run:

```text
gofmt -w <owned Go files>
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go mod verify
git diff --check
git diff --cached --check
```

Also run the focused shard tests, `go test ./conformance/upstream -count=1`, and
the exact facade full-run test after suite changes.

The extracted `reference/` corpus is intentionally untracked. Do not commit it.
Do not commit `.DS_Store`. Agents do not stage, commit, push, or edit suite,
manifest, facade, or workplan unless explicitly assigned coordinator ownership.
