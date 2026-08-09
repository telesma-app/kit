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
- Manifest and suite: all 295 integrated cases.
- Safe/full selections: 78 / 295.
- Workplan: all 56 rows `merged`.
- GetAssertion Resp-1 is independently approved and integrated. Its facade
  simulator now signs dynamic GetAssertion responses with the credential key.
- `fido-registry` COSE profiles and the shared MakeCredential/GetAssertion raw,
  canonical, typed, crypto, lifecycle, and token fixtures are already present.
- PIN-issued protocol-2 permissions are independently approved and integrated:
  all five cases preserve exact masks, RP binding, downstream UV proof,
  credential-management proof, force-PIN-change behavior, and secret wiping.

Do not re-review or re-port `merged` rows merely because their diffs are large.

## Immediate parallel queue

The immediate three-shard wave is complete. The coordinator retained suite,
manifest, facade, workplan, and integration ownership throughout.

### A. PIN-issued protocol-2 permissions — integrated

Workplan row:
`ctap23-authr-client-pin2-get-pin-uv-auth-token-using-pin-with-permissions`
(`merged`). Independent rereview approved the exact five-case matrix; the
focused, upstream, facade, package, race, vet, module, and diff checks were run
before integration.

### B. Reset-1 — integrated

Workplan row: `ctap23-authr-reset-1` (`merged`).

Owned files:

- `conformance/ctap23/authr_reset_1.go`
- `conformance/ctap23/authr_reset_1_test.go`

Independent rereview approved the distinct post-reset clientDataHash, fresh
RP-scoped authorization/HMAC, exact `0x07`, reset-window and credential
invalidation requirements, pre-reset proof, exact
`CTAP2_ERR_NO_CREDENTIALS`, cleanup, and token wiping.

### C. Built-in-UV protocol-2 permissions — integrated

Workplan row:
`ctap23-authr-client-pin2-get-pin-uv-auth-token-using-uv-with-permissions`
(`merged`).

Current file:

- `conformance/ctap23/authr_client_pin2_get_pin_uv_auth_token_using_uv_with_permissions.go`

Production and deterministic tests are integrated. Independent review found two
source-fidelity issues:

1. P-2/P-3 must omit MakeCredential `options` exactly like upstream instead of
   requiring `rk=true`.
2. P-4's executed `perCredMgmtRO` precondition must cite §6.8.2, not §6.8.3.

A separate fixer corrected only those issues, and the same independent reviewer
approved the narrow rereview. Focused/package/race/vet/diff checks are green.

## Completed immediate integration

The approved shards were integrated in exact catalog/source order, one at a
time. The full suite is now 295 cases; safe is 78.

The latest integrated wave adds all six `ResidentKey`, six `hmacSecret2`,
seven `hmacSecretMC`, four `credProtect`, three `credBlob`, three
`thirdPartyPayment`, and one `uvm` case. The ports use independent reset and
authorization lifecycles, exact raw extension presence/type checks, current
effective-policy semantics, protocol-aware token lengths, metadata/registry
correlation, and deterministic no-hardware transcript and buffer-lifetime
tests. No new sibling constants or conformance package was needed: CTAP wire,
crypto, DTO, and Registry ownership remains in the existing Telesma modules.

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

`ctap23-authenticator-config` is independently approved and integrated. Its
seven cases restore the upstream exact-length post-reset PIN precondition,
select protocol 2 explicitly for both PIN and UV flows, preserve exact
authorization transcripts, and treat false `setMinPINLength` as unsupported.

`ctap23-credential-management-enumerate-rps` is independently approved and
integrated. Its six cases use the approved private fixture for independent
reset/PIN lifecycles, exact protocol-2 `cm`/`pcmr` scopes, canonical
begin/continuation requests, deterministic RP sets, cleanup, and secret
wiping.

`ctap23-credential-management-enumerate-credentials` is independently approved
and integrated. Its three cases use exact protocol-2 `cm`/`pcmr` scopes,
canonical continuation state, optional response-field semantics, and explicit
raw/decoded large-blob-key wiping.

`ctap23-credential-management-update-and-delete` is independently approved and
integrated. Its two cases require a truly empty success body, preserve exact
protocol-2 authorization, verify mutation effects independently, and wipe
optional enumerated key material.

`ctap23-large-blob-key` is independently approved and integrated. Its six
cases use exact protocol-2 PIN/UV authorization, fresh RP-scoped tokens,
typed positive responses and raw false/type-negative requests without a new
public API.

`ctap23-bio-enroll-bio-mod-and-sensor-info` is independently approved and
integrated. Its two read-only typed commands retain reset/rebind lifecycle but
do not add a false PIN/UV or biometric-sample interaction dependency.

Known current adjudications:

- All 23 `hmac-secret`, `hmac-secret2`, `hmac-secret-mc`, and `credProtect`
  markers are integrated. Their shared private fixture executes exact
  protocol-1/protocol-2 crypto, implicit/explicit wire semantics, every
  advertised protocol and resident-key matrix, effective credential-policy
  behavior, raw authData presence/canonical checks, and exhaustive
  secret-buffer ownership. No public or sibling package API was justified.

- All six `ctap23-resident-key` cases are integrated. `RunRequest` declares
  account-selection display presence explicitly, Config has a runtime-backed
  account selection preparer for display-driven P-4, and the suite validates
  current userSelected/count semantics plus same-account overwrite behavior.
  The declaration is not inferred from transaction-confirmation metadata.
- All nine `ctap23-enteprise-attestation` cases are integrated. `RunRequest`
  selects an explicit consumer or enterprise security profile; an unspecified
  profile skips these cases before any mutation. The enterprise RP and expected
  leaf-certificate digest remain private pinned corpus fixtures, and the port
  verifies packed signatures plus exact `epAtt` identity disclosure semantics.
- Both `minPINLength`, both `pinComplexityPolicy`, all `credBlob`, all
  `thirdPartyPayment`, and the `uvm` markers are integrated. They share private
  no-reset or independent credential-extension fixtures, preserve exact target
  member presence semantics, correlate UVM values with `fido-registry` and
  metadata, and own all raw/decoded response buffers. Existing `ctap` DTOs and
  `fido-registry` values cover them; raw wire observers stay private to the
  conformance package.
- AuthenticatorConfig's old blocker is stale: existing typed
  `github.com/telesma-app/ctap` commands and current Config callbacks cover all
  seven cases without a new public boundary.
- All three Credential Management rows are independently approved and
  integrated. They share one private fixture with independent reset/PIN
  lifecycles, deterministic identities, exact protocol-2 scopes, cleanup, and
  buffer wiping.
- `LargeBlobs-1` is independently approved and integrated. Its P-4 path
  recreates the post-reset PIN-first/UV-fallback environment locally and
  obtains an exact protocol-2 `lbw` token without broadening the runtime token
  API.
- `largeBlobKey` and `BioEnroll-BioModAndSensorInfo` are independently approved
  and integrated. Existing `github.com/telesma-app/ctap` typed commands,
  permission-token APIs, and the current reset/rebind environment cover all
  eight cases. The upstream `largeBlobKey` typo is adjudicated by CTAP 2.3
  §12.3's fresh 32-byte key requirement.
- All 12 `largeBlob` markers are independently approved and integrated.
  `RunRequest` and `Config` carry an explicit tri-state
  `LargeBlobEnabledByDefault` declaration; P-6/P-7 skip when it is nil and the
  policy is never inferred from a failed write. Closed raw output shapes,
  exact protocol-2 authorization, independent state, and response-buffer
  ownership are covered by deterministic tests.
- Both Bio enrollment and all three enumerate/rename/remove markers are
  independently approved and integrated. The shared Config exposes a
  suite-owned biometric-sample callback backed by the runtime's fingerprint
  interaction; the private fixture uses typed CTAP commands, fresh protocol-2
  `be` tokens, independent lifecycle state, and explicit response/secret
  ownership.
- All 37 HID, NFC, and BLE markers are integrated in original catalog order.
  `RunRequest` carries callback-scoped raw-session providers through the public
  authenticator facade; providers own exclusive lease/rebind, and the suite
  validates reports, channels, keepalives, cancellation, APDU framing/status,
  GATT properties, revision bits, and ping semantics. The four upstream cases
  with intentionally missing bodies remain explicit skips, and an unavailable
  raw provider skips before mutation rather than synthetic-passing over CBOR.
  HID P-9 follows the source cancellation flow after observing user-presence
  keepalive, so it needs no separate touch callback. INIT validation accepts
  extension bytes after the required 17-byte prefix, as required by the current
  CTAPHID forward-compatibility rule; LOCK support is probed through the
  optional command rather than a nonexistent capability flag.

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
