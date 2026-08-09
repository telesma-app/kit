# CTAP 2.3 multi-agent porting playbook

This document is the entry point for parallel work on the independent Go
implementation of the FIDO CTAP 2.3 authenticator tests. It is designed so a
porter reads one small context packet, one assigned upstream script, and only
the Go packages relevant to that script.

## Current baseline

- Pinned upstream artifact: `fido-conformance-tools` 1.9.1.
- Corpus identity: `sha256:028729315ecd36f76b9166c014ae4af3c3dde41efcad99444b519c3a867cef43`.
- CTAP 2.3 authenticator inventory: 49 declared scripts and 295 Mocha cases.
- Implemented and manifest-registered: 152 cases — `Authr-Generic-1` P-1
  through P-5, all 41 active MakeCredential request markers, all six active
  MakeCredential response markers, all 17 active GetAssertion Req-1 through
  Req-3 markers, all seven protocol-1 and all four protocol-2 NewPIN markers,
  all five protocol-1 PIN-policy markers,
  both ClientPIN key-agreement cases, both ClientPIN GetRetries scripts, and
  all 37 active `Metadata-Stmt-1` markers.
- Runtime: `ctapkit.Authenticator.RunCTAP23Conformance` can execute a safe or
  full suite on the currently opened authenticator; the safe/full selections
  currently contain 43/152 cases. Destructive MakeCredential, GetAssertion,
  and ClientPIN retry cases use the
  manager-owned physical power-cycle/NFC-session-reset and verified rebind
  boundary; the disabled protocol-1 P-4 remains a non-destructive skip.

The extracted corpus is a reference input, not repository-owned source. Its
files contain restrictive FIDO Alliance notices. Implement the protocol
behavior independently in Go; do not copy source, comments, assertion prose,
or helper implementations into production files. Keep the extracted corpus
private until adaptation and redistribution rights have been confirmed.

## The short read list

Every implementation agent reads exactly these items before starting:

1. The repository `AGENTS.md`.
2. This playbook.
3. `conformance/PORTING_HANDOFF.md` when resuming from a repository checkpoint.
   It records transient review findings and the exact next queue; the workplan
   remains authoritative for task state.
4. Its assigned entry from the planned `conformance/upstream/workplan.json`.
5. The assigned upstream script and only the helper scripts named by that
   workplan entry.
6. The matching low-level types and commands under the sibling `ctap` module.
7. One existing Go case that uses the same execution style.

Do not scan the whole extracted application, all 49 scripts, or all of
`ctap/client/commands.go`. Broader reading is justified only by a concrete
missing dependency, which must be named in the handoff.

Canonical locations:

- Upstream test list:
  `reference/fido-conformance-tools-1.9.1/modules/ctap2.3-conformance-module/authr-testlist.json`
- Upstream test root:
  `reference/fido-conformance-tools-1.9.1/modules/ctap2.3-conformance-module/`
- Shared upstream helpers: the module's `js/` directory.
- Go execution contracts: `conformance/execution.go` and
  `conformance/runner.go`.
- Existing port: `conformance/ctap23/`.
- Low-level Go API: the sibling module's `ctap/client`, `ctap/protocol`,
  `ctap/crypto`, `ctap/cose`, and `ctap/transport` packages.
- Source pin and merged coverage: `conformance/upstream/manifest.json`.

`reference/` is currently untracked. Collaboration agents in the same
worktree can read it directly. Agents in separate Git worktrees must receive
the absolute read-only source root from the coordinator, for example
`/Users/savely/Projects/go-ctap/kit/reference/fido-conformance-tools-1.9.1`.
Do not duplicate the corpus into every worktree.

## Architecture rules

These decisions are shared and must not be rediscovered per shard:

- One upstream Mocha `it(...)` case becomes one `conformance.Test`. Do not hide
  several upstream cases inside one result.
- `Test.Source.Path` is the exact test-list-relative path. `Source.Case` is the
  exact short marker such as `P-1` or `F-3`.
- Stable IDs use `fido.ctap2.3.<script-slug>.<case-slug>` and never depend on
  array position.
- A `conformance.Step` represents a meaningful protocol phase, not every Go
  assertion.
- Valid command flows use the typed `ctap/client.Client` where it preserves the
  assertion being tested. Malformed CBOR, wrong wire types, duplicate keys,
  missing fields, and canonical-encoding checks use `TestContext.CBOR()`.
- Use `conformance.Fail` for observed nonconformance, `conformance.Skip` only
  when an upstream precondition does not apply, and an ordinary error for an
  environment or transport failure.
- Every normative assertion carries a precise specification reference. Do not
  treat the upstream JavaScript as the normative source.
- PIN, PIN/UV token, user-presence, built-in UV, reset, power-cycle, and
  destructive confirmation are environment capabilities. They are injected
  by the suite/runtime boundary; cases must not create a second product flow.
- Secret buffers are suite-owned only under an explicit ownership contract and
  are wiped at release. Never include PINs, tokens, shared secrets, salts, or
  decrypted extension outputs in messages or fixtures intended for logs.
- Default unit tests are hardware-free and deterministic. Real-device runs are
  a separate opt-in verification layer.
- A case is not `ported` merely because it compiles. Its success, failure, and
  skip/error classification must be covered by tests.

Keep the Go files domain-shaped. During fan-out each source script may have a
unique implementation and test file so agents do not collide. The integrator
may coarsen files after a wave; porters must not perform unrelated reshaping.

## Bootstrap gate

Do not fan out all implementation agents until two small shared artifacts
exist. This is the only deliberate up-front investment.

### 1. Generate the source catalog

Extend `conformance/upstream` with a deterministic catalog generator and commit
`conformance/upstream/catalog.json`. The catalog records only observed facts:

- module and test-list group;
- source path and SHA-256;
- ordered case markers and source lines;
- declared helper paths;
- case and script totals.

It must reject duplicate case markers within a script, unresolved references,
and totals different from 49 scripts or 295 cases. Do not put upstream case
prose or JavaScript bodies into the catalog.

### 2. Curate the work plan

Commit `conformance/upstream/workplan.json`. It is repository-owned scheduling
data, separate from the observed catalog. Each task has:

```json
{
  "id": "ctap23-make-req-1",
  "source": "tests/CTAP2/Protocol/Make/Authr-MakeCred-Req-1.js",
  "cases": ["P-1", "F-1", "F-2"],
  "dependsOn": ["ctap23-harness-command-fixtures"],
  "helpers": ["js/CTAP2.js"],
  "risk": ["credential-write", "pin-uv"],
  "implementationFiles": ["conformance/ctap23/make_credential_req_1.go"],
  "testFiles": ["conformance/ctap23/make_credential_req_1_test.go"],
  "status": "ready"
}
```

Allowed task states are `blocked`, `ready`, `active`, `review`, and `merged`.
Only the coordinator changes task state. Porters never edit `workplan.json` or
`manifest.json`, which removes the two largest merge-conflict hotspots.

The workplan should also name any shared primitive already available. When a
porter discovers a missing shared primitive, it reports a `shared need`
instead of independently adding another abstraction.

The harness bootstrap stabilizes only the environment callback contract and a
deterministic scripted CBOR transport for tests. It does not prebuild a generic
DSL or speculative helpers for all CTAP commands. Keep a domain helper local
until a second concrete domain needs the same behavior; the coordinator then
decides whether to promote it.

## Roles and ownership

There is always one coordinator/integrator.

| Role | Owns | Must not edit |
| --- | --- | --- |
| Coordinator/integrator | Public suite/config contracts, `suite.go`, shared helpers, workplan state, manifest, final verification | A porter's in-flight files |
| Catalog agent | Catalog scanner/generator and its tests | Suite implementations and manifest ports |
| Harness agent | Minimal shared command fixtures and test utilities approved by the coordinator | Domain cases, suite registry, manifest |
| Porter | Only files listed in one task packet | Shared helpers, `suite.go`, workplan, manifest, facade/runtime |
| Reviewer | Semantic case matrix and actionable findings | Production files unless explicitly reassigned as a fixer |

Agents do not commit by default when they share a worktree. The coordinator
reviews the combined diff and creates one signed Conventional Commit per wave.
For separate Git worktrees, give each agent a branch and preserve the same file
ownership; merging commits then requires the repository's normal hardware
signing policy.

## Agent framework operations

Execution slots and agent-tree nodes are separate limits. A four-slot session
can run the coordinator plus three agents, yet still reject `spawn_agent` with
`agent thread limit reached` when old nodes remain in the collaboration tree.
`interrupt_agent` stops work but some `pending_init` nodes can remain visible,
and the current framework exposes no delete/remove operation for them.

Use the following operating rules:

1. Do not pre-create speculative agents. Spawn a node only when its exact task
   packet and non-overlapping ownership are ready.
2. Prefer one bounded task per fresh node: porter, independent reviewer, and
   fixer are separate roles. Reuse the same reviewer only for a narrowly scoped
   rereview of its own findings.
3. Interrupt completed nodes promptly. Before spawning, inspect the live tree
   and distinguish active execution from retained `pending_init`/`completed`
   nodes.
4. If fresh spawn is rejected by the tree-node limit, use `followup_task` on an
   idle completed node as an execution-container fallback. The follow-up prompt
   must be self-contained, say to ignore the old task context, repeat the exact
   read list and ownership, and preserve independent review semantics.
5. Do not let a porter approve its own shard merely because a fresh reviewer
   could not be spawned. Keep the workplan row in `review`, record the missing
   review in the handoff, and retry with another node/container.
6. In the shared worktree, announce the files owned before editing. Other agents
   may read them but must not patch them. Avoid repository-wide tests while an
   agent is actively writing a Go file; use focused checks, then run full normal,
   race, vet, and diff checks after an atomic handoff.
7. Keep all execution slots useful when possible. With four slots, the normal
   steady state is coordinator/integrator + porter + independent reviewer +
   second porter/auditor. Rotate completed nodes instead of serializing the
   whole pipeline behind one long task.

### Review and fix pipeline

The default lifecycle for one shard is:

```text
ready -> active (porter) -> review (independent reviewer)
      -> active (separate fixer, when needed) -> review (rereview)
      -> merged (coordinator integration only)
```

`merged` means all cases are registered in the suite and manifest in exact
source order, facade/runtime fixtures and counts are updated, workplan and
manifest agree index-by-index, and the full verification matrix is green. A
compiling production draft without deterministic tests remains `active`. An
implemented shard with unresolved review findings remains `review`.

### Session checkpoint protocol

Before handing execution to a fresh Codex session:

1. Freeze scope and ask active agents for atomic handoffs. Do not start new
   edits while the checkpoint is being assembled.
2. Make workplan states honest. Preserve `active` for an unregistered coherent
   draft, `review` for implemented-but-unapproved work, and `merged` only for
   fully integrated cases.
3. Update `conformance/PORTING_HANDOFF.md` with exact findings, owned files,
   published sibling-module versions, verification state, and ordered next
   actions. Do not use chat history as the only record.
4. Run `gofmt`, `go test ./... -count=1`, `go test -race ./... -count=1`,
   `go vet ./...`, `go mod verify`, both staged and unstaged `git diff --check`,
   and the workplan/manifest invariants.
5. Create a signed Conventional Commit containing the coherent checkpoint.
   Leave the extracted `reference/` corpus and local desktop artifacts
   untracked.
6. A fresh session starts by reading `AGENTS.md`, this playbook, the handoff,
   workplan, and `git status`; it resumes the first ordered handoff action rather
   than re-auditing merged shards.

## Allocating N agents

During bootstrap:

- Agent 1 is the coordinator.
- Agent 2 builds the catalog.
- Agent 3 builds the minimal harness baseline.
- Additional agents perform read-only analysis of disjoint first-wave domains
  and return proposed workplan entries; they do not implement cases yet.

The first launch can use these prompts.

Catalog agent:

```text
Read AGENTS.md, conformance/PORTING_PLAYBOOK.md, the existing
conformance/upstream scanner and manifest, the pinned CTAP 2.3 authr test list,
and no case bodies. Implement the deterministic catalog described by the
Bootstrap gate, with tests for ordering, source hashes, exact case markers,
duplicate rejection, unresolved references, and the 49/295 totals. Own only
conformance/upstream catalog/scanner files. Do not edit manifest.json, suite
code, or ports. Run gofmt and go test ./conformance/upstream -count=1. Do not
commit. Report files changed, commands run, and any parser limitation.
```

Harness agent:

```text
Read AGENTS.md, conformance/PORTING_PLAYBOOK.md, conformance execution/runner
contracts, the current ctap23 generic port, and the low-level ctap transport
contract. Propose and implement only the minimum shared environment contract
and deterministic scripted CBOR test transport needed for the first porting
wave. Do not build a test DSL and do not add command-domain helpers without a
second concrete consumer. Own only coordinator-assigned harness files. Do not
edit suite.go, manifest.json, workplan.json, facade/runtime files, or domain
cases. Run gofmt and focused conformance tests. Do not commit. Report the
contract, deliberately deferred helpers, and exact files changed.
```

Read-only workplan analyst:

```text
Read AGENTS.md, conformance/PORTING_PLAYBOOK.md, the assigned test-list group,
its case scripts, and only helpers directly used by those scripts. Do not edit
files. Return proposed workplan tasks with exact source/case ranges, helper and
Go read lists, dependencies, risk flags, target file ownership, and balanced
case counts. Identify shared needs but do not design their implementation.
Do not reproduce upstream case prose or code in the report.
```

After the bootstrap gate:

- Keep one coordinator.
- Allocate one reviewer for roughly every three porters.
- All remaining agents take ready, non-overlapping tasks.
- With fewer than five agents, the coordinator also reviews.

A practical allocation is:

```text
integrators = 1
reviewers   = max(1, floor((N - 1) / 4))
porters     = N - integrators - reviewers
```

Assign tasks by dependency readiness, then balance the sum of case counts.
Add weight for destructive state, transport-specific behavior, or a previously
unimplemented shared primitive. Never give two agents overlapping cases or the
same target Go file. A normal shard is one upstream script and 4–15 cases.
Split exceptional scripts such as the 37-case metadata script into contiguous
case ranges with distinct target files.

## Dependency waves

The test-list inventory is:

| Wave | Domain | Scripts | Cases | Dependency note |
| --- | --- | ---: | ---: | --- |
| Existing | Generic GetInfo | 1 | 5 | Already ported; reference implementation |
| 1 | Metadata statement | 1 | 37 | Independent typed metadata validation |
| 1 | MakeCredential request/response | 7 | 47 | Shared valid request and raw CBOR mutation fixtures |
| 1 | GetAssertion request/response | 4 | 22 | MakeCredential fixture for credential setup |
| 1 | RK and enterprise-attestation options | 2 | 15 | MakeCredential and reset/provisioning environment |
| 2 | Client PIN protocol 1 | 4 | 17 | PIN protocol crypto and reset/provisioning |
| 2 | Client PIN protocol 2 | 7 | 33 | Protocol 2 crypto, permissions, PIN/UV environment |
| 2 | Reset | 1 | 1 | Destructive interaction and transport reset policy |
| 3 | Credential management | 3 | 11 | Client PIN 2 token and credential fixtures |
| 3 | Authenticator configuration | 1 | 7 | Client PIN 2 token and reset/provisioning |
| 3 | Biometric enrollment | 3 | 7 | Built-in UV/token and interactive capture environment |
| 3 | Large blobs command | 1 | 4 | Client PIN 2 and credential inventory fixtures |
| 4 | Extensions | 11 | 52 | Make/Get, PIN protocol, crypto, and large-blob fixtures |
| 5 | HID, NFC, and BLE transports | 3 | 37 | Separate transport capability boundary |

The table totals 49 scripts and 295 cases. Waves express shared-helper
dependencies, not a requirement to serialize every task in a wave.

Recommended first fan-out after bootstrap:

1. MakeCredential request scripts.
2. Metadata case ranges.
3. Client PIN key agreement and retry scripts.
4. GetAssertion request scripts once the credential fixture lands.

Extensions come later because otherwise several agents will independently
reimplement MakeCredential, GetAssertion, PIN protocol crypto, authenticator
data parsing, and credential setup.

Transport cases are their own lane. `ctapkit` currently has HID and smart-card
transport boundaries but no BLE runtime. A case whose required observation is
not expressible must remain pending with a reason; do not report a synthetic
pass or silently weaken it.

## Task packet

The coordinator gives each porter one self-contained packet:

```text
Task ID:
Upstream source and exact case markers:
Allowed implementation/test files:
Required helper scripts to read:
Relevant Go packages/files:
Dependencies already merged:
Preconditions and skip conditions:
State changes and cleanup:
Required specification sections:
Focused test command:
```

The packet must fit in one message and link to exact paths. It must not ask the
agent to inspect the whole module or "port as much as possible".

## Porter prompt

Use this prompt after replacing the placeholders from one ready workplan task:

```text
You own {TASK_ID}. Read AGENTS.md, conformance/PORTING_PLAYBOOK.md, and the
single assigned workplan entry. Implement an independent Go port of exactly
{SOURCE_CASES} from {SOURCE_PATH}.

You may edit only {OWNED_FILES}. Do not edit suite.go, shared helpers,
workplan.json, manifest.json, facade/runtime files, or another agent's files.
Read only the upstream helpers and Go files named in the task packet unless a
concrete missing dependency forces more reading.

Preserve one conformance.Test per upstream case, exact Source.Path/Case,
stable IDs, normative references, and fail/skip/error semantics. Use typed
ctap/client calls for valid flows and raw TestContext.CBOR for malformed wire
cases. Do not copy upstream implementation or prose. Do not use real hardware.

Add deterministic tests for pass plus the relevant fail/skip/error paths. Run
the focused package tests and gofmt. If a missing shared primitive blocks you,
do not invent a competing shared abstraction: report it as SHARED NEED with
the smallest required contract.

Handoff with: implemented case matrix, deliberate semantic deviations,
shared needs, state/secret behavior, commands run, and exact files changed.
Do not commit unless the coordinator explicitly asks.
```

## Reviewer prompt

```text
Review {TASK_ID} without changing production code. Read only its task packet,
assigned upstream cases, normative CTAP sections, changed Go files, and the
shared contracts they call.

Produce a case-by-case matrix: exact source mapping, preserved preconditions,
request mutation, expected status/response assertions, fail/skip/error class,
cleanup, secret handling, and test coverage. Flag copied upstream prose/code,
weakened assertions, typed encoding that accidentally prevents a malformed
wire case, hidden hardware dependencies, or edits outside ownership. Rank only
actionable findings. End with APPROVE or CHANGES REQUIRED.
```

## Integrator prompt

```text
Integrate the reviewed tasks in this wave. Resolve only approved SHARED NEEDS,
then register tests in upstream test-list order. Add manifest port rows only
for cases whose implementation and deterministic tests are complete. Update
workplan states centrally. Do not mark unsupported transport observations as
ported.

Run gofmt, go test ./conformance/... -count=1, go test ./... -count=1, go vet
./..., and go test -race ./... -count=1 when lifecycle, interaction, token, or
shared runner behavior changed. Confirm catalog/workplan/manifest totals and
source mappings. Summarize merged cases, remaining blockers, and the next ready
tasks.
```

## Definition of done

A case can move to `ported` only when all items are true:

1. Stable Go test ID and exact upstream source mapping exist.
2. The implementation preserves all material preconditions and assertions.
3. Normative references point to the actual CTAP/WebAuthn requirement.
4. Unsupported capability is skipped for the same semantic reason as upstream.
5. Protocol nonconformance is `failed`; environment/transport failure is
   `error`.
6. State setup and cleanup are explicit; destructive actions use the runtime
   boundary.
7. Owned secret buffers are wiped and no sensitive value reaches messages.
8. Deterministic tests cover pass and relevant non-pass classifications.
9. Focused tests and `go test ./conformance/... -count=1` pass.
10. A reviewer approves the case matrix.
11. The integrator adds the manifest row and suite registration.

## Upstream refresh flow

For a new FIDO artifact:

1. Extract and integrity-check it outside tracked production sources.
2. Run the existing manifest scan and the catalog generator.
3. Diff source identity, test lists, script hashes, and ordered case markers.
4. Mark tasks touching changed scripts as `review`; leave unchanged script
   ports intact.
5. Create tasks only for added/changed cases and helper-induced semantic
   reviews.
6. Run porters and reviewers through the same ownership protocol.
7. After review, update the pinned source identity, counts, catalog, workplan,
   and manifest together.

Script hashes make the refresh incremental: agents reread only changed scripts
and changed shared helpers, rather than the complete upstream corpus.
