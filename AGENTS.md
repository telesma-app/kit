# AGENTS.md

## Project
- `ctapkit` is a reusable CTAP/FIDO2 runtime library for the `go-ctap` application family.
- The root `ctapkit` package is the public runtime facade; this repository is not a CLI.
- Do not add terminal UX, renderers, prompts, spinners, command trees, or product-specific output.

## ACTIVE DEVELOPMENT AND PROTOTYPING
- THIS RUNTIME IS NOT A STABLE PUBLIC API. IT IS IN ACTIVE DEVELOPMENT AND PROTOTYPING.
- LARGE-SCALE REFACTORINGS AND BREAKING API CHANGES ARE EXPLICITLY ALLOWED AND PREFERRED OVER COMPATIBILITY LAYERS WHEN THEY PRODUCE A SIMPLER DESIGN.
- DO NOT PRESERVE OBSOLETE API SHAPES WITH ALIASES, WRAPPERS, RE-EXPORTS, OR SHIMS.

## Boundaries
- Public runtime API belongs in `ctapkit`; DTOs in `model`; device/transport abstractions in `device` and `transport`.
- Sessions, workflows, authenticator handles, caches, tokens, and secrets stay private under `internal/`.
- Wails service facades, request envelopes, client interaction state, and product-specific orchestration belong in the consuming application, not in this runtime.
- When behavior is unclear, read the package that owns the concern before changing it.

## Trust Boundary
- `ctapkit` and its consuming applications are trusted first-party layers. Do not add defensive copies, normalization, immutable wrappers, or redundant validation solely to protect one trusted layer from programmer mistakes in another.
- Caller-owned result mutation is outside the runtime threat model. Protect runtime-owned mutable state from races, but do not redesign APIs merely because a caller could mutate a returned Go value.
- Wails-compatible public DTOs may expose fields needed by binding generation. The application/client boundary owns transport redaction, display policy, and persistence policy for those fields.
- The runtime must still never log secrets or retain them longer than required. Internal token material remains runtime-owned and must be wiped on release.

## Safety And Runtime
- Rely on `go-ctaphid` for per-command CTAP serialization.
- Use session workflow serialization only to prevent multi-step flows from interleaving on the same opened authenticator.
- Do not add process-wide or cross-process device leases; CTAPHID channel isolation owns multi-client transport coordination.
- Assume that the consuming application is the sole mutating user of an opened authenticator while it is selected. Concurrent state changes by other applications or processes are outside the supported usage model; users are responsible for not performing simultaneous writes through another program.
- Do not add refresh-before-every-write behavior, optimistic concurrency, external-change detection, cross-process coordination, or other complexity solely to preserve concurrent mutations made by another program. Runtime-owned snapshots and caches may be reused across serialized workflows when that materially simplifies the design.
- Workflow serialization does not make a sequence of CTAP commands atomic. Handle command failures and device invalidation, and keep runtime-owned state consistent with mutations performed through this runtime.
- Public close/cancel/continue paths must release owned resources and tolerate duplicate or racing consumer calls.
- Never log or persist `pinUvAuthToken`, PINs, reset phrases, or tokens. Do not hide Wails-bound DTO fields with custom JSON marshaling merely to enforce this policy; the client boundary is responsible for transport and presentation redaction.
- When the runtime creates or owns secret byte buffers, wipe them at release. Do not mutate caller-owned buffers unless the API explicitly transfers ownership.
- Mutating operations should expose dry-run previews when useful, but dry-run is optional for callers and the runtime must not enforce product confirmation flows. The consuming client owns warnings, confirmation UX, and the decision to execute destructive operations.

## API And Go
- USE Goland MCP!
- Following Go formatting/style is critical: use `gofmt`/`goimports`, Google Go Style Guide, and Go Code Review Comments.
- Preserve semantic whitespace: separate logical phases with blank lines; keep `x, err := ...` cuddled with its `if err != nil`; do not cuddle unrelated statements, side effects, or final returns; keep tiny error pairs tight; do not wrap long lines only for arbitrary width.
- Do not add compatibility aliases or re-export wrappers for old layouts.
- Keep `New` minimal; add runtime configuration only when consumers truly need it.
- Prefer `go-ctap/ctaphid` helpers for HID/proxy discovery; authenticator opening belongs behind the runtime's private opener.
- Custom sentinel errors should include the `ctapkit: ` prefix, with small explicit runtime category mapping.
- Supported Go version: Go 1.27.x only. Keep `go.mod` aligned; do not add old-version shims.
- Keep file splits coarse and domain-shaped; keep hardware-dependent behavior out of default no-hardware tests.

## Verification
- Run `go test ./... -count=1` and `go vet ./...` before handoff; add `go test -race ./... -count=1` for runtime lifecycle/session changes.
