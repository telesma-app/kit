# telesma-app/kit

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/kit.svg)](https://pkg.go.dev/github.com/telesma-app/kit)
[![Go](https://github.com/telesma-app/kit/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/kit/actions/workflows/go.yml)

`telesma-app/kit` is a reusable Go runtime for applications that work with local FIDO2 authenticators. It provides device
discovery, safe multi-step workflows, typed results, user interaction callbacks, and stable errors.

The library is the shared runtime used by the `telesma-app` application family. It can be used by desktop, command-line, and
terminal applications, but it does not contain any user interface code.

> [!WARNING]
> The project is in active development and is not yet v1.0. Minor releases may
> include breaking API changes.

## Support

The runtime is built on [`telesma-app/ctap`](https://github.com/telesma-app/ctap) and supports authenticator features from CTAP
2.0 through CTAP 2.3. Each operation still depends on the capabilities reported by the connected authenticator.

Main features include:

- authenticator inspection and CTAP conformance reports;
- PIN setup and change;
- built-in user verification and biometric enrollment;
- authenticator configuration and factory reset;
- resident credential listing, update, and deletion;
- large-blob reading, writing, deletion, and garbage collection;
- WebAuthn credential creation and assertion;
- progressive vendor device identity resolution;
- FIDO Metadata Service (MDS3) lookup and verification;
- operation progress events and interaction callbacks;
- bounded and redacted CTAP diagnostic logs.

This repository is a library, not a CLI. It does not provide command parsing, prompts, confirmation screens, tables,
JSON rendering, or product-specific workflows. Applications must provide those parts.

## Transports

| Mode                         | Platform              | Behavior                                                                                                                                                |
|------------------------------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `transport.ModeAuto`         | Linux, macOS, Windows | Discovers PC/SC smart cards together with the platform HID policy. On Windows, HID uses direct access when elevated and the Windows proxy otherwise.     |
| `transport.ModeHID`          | Linux, macOS, Windows | Opens the authenticator through direct USB HID access.                                                                                                  |
| `transport.ModeSmartCard`    | Linux, macOS, Windows | Discovers present PC/SC cards exposing the standard FIDO ISO 7816 applet and opens them exclusively for CTAP commands.                                  |
| `transport.ModeWindowsProxy` | Windows               | Connects to a running [`telesma-app/windows-proxy`](https://github.com/telesma-app/windows-proxy).                                                              |

BLE and hybrid transports are not part of this runtime.

## Installation

```sh
go get github.com/telesma-app/kit@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

The example below discovers authenticators, opens the first one, and reads its public information. A real application
should let the user choose when more than one device is available.

```go
package main

import (
	"context"
	"fmt"
	"log"

	ctapkit "github.com/telesma-app/kit"
	"github.com/telesma-app/kit/transport"
)

func main() {
	ctx := context.Background()

	devices, err := ctapkit.NewDeviceManager(ctx, transport.ModeAuto)
	if err != nil {
		log.Fatal(err)
	}
	defer devices.Close()

	authenticator := devices.State().Selected
	if authenticator == nil {
		log.Fatal("no FIDO2 authenticator found")
	}

	inspection, err := authenticator.Inspect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("attachment: %s\n", inspection.Device.Attachment.ID)
	fmt.Printf("versions: %v\n", inspection.Info.Versions)
	fmt.Printf("AAGUID: %s\n", inspection.Info.AAGUID)
}
```

`DeviceManager` watches FIDO HID attachments and inserted PC/SC cards. It keeps
the current selection open, selects the first available attachment when the
selection is empty, and publishes complete snapshots through `Updates`.

## Runtime lifecycle

A normal application follows this lifecycle:

1. Create one `ctapkit.DeviceManager` for a fixed transport mode.
2. Read `State` and use the automatically selected authenticator.
3. Call `Select` when the user chooses another attachment.
4. Run typed operations on `State().Selected`.
5. Close the manager when the application exits.

The manager owns the selected `Authenticator`; callers must not close it.
Selection changes and manager shutdown close it automatically. An
`Authenticator` owns one open transport channel, its token cache, and its close
and cancellation state. It runs one complete workflow at a time.

Credential-list and configuration workflows read current state per operation. Large-blob workflows are the deliberate
exception: `ListLargeBlobs` refreshes private in-memory inventory for the selected open authenticator, and read,
preview, and mutation operations reuse that inventory. A successful mutation updates the retained large-blob array.
Credential mutations, WebAuthn large-blob writes, and factory reset invalidate the inventory so the next large-blob
operation reloads it. Dry runs leave it unchanged, and an explicit
`ListLargeBlobs` always refreshes it. The state never crosses the authenticator boundary, and its credential keys are
cleared on invalidation, refresh, and close.

`Authenticator.Close` is safe to call more than once or while another goroutine is using the authenticator. It cancels
the active operation, clears owned secret state, and closes the transport.

## Operations

The root `ctapkit` package is the public runtime facade. Operation inputs and results are typed DTOs from the `model`
packages.

| Area            | Main methods                                                                                                       |
|-----------------|--------------------------------------------------------------------------------------------------------------------|
| Inspection      | `Inspect`                                                                                                          |
| Configuration   | `ConfigStatus`, `SetPIN`, `ChangePIN`, `SetAlwaysUV`, `SetMinPINLength`, `EnableLongTouchForReset`, `ResetFactory` |
| Biometrics      | `BioSensorInfo`, `BioList`, `BioEnroll`, `BioRename`, `BioRemove`                                                  |
| Credentials     | `ListCredentials`, `CredentialStoreState`, `DeleteCredential`, `UpdateCredentialUser`                              |
| Large blobs     | `ReadLargeBlob`, `ListLargeBlobs`, `WriteLargeBlob`, `DeleteLargeBlob`, `GarbageCollectLargeBlobs`, `DecodeLargeBlob` |
| WebAuthn        | `MakeCredential`, `GetAssertion`, `VerifyMakeCredential`, `VerifyGetAssertion`                                     |

Operation methods return concrete result values. When an operation returns an error, its result is always the zero
value, regardless of whether the workflow had already started. A populated result is returned only for a successful
workflow, including preview-only dry runs; outputs may leave a nested mutation result nil for previews.

Large-blob behavior follows CTAP 2.3 section 6.10. `ReadLargeBlob` returns the credential's opaque bytes without
interpreting their application format. A successful `missing` state means either that no `largeBlobKey` was returned
for the credential or that no conforming array entry authenticated with that key. Once an entry authenticates, a
DEFLATE or `origSize` failure is an operation error and the read report is zero.

`DecodeLargeBlob` is a pure helper for interpreting successfully read bytes as UTF-8, JSON, or CBOR. Decode failures
return a zero decode result. `ListLargeBlobs` is the diagnostic array view: entries are `matched`, `orphaned`,
`nonconforming`, or `corrupt`. Here `corrupt` means that AEAD authentication matched an enumerated credential but
DEFLATE or `origSize` validation failed. Garbage collection follows the narrower CTAP rule: it retains every
AEAD-matched entry, including one with corrupt compressed data, and removes each conforming entry that fails
authentication with all valid enumerated `largeBlobKey` values.
If the serialized array's trailing integrity hash is invalid, the runtime discards it and observes the CTAP initial empty
array, as required for a corrupt or torn write.

## Interactions and verification

Some operations need a PIN, built-in user verification, or a physical touch. Pass `ctapkit.WithInteractionHandler` to
the operation that may need this input. The handler receives a typed `model.InteractionRequest` and returns a typed
`model.InteractionResponse`.

Progress is separate from interaction. Pass `ctapkit.WithEventSink` to receive typed `model.OperationEvent` values, such
as credential enumeration or biometric sample progress.

Both callbacks belong to one operation. The runtime does not store them on the open authenticator. This makes request
ownership and cancellation easier for applications with several tasks or windows.

The default verification flow prefers built-in user verification when the authenticator supports it and falls back to
PIN when CTAP allows this. To ask for PIN first, pass:

```go
ctapkit.WithVerificationFlow(ctapkit.VerificationFlowPIN)
```

The authenticator always makes the final decision about whether a verification method succeeds.

## WebAuthn result verification

`ctapkit.VerifyMakeCredential` and `ctapkit.VerifyGetAssertion` perform local structural and signature verification.
They correlate the operation input with the runtime result and return a compact `verified`, `failed`, or `unavailable`
summary. Verification does not use the network, clock, MDS, or an application trust policy.

These helpers do not replace relying-party validation of the WebAuthn ceremony. The application still owns expected
challenge and origin checks, client-data type policy, and attestation trust decisions. Applications can obtain verified
FIDO metadata separately with [`github.com/telesma-app/mds`](https://github.com/telesma-app/mds).

## Previews and dry runs

Mutating operations return a typed preview before they change authenticator state. Many operation DTOs also have a
`DryRun` field.

```go
output, err := authenticator.DeleteCredential(
	ctx,
	credentials.DeleteOperation{
		CredentialIDHex: credentialID,
		DryRun:          true,
	},
)
```

For a dry run, the preview is filled and the mutation result is nil. The consumer must show warnings, ask for
confirmation when needed, and decide whether to run the real operation. The runtime does not implement product
confirmation rules.

## Errors

Public failures use `model/failure`. Each known error has a stable code and a recovery category. CTAP errors can also
include the command, subcommand, and status that caused the failure.

```go
result, err := authenticator.ListCredentials(ctx)
if err != nil {
	if failure.IsCode(err, failure.CodeInteractionHandlerRequired) {
		// Run the operation again with an interaction handler.
	}

	snapshot := failure.Snapshot(err)
	_ = result
	_ = snapshot
}
```

Use `failure.IsCode` for application decisions. Do not parse `err.Error()`. The full wire format and recovery rules are
described in
[`docs/error-contract.md`](docs/error-contract.md).

## Diagnostic journal

Create a journal and pass it when the device manager is created:

```go
journal := ctapkit.NewLogJournal()

devices, err := ctapkit.NewDeviceManager(
	ctx,
	transport.ModeAuto,
	ctapkit.WithLogJournal(journal),
)
if err != nil {
	return err
}
authenticator := devices.State().Selected

batch := journal.Read(0)
```

The journal stores a bounded, in-memory list of CTAP exchanges. Request and response CBOR is decoded through known
protocol types and sensitive fields are redacted. It is useful for debugging, but it is not a byte-exact wire capture.
Unknown CBOR fields may be missing.

Diagnostic records can still contain device, relying-party, user, credential, or biometric identifiers. Treat them as
sensitive data.

## Executable conformance suites

The public `conformance` package can run multi-step suites directly over the transport-independent boundary from
`github.com/telesma-app/ctap/transport`. A runner exposes the same connection to tests as both a typed
`ctap/client.Client` and raw CBOR, so positive command flows and malformed-request cases use one execution model.

```go
runner, err := conformance.NewRunner(device)
if err != nil {
    return err
}

result, err := runner.Run(ctx, suite)
```

`Suite`, `Test`, and `Step` carry stable IDs, specification references, exact upstream source locations, and an explicit
destructive marker used by run-mode selection. Step callbacks return `conformance.Fail(...)` for a conformance failure,
`conformance.Skip(...)` when a case does not apply, or an ordinary error for an execution failure. Results are
presentation-neutral JSON DTOs. The caller retains ownership of the CTAP connection.

`conformance/ctap23` contains independent Go ports for GetInfo and encrypted-state behavior, PIN/UV protocol 1 and 2
key agreement, and Metadata Statement validation. Metadata validation preserves JSON member presence and uses the
released `github.com/telesma-app/mds/model` document parser plus `github.com/telesma-app/fido-registry` values.
Encrypted-state and key-agreement tests can factory-reset the authenticator. When an encrypted field is advertised,
`ctap23.Config.TokenProvider` must acquire a `pinUvAuthToken` with the requested permission and return the exact
PIN/UV protocol that created it. Ownership of the token buffer transfers to the suite, which wipes it after the test.

Applications with an opened `ctapkit.Authenticator` should use the managed facade. The zero-value mode runs every
implemented test that is not marked destructive:

```go
result, err := authenticator.RunCTAP23Conformance(ctx, ctap23.RunRequest{
    Metadata: metadata,
})
```

The metadata must come from the authenticator's verified metadata statement, include its raw JSON in `StatementJSON`,
and record the exact advertised GetInfo field set. A complete run is deliberately explicit and should be paired with
the application's normal interaction handler:

```go
result, err := authenticator.RunCTAP23Conformance(
    ctx,
    ctap23.RunRequest{
        Mode:     ctap23.RunModeFull,
        Metadata: metadata,
    },
    ctapkit.WithInteractionHandler(handler),
)
```

Full mode additionally runs every implemented destructive test. Resetting cases ask for a destructive touch and route
the reset through the runtime. PIN and built-in UV requests use the same interaction flow as other runtime operations.
When neither is configured, the runtime asks for and configures a temporary PIN; a successful following reset removes
it. If the run is interrupted before that reset, the PIN can remain configured. The operation is serialized with all
other work on the opened authenticator and invalidates runtime-owned token and state caches after reset.

The exact upstream artifact, corpus counts, and case-to-Go mappings are pinned in
`conformance/upstream/manifest.json`. To inspect a newly extracted artifact without adding a CLI to this library, scan
it through the public filesystem API and compare it with the pin:

```go
expected := upstream.Current()
observed, err := upstream.Scan(os.DirFS(extractedCorpus), expected)
if err != nil {
    return err
}

changes := upstream.Diff(expected, observed)
```

The scanner follows every declared test-list reference, counts unique scripts and pinned Mocha case markers, and reports
source, total, added, removed, and modified module drift. After reviewing an upstream change, update the source identity,
module inventory, and port mappings in the manifest. Its loader rejects inconsistent totals, duplicate mappings, and
unknown modules. These are independent Go implementations; passing them does not itself constitute FIDO certification.

For parallel porting, use the [multi-agent porting playbook](conformance/PORTING_PLAYBOOK.md). It defines the short read
list, task catalog, file ownership, dependency waves, review gates, and copy-ready prompts for coordinators, porters,
and reviewers.

## Packages

| Package                                                                             | Use it for                                                                                |
|-------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| `ctapkit`                                                                           | Device discovery, authenticator lifecycle, typed operations, and diagnostic journals      |
| `model`                                                                             | Shared event, interaction, and log DTOs                                                   |
| `model/config`                                                                      | Configuration and biometric operation DTOs                                                |
| `model/credentials`                                                                 | Credential inventory and mutation DTOs                                                    |
| `model/inspect`                                                                     | Authenticator inspection DTOs                                                             |
| `model/largeblobs`                                                                  | Large-blob operation DTOs                                                                 |
| `model/webauthn`                                                                    | WebAuthn operation DTOs                                                                   |
| `model/failure`                                                                     | Stable public error codes and snapshots                                                   |
| `conformance`                                                                       | Authenticator conformance assessment API and contracts                                    |
| `conformance/ctap23`                                                                | Executable CTAP 2.3 authenticator tests                                                    |
| `conformance/upstream`                                                              | Pinned upstream corpus manifest and Go port coverage                                       |
| `model/operation`, `model/report`, `model/safety`                                   | Shared report and contract DTOs                                                           |
| `transport`                                                                         | HID, PC/SC smart-card, and Windows proxy discovery modes                                  |

Packages under `internal` contain runtime implementation details and are not a public API.

## Safety and usage notes

- Always close `Authenticator` when it is no longer needed.
- Treat authenticator state as changeable between commands.
- Do not log or store PINs, PIN/UV tokens, credential secrets, or large-blob payloads.
- PIN fields in public configuration operation DTOs are omitted during JSON encoding.
- Runtime-owned PIN/UV token buffers are wiped when they are released.
- A dry run is a preview, not authorization to run a mutation.
- Credential deletion, large-blob deletion, and factory reset need clear confirmation in the consuming application.
- Many displayless authenticators require factory reset soon after power-up. Ask for confirmation before reconnecting or
  power-cycling the device.
- One opened authenticator runs its own workflows one at a time. It does not create a process-wide or device-wide lock.

More lifecycle details are available in
[`docs/current-runtime-flows.md`](docs/current-runtime-flows.md).

## Development

Run the default checks with:

```sh
go test ./... -count=1
go vet ./...
```

For authenticator lifecycle, interaction, token, or synchronization changes, also run:

```sh
go test -race ./... -count=1
```

Hardware-dependent behavior must not be required by the default test suite.

## References

- [`telesma-app/ctap`](https://github.com/telesma-app/ctap)
- [`telesma-app/hid`](https://github.com/telesma-app/hid)
- [`telesma-app/windows-proxy`](https://github.com/telesma-app/windows-proxy)
- [Client to Authenticator Protocol 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Client to Authenticator Protocol 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20220621/ctap-2.1-spec-plus-errata-v2.1-ps-20220621.html)
- [Client to Authenticator Protocol 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
- [Client to Authenticator Protocol 2.3](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
- [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
