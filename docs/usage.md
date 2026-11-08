# Application guide

[Back to the overview](../README.md).

## Runtime lifecycle

A normal application follows this lifecycle:

1. Create one `ctapkit.DeviceManager` for a fixed transport mode.
2. Read `State` and use the automatically selected authenticator.
3. Call `Select` with a physical `DeviceID` when the user chooses another token.
4. Run typed operations on `State().Selected`.
5. Close the manager when the application exits.

`DeviceManager` owns physical devices and their endpoint membership. Snapshots
store `Devices` (identity and endpoint IDs) and `Endpoints` (transport observations
and source results) separately. `Selected` is a physical `DeviceID`;
`SelectedEndpoint` identifies the active or viewed transport endpoint.
`DeviceUpdate.Selected` is non-nil only while that endpoint has a usable runtime.
`Authenticator.Endpoint()` returns the selected endpoint's observations.

Discovery reads vendor observations once per endpoint and uses those same saved
results to establish a Yubico or Token2 identity. Matching full vendor serials
pair HID and PC/SC endpoints; unknown or ambiguous identities remain separate.
Failed refreshes retain established identity for that attachment lifetime.
Membership is rebuilt after applying each source result, before selection or
snapshot publication. Endpoint preference and aggregate startup errors use the
same fixed transport/path order, independent of enumeration and map order.
`RefreshSources` refreshes all endpoints of a device. `ReadEndpointSources` and
`SelectEndpoint` are explicit endpoint-level operations. Management reads on a
sibling interface share the selected authenticator's operation gate.

Changing the selected endpoint cancels the current local source read and waits
for its owned resources to be released before opening the replacement. Selecting
the current open endpoint leaves that read and runtime intact. Removing the
selected endpoint uses the same cleanup boundary before fallback.

Hotplug publishes the endpoint before inspecting it. Until its identity is known,
inspection waits for the selected authenticator's operation gate; topology and
metadata updates remain available while it waits. PC/SC FIDO availability comes
from that opening exchange, without a separate watcher probe.
If an existing HID enumeration later reports changed descriptors, the snapshot
receives those observations without reopening its runtime or starting another
vendor read. A subsequent explicit source refresh uses the updated descriptors.

`Snapshot.DiscoveryErrors` retains startup or terminal watcher failures by
transport, including when another discovery source remains usable. Terminal
failures also appear in `DeviceUpdate.Error`. Applications can recreate the
manager to restart failed discovery; the runtime does not reconnect automatically.

An auxiliary interface appearing or disappearing does not replace the selected
runtime. If the selected endpoint disappears, the manager prefers another usable
endpoint of that physical token. A remaining management-only endpoint keeps the
physical selection, without fabricating an operational authenticator. Only the
last endpoint disappearing removes the physical token.

Token2 source data uses `report.Token2Report`. Each independent reading carries
its optional value and diagnostic error; a partial read can retain both. A valid
ATR without vendor identity succeeds with `ATR.Identity == nil`. Independent
read failures retain successful values and produce a partial source result.

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

## Operations

The root `ctapkit` package is the public runtime facade. Operation inputs and results are typed DTOs from the `model`
packages.

| Area            | Main methods                                                                                                       |
|-----------------|--------------------------------------------------------------------------------------------------------------------|
| GetInfo         | `GetInfo`                                                                                                          |
| Configuration   | `ConfigStatus`, `SetPIN`, `ChangePIN`, `SetAlwaysUV`, `SetMinPINLength`, `EnableLongTouchForReset`, `ResetFactory` |
| Biometrics      | `BioSensorInfo`, `BioList`, `BioEnroll`, `BioRename`, `BioRemove`                                                  |
| Credentials     | `ListCredentials`, `CredentialStoreState`, `DeleteCredential`, `UpdateCredentialUser`                              |
| Large blobs     | `ReadLargeBlob`, `ListLargeBlobs`, `WriteLargeBlob`, `DeleteLargeBlob`, `GarbageCollectLargeBlobs`, `DecodeLargeBlob` |
| WebAuthn        | `MakeCredential`, `GetAssertion`, `VerifyMakeCredential`, `VerifyGetAssertion`                                     |

Authenticator operation methods return concrete result values. When an operation returns an error, its result is always the zero
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
[`docs/error-contract.md`](error-contract.md).

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
defer devices.Close()

batch := journal.Read(0)
```

The journal stores a bounded, in-memory list of CTAP exchanges. Request and response CBOR is decoded through known
protocol types and sensitive fields are redacted. It is useful for debugging, but it is not a byte-exact wire capture.
Unknown CBOR fields may be missing.

Diagnostic records can still contain device, relying-party, user, credential, or biometric identifiers. Treat them as
sensitive data.

See [runtime flows](current-runtime-flows.md) for the implementation map.
