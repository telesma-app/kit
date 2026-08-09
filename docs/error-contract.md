# Machine-Readable Error Contract

Public runtime failures use `model/failure`. Go callers receive a
`*failure.Error`; consumer-owned transport DTOs can expose the same data as
`*failure.Failure` under their `error` or `failure` field.

## Go API

```go
result, err := authenticator.ListCredentials(
	ctx,
	ctapkit.WithInteractionHandler(handler),
)
if err != nil {
	if failure.IsCode(err, failure.CodeCredentialNotFound) {
		// Choose recovery or localized UI by the stable code.
	}

	snapshot := failure.Snapshot(err)
	_ = snapshot
}
```

- `failure.New` creates a semantic error without a lower-level cause.
- `failure.Wrap` retains a cause for trusted in-process `errors.Is` and
  `errors.As` use.
- `failure.IsCode` matches a stable semantic code.
- `failure.CodeOf` returns `("", false)` for nil and `INTERNAL_ERROR` for an unknown non-nil Go error.
- `failure.Snapshot` returns the normalized, transport-safe failure stored by the error, or nil for a nil error.
- `failure.Error.Error()` returns only the code string, never diagnostic prose.

Use `failure.IsCode`, not `errors.Is`, for semantic conditions. `errors.Is` and
`errors.As` are only for inspecting a retained low-level cause inside the Go process.

## Wire Shape

```json
{
  "code": "PIN_INVALID",
  "category": "invalid-state",
  "operation": "webauthn.getAssertion",
  "phase": "token-acquisition",
  "ctap": {
    "command": "authenticatorClientPIN",
    "commandCode": 6,
    "subCommandFamily": "clientPIN",
    "subCommand": "getPinUvAuthTokenUsingPinWithPermissions",
    "subCommandCode": 9,
    "status": "CTAP2_ERR_PIN_INVALID",
    "statusCode": 49
  }
}
```

Only `code` and `category` are always present.

| Field       | Meaning                                            |
|-------------|----------------------------------------------------|
| `code`      | Stable localization and recovery key.              |
| `category`  | Coarse recovery class; not a localization key.     |
| `params`    | Allowlisted non-secret interpolation values.       |
| `operation` | Public operation kind.                             |
| `phase`     | Runtime phase that owned the failure.              |
| `ctap`      | Exact authenticator command and status provenance. |

`failure.Failure` is an ordinary typed struct. It does not implement custom JSON marshaling, so binding generators can
expose it directly. Runtime code constructs errors through `New` or `Wrap`; consumer transport DTOs use
`Snapshot` to apply the registry without cloning the stored failure.

## Stable Registry

`failure.Code` values are public compatibility surface. Do not rename or reuse an existing value for a different
condition. Changing a code's category or removing an allowed parameter is also breaking.

Construction and snapshots apply these rules:

- an unknown code becomes `INTERNAL_ERROR`;
- category comes from the code registry;
- unknown or invalid parameters are removed;
- unknown operation names and phases are removed;
- CTAP symbolic names are derived from their numeric values.

Frontends must retain a generic localized fallback for codes introduced by a newer runtime.

## Parameters And Secrets

The current interpolation allowlist is:

| Code                                  | Parameters                 |
|---------------------------------------|----------------------------|
| `PIN_REQUIRED`                        | `field`                    |
| `MDS_FETCH_FAILED`                    | `httpStatus`               |
| `MIN_PIN_LENGTH_DECREASE_NOT_ALLOWED` | `requested`, `current`     |
| `LARGE_BLOB_ARRAY_TOO_LARGE`          | `requested`, `limit`       |

`field` accepts registered enum values.
`requested`, `current`, and `limit` accept canonical unsigned decimal values.
`httpStatus` accepts decimal HTTP status codes from 100 through 599.

Parameters must never contain PINs, `pinUvAuthToken` values, reset phrases, credential material, identifiers, URLs,
paths, raw payloads, or `err.Error()`
text. The wrapped Go cause is not part of `Failure` and is therefore absent from snapshots and JSON.

## CTAP Provenance

For authenticator errors, numeric command and status values are authoritative. Symbolic names are included only when the
pinned upstream protocol package recognizes the value. Unknown reserved, extension, and vendor values keep their numeric
code and omit the name.

Command-aware mapping can assign different semantic codes to the same raw status. For example, `CTAP2_ERR_NOT_ALLOWED`
becomes:

- `ASSERTION_NOT_ALLOWED` for GetAssertion;
- `ASSERTION_CONTINUATION_UNAVAILABLE` for GetNextAssertion;
- `RESET_WINDOW_EXPIRED` for Reset.

ClientPIN token acquisition records the ClientPIN command and subcommand while retaining the outer public operation.
LargeBlobs `get` and `set` request fields are CBOR map keys, not CTAP subcommands, and are never emitted as subcommand
metadata.

The original typed CTAP or transport cause is not part of the public failure envelope and remains available only through
the in-process Go error chain. Public error consumers must not forward or concatenate its text.

## PIN Interaction State

Before the first PIN token attempt, the runtime reads the current retry state and includes it in the PIN interaction
request without a previous failure:

```json
{
  "kind": "pin",
  "permission": "credentialManagement",
  "pinState": {
    "retriesRemaining": 7,
    "powerCycleState": false
  }
}
```

`PIN_INVALID` during PIN token acquisition does not complete the public operation. The runtime reads the updated PIN
retry state and emits another PIN interaction request with the previous failure:

```json
{
  "kind": "pin",
  "permission": "credentialManagement",
  "pinState": {
    "failure": {
      "code": "PIN_INVALID",
      "category": "invalid-state",
      "phase": "token-acquisition",
      "ctap": {
        "command": "authenticatorClientPIN",
        "commandCode": 6,
        "status": "CTAP2_ERR_PIN_INVALID",
        "statusCode": 49
      }
    },
    "retriesRemaining": 6,
    "powerCycleState": false
  }
}
```

`retriesRemaining` is present after `getPINRetries` succeeds.
`powerCycleState` preserves the authenticator's optional boolean, including an explicit `false`; it is omitted when the
authenticator does not return it. A failure to read retry state completes the operation before requesting the PIN. The
embedded previous failure is secret-free and omits runtime correlation identifiers.

Every retry requires a new interaction response. The runtime never resubmits a previous PIN. Blocked states,
cancellation, other token failures, and a failure to read retry state complete the operation with an ordinary public
failure.

The journal records only the rejected CTAP exchange. Interaction retries are delivered through the operation-scoped
handler or event sink and are not journal entries. The following `InteractionRequest` contains the safe `pinState`
payload with the previous failure, remaining retries, and power-cycle state. The submitted PIN remains redacted.

## Rejected Token Recovery

`PIN_UV_AUTH_INVALID` can occur after successful token acquisition when an authenticator rejects that token on a
consuming command. Every token-backed workflow goes through `TokenService.Use`, which owns token acquisition,
caller-copy wiping, rejection classification, and cache invalidation. Optional uses first run without a token and
acquire one only after the authenticator reports that PIN/UV authorization is required.

A `TokenUse` marked `ReplaySafe` permits one reacquisition after a rejected token. Credential inventory, biometric
enrollment listing, and persistent credential-store state use this policy because their complete consumers are safe to
replay. Mutating consumers leave replay disabled; a rejected token is still invalidated, but the mutation callback is
not called again.

Before persistent credential-store state acquisition, the authenticator token store retains only an already-standalone
`persistentCredentialManagementReadOnly` grant; credential-management and composite grants are discarded.

If the fresh token is also rejected, the operation completes with the second normalized failure. The token is still
invalidated, preventing subsequent operations from repeatedly using the same rejected secret. Other consuming- command
failures neither invalidate the cached token nor trigger an automatic retry.

## Engineering Log Diagnostics

Engineering journal entries retain bounded, redacted request and response CBOR diagnostic notation in
`request.cborDiagnostic` and
`response.cborDiagnostic`. This is produced from the known typed CTAP schema:
unknown CBOR fields are omitted and map ordering may be normalized. It is an engineering view of the exchange, not a
byte-exact capture. The raw bytes and secret-bearing typed fields never enter the journal.

The journal contains only CTAP exchanges. Application events, request state, and product correlation identifiers belong
to the consuming application.

Completed journal entries include the bounded retained cause of transport failures as a log-only `errorMessage`:

```json
{
  "error": {
    "code": "TRANSPORT_FAILURE",
    "category": "transport-failure",
    "operation": "credentials.list",
    "phase": "discovery"
  },
  "errorMessage": "transport read: io: read/write on closed pipe"
}
```

`errorMessage` is engineering evidence, not stable recovery or localization input. It is limited to 4 KiB and is emitted
only for transport failure codes. Use `error.code` for application behavior.
