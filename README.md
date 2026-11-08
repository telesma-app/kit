# telesma-app/kit

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/kit.svg)](https://pkg.go.dev/github.com/telesma-app/kit)
[![Go](https://github.com/telesma-app/kit/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/kit/actions/workflows/go.yml)

`telesma-app/kit` is a reusable Go runtime for applications that work with local FIDO2 authenticators. It provides device
discovery, safe multi-step workflows, typed results, user interaction callbacks, and stable errors.

The library is the shared runtime used by the `telesma-app` application family. It can be used by desktop, command-line, and
terminal applications, but it does not contain any user interface code.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Features

The runtime is built on [`telesma-app/ctap`](https://github.com/telesma-app/ctap) and supports authenticator features from CTAP
2.0 through CTAP 2.3. Each operation still depends on the capabilities reported by the connected authenticator.

Main features include:

- authenticator inspection and capability reports;
- PIN setup and change;
- built-in user verification and biometric enrollment;
- authenticator configuration and factory reset;
- resident credential listing, update, and deletion;
- large-blob reading, writing, deletion, and garbage collection;
- WebAuthn credential creation and assertion;
- independent USB, CTAPHID INIT, GetInfo, and vendor command reports;
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
| `transport.ModeSmartCard`    | Linux, macOS, Windows | Discovers inserted PC/SC cards and reports FIDO availability separately; vendor sources remain readable when FIDO is absent.                                  |
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

	info, err := authenticator.GetInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("attachment: %s\n", authenticator.Endpoint().Attachment.ID)
	fmt.Printf("versions: %v\n", info.Versions)
	fmt.Printf("AAGUID: %s\n", info.AAGUID)
}
```

`GetInfo` reads CTAP capabilities. For vendor details, call
`DeviceManager.RefreshSources(ctx, deviceID)`; call `RefreshMetadata` separately
for an MDS lookup. The device report keeps each source's data and errors separate,
including usable partial results.

## Runtime lifecycle

Create one `ctapkit.DeviceManager`, read its state, run operations on the selected
authenticator and close the manager when the application exits. The manager owns
the selected authenticator; selection changes and shutdown close it automatically.
Each open authenticator serializes complete workflows.

The [application guide](docs/usage.md#runtime-lifecycle) covers physical devices,
transport endpoints, discovery errors, selection and cached state.

## Operations

The root `ctapkit` package exposes typed operations with inputs and results from
`model` packages:

| Area            | Main methods                                                                                                       |
|-----------------|--------------------------------------------------------------------------------------------------------------------|
| GetInfo         | `GetInfo`                                                                                                          |
| Configuration   | `ConfigStatus`, `SetPIN`, `ChangePIN`, `SetAlwaysUV`, `SetMinPINLength`, `EnableLongTouchForReset`, `ResetFactory` |
| Biometrics      | `BioSensorInfo`, `BioList`, `BioEnroll`, `BioRename`, `BioRemove`                                                  |
| Credentials     | `ListCredentials`, `CredentialStoreState`, `DeleteCredential`, `UpdateCredentialUser`                              |
| Large blobs     | `ReadLargeBlob`, `ListLargeBlobs`, `WriteLargeBlob`, `DeleteLargeBlob`, `GarbageCollectLargeBlobs`, `DecodeLargeBlob` |
| WebAuthn        | `MakeCredential`, `GetAssertion`, `VerifyMakeCredential`, `VerifyGetAssertion`                                     |

PIN, built-in verification and touch requests use per-operation interaction
callbacks. Progress events use a separate callback. Mutating operations support
previews and dry runs; the consuming application owns confirmations.

See the [application guide](docs/usage.md) for interaction handlers, verification,
large-blob behavior, previews, errors and diagnostic journals. Public error codes
and recovery categories are defined in the [error contract](docs/error-contract.md).

## Packages

| Package                                                                             | Use it for                                                                                |
|-------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| `ctapkit`                                                                           | Device discovery, authenticator lifecycle, typed operations, and diagnostic journals      |
| `model`                                                                             | Shared event, interaction, and log DTOs                                                   |
| `model/config`                                                                      | Configuration and biometric operation DTOs                                                |
| `model/credentials`                                                                 | Credential inventory and mutation DTOs                                                    |
| `model/inspect`                                                                     | GetInfo responses and capability assessments                                                             |
| `model/largeblobs`                                                                  | Large-blob operation DTOs                                                                 |
| `model/webauthn`                                                                    | WebAuthn operation DTOs                                                                   |
| `model/failure`                                                                     | Stable public error codes and snapshots                                                   |
| `model/operation`, `model/report`, `model/safety`                                   | Shared report and contract DTOs                                                           |
| `transport`                                                                         | HID, PC/SC smart-card, and Windows proxy discovery modes                                  |

Packages under `internal` contain runtime implementation details and are not a public API.

## Safety and usage notes

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

Run the standard linters and `wsl_v5` with [golangci-lint v2](https://golangci-lint.run/docs/welcome/install/):

```sh
golangci-lint run ./...
```

For authenticator lifecycle, interaction, token, or synchronization changes, also run:

```sh
go test -race ./... -count=1
```

Hardware-dependent behavior must not be required by the default test suite.

## License

[PolyForm Shield 1.0.0](LICENSE.md).

## References

- [`telesma-app/ctap`](https://github.com/telesma-app/ctap)
- [`telesma-app/hid`](https://github.com/telesma-app/hid)
- [`telesma-app/windows-proxy`](https://github.com/telesma-app/windows-proxy)
- [Client to Authenticator Protocol 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Client to Authenticator Protocol 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20220621/ctap-2.1-spec-plus-errata-v2.1-ps-20220621.html)
- [Client to Authenticator Protocol 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
- [Client to Authenticator Protocol 2.3](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
- [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
