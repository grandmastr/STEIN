# Windows MSIX private-client package

This directory packages exactly two applications under one signed production
identity:

- `STEIN.PersonalIntelligence_<PublisherId>!Desktop` is the Tauri backend as a
  packaged classic, medium-integrity/full-trust desktop process.
- `STEIN.PersonalIntelligence_<PublisherId>!PrivateBroker` is the narrow relay
  as a packaged classic AppContainer process. It is hidden from the app list.

`PublisherId` is derived by Windows from the explicitly selected certificate
subject. The build publishes four inseparable release artifacts: the MSIX, an
adjacent `.msix.core.exe` containing the exact signed CORE bytes pinned into the
broker, a signed diagnostic `.msix.cli.exe`, and an `.identity.json` record with
the exact PFN, both AUMIDs, the MSIX and executable-companion filenames/sizes/
SHA-256 values, package version, and exact signer thumbprint. Changing Publisher
deliberately rotates the package family and therefore the admitted AppContainer
SID.

The signed MSIX also contains the closed `Metadata\CoreBinding.json` record.
Its digest must equal both the adjacent CORE digest and the value supplied to the
broker build. Lifecycle preflight rejects a bundle unless that signed internal
binding, the adjacent identity record, and the exact signed CORE bytes agree.

The package declares only the `runFullTrust` restricted capability required by
the desktop application. It declares no network, broad-file-system, device,
app-service, protocol, alias, or custom capability. The broker remains in an
AppContainer because its application entry explicitly uses
`uap10:TrustLevel="appContainer"`.

## Trust chain

The broker creates one session-local `LOCAL` relay instance, kernel-verifies the
connected desktop as the exact same PFN plus `Desktop` AUMID, then connects only
to CORE's fixed private endpoint. Before reading or forwarding a desktop frame,
it verifies the CORE pipe server as the same Windows user, unpackaged,
non-AppContainer process whose executable SHA-256 was compiled into this signed
broker build. Frames are length-bounded opaque bytes; the broker never parses or
logs them. A body/write deadline and one-frame-per-direction buffering provide
bounded backpressure. Either side ending tears down the whole relay.

The two consumers must complete the symmetric checks at their own ends:

1. Before Tauri writes a byte, its Rust backend calls
   `stein_broker_windows::verify_package_pipe_server` for the exact broker PFN,
   `PrivateBroker` AUMID, and `AppContainerBroker` class. This defeats a
   same-user process that pre-creates the fixed relay name.
2. CORE creates its private pipe with `PrivatePipeSecurity`, then calls
   `admit_named_pipe_peer` for the exact production PFN, `PrivateBroker` AUMID,
   and `AppContainerBroker` class. It moves the returned opaque authority into
   that connection only. The broker does not serialize capability material.

Until both integrations are active, private protocol access must remain
disabled. Diagnostic IPC is a separate endpoint and is never a fallback.

CORE deliberately remains an unpackaged, non-elevated Task Scheduler daemon.
It is not placed in this MSIX. The same release script signs CORE first and
pins those exact signed bytes into the broker; the installer must verify the
identity record and deploy the adjacent CORE companion without modification.

## Build and verify

Run the static contract first from a normal Windows PowerShell session:

```powershell
.\packaging\windows-msix\Test-Static.ps1
```

Build with an already provisioned, currently valid code-signing certificate:

```powershell
.\packaging\windows-msix\Build-Msix.ps1 `
  -CertificateThumbprint '<40 hex characters>' `
  -Publisher '<exact certificate Subject DN>' `
  -PublisherDisplayName '<display name>' `
  -TimestampUrl 'https://<RFC3161 service>' `
  -Version '0.1.0.0'
```

The build script searches only `Cert:\CurrentUser\My`, requires the exact thumbprint,
exact Subject/Publisher match, an accessible private key, current validity, and
the code-signing EKU. They never generate, import, trust, install, or remove a
certificate or package. Missing identity or trust prerequisites fail closed.

`Verify-Msix.ps1` re-runs SignTool trust validation, checks the exact signer,
unpacks with MakeAppx, validates the closed manifest/file layout, and requires
the expected broker-pinned CORE SHA-256. It does not
require access to the signing private key, so an installer/verifier can pin the
public signer identity independently. The fail-closed current-user install,
upgrade, status, uninstall, and rollback workflow is documented under
[`scripts/windows/phase2`](../../scripts/windows/phase2/README.md).

Static verification never installs/removes an app package, changes a task,
stops a process, mutates Credential Manager, or changes a certificate store. A
real signed installed-package/adversarial run is still required by
`P2-PRIVATE-CLIENT`; a successful build or parser/static run is not that
evidence.

## Development identity

The broker crate has a `development-package` feature which selects the distinct
`STEIN.PersonalIntelligence.Dev` package name. Its build script rejects that
feature in the release profile. The production packaging script never enables
it. A future development harness must provide a separate manifest, certificate,
endpoint, synthetic data, and CORE allowlist; it cannot introduce a production
bypass.
