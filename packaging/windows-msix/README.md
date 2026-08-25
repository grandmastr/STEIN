# Windows MSIX private-client package

This directory packages exactly three applications under one signed production
identity:

- `STEIN.PersonalIntelligence_<PublisherId>!Desktop` is the Tauri backend as a
  packaged classic, medium-integrity/full-trust desktop process.
- `STEIN.PersonalIntelligence_<PublisherId>!PrivateBroker` is the narrow relay
  as a packaged classic AppContainer process. It is hidden from the app list.
- `STEIN.PersonalIntelligence_<PublisherId>!BrowserObservationProducer` is the
  hidden, medium-integrity Edge native host. Its distinct producer role cannot
  access the private-client protocol.

`PublisherId` is derived by Windows from the explicitly selected certificate
subject. The build publishes the MSIX, an
adjacent `.msix.core.exe` containing the exact signed CORE bytes pinned into the
broker, a signed diagnostic `.msix.cli.exe`, and an `.identity.json` record with
the exact PFN, all three AUMIDs, the signed browser-host digest, and the MSIX and executable-companion filenames/sizes/
SHA-256 values, package version, exact signer thumbprint, candidate Git
commit/tree, and Phase 2 source-report/root-anchor digests. A separate
`.browser.json` binds the blocked browser host AUMID/digest/publisher and exact
Edge Add-ons ID/version without changing the Phase 2 lifecycle identity schema. Changing Publisher
deliberately rotates the package family and therefore the admitted AppContainer
SID.

The release identity also projects the signer-bound diagnostic CLI size/hash,
packaged desktop size/hash, and fresh renderer file-count/manifest digest. The
signed MSIX contains the closed schema-3
`Metadata\CoreBinding.json` record. Its CORE digest must equal both the
adjacent CORE digest and the value supplied to the broker build. The same
signed record binds the exact clean Git commit/tree and the SHA-256 of the
passing `source-verification.json`, its `root-anchor.json`, and the anchor's
root digest. It also binds the external CLI and packaged desktop/renderer byte
identities. Lifecycle preflight rejects a bundle unless that signed internal
binding, the adjacent schema-3 identity record, both signed companions, and the
packaged desktop bytes agree.

This is a signer attestation about which candidate and source-evidence bytes
were selected for the package. It does not make the Git commit a Git-signed
commit, authenticate the source verifier as a person, or turn source-only
evidence into installed acceptance evidence. The report must be evaluated only
after its exact signed hash and anchor chain have been reproduced.

The package declares only the `runFullTrust` restricted capability required by
the desktop application. It declares no network, broad-file-system, device,
app-service, protocol, alias, or custom capability. The broker remains in an
AppContainer because its application entry explicitly uses
`uap10:TrustLevel="appContainer"`.

The desktop application declares exactly two activation extensions: a packaged
COM local server and `windows.toastNotificationActivation`. Both pin CLSID
`3DB3B5B0-1BA5-49D1-A8F0-CF2B3EA6D781` to the existing
`bin\stein-desktop.exe` with the exact `-ToastActivated` server marker. No
protocol handler, app service, execution alias, or input-capable toast is
registered. The Rust callback verifies the current production
desktop AUMID and accepts only `action=open&intervention=<canonical UUID>` before
reconnecting through the private broker and querying CORE's typed intervention
explanation API.

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

The bounded Windows Graphics Capture implementation also runs inside that
unpackaged CORE daemon and invokes only the consent-bearing system picker. The
MSIX desktop does not capture pixels and therefore does not declare a graphics
capture capability on behalf of another process. In particular the package
must not request `graphicsCaptureProgrammatic` or
`graphicsCaptureWithoutBorder`; the implementation cannot create a capture item
programmatically or hide Windows' capture border. Static verification pins
those source and manifest invariants, while the real installed `P2-PIXELS`
picker/capture fixture remains separately required.

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
  -Version '0.1.0.0' `
  -EdgeExtensionId '<exact published 32-character ID>' `
  -EdgeExtensionVersion '<exact published version>' `
  -EdgePublisherSha256 '<lowercase SHA-256 certificate thumbprint>' `
  -ExpectedCandidateGitCommit '<git rev-parse HEAD>' `
  -ExpectedCandidateGitTree '<git rev-parse HEAD^{tree}>' `
  -SourceVerificationReportPath '<repository artifacts path>\source-verification.json' `
  -SourceRootAnchorPath '<same evidence directory>\root-anchor.json' `
  -ExpectedSourceVerificationSha256 '<lowercase report SHA-256>' `
  -ExpectedSourceRootAnchorSha256 '<lowercase root-anchor file SHA-256>'
```

The build script searches only `Cert:\CurrentUser\My`, requires the exact thumbprint,
exact Subject/Publisher match, an accessible private key, current validity, and
the code-signing EKU. It requires matching operator-pinned commit/tree IDs and
a passing schema-2 Phase 2 source report plus valid schema-1 root anchor below
`artifacts\evidence\phase-2`. It exports the pinned Git tree into a random,
owner-only private directory, rejects omitted/extra archive entries, verifies
every extracted file against its Git blob ID, and holds tracked files against
replacement throughout the build. Cargo uses private home/target directories,
the rustup-resolved Cargo/rustc payloads recorded by source verification, and
`--locked`. The desktop begins without `node_modules` or `dist`, installs with
the recorded Node/pnpm entrypoint and frozen lockfile, then generates and locks
a fresh renderer manifest before Tauri compilation. Each final compiler output
is locked and compared to the complete fixed staging path/size/SHA-256 map.
MakeAppx receives only an immutable eight-file `/f` mapping, and verification
requires the unpacked fixed payload map to equal that pre-pack map exactly. The mutable public
worktree and ignored stale renderer/target outputs are never build inputs. The scripts never
generate, import, trust, install, or remove a certificate or package. Missing
identity, provenance, or trust prerequisites fail closed.

Before signing, packaging validates the frozen source-fixture registry
(`SHA-256
d2414e552dfbc00b3ecf5837cfc431c64f670508ae4e8696b9fce4f85a75c5c5`),
all 13 receipts/71 ordered subchecks, their exact commands and locked binaries,
the suite index, and all 140 invocation mappings. It grounds every semantic
source size/SHA-256/Git blob plus the receipt's tree count/manifest against the
locked candidate snapshot. The installed reviewer then rehashes the signed
schema-3 package's bound source report and validates its embedded receipts; it
does not substitute the operator's mutable checkout for that signer-grounded
candidate.

The frozen source-command registry (`SHA-256
9a1bb265a11a3b7ca18d1e8b67a2b1c47f9cb090910a458ca3d41fb221b50cbc`)
also fixes every row category and, for the 37 executed rows, the executable
role, ordered argument vector, working directory, environment profile, timeout,
and execution group. Packaging independently
validates and rehashes the resulting 37 per-check receipts, 25 execution groups,
and 50 unique bounded logs before the signed binding can select the report. It
also recomputes the receipt candidate manifest from the locked candidate's
canonical Git tree records (`UTF-8 path length:path|mode|blob object ID`). The
runner separately locks every worktree file and permits only exact blob bytes or
a bytewise CRLF-to-LF checkout difference while rejecting hidden index flags and
active content-transform attributes. This keeps clean `core.autocrlf=true`
Windows checkouts compatible without weakening the signed candidate identity.
The command index and every receipt bind the source report's exact
Git-for-Windows launcher and resolved payload SHA-256 values; packaging rejects
any divergent Git identity before signing.

The source contract has 44 checks: 39 required `pass` and five exact frozen
`not_run`, with twenty-one generator files. This is deliberately not a hermetic
native-toolchain claim. The selected
VS/MSVC compiler, linker, assembler, librarian and library catalogs, Windows
SDK resource/libraries, and MakeAppx/SignTool payloads are not yet represented
by a closed signer-attested toolchain manifest. Packaging also validates the
source report's exact check catalog, shapes, statuses, log bytes, generator
files and integrity digests. `source-report-command-provenance` is now a required
pass derived from the closed registry and receipt set. The independent
`native-toolchain-provenance` and `pinned-clean-build-environment` receipts
remain explicit P2-BUILD NOT RUN obligations. This slice cannot promote
P2-BUILD until dedicated closed receipts satisfy those obligations. The source
contract can also carry other
named NOT RUN rows, including `portable-runner-attestation`; accepting their
exact presence for signing never promotes the gate to which they belong.
The portable workflow can now create a GitHub/Sigstore bundle only from a
manually dispatched exact candidate ref, after a separate write-scoped job
revalidates the successful read-only fixture artifact. Packaging must continue
to reject promotion until the source report contains a passing, independently
verified `portable-runner-attestation` binding for that exact fixture and bundle;
the workflow's bundle file or upload result is not a packaging trust shortcut.

Every new MSIX, companion, and identity record is built and verified at an
explicit sibling temporary path. Existing final artifacts are left untouched
until the complete set is ready. At the final publication boundary the script
backs up existing finals, replaces the set, and restores the prior files after
a controlled mid-publication move or final-byte verification failure. That
rollback is error recovery, not a filesystem transaction against another
same-user process concurrently modifying the old backup paths. The stronger
interference invariant applies to the selected new bytes: before any backup is
deleted, every published final is re-read against its exact verified temporary
size/SHA-256 while a read handle prevents writes or replacement. If old-backup
cleanup alone fails after that verification, the exact new finals remain
published, any undeleted backup is retained for explicit operator cleanup, and
the build exits with an error instead of claiming an entirely clean publish.
The script never deletes the last known-good bundle merely because compilation,
signing, verification, or a controlled publication failed.

Schema-1 and schema-2 CoreBinding/main `.identity.json` release records are
intentionally rejected; they do not contain the complete signer-attested
source, CLI, desktop, and renderer provenance. Such artifacts must be
rebuilt from a newly verified clean candidate. The protected Phase 2 install
record remains schema 2 because it already pins the complete MSIX hash and
revalidates the retained schema-3 release identity plus signed CoreBinding on
every lifecycle read. Consequently, a previously installed Phase 2 bundle that
retains schema-1 or schema-2 package metadata is not an in-place upgrade or rollback source
for these scripts; use its version-matched lifecycle tooling to uninstall or
recover it before a fresh schema-3 install. The supported checked transition
from the installed Phase 1 layout is unchanged.

`Verify-Msix.ps1` re-runs SignTool trust validation, checks the exact signer,
unpacks with MakeAppx, validates the closed manifest/file layout, and requires
the expected broker-pinned CORE SHA-256. The closed unpacked layout consists of
the eight application-owned files plus `AppxBlockMap.xml`; the verifier permits
only the exact tool/signing metadata names `[Content_Types].xml`,
`AppxSignature.p7x`, and `AppxMetadata\CodeIntegrity.cat`. Arbitrary content
under `AppxMetadata` is rejected. It does not
require access to the signing private key, so an installer/verifier can pin the
public signer identity independently. The fail-closed current-user install,
upgrade, status, uninstall, and rollback workflow is documented under
[`scripts/windows/phase2`](../../scripts/windows/phase2/README.md).

Static verification never installs/removes an app package, changes a task,
stops a process, mutates Credential Manager, or changes a certificate store. A
real signed installed-package/adversarial run is still required by
`P2-PRIVATE-CLIENT`, `P2-NOTIFICATION`, and `P2-BROWSER`; a successful build or parser/static
run is not that evidence. The native notification fixture must prove both
cold-start and already-running COM activation, focus behavior, private-broker
reconnection, authoritative explanation lookup, and rejection of malformed or
wrong-identity callbacks.

## Development identity

The broker crate has a `development-package` feature which selects the distinct
`STEIN.PersonalIntelligence.Dev` package name. Its build script rejects that
feature in the release profile. The production packaging script never enables
it. A future development harness must provide a separate manifest, certificate,
endpoint, synthetic data, and CORE allowlist; it cannot introduce a production
bypass.
