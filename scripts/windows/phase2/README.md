# Phase 2 Windows signed-bundle lifecycle

These scripts install the signed Phase 2 release for the current Windows user.
They are separate from the retained Phase 1 proof lifecycle. Run the `.cmd`
entrypoints from a normal, non-administrator shell; each launcher applies only a
process-scoped PowerShell execution-policy bypass for hosts whose effective
policy is `Restricted`.

## Release inputs and trust pins

The four release files produced together by `Build-Msix.ps1` are inseparable:

```text
STEIN-<version>-x64.msix
STEIN-<version>-x64.msix.core.exe
STEIN-<version>-x64.msix.cli.exe
STEIN-<version>-x64.msix.identity.json
```

Every mutating command requires the operator to repeat the exact certificate
Subject/Publisher, 40-hex signing-certificate thumbprint, and four-component
package version. Before any package, task, process, or installed-file change,
the lifecycle:

- verifies the closed identity-record schema and companion filenames;
- derives the exact PFN from the pinned Publisher and checks both exact AUMIDs;
- checks every recorded file size and SHA-256;
- checks that the signed MSIX's closed schema-3 `Metadata\CoreBinding.json`
  equals the adjacent schema-3 release identity for the CORE, diagnostic CLI,
  desktop executable, and desktop-distribution identities plus the candidate
  Git commit/tree, source-verification report digest, source-root-anchor digest,
  and source-root digest; schema-1/2 bundles are rejected;
- verifies valid Authenticode trust, exact signer thumbprint, exact signer
  Subject, and code-signing EKU on the MSIX, CORE, and diagnostic CLI;
- unpacks and validates the closed MSIX manifest/layout; and
- rejects reparse points, elevation, non-x64 hosts, and any install root other
  than the current user's `%LOCALAPPDATA%\STEIN`.

The scripts never generate, import, trust, replace, or remove a certificate.
The selected signing chain must already be trusted by Windows.
Release bundles with schema-1/2 CoreBinding/identity metadata are not accepted
as schema-3 upgrade inputs. Use the version-matched lifecycle to remove or
recover that older release before a fresh schema-3 install. The protected
installed `install.json` record remains schema 2.

## Fresh install

```text
scripts\windows\phase2\Install.cmd ^
  -PackagePath C:\release\STEIN-0.2.0.0-x64.msix ^
  -Publisher "<exact certificate Subject DN>" ^
  -CertificateThumbprint "<40 hex characters>" ^
  -Version 0.2.0.0
```

Fresh install refuses an existing package or SID-qualified task. A cleanly
uninstalled record may be reused only when its Publisher/PFN agrees. The exact
verified release is copied into an owner-only staging directory and reverified
there before use. Installation then:

1. registers the MSIX for the current user;
2. deploys the broker-pinned signed CORE and signed diagnostic CLI under
   `%LOCALAPPDATA%\STEIN\bin`;
3. registers exactly one `STEIN Core SID-<SID>` task with one action: the exact
   CORE path and only `--installed`;
4. uses the current SID, interactive logon, limited run level, battery-enabled
   execution, `IgnoreNew`, and bounded restart policy; and
5. requires one exact package, task, CORE process, and healthy diagnostic
   runtime before committing `install.json`.

The MSIX is the desktop/broker package. CORE remains an unpackaged, non-elevated
Task Scheduler daemon and does not take PFN/AUMID values from task arguments.

## Checked upgrade

```text
scripts\windows\phase2\Upgrade.cmd ^
  -PackagePath C:\release\STEIN-0.2.1.0-x64.msix ^
  -Publisher "<exact certificate Subject DN>" ^
  -CertificateThumbprint "<40 hex characters>" ^
  -Version 0.2.1.0
```

Phase 2-to-Phase 2 upgrade requires a strictly newer version and the same exact
Publisher/PFN. It verifies the current protected bundle, installed package,
task, binaries, ACLs, one process, and healthy diagnostic runtime before
shutdown. It retains one transaction-local old package/binary/task copy. After
a clean CORE shutdown it takes an exclusive cold copy of
`data\stein.db` when that database exists, rejecting SQLite journal/WAL/SHM
sidecars. The copy is owner-only and is deleted after successful readiness.

The same command recognizes the exact installed Phase 1 schema-1 record and can
transition that unpackaged proof to the signed MSIX topology. Its old binaries
and task XML are retained only for the active transaction. Because the shipped
Phase 1 proof has no SQLite repository, this transition alone is not evidence
for a real previous-SQLite-schema migration.

If the new runtime does not become ready, the script attempts to restore the
database, signed prior MSIX (using an explicit version rollback), binaries, task
XML, and prior readiness. A failed automatic restore leaves owner-only
`recovery-required.json`/recovery artifacts and refuses to present the update as
successful. Rollback is best effort: Windows package/application-data migration
and failures outside the protected database/binary/task snapshots can still
require manual recovery.

## Status

```text
scripts\windows\phase2\Status.cmd ^
  -Publisher "<exact certificate Subject DN>" ^
  -CertificateThumbprint "<40 hex characters>" ^
  -Version 0.2.1.0 ^
  -Json
```

Status revalidates the protected current bundle, deployed file signatures,
hashes and sizes, owner-only ACLs, exact installed package/PFN/AUMIDs/version,
exact task action/principal/settings, one CORE process, diagnostic runtime
health, exactly one `durable_persistence` capability in `healthy` state with no
unavailable reason, and absence of unresolved upgrade artifacts. CORE publishes
that capability only after startup migration, schema/catalog, PRAGMA, physical
integrity, logical integrity, and owner-only SQLite ACL checks succeed. Status
therefore reports `migration_readiness_verified: true` only after that gate.
The diagnostic wire contract does not expose a numeric database schema version,
which is reported separately as `numeric_schema_version_reported: false`. A
false overall `healthy` result exits nonzero.

## Read-only installed evidence collection

Use the installed evidence harness only after the exact signed release is
already installed and running:

```text
scripts\windows\phase2\Verify-Installed.cmd ^
  -PackagePath C:\release\STEIN-0.2.1.0-x64.msix ^
  -Publisher "<exact certificate Subject DN>" ^
  -CertificateThumbprint "<40 hex characters>" ^
  -Version 0.2.1.0
```

`PackagePath` identifies the signed MSIX beside its exact identity, CORE, and
diagnostic-CLI companions. The harness validates that source bundle, then proves
that the protected installed copy has the same hashes, Publisher, PFN, desktop
broker, and browser-producer AUMIDs, version, browser-host digest, and
broker-pinned CORE digest. The fixed deployed manifest, three executables,
CORE binding, and three logo assets are independently hashed below the exact
AppX install location and compared with the operator-pinned signed MSIX; package
identity/version alone is not accepted as byte equality. The deployed tree must
also contain the AppX block map and signature, may contain only the exact optional
`AppxMetadata\CodeIntegrity.cat` catalog, and rejects every other installed file;
the eight hashed application files cannot be hidden beside an unreviewed payload.
It finally invokes
the existing read-only status path and retains a minimized projection of package,
task, process, ACL, runtime, protocol, capability, persistence-readiness, and
recovery health. Authenticated actor identifiers, daemon identifiers, private
snapshots, provider credentials, and private source payloads are not retained.

Every invocation creates a new owner-only
`artifacts\evidence\phase-2\installed-<UTC timestamp>-<run>` directory. A custom
`-EvidenceRoot` is allowed only below the repository `artifacts` directory and
still receives a new timestamped child. Local filesystem arguments are recorded
as deterministic path hashes; signed artifact hashes and public package/signing
identity remain exact. The only non-evidence filesystem activity is the
temporary, independently verified MSIX unpack used by the existing verifier.
Native signature and unpack tool output is discarded so source and temporary
paths do not escape through a console transcript; failures retain only bounded
codes.
The harness does not install, upgrade, uninstall, start, stop, restart, or alter
the package, daemon, task, Credential Manager, or installed database.

`generator.json` records repository-relative paths, sizes, and SHA-256 digests
for the harness, launcher, shared lifecycle/status code, and MSIX verifier code;
the set is rehashed before the ledger is built. `ledger.json` contains every
gate from the Phase 2 runbook and gives every row generator and host-provenance
hashes, a command record, exit result, content-minimized output hash, and
row-artifact hash. `root-anchor.json` binds the run, generator, host, and ledger
digests through one deterministic root digest. This is a durable content-
integrity chain, not a signature or independent authenticity claim; preserve
the printed root digest in an external operator record when tamper evidence is
required. The signed-bundle, installed-identity, and status checks
are supporting evidence only. They cannot by themselves turn the broader
private-client, persistence, upgrade, policy, native, interactive, or external
gates into `pass`. Missing fixtures remain `not_run`; unavailable prerequisites
are `blocked`; an observed prerequisite or attached native failure is `fail`.

The optional `-AttachmentManifest` accepts schema 2 only. Start with the
generated `attachments-template.json`. `Evidence-Spec.json` is the checked-in
policy root for the exact 32 gate IDs. For every gate it fixes the outer
fixture/runner IDs, proof classes, required subchecks, each subcheck's
`source_verification`, `installed_native`, or `linux_ci` origin, and required
package/commit/source/Linux/runner bindings. The native result schema 2 must
match that specification exactly. An arbitrary JSON object, a zero exit code,
or caller-authored success booleans cannot promote a row.

Each native result enumerates its proof artifacts by content-free ID, class,
origin, size, and SHA-256. The manifest separately maps every one of those IDs
to a regular, non-reparse file. The collector opens bounded JSON through a
write-denying file handle, reads the bytes once, and computes the size/hash and
strict UTF-8 parse from those same bytes. It rechecks the exact external set
before and after ledger finalization, but retains neither source paths nor
private payloads. Source-origin subchecks name exact `source-verification.json`
check IDs; the report and root anchor must match the provenance values attested
by the signed schema-3 CoreBinding. That signature selects and binds the source
evidence; the source report remains source-only content-integrity evidence, not
installed runtime proof.

The contract maps every named source subcheck to its exact check ID set. A broad
`rust-tests` pass cannot promote a gate-specific deterministic claim. Thirteen
gate-specific source-fixture checks therefore remain explicit `not_run` rows
until closed targeted commands/receipts exist. In addition, every
`source_verification` subcheck has the common required dependency
`pinned-clean-build-environment` and `source-report-command-provenance`. They
are currently `not_run` because `Verify-Source.ps1` still executes the mutable
worktree, may reuse ignored Rust/frontend outputs, and has no independently
closed command/argument/working-directory registry; consequently no source-
backed row can promote from the current report. Native-only rows remain
independently reviewable.

The source-report contract fixes 44 exact checks—25 required `pass` rows and 19
allowed `not_run`/`pass` rows—and fourteen generator files.
Source provenance schema 2 binds launcher and rustup-selected Cargo/rustc
payloads, the pnpm JavaScript entrypoint, and both the Git-for-Windows launcher
and resolved `mingw64\bin\git.exe` payload without retaining local paths.
`P2-BUILD` also remains `not_run` on `native-toolchain-provenance`: the
VS/MSVC/Windows SDK/MakeAppx/SignTool payload/library set is not yet attested.

The closed private-diagnostic and toast-COM denial receipts have fixed CLI
fixture/runner IDs and exact ordered subchecks. The portable Linux receipt has
fixed workflow/fixture/runner IDs, candidate commit/tree and toolchain/workflow
hashes, seven exact ordered checks, and separately extracted log files whose
sizes and hashes are recomputed. Its `runner_id` is still a content claim, not
authenticated GitHub execution provenance. `P2-NO-LEAKS` additionally requires
the fixed sentinel-producer receipt, producer source and manifest hashes, and
the exact `no-leaks-producer-workflow` source check; producer and scanner must
bind the same package, commit, source report, artifact-catalog digest, and count.
Until that real candidate-owned producer/check exists, the gate remains
`not_run`; a synthetic scanner self-test or clean filler cannot promote it.
`P2-PORTABLE-FIXTURE` also requires `portable-runner-attestation=pass`. That
check remains `not_run` until an authenticated GitHub artifact attestation (or
equivalent Sigstore bundle) binds the repository, workflow, candidate commit,
and exact portable-artifact digest; self-declared runner JSON cannot promote it.

A screenshot never changes a result. Native `fail` or `blocked` results are
reflected conservatively; a structurally valid native `pass` remains `not_run`
until a trusted independent reviewer inspects the exact signed package, closed
fixture receipts, underlying artifact hashes, and the claimed native semantics.
The mechanism is tamper-evident and content-bound; it is not proof against a
malicious evidence owner and does not independently authenticate the fixture
operator or local runner.

Exit code `0` means the read-only installed machine checks passed and the ledger
was written. It does not mean Phase 2 acceptance is complete. Exit `1` means a
machine check or declared native fixture failed; exit `2` means a required
machine prerequisite or declared native fixture was blocked. All evidence,
including failed runs, should be retained.

## Independent installed-evidence review

After retaining the collector directory and recording the SHA-256 of its
`root-anchor.json` file outside that directory, run the separate read-only
reviewer with a closed review manifest and the exact attachment files it maps:

```text
scripts\windows\phase2\Review-Installed.cmd ^
  -EvidenceDirectory C:\projects\STEIN\artifacts\evidence\phase-2\installed-<run> ^
  -ExpectedRootAnchorSha256 "<SHA-256 of collector root-anchor.json>" ^
  -ReviewManifest C:\projects\STEIN\artifacts\evidence\phase-2\review-input\review.json
```

`-OutputRoot` is optional and, when supplied, must remain below the repository
`artifacts` directory. The reviewer rehashes the collector generator, host,
ledger, all 32 row artifacts, every native result, and every mapped underlying
proof file before it evaluates the 32 closed review records. JSON policy and
evidence are decoded from the same locked bytes that supplied their size and
SHA-256, and all files are checked again during finalization. A row can become
`pass` only when its collector row is not `fail` or `blocked`, its evidence
matches the exact checked-in gate contract and signed candidate/source
bindings, all required subchecks and closed runner receipts pass, and the
manifest records completed independent semantic, privacy, and synthetic-only
review. Screenshots never promote a row. Source `fail` and `blocked` results
propagate conservatively.

The manifest booleans and `review_identity` are process declarations. They
record that a review procedure was followed; they do not cryptographically
authenticate a reviewer, person, or organization. The reviewer output root is
likewise a content-integrity chain, not a signature or authenticated reviewer-
identity claim. Bind reviewer identity through a separately controlled and
authenticated operator record when that assurance is required.

Reviewer exit `0` means all 32 rows passed and `complete_acceptance` is true.
Exit `1` means a row failed or an input, hash, schema, privacy, or trust binding
was invalid. Exit `2` means no row failed but at least one row is blocked. Exit
`3` means the review is valid but incomplete because at least one row remains
`not_run`. Retain every output, including failed and incomplete review attempts.

## Uninstall and explicit data removal

```text
scripts\windows\phase2\Uninstall.cmd ^
  -Publisher "<exact certificate Subject DN>" ^
  -CertificateThumbprint "<40 hex characters>" ^
  -Version 0.2.1.0

scripts\windows\phase2\Uninstall.cmd ^
  -PackagePath C:\release\STEIN-0.2.1.0-x64.msix ^
  -Publisher "<exact certificate Subject DN>" ^
  -CertificateThumbprint "<40 hex characters>" ^
  -Version 0.2.1.0 ^
  -RemoveData
```

Default uninstall removes the exact current-user MSIX registration, task, CORE
process, binaries, and release cache. It preserves `%LOCALAPPDATA%\STEIN\data`,
logs, the owner-bound uninstalled record, and all Windows Credential Manager
entries. Canonical STEIN data must remain outside MSIX application-data folders,
because normal package removal owns those folders.

`-RemoveData` additionally removes the verified owner-only STEIN root and only
current-user generic credentials under the exact `STEIN:model-route:` prefix.
It never enumerates or deletes another credential namespace. This operation is
destructive and uses PowerShell's high-impact confirmation behavior. When it is
run after an earlier default uninstall removed the protected release cache,
`-PackagePath` is mandatory so the four signed release files can be freshly
verified against the owner-bound uninstalled record. It is optional when the
signed installed bundle is still present.

## Required live evidence (not supplied by static validation)

`Test-VerifyInstalled.ps1` statically proves that the installed harness contains
the exact 32-gate set, mandatory trust pins, quoted launcher, attachment
fail-closed rules, and no direct install/task/process/credential mutation
commands. `Test-ReviewInstalled.ps1` exercises one complete 32-row promotion and
24 fail-closed source-contract, source-set, tree-closure, tamper,
command-binding, output-integrity, mapping, privacy, result-propagation, and
incomplete-review cases.
`packaging\windows-msix\Test-Static.ps1` runs both contracts alongside its
parser, launcher, source-contract, MakeAppx schema, and temporary-directory
safety checks only. It does not run
`Add-AppxPackage`, `Remove-AppxPackage`, register/stop/start a task, stop a
process, mutate Credential Manager, or alter certificate stores.

Before any Windows Phase 2 completion claim, retain native non-elevated evidence
for at least:

- a real production-certificate build and trust verification of all four files;
- fresh install, exact PFN/AUMID/private-broker admission, one daemon, and task
  policy while the desktop is closed;
- a real prior SQLite schema/package upgrade, explicit schema/integrity readiness,
  and an injected migration failure whose restore succeeds;
- same-version rejection and a newer-version update with no orphan package,
  task, process, endpoint, or recovery copy;
- normal uninstall preservation followed by explicit remove-data cleanup,
  including Credential Manager, package/AppContainer/AUMID, task, process, data,
  and endpoints; and
- the disruptive sign-out/sign-in, lock/switch, second-SID, same-SID adversary,
  toast activation, and private-client fixtures in the Phase 2 runbook.

Until those are run, signing, installation, migration, rollback, notification,
and private-client gates remain `NOT RUN` or `BLOCKED`, never `PASS`.

## Repeatable source verification

Run the non-installing source/build suite from native Windows with:

```text
scripts\windows\phase2\Verify-Source.cmd
```

It records format, all-target/all-feature Rust check/Clippy/tests, renderer
typecheck/lint/tests/build, Edge-extension policy tests, isolated native-host
format/check/Clippy/tests, dependency-boundary checks, static MSIX/lifecycle
checks, the installed-reviewer suite under both exact Windows PowerShell 5.1 and
PowerShell 7 (`pwsh`), release workspace/production-CORE/native-host builds, and
the no-bundle Tauri build under a timestamped
`artifacts\evidence\phase-2\source-*` directory. The report labels itself
`source_verification_only`; synthetic
compile-time PFN/hash/extension values are never represented as an installed or
signed identity.

`source-verification.json` schema 2 also records bounded, content-free source
provenance schema 2: the exact Git HEAD, clean/dirty categories and digests
without file names, tool versions and launcher hashes, the exact
rustup-selected Cargo/rustc payload hashes and toolchain ID, the pnpm JavaScript
entrypoint hash, checked-in package and lockfile hashes, and the
application-schema, migration-catalog,
protocol, message-schema, and policy-profile identifiers compiled by the run.
The discovered `pwsh.exe` is mandatory and fails closed unless it is a regular,
non-reparse file with a valid Authenticode signature whose exact signer Subject
is Microsoft Corporation; an unsigned earlier PATH entry is rejected. Its
validated signer Subject, signature status, version, and executable hash are
retained in the bounded provenance. The verifier samples provenance before and
after the suite and fails the run if it changes. Its fourteen-file generator
binds the source verifier, installed reviewer, fail-closed evidence
specification/contract, no-leaks scanner/launcher/test, and their runtime
dependencies. The separate passing `no-leaks-scanner-static` source check
exercises the scanner contract without claiming that the absent real sentinel
producer ran. The separately required `no-leaks-producer-workflow` check is
retained explicitly as `not_run` with a bounded implementation-gap reason.
`root-anchor.json` binds the report, generator,
provenance, check records, and hashed logs through one deterministic root digest.
Generator files are accepted only through regular, non-reparse ancestors below
the repository root; a junction-to-external-source negative fixture enforces that
containment.
The root is content-integrity evidence only, not a signature, installed identity,
signed-package claim, authenticated reviewer-identity claim, or Phase 2
completion claim.

The opt-in ignored Windows fixtures can display native UI and temporarily create
synthetic current-user OS resources. Run them only in an unlocked disposable
acceptance session:

```text
scripts\windows\phase2\Verify-Source.cmd -IncludeInteractiveNative
```

Omitting that switch records the native fixture as `not_run`, not `pass`.
