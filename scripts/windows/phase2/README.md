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
- checks that the signed MSIX's closed `Metadata\CoreBinding.json` digest equals
  the adjacent CORE digest that the broker build was given;
- verifies valid Authenticode trust, exact signer thumbprint, exact signer
  Subject, and code-signing EKU on the MSIX, CORE, and diagnostic CLI;
- unpacks and validates the closed MSIX manifest/layout; and
- rejects reparse points, elevation, non-x64 hosts, and any install root other
  than the current user's `%LOCALAPPDATA%\STEIN`.

The scripts never generate, import, trust, replace, or remove a certificate.
The selected signing chain must already be trusted by Windows.

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

`packaging\windows-msix\Test-Static.ps1` performs parser, source-contract,
MakeAppx schema, and temporary-directory safety checks only. It does not run
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
checks, release workspace/production-CORE/native-host builds, and the no-bundle
Tauri build under a timestamped `artifacts\evidence\phase-2\source-*`
directory. The report labels itself `source_verification_only`; synthetic
compile-time PFN/hash/extension values are never represented as an installed or
signed identity.

The opt-in ignored Windows fixtures can display native UI and temporarily create
synthetic current-user OS resources. Run them only in an unlocked disposable
acceptance session:

```text
scripts\windows\phase2\Verify-Source.cmd -IncludeInteractiveNative
```

Omitting that switch records the native fixture as `not_run`, not `pass`.
