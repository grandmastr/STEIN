# 0012: Persist Phase 2 state in a daemon-owned SQLite database

Status: Accepted
Date: 2026-08-19

## Context

Phase 2 needs durable goals, identity/preferences, model-route approvals,
permission and focus-session continuity state, a bounded intervention outbox, and
minimal audit records. Phase 1 intentionally keeps proof state in memory. ADR
0005 explicitly forbids turning raw observations, working context, or model
exchanges into durable history.

The first deployment has one non-elevated daemon and one local user. A remote
database service, event store, or one database per logical module would add
operations and cross-process failure modes without satisfying a measured need.
Persistence must nevertheless preserve the ownership boundaries in ADR 0002 and
must support safe schema upgrades.

This selects the repository required by the
[Phase 0 implementation gate](../phase-0/README.md#implementation-gate), implements
the accepted [slice-local data classes and retention](../phase-0/trust-and-memory.md#slice-local-data-classes-and-retention),
and preserves the [slice ownership rules](../phase-0/slice-contracts.md#ownership-rules).

## Decision drivers

- Recover explicitly authorized workflows after daemon restart.
- Persist only the Phase 2 records named by accepted contracts.
- Keep repository ownership and transactions explicit inside the modular
  monolith.
- Support deterministic migrations, corruption detection, upgrade rollback, and
  user deletion.
- Remain non-elevated, local, portable, and simple to package.
- Avoid introducing durable copies of raw observation or provider content.

## Considered options

### Option A: Continue with in-memory repositories

This preserves the smallest privacy surface but cannot satisfy durable goals,
restart continuity, route approvals, audit, or pending delivery.

### Option B: Use independent files per owner

Owner-specific JSON or binary files avoid a database dependency but make atomic
revision updates, migrations, integrity constraints, bounded expiry, and crash
recovery bespoke.

### Option C: Use embedded SQLite through `rusqlite`

SQLite provides transactions, constraints, a mature file format, and an embedded
deployment. One file can host multiple logical owners while repository interfaces
and schema namespaces preserve boundaries.

### Option D: Use a database server or event store

This exceeds the single-user local requirement and introduces service lifecycle,
credentials, network configuration, and distributed recovery.

## Decision

Adopt option C. Use `rusqlite` with the bundled SQLite build and one database
owned exclusively by the per-user CORE daemon.

### File and access boundary

On Windows the database lives below the owning user's
`%LOCALAPPDATA%\STEIN\data` directory. The directory, database, rollback journal,
temporary migration copy, and recovery artifacts use a protected DACL restricted
to the owning user SID. No broad inherited user/group write access is accepted.
CORE verifies the owner and DACL before opening the database and fails private
capabilities closed if it cannot establish them.

Bundled SQLite does not provide application-level database encryption. This
slice accepts an access-controlled user-profile database under the existing
single-user/OS-account threat boundary; it does not describe that file as
encrypted. Provider credentials are excluded and use ADR 0013. A future need to
protect database content from other processes already controlling the user's
account requires an encryption-key and stronger process-isolation decision.

### Connection policy

Every database connection establishes and verifies:

- `journal_mode=DELETE`;
- `synchronous=EXTRA`;
- `foreign_keys=ON`;
- `secure_delete=ON`;
- `temp_store=MEMORY`; and
- a bounded busy timeout.

Rollback-journal mode is selected because one daemon is the only database writer
and the slice does not need cross-process readers. It also avoids a long-lived WAL
copy of private pages. `synchronous=EXTRA` favors crash durability over maximum
write throughput. Failure to establish any required pragma is a startup health
failure, not a warning followed by weaker operation.

### Ownership and transactions

One physical database does not create shared ownership. Goals,
Identity/Permissions, Focus Workflow, Intervention, and Audit each define a
repository interface, migration namespace, table prefix or otherwise enforced
schema ownership, and typed records. Only the owning repository writes or queries
its tables. Other boundaries use published queries/views or application
operations.

A repository transaction is scoped to one owner. Application orchestration does
not reach through repositories to construct cross-owner SQL transactions. A
multi-owner workflow uses explicit results, idempotency, audit ordering, and
compensation as required by ADR 0002. SQLite connection and row types do not enter
domain or client-protocol contracts.

Every existing focus-session lifecycle revision transition commits through one
typed repository write with its content-free `FocusSessionStateChanged` audit.
The session row and audit row are therefore visible together or not at all;
activation, recovery, failure, stop, and end paths do not append their lifecycle
audit in a later fallible operation. This uses the existing focus and audit
tables and does not require a schema-version change.

The same rule applies to consequential permission and intervention revisions.
An active grant becomes revoked in the same repository transaction as its
`PermissionRevoked` audit, before fallible adapter cleanup begins. An
intervention delivery or explicit user outcome revision commits with its
required audit; when that delivery transition enqueues or updates an outbox row,
the outbox mutation joins the same transaction. Native notification submission
cannot be part of a SQLite transaction, so the pre-delivery policy/audit
acknowledgement remains the action boundary and the strongest post-attempt state
and delivery audit commit together immediately afterward.

Because the external submission cannot join that transaction, `delivering` is a
durable pre-attempt marker rather than an in-memory status. Direct delivery
commits the intervention marker plus its content-free delivery audit before the
adapter call. Recovered delivery commits the intervention marker, matching
outbox marker and attempt metadata, fresh policy-decision reference, and audit in
one transaction. The repository accepts a recovery policy update only as a
narrow `queued -> queued` revalidation: revision increments by one and no
intervention content or identity may be overwritten.

Opening SQLite establishes schema, pragmas, integrity, and physical privacy
maintenance, but it does not infer or mutate a delivery outcome. Before any
workflow or delivery scheduler is reactivated, application startup reconciles
interrupted records through the typed intervention transaction. A direct
`delivering` record, an outbox `delivering` record, or the legacy mismatch where
the outbox is already `delivery_unknown` becomes an atomic intervention/outbox/
audit `delivery_unknown` result and is never retried. Definitely unattempted
orphan `allowed` records are cancelled and scrubbed. These rules use the existing
states and tables, so they require no schema migration.

A durable `Stopping` session is also the bounded cleanup obligation for that
workflow. Authority and queued delivery text are revoked before native cleanup.
If the daemon exits after `Stopping` commits, startup scrubs the session outbox
again, retries every known adapter stop and the exact native-status clear under
the accepted deadlines, and then records `Ended` plus its lifecycle audit in one
transaction. Failed native cleanup is recorded as `ended_cleanup_incomplete`;
it never restores authority or leaves the session active.

### Persisted records

The database may contain only the durable state accepted for the slice:

- structured STEIN identity and directly editable user preferences;
- goals and revisions;
- model-route approvals and non-secret route configuration;
- permission grants, revocation/expiry state, and consent-copy versions;
- focus-session lifecycle, continuity, grant/resource references, and recovery
  metadata;
- selected-resource bindings only when restart continuity is explicitly granted;
- minimal candidate/delivery state allowed by ADRs 0005 and 0008;
- content-free policy traces containing only profile/preference revisions,
  canonical input-schema version, and a SHA-256 input digest;
- the bounded pending-delivery outbox and non-interruptive missed-history state;
- privacy-aware permission/intervention audit and outcome records; and
- migration and content-free operational bookkeeping.

Private cleanup bookkeeping includes opaque native selected-resource release
records and model-route credential-deletion records. These tables are not part
of owner snapshots or public protocol views. Schema version 6 adds the latter as
one bounded, idempotent record per revoked route so an OS cleanup failure or
daemon exit after revocation cannot lose the retry obligation.

It must not contain raw source artifacts, normalized observation payloads,
derived working context, screenshots, accessibility trees, full browser or file
payloads, model request packets, raw model responses, chain of thought, provider
credentials, broker capabilities, or general logs. Full local paths appear only
inside the adapter-owned selected-resource binding needed for explicitly approved
restart continuity; all other records use opaque resource identifiers.

### Migration and compatibility

Each owner supplies ordered, immutable migrations with a stable identifier and
checksum. CORE records the application schema version and every applied owner
migration. Startup runs an integrity check and compares the on-disk version with
the binary's supported range before exposing private capabilities.

Forward migrations run under an exclusive migration lock and transaction. A
binary never guesses at an unknown schema, silently drops a column, or performs a
destructive downgrade. An older binary encountering a newer unsupported schema
stays unavailable with an actionable compatibility status.

Policy/audit payloads written before the content-free policy trace was added
decode with an explicitly invalid empty trace so upgrades can inspect and delete
them. They are never upgraded into delivery authority: only a fresh policy
evaluation can create a complete trace.

The release package must include migration fixtures for:

- an empty database;
- the immediately preceding released schema;
- the current schema at restart;
- a partially attempted/rolled-back migration; and
- a database whose schema version or checksum is unsupported.

### Upgrade and recovery copy

Before a schema-changing upgrade, the installer stops CORE through its typed
protocol, verifies exclusive access, and creates one SQLite-consistent temporary
recovery copy with the same owner-only DACL. The new binary migrates, runs
`foreign_key_check` and `integrity_check`, starts, and reports ready before the
upgrade is accepted.

After successful readiness and migration verification, the temporary pre-upgrade
copy is deleted; STEIN does not retain rolling private backups in this slice. If
migration or readiness fails, installation stops the new binary, restores the
verified pre-upgrade copy and compatible prior package when possible, removes the
failed database copy, and reports the failure. It never runs an older binary
against a schema it cannot read.

A failed recovery artifact is private state, not an ordinary log. If automatic
restore itself fails, it remains protected, is excluded from all normal read
paths, is surfaced as cleanup-required health, and requires explicit recovery or
deletion. Phase 2 does not introduce cloud backup, automatic replica, or general
user backup/export behavior.

### Deletion and expiry

Owners enforce TTL and user deletion through their repositories. Successful
deletion makes content unavailable to every normal query, context/model assembly,
explanation, evaluation export, and outbox path. `secure_delete=ON` reduces
recoverable deleted cell content in live database pages, but STEIN does not claim
forensic erasure from storage hardware, volume snapshots, or external backups.

Session cleanup and TTL jobs are idempotent and run at startup as well as on their
normal timers. Database errors during grant resolution, audit-before-delivery,
outbox mutation, or workflow recovery fail the protected operation closed.

## Consequences

- `rusqlite` and bundled SQLite become provider dependencies justified by durable
  Phase 2 state and transactional migration requirements.
- The single file simplifies installation but does not permit owners to read one
  another's tables.
- Private database text is protected by per-user OS ACLs, not application-level
  encryption; that limitation must be visible in the security documentation.
- SQLite rollback and migration files inherit the same sensitivity as the
  database.
- The outbox and audit can survive daemon restart without making observations or
  model exchanges durable.
- Version-to-version upgrade becomes a required acceptance fixture rather than a
  same-package rehearsal.

## Validation

- Restart and crash fixtures recover durable goals, approvals, allowed session
  continuity, audit, and outbox state while finding no prior observation or
  working context.
- Repository boundary tests prevent cross-owner table access outside declared
  views/operations.
- Startup rejects wrong owner/DACL, required-pragma failure, corruption, foreign
  key violation, unknown schema, and migration-checksum mismatch.
- A real prior-version package upgrades to the current schema, passes integrity
  checks, and preserves supported state exactly once.
- Forced migration failure restores the prior database/package or leaves a
  truthful protected recovery state; it never starts with a half-migrated schema.
- Database, journal, migration-copy, and package inspections contain no raw
  observations, model packets/responses, credentials, or broker capabilities.
- Controllable-clock tests expire observation-independent records at their
  declared boundaries, and deletion removes them from every public read path.
- Audit-before-delivery and outbox writes fail closed under busy, I/O, full-disk,
  and transaction-rollback injection.
- Repository open does not perform an outbox-only delivery-state recovery.
  Startup crash fixtures prove direct and queued pre-attempt markers, terminal
  reconciliation, and the correlated delivery audit are visible together or not
  at all, including the legacy outbox-unknown/intervention-delivering mismatch.
- A conflicting lifecycle-audit insert rolls back its focus-session revision,
  while restart fixtures prove a durable `Stopping` session resumes bounded
  adapter/native-status cleanup and reaches an audited terminal state.
- Conflicting permission-revocation, intervention-delivery, and explicit-outcome
  audit inserts roll back their aggregate revisions; a queued-delivery conflict
  also leaves no orphan outbox row.
- Linux and macOS fake-adapter suites use the same repository contracts and
  migration fixtures without importing Windows types.

## Revisit when

- multiple processes need concurrent direct database access;
- measured write load makes rollback-journal mode unsuitable;
- the threat model requires application-level encryption from same-user
  processes;
- durable personal memory or large embeddings enter Phase 3;
- local backup/export or multi-device replication is requested; or
- a repository boundary requires an independently managed security or deployment
  lifecycle.
