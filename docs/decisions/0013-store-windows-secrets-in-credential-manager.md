# 0013: Store Windows provider secrets in Credential Manager

Status: Accepted
Date: 2026-08-19

## Context

Phase 2 introduces the first remote model adapter and therefore a provider API
credential. ADR 0007 requires credentials to remain in an approved daemon-owned
secret provider and never enter React or client-protocol payloads. The SQLite
database selected by ADR 0012 is intentionally not a credential store.

The platform-neutral application needs only a small secret lifecycle. Selecting
a broad vault framework or storing encrypted blobs with a daemon-managed master
key would create a second key-management problem before it is needed.

This selects the secret provider required by the
[Phase 0 implementation gate](../phase-0/README.md#implementation-gate) and
implements ADR 0007's rule that
[model credentials remain daemon-owned](0007-permit-configured-remote-model-routes.md#consequences).

## Decision drivers

- Keep provider credentials out of source control, configuration files, SQLite,
  protocol payloads, browser/webview memory, logs, audit, and evidence artifacts.
- Use a non-elevated, per-user Windows facility that persists across logon.
- Give CORE typed read, write, and delete operations with truthful health and
  structured failure behavior.
- Make overwrite, revocation, zeroization, and uninstall behavior explicit.
- Preserve one semantic secret-store port for Linux and macOS.

## Considered options

### Option A: Environment variable or plaintext configuration

This is simple for development but leaks through process environment,
diagnostics, shell history, files, and accidental evidence capture.

### Option B: Encrypt secrets in SQLite with a daemon-owned key

This merely moves the problem to storing and rotating the encryption key and
couples credentials to the persistence repository.

### Option C: Use Windows Credential Manager generic credentials

Credential Manager provides user-scoped durable secret storage through native
APIs and avoids a new master key or elevated service.

### Option D: Require a third-party password manager or cloud vault

This adds an account, network/provider dependency, and availability boundary not
required by the single-machine slice.

## Decision

Adopt option C for Windows. Implement the platform-neutral `SecretStore` port
with typed `write`, `read`, and `delete` operations plus content-free capability
health.

### Windows representation

The adapter uses `CredWriteW`, `CredReadW`, and `CredDeleteW` with
`CRED_TYPE_GENERIC` and per-user `CRED_PERSIST_LOCAL_MACHINE` persistence. Target
names are deterministic, non-secret identifiers under a STEIN namespace such as
`STEIN/<owner-sid-hash>/<secret-kind>/<model-route-approval-id>`. They do not contain the
credential, provider account name, goal text, resource path, or other personal
content.

Despite the native enum name, `CRED_PERSIST_LOCAL_MACHINE` here means that the
credential persists for later logons of the same user on this machine; it does
not make the credential machine-wide state readable by every user.

Route and approval records hold only an opaque `SecretRef`. The secret store
resolves that reference only inside the daemon's model-adapter boundary for the
duration of one authorized request. Protocol clients can query whether a required
secret is configured and healthy, but cannot read the value.

For every newly created model-route approval, `SecretRef` is the canonical UUID
of that approval—not the provider's reusable route/model name. CORE rejects a
new approval whose reference is not scoped this way. The native setup transaction
therefore writes the collected credential under the approval ID returned by
CORE. Each approval owns one credential target, so revoking or compensating one
approval cannot delete or replace a credential used by a sibling approval for
the same provider route.

### Entry and handling

A provider credential is entered through a trusted native setup surface owned by
the capability-bound Tauri backend or a separately capability-bound bootstrap
tool. The React webview does not receive, retain, echo, validate, or transport the
credential. Paste behavior, if offered by the native surface, is bounded to the
entry operation and STEIN does not read the clipboard itself.

Secret buffers are length-bounded, zeroized after the native call or provider
request is initialized, excluded from generic debug formatting, and never cloned
into long-lived configuration. Errors contain only the secret reference, native
error category, correlation identifier, and retryability; they never include a
credential prefix, suffix, hash, or byte count that is unnecessary for recovery.

Desktop route setup is one native Tauri transaction, not separate renderer
secret-write and approval calls. Rust validates and builds the closed approval
request before opening the native prompt--including the exact
`openai-responses-default-2026-08` profile, required `goal` category, and no
data-residency claim--retains the collected credential only
in zeroizing native memory, submits the approval through the capability-bound
private client, and writes Credential Manager only after approval succeeds.
The provider route ID remains prompt/display metadata; the credential target is
the canonical approval UUID returned by CORE.
Prompt cancellation or approval failure therefore never creates a new target or
changes an existing target. If the final atomic credential write fails, the
desktop best-effort revokes the approval it just received, deleting only that
approval-scoped target while leaving prior approval targets untouched, and returns one
content-free setup error; a retry uses a new approval idempotency key after that
rollback boundary. No standalone renderer-callable credential mutation exists.

Writing an existing approval-scoped reference is an explicit atomic rotation for
that approval. Deleting a secret makes later reads fail immediately, cancels
in-flight model work when the associated route is revoked, and sets route
capability health to unavailable.
Deleting the secret does not silently delete the route approval or audit record;
those owners report the missing dependency and are changed through their own
commands.

Route revocation, its minimal audit fact, and a private credential-deletion
obligation are committed atomically before the fallible Credential Manager call.
The obligation contains only owner, route identifier, the bounded opaque
`SecretRef`, and creation time--never secret bytes or provider content. A failed
delete therefore cannot restore route authority or lose cleanup work. Startup
and the bounded maintenance sweep retry at most three obligations per owner per
pass; `delete` reporting an already-missing target is successful idempotent
cleanup. Individual native failures remain pending and surface only as
content-free counts. Repository corruption or an obligation not fenced by its
revoked route fails maintenance closed.

### Threat boundary

Credential Manager protects the secret as per-user OS credential state. This
decision does not claim protection from malware already controlling the user's
logon session and able to act as that user. The private-client broker in ADR 0011
prevents an unregistered client from asking CORE to reveal or mutate route state,
but it is not represented as a defense against full account compromise.

### Portability

Domain and application code see `SecretRef`, `SecretPurpose`, operations, and
structured health/errors only. They do not import Credential Manager types.
Linux and macOS must implement equivalent per-user native stores with read,
write, delete, no-protocol-disclosure, restart persistence, and uninstall
semantics before their model adapters are called supported.

## Consequences

- Windows Credential Manager becomes a Phase 2 runtime dependency.
- Provider secrets are not included in database migration copies, ordinary
  backups, logs, audit, model-route views, or package evidence.
- Removing application files does not automatically erase credentials. Normal
  uninstall preserves user data and credentials; an explicit, clearly disclosed
  remove-data operation deletes the known STEIN credential targets.
- A locked, damaged, denied, or unavailable credential store degrades model
  capability truthfully; CORE does not fall back to an environment variable,
  file, another provider, or embedded key.
- Credential rotation is a write to the same approval-scoped reference followed
  by a health check; route approval is re-reviewed if provider/account/handling
  meaning changes.
- Failed route-credential deletion survives daemon restart in the private SQLite
  cleanup table while the revoked route remains unusable. Successful retry
  removes only the obligation, not the revocation or its audit history.

## Validation

- A native Windows test writes, reads, replaces, and deletes a synthetic secret
  across daemon restart under the owning non-elevated user.
- A deleted, missing, oversized, malformed, or inaccessible secret produces a
  typed failure and no provider request.
- A different Windows user cannot resolve the owner's STEIN credential target.
- The production private protocol and React bridge expose configuration state but
  no operation that returns secret bytes.
- Source, process environment, SQLite/database copies, logs, errors, traces,
  audit, package manifests, crash reports, and retained evidence contain no test
  secret or derived fingerprint.
- Revoking the route and deleting its secret cancels in-flight work and prevents
  new requests without changing historical audit facts.
- Two approvals for the same provider route receive distinct approval-scoped
  targets; revoking one leaves the other's credential byte-for-byte unchanged.
  Re-revoking an already revoked approval changes no revision/audit/cleanup and
  makes no additional native delete attempt.
- A forced delete failure proves the route, revocation audit, and cleanup
  obligation commit together; restart and periodic maintenance retry deletion
  without reissuing authority, and an already-absent credential completes the
  obligation idempotently.
- Normal uninstall preserves the credential; explicit remove-data deletes only
  the validated STEIN namespace for the current user and reports each outcome.
- Fake secret-store adapters never fabricate a value or healthy status.

## Revisit when

- multiple provider accounts require user-visible secret enumeration;
- a secret must be shared with another trusted local process or device;
- enterprise deployment supplies workload identity or a managed vault;
- the threat model must resist malware executing as the signed-in user; or
- a platform store cannot provide equivalent read/write/delete and recovery
  semantics.
