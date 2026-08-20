# 0016: Use native Windows status, notifications, and a durable outbox

Status: Accepted
Date: 2026-08-19

## Context

ADRs 0001, 0008, and 0009 require CORE to show truthful background capture
state, offer an emergency stop independent of the full desktop, deliver a native
notification while Tauri is closed, and queue a bounded intervention when no
suitable channel is available. Phase 1 defines these ports but reports them
unavailable.

Windows notification delivery, Start-menu identity, Explorer tray lifecycle,
session lock state, and delivery acknowledgement are native concerns. Treating a
connected React window as the only status or delivery channel would violate the
accepted presentation-independent daemon boundary.

This implements ADR 0008's
[durable revalidated outbox](0008-queue-interventions-when-channels-are-unavailable.md#decision),
the vertical slice's [channel-recovery contract](../phase-0/vertical-slice.md#channel-recovery),
and its [native-channel failure behavior](../phase-0/vertical-slice.md#failure-behavior).

## Decision drivers

- Keep capture visibly controllable while the full desktop is closed or crashed.
- Deliver one concise native notification from the daemon-owned workflow.
- Suppress private content while locked or when channel suitability is unknown.
- Distinguish queued, attempted, OS-accepted, displayed, and seen outcomes.
- Preserve useful allowed interventions through a short channel outage without a
  stale-notification burst.
- Keep policy and delivery authority outside the native adapter.

## Considered options

### Option A: Use only the Tauri window

This is easy to present but makes status, stop, and delivery unavailable when the
presentation client closes.

### Option B: Let CORE host native Windows status and delivery adapters

The interactive per-user daemon owns a small native tray/message loop and WinRT
toast adapter while domain behavior stays behind ports. This avoids a second
always-running process.

### Option C: Add a separately supervised status process

This provides stronger UI/runtime isolation but adds another binary, private IPC,
supervision, compatibility, and package identity before a measured failure
requires it.

## Decision

Adopt option B for the first Windows slice. CORE hosts platform adapters for a
Windows notification-area status/control surface and WinRT toast delivery. The
full Tauri desktop remains a replaceable client and need not be running.

### Installed native identity

Installation creates the Start Menu registration/shortcut and stable Application
User Model ID (AUMID) required for desktop WinRT toast attribution and activation.
The AUMID, package/publisher identity, toast activation registration, executable
path, and ADR 0011 private-client identity must agree with the installed manifest.
A copied/uninstalled binary cannot borrow that identity.

Toast activation carries only an opaque intervention identifier and action verb.
It opens or focuses the registered desktop client, which authenticates normally
and queries authoritative state. Activation arguments contain no goal,
notification text, grant, capability, credential, file path, or authority.

The production MSIX registers fixed CLSID
`3DB3B5B0-1BA5-49D1-A8F0-CF2B3EA6D781` as a local COM server implemented by the
existing `stein-desktop.exe`; it does not add another executable or background
process. Windows starts that executable with the exact `-ToastActivated` marker
when needed, after which the `INotificationActivationCallback` supplies the
opaque launch value. The desktop registers the class only after its process
token proves the exact production package family and `Desktop` AUMID.

The callback accepts only the exact lowercase canonical form
`action=open&intervention=<UUID>`, the exact current desktop AUMID, and zero
notification input fields. It rejects extra keys, differently encoded UUIDs,
wrong identities, malformed arguments, and closed receivers. Command-line text
is never accepted as an intervention identifier; an unpackaged or malformed
direct `-ToastActivated` launch exits before Tauri starts.

After a valid callback, Tauri shows, restores, and focuses its main window. The
activation worker waits through the existing bounded private-broker connection,
uses the typed `explain_intervention` request for that UUID, and refreshes the
authoritative dashboard snapshot. The UUID remains a selector, not authority:
missing, expired, deleted, foreign-owner, or diagnostic-only lookups fail through
the normal private protocol boundary.

### Status and emergency stop

The daemon creates a notification-area icon using the native Windows shell API
and maintains it across Explorer `TaskbarCreated` recovery. Its tooltip and base
icon expose only content-free states such as inactive, observing, degraded,
muted, or unavailable. Opening the native status surface shows the active capture
categories and user-approved resource display labels, current mute/channel
health, and a prominent `Stop all observation` action without requiring React.

The emergency stop is a direct native user command routed into the same Identity/
Permissions and Focus Workflow handlers as any other stop/revoke command. It
atomically makes affected authority checks fail, cancels observation/reasoning/
pending delivery, rejects late events, and then performs adapter cleanup. It does
not kill the process or bypass audit/cleanup reporting.

The tray/status adapter publishes an acknowledgement and heartbeat. Capture
cannot start until the independent surface has acknowledged the exact active
category set. If the icon/control registration, message loop, heartbeat, or
truthful category mapping fails, affected capture pauses and CORE exposes
degraded content-free health. Explorer restart may restore it, but capture resumes
only after grants/resource bindings and every required source are revalidated.

When Windows is locked or switched away, the surface shows no private labels and
cannot expose private flyout content. Emergency stop remains effective through
the available native session path.

### Native notification delivery

The delivery adapter uses Windows App Notifications/WinRT toast APIs under the
registered AUMID. Before every attempt, application policy re-resolves the exact
candidate, grants, audit acknowledgement, user presence/unlocked state, channel
permission/health, sensitivity, expiry, cooldown, deduplication identity, and
cancellation state.

No private toast is submitted while the user session is locked, switched away,
logged out, or of ambiguous presence. Such a candidate is queued only if ADR
0008 and current policy allow it. The toast contains only the approved bounded
user-visible text and opaque activation data; it contains no raw evidence,
source path, prompt, credential, or hidden policy material.

The adapter reports:

- `accepted_by_channel` when Windows accepts the toast submission;
- `delivery_failed` when Windows reports a definite failure;
- `delivery_unknown` when acceptance cannot be established safely; and
- an explicit displayed or action/seen signal only if a future API supplies that
  stronger evidence.

`accepted_by_channel` is never presented as displayed or seen. Do-not-disturb,
Focus Assist, user notification settings, and OS suppression may leave that as
the strongest known outcome. An ambiguous result is not blindly retried.

### Durable bounded outbox

The Intervention owner persists the `PendingInterventionDelivery` accepted in
ADR 0008 through the repository in ADR 0012. It contains only intervention and
candidate revisions, exact proposed user-visible text, reason/urgency, policy and
grant references, sensitivity/permitted channel class, timing, deduplication
identity, and attempt state. It never contains observation payloads, paths,
prompts/responses, chain of thought, credentials, or broker capability.

Queue creation and every audited terminal delivery update commit the matching
intervention revision, outbox mutation, and content-free delivery audit in one
repository transaction. A failed or conflicting audit insert therefore cannot
leave an orphan queued item or an unaudited delivery outcome. The native call is
still outside SQLite: its candidate-specific policy decision and audit must be
durably acknowledged before submission, and the strongest known result is
persisted atomically with its post-attempt audit immediately afterward.

Channel recovery schedules bounded revalidation; it does not drain the table.
Current policy rechecks goal/session relevance, grants, expiry, novelty, cooldown,
load, presence/unlock, channel suitability, prior acknowledgements, and
deduplication. A still-valid item receives one delivery attempt. An invalid item
is cancelled or expired; its private queued text is removed and an authorized
client may later show a minimal non-interruptive missed-history record.

Mute, session end, goal deletion, relevant permission/route revocation, and
actionable expiry cancel matching entries immediately. Restart recovery respects
the same limits and never duplicates an acknowledged or ambiguous attempt. The
initial capacities and timings are fixed by ADR 0017.

### Portable semantics

Domain and application code depend on `NativeStatus`, `EmergencyControl`,
`NotificationChannel`, and `PendingDeliveryRepository` contracts and normalized
outcomes only. AUMID, WinRT, shell icon, HWND, and Windows session types remain in
the adapter. Linux and macOS must implement equivalent independently available
status/stop, native delivery, lock safety, truthful acknowledgement, and outbox
recovery before those platform capabilities are called supported.

## Consequences

- The Windows CORE daemon hosts a small native UI/message loop in its adapter
  layer but remains one modular-monolith deployment.
- Packaged toast activation reuses the desktop executable as its COM local
  server; there is no additional activator binary or durable activation payload.
- A failure in that loop cannot become invisible capture; it deliberately pauses
  affected sources.
- Installation and upgrade must register and validate Start Menu/AUMID/toast
  activation state as well as binaries and Task Scheduler state.
- Native notification content can surface without Tauri, but every attempt still
  requires current policy and prior audit acknowledgement.
- The outbox is durable intervention state, not working context or personal
  memory.
- If native UI isolation becomes necessary, extracting the adapter requires a new
  ADR under the criteria in ADR 0002.

## Validation

- With no Tauri process, the native icon shows exact capture state, emergency stop
  revokes capture, and an allowed unlocked notification is submitted from the
  daemon.
- Starting capture with missing, stale, mismatched, or failed status/control
  acknowledgement fails; killing/restarting Explorer or faulting the native
  message loop pauses capture until revalidated recovery.
- Lock, switch-user, and logout fixtures pause sensitive capture/delivery and show
  no private toast or status content; unlock waits for fresh source health.
- A toast activation opens the registered client with only opaque arguments and
  resolves the intervention through an authenticated authoritative query.
- Tests distinguish OS acceptance, definite failure, ambiguous outcome, and any
  stronger future receipt; no fixture equates acceptance with sight.
- With every channel unavailable, one allowed item queues. Recovery before expiry
  revalidates and attempts it once; recovery after expiry yields only minimal
  missed history and no toast burst.
- Mute, stop, session end, deletion, and relevant revocation each cancel queued
  items and remove private text.
- Daemon restart with queued, attempted, acknowledged, and ambiguous fixtures
  does not duplicate delivery.
- Golden outbox, toast activation, logs, audit, protocol, and database inspection
  contain none of the prohibited fields.
- Install, upgrade, reinstall, and uninstall tests leave exactly the intended
  AUMID/shortcut/activation registrations and no orphan native endpoint.

## Revisit when

- the in-daemon native message loop cannot meet reliability or isolation needs;
- Windows exposes a reliable displayed or seen receipt;
- notification activation requires a different package topology;
- a second native delivery channel is added;
- user research changes missed-history or emergency-stop interaction; or
- cross-device or voice delivery requires shared queue ownership.
