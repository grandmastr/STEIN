# Slice Contracts and Data Ownership

Status: Accepted for implementation

This document names only the logical boundaries and contracts exercised by the
[deadline-aware focus session](vertical-slice.md). A boundary is not
automatically a crate, process, database, or network service.

## Boundary map

| Boundary | Owns | Does not own |
| --- | --- | --- |
| Desktop client | Presentation state, user input in progress, visualization, and control requests | CORE lifecycle, native background delivery, canonical goals, permissions, context, intervention decisions, or audit history |
| Local client transport | Per-user endpoint discovery, peer authentication, connection limits, framing, and transport health | Domain meaning, user consent, or permission policy |
| Client protocol | Version negotiation, authenticated client sessions, typed request/response, authoritative snapshots, and subscriptions | Domain policy or operating-system transport details |
| Runtime | Daemon composition, OS-supervised lifecycle, recovery, dependency wiring, component/client health, shutdown, and cancellation propagation | Goal rules, context interpretation, intervention policy, or model-provider logic |
| Goals | Goal identity, owner, state, deadline, success statement, and revision | Focus-session lifecycle, observed activity, or authority to act |
| Focus workflow | Durable focus-session identity, lifecycle, continuity settings, recovery state, and orchestration across goals, sources, context, reasoning, policy, audit, and delivery | The private records of those collaborating boundaries |
| Identity and permissions | Local user/device identity, permission grants, scopes, expiry, revocation, and policy authority context | Capability availability or intervention significance |
| Desktop observation adapter | Native application, window, browser, document, accessibility, and bounded-pixel source connection; local extraction/redaction; normalization into the allowed observation contract | Retained observation history, context conclusions, permissions, or durable raw capture |
| Context | Accepted observation evidence, provenance, freshness, session associations, and derived working context | Durable goals, provider prompts, or intervention delivery |
| Agent loop | Minimal working-context assembly, reasoning request orchestration, candidate validation, and cancellation | Permission decisions, provider SDK behavior, canonical context, or delivery authority |
| Model gateway | Provider-neutral request/stream contract, capability matching, budgets, cancellation, and normalized failures | Prompts outside the supplied request, domain state, permissions, or action authority |
| Intervention | Candidate intervention, deterministic delivery policy, bounded delivery outbox, missed history, delivery/cooldown state, and user outcome | Observation capture, goal mutation, or notification transport implementation |
| Native status and delivery adapter | OS-visible background state, emergency stop routing, notification rendering, delivery acknowledgement, and channel health | Intervention selection, goal mutation, or permission decisions |
| Audit | Append-only, privacy-aware accountability records for permission and intervention decisions and outcomes | Raw observation storage or a second copy of domain state |

Memory is intentionally absent from the first execution path. A correction can
change current context, but no observation, correction, or intervention outcome
becomes durable personal memory in this slice.

Initially these boundaries should be modules or a small number of crates inside
one CORE codebase. Their contracts and data access rules matter before their
physical packaging does.

## Ownership rules

- A boundary is the only writer of its canonical records.
- Another boundary reads state through a query or an intentionally published
  view; it does not read the owner's tables or repository directly.
- Events contain the facts needed by subscribers, not private snapshots of the
  publisher's storage.
- An adapter has no independent authority. It receives a validated scope and an
  active grant from its caller and emits only observations permitted by both.
- Raw source artifacts never enter the general event bus or client protocol. If
  pixels or another full payload require processing, the adapter exposes an
  opaque, single-use, expiring handle to the one approved normalization or model
  operation and destroys the artifact at completion or cancellation.
- The agent loop receives an assembled working-context packet. Model adapters
  cannot query Goals, Context, Identity, Audit, or a conversation database.
- An `InterventionProposed` event does not authorize delivery. Delivery requires
  a current policy decision bound to the exact candidate and authority context.
- Audit append operations use the Audit contract. Other boundaries do not write
  an audit table as a side effect.

One physical database is acceptable for the first slice if repositories,
migrations, and access in code preserve these ownership rules.

## Minimal state models

### Goal

The slice needs these goal states:

```text
draft -> active -> completed
                 -> abandoned
```

Only a direct user command can change the success statement, deadline, or state.
Creating a goal uses an idempotency key. Every update to an existing goal carries
an expected revision so concurrent or stale edits fail with a conflict instead
of silently overwriting a correction.

### Focus session

```text
requested -> starting -> active -> stopping -> ended
                |          |          |
                v          v          v
              failed     failed     failed
```

`muted` and `source_degraded` are explicit properties of an active session, not
terminal states. Muting intervention delivery does not imply that observation
stopped. Revoking an optional observation scope removes its evidence and updates
capture state. Revoking all observation required by the workflow starts the
transition to `stopping` unless a permitted observation-free mode is added in a
future slice.

An active session may also enter `recovering` after supervised daemon restart.
Recovery revalidates its grants and resource bindings, restarts allowed adapters,
and resets source health to unknown. It returns to `active` only after required
sources acknowledge healthy state; otherwise it becomes visibly degraded,
stopped, or failed according to policy. A client connection is not part of this
state machine.

### Intervention

```text
candidate -> denied
          -> allowed -> queued -> delivering -> accepted_by_channel
                     |         |             -> delivery_unknown
                     |         |             -> delivery_failed
                     |         +------------ -> expired
                     |         +------------ -> cancelled
                     +-------- -> delivering
```

After `accepted_by_channel`, the independently tracked user outcome is
`unacknowledged`, `accepted`, `dismissed`, `corrected`, or `expired`. Channel
acceptance does not prove display or sight.

An allow decision is bound to the candidate revision, grant identifiers,
delivery channel, and a short validity window. Any relevant change requires a
new decision.

## Client-facing commands

Each command has one accountable handler and a typed result.

| Command | Owner | Important input | Result |
| --- | --- | --- | --- |
| `CreateGoal` | Goals | Owner, title, success statement, optional deadline | Goal identifier and revision |
| `UpdateGoal` | Goals | Goal identifier, expected revision, changed fields | Updated revision or conflict |
| `CompleteGoal` | Goals | Goal identifier and expected revision | Completed goal view |
| `AbandonGoal` | Goals | Goal identifier, expected revision, optional reason | Abandoned goal view |
| `ApproveModelRoute` | Identity and permissions | Provider/route, placement, allowed data categories, handling profile, purpose, fallback, optional expiry | Model-route approval identifier and revision |
| `GrantSessionPermission` | Identity and permissions | Exact scope, selected resource, device, purpose, expiry, client-disconnect and daemon-restart continuity | Grant identifier and effective scope |
| `RevokePermission` | Identity and permissions | Grant identifier and user authority | Revocation acknowledgement |
| `StartFocusSession` | Focus workflow | Goal revision, resource references, required session grants, and model-route approval | Session identifier and starting state |
| `SetInterventionsMuted` | Focus workflow | Session identifier, muted flag, user authority | Current capture and delivery state |
| `EndFocusSession` | Focus workflow | Session identifier and reason | Stopping state and cancellation token |
| `RecordInterventionFeedback` | Intervention | Intervention identifier, expected revision, accepted/dismissed/corrected outcome | Updated outcome and context-correction status |

Granting permission and starting observation are separate operations. This keeps
consent inspectable and lets the start handler verify that every referenced
grant is still valid rather than treating a checked UI control as permanent
authority.

## Client-facing queries and subscriptions

The first client needs these queries:

- `GetClientSnapshot`
- `GetRuntimeStatus`
- `GetGoal`
- `GetFocusSessionView`
- `GetCapabilityHealth`
- `GetPermissionView`
- `GetInterventionHistory`
- `ExplainIntervention`

`ExplainIntervention` returns a privacy-filtered view of the candidate reason,
evidence summary, source freshness, policy result, delivery state, and user
outcome. It does not expose a hidden model chain of thought, provider request, or
raw observation stream.

An authenticated connection opens with a snapshot and connection-scoped event
cursor produced atomically. The client applies only later events from that
cursor. If it detects a gap or reconnects, it discards affected cached state and
opens a new snapshot rather than guessing what happened while absent.

The client subscribes to versioned view events rather than internal domain
events:

- `GoalViewChanged`
- `FocusSessionViewChanged`
- `CaptureStateChanged`
- `CapabilityHealthChanged`
- `DeliveryChannelViewChanged`
- `PermissionViewChanged`
- `InterventionAvailable`
- `InterventionViewChanged`
- `InterventionHistoryChanged`

Subscriptions are state hints, not the only source of truth. The daemon may keep
a bounded connection buffer, but the first protocol promises no durable replay
for a disconnected client.

## Internal commands and events

The exact Rust names may change, but the semantic separation must remain.

### Observation events

- `UserPresenceObserved`
- `ForegroundApplicationObserved`
- `WindowMetadataObserved`
- `BrowserLocationObserved`
- `VisibleTextObserved`
- `SelectedDocumentContentObserved`
- `SelectedWorkspaceActivityObserved`
- `ObservationSourceHealthChanged`

Each observation carries the session and grant that authorized capture, source
identity, selected-resource reference, observed time, received time, extraction
and redaction version, confidence/completeness where applicable, sensitivity,
and retention class. Browser-location fields declare their included granularity.
Content fields are bounded normalized values, not general source dumps.

Bounded screen pixels are deliberately absent from this event list. The adapter
passes a short-lived capture handle only to `NormalizeTransientCapture` or an
approved vision request; a permitted normalized result may then produce one of
the events above.

### Domain events

- `GoalCreated`, `GoalUpdated`, `GoalCompleted`, `GoalAbandoned`
- `PermissionGranted`, `PermissionRevoked`, `PermissionExpired`
- `FocusSessionStarted`, `FocusSessionStopping`, `FocusSessionEnded`,
  `FocusSessionRecoveryStarted`, `FocusSessionRecovered`, `FocusSessionFailed`
- `WorkingContextChanged`
- `InterventionProposed`, `InterventionDenied`, `InterventionAllowed`
- `InterventionQueued`, `InterventionExpired`, `InterventionCancelled`
- `InterventionDelivered`, `InterventionDeliveryFailed`
- `InterventionFeedbackRecorded`
- `DeliveryChannelHealthChanged`

Events state what happened. Subscribers may update a view or request a new
command, but an event never conveys permission to perform a consequential
follow-up operation.

### Application operations

The focus workflow invokes typed operations for:

- `EvaluateSignificance`
- `AssembleWorkingContext`
- `RequestReasoning`
- `EvaluateInterventionPolicy`
- `AppendAuditRecord`
- `DeliverIntervention`
- `QueueInterventionDelivery`
- `RevalidatePendingDeliveries`
- `PublishBackgroundCaptureState`
- `NormalizeTransientCapture`
- `RecoverFocusSession`
- `StopObservationSource`
- `DeleteEphemeralSessionData`

These are orchestration calls, not necessarily messages on a shared bus.
In-process function calls are preferred until asynchronous delivery provides a
concrete benefit.

## Nominal message flow

1. The OS starts and supervises the per-user daemon. CORE opens its protected
   local endpoint and recovers only explicitly restart-authorized work.
2. The desktop authenticates to the daemon, negotiates protocol compatibility,
   and receives an authoritative snapshot plus event cursor.
3. The client queries capability health and permission requirements.
4. Direct user commands create the goal and required session grants. The workflow
   selects an already approved model route or reports reasoning unavailable.
5. `StartFocusSession` validates goal revision, grants, resources, and source
   health before activating the adapter.
6. The adapter emits permitted observations; Context accepts or rejects each one
   based on session state, grant, freshness, and schema.
7. The client may disconnect without changing daemon-owned workflow state.
8. A cheap significance gate may ask the focus workflow to assemble a bounded
   working context.
9. The agent loop sends one typed request through the model gateway and validates
   the returned candidate.
10. Intervention policy returns `deny` or `allow` for that exact candidate. The
   first slice has no execute-action or model-initiated confirmation outcome.
11. Audit persists the decision record. Failure to acknowledge the append cancels
   delivery.
12. If a permitted channel is healthy, the workflow invokes its adapter with the
    still-valid allow decision; the full desktop client need not be connected.
    If none is healthy, it writes the bounded pending-delivery record from ADR
    0008.
13. Channel recovery triggers current policy revalidation. Still-actionable
    queued items receive one deduplicated attempt; stale items become
    non-interruptive missed history.
14. Delivery and later user feedback update the Intervention aggregate and append
    outcome records to Audit without equating channel acceptance with user sight.
15. A reconnecting client obtains a new snapshot, including authorized missed
    history, before accepting subsequent
    view events.

## Common message metadata

Every cross-boundary command, query result, and event carries metadata appropriate
to its interaction form:

| Field | Purpose |
| --- | --- |
| `message_id` | Globally unique identity for deduplication and audit correlation |
| `message_type` | Stable semantic name independent of Rust or TypeScript module names |
| `schema_version` | Version of the typed payload contract |
| `issued_at` or `occurred_at` | UTC wall-clock timestamp with declared meaning |
| `correlation_id` | Groups one user intent or workflow |
| `causation_id` | Identifies the command or event that directly caused this message |
| `actor` | Authenticated user, client, device, component, or system initiator |
| `authority` | Required grant and policy-decision references; omitted when irrelevant |
| `sensitivity` | Handling classification for payload and telemetry |
| `retention` | Declared lifecycle class for the message payload |
| `trace_context` | Privacy-safe operational correlation, never an authority token |

Payloads are typed per message. Unknown fields, missing fields, and unsupported
versions follow an explicit compatibility rule; they are not collected into a
global JSON property bag.

Commands that can be retried also carry an idempotency key scoped to actor,
command type, and a documented time window. Updates to an existing aggregate
carry an expected revision.

## Errors

Public failures use a stable code and a structured shape containing:

- category;
- safe user-facing summary;
- whether retry might succeed;
- correlation identifier;
- optional field-level validation details; and
- optional supported-version or current-revision information.

The minimum categories are `invalid_argument`, `unauthenticated`,
`permission_denied`, `confirmation_required`, `not_found`, `conflict`,
`incompatible_version`, `unavailable`, `deadline_exceeded`, `cancelled`, and
`internal`.

Errors and telemetry must not include observation payloads, prompts, secrets,
provider credentials, full local paths, or private goal text unless an explicit
sensitivity-aware diagnostic mode is active.

## Cancellation, time, and ordering

- Long-running requests carry a deadline and cancellation context from the
  client through CORE to adapters.
- Cancelling a client request cancels work owned by that request. Once a command
  has created a daemon-owned workflow, closing the request or client connection
  does not cancel the workflow.
- Client disconnect, renderer failure, or desktop exit never acts as implicit
  mute, stop, revocation, or permission expiry.
- Ending a session cancels pending reasoning and delivery before stopping the
  observation source and deleting ephemeral context.
- Cancellation or permission revocation wins over a delivery that has not
  received a terminal acknowledgement.
- Mute, session end, goal deletion, relevant approval revocation, and actionable
  expiry cancel matching outbox entries.
- Event consumers deduplicate by message identity. Ordering is guaranteed only
  within the documented aggregate or source stream, not globally.
- Wall-clock time records deadlines and user-visible history. Monotonic time
  measures elapsed windows, cooldowns, and timeouts while one runtime is alive.
- Late observation events from an ended session or invalid grant are rejected,
  not attached to a newer session.

## Contract tests by implementation phase

Phase 1 proves the daemon and desktop handshake. Before Phase 1 exits:

- Rust and TypeScript fixtures encode and decode the same supported messages.
- Wrong-user, unauthenticated, endpoint-spoofing, and excessive-connection tests
  fail before domain commands are accepted. Client registration credentials are
  not present until the pre-Phase-2 hardening decision adds them.
- Unsupported protocol and schema versions fail predictably.
- The public Phase 1 `CreateGoal` proof command is idempotent: retrying the same
  actor-scoped key and input returns the original result without duplicating the
  goal or its event.
- Application-level goal-update tests prove that an expected-revision conflict
  preserves the winning state. `UpdateGoal` is not a Phase 1 public protocol
  requirement; when it enters the public protocol, its wire fixtures and
  transport contract tests enter scope in the same change.
- Public errors and telemetry fixtures contain no prohibited private fields.
- Closing the desktop leaves the daemon and its proof state running.
- Reconnect atomically establishes a current snapshot and later event cursor even
  when prior subscription events were missed.
- Cancellation, deadline, clean shutdown, frame-size, connection-limit, and
  malformed-input behavior is deterministic.
- A non-Tauri client drives the same protocol, and dependency checks keep
  Windows/Tauri types outside domain and application code.

On Windows, wrong-user evidence must use a process token with a different user
SID. Another process or shell under the daemon owner's SID remains inside the
accepted [same-user trust boundary](../decisions/0003-version-the-typed-client-protocol.md#same-user-trust-implication)
and cannot satisfy that test. The current CLI discovers only its own SID-derived
endpoint, so direct ACL and peer-SID rejection evidence remains pending until a
second-user transport harness can target the owning user's endpoint; see the
[Phase 1 verification runbook](../phase-1-runbook.md#scope-and-expected-limitations).

The following tests gate Phase 2, when their owning behavior enters the executable
slice:

- Retried commands do not duplicate focus sessions, permissions, or
  interventions.
- Cancellation and revocation beat candidate delivery in deterministic race
  tests.
- Events cannot be used as authority when the required grant or policy decision
  is missing or expired.
- Closing the desktop leaves an active focus-session fixture running in the
  daemon.
- Supervised daemon restart recovers only unexpired, restart-authorized workflows
  and does not reason from absence until fresh source health arrives.
- Channel-outage tests queue only the accepted minimal record, revalidate before
  one recovery delivery, and turn stale items into missed history without a
  notification burst.
