# 0005: Keep observations ephemeral and audit minimal

Status: Accepted
Date: 2026-08-19

## Context

The first slice needs recent desktop evidence to maintain working context and an
audit record to explain proactive decisions. It does not need durable personal
memory, raw activity history, embeddings, or cross-session behavioral learning.

Retaining all observations would make later reasoning easy but violate the
product's local-first, deliberate-retention promise. Retaining nothing would make
intervention explanations and permission accountability disappear. The slice
needs a precise distinction between ephemeral evidence, durable domain state,
and minimal audit data.

## Decision drivers

- Retain only data required by the first product experiment.
- Explain intervention and permission decisions without copying raw evidence.
- Make correction, expiry, and user deletion behavior explicit and testable.
- Prevent observation, model output, and feedback from becoming implicit memory.
- Keep provider-side processing visible and constrained.
- Preserve enough history to diagnose trust failures during evaluation.

## Considered options

### Option A: Persist normalized observations and model exchanges

Store the session's event stream, prompts, responses, context, and interventions
for replay and later learning.

Benefits:

- easiest debugging, offline evaluation, and reprocessing; and
- complete historical explanations.

Costs and failure modes:

- creates a detailed activity history unrelated to demonstrated user value;
- deletion and provider-retention semantics become much harder;
- sensitive content may leak through prompts, logs, or fixtures; and
- “temporary context” silently becomes durable memory.

### Option B: Keep all slice state in memory and retain no audit

Delete goals, observations, context, decisions, and feedback when the process or
session ends.

Benefits:

- smallest persistence and privacy surface; and
- simple deletion behavior.

Costs and failure modes:

- the user cannot inspect or delete a recent intervention history;
- permission and delivery failures have no accountable record; and
- evaluation cannot distinguish a policy decision from a delivery defect after
  the session.

### Option C: Ephemeral observation/context with durable goals and minimal audit

Keep normalized observations and derived context in bounded memory, persist
user-owned goal state, and retain a redacted decision/outcome record for a
limited period.

Benefits:

- supports current reasoning and explainability without activity surveillance;
- separates domain continuity from raw evidence retention;
- deletion and correction can be tested by owner; and
- no memory-learning system is implied.

Costs and failure modes:

- exact historical context cannot be reconstructed after expiry;
- audit summaries must be designed carefully to avoid becoming observations by
  another name; and
- crashes lose working context even when minimal workflow state can recover.

## Decision

Use ephemeral observation and working context, durable user-owned goals, and a
minimal, expiring audit record.

### Lifecycle by record type

- Raw source artifacts such as screen frames, unfiltered accessibility trees,
  and full source payloads remain in adapter-controlled transient processing
  only. They are discarded immediately after normalization or one explicitly
  approved model request and are never persisted, audited, logged, or published
  as client/domain events. ADR 0009 defines the rich-capture boundary.
- Raw normalized observations use an in-memory bounded buffer and expire after
  ten minutes, focus-session end, or relevant permission revocation, whichever
  occurs first.
- Derived working context remains in memory only and expires at focus-session end
  or relevant permission revocation and is lost on daemon restart. It may retain
  a last-observed time or coarse aggregate after source events expire, but only
  for the active session and with source-category provenance.
- Minimal focus-session lifecycle, grant references, continuity policy, and
  recovery metadata are durable until session end so the daemon can recover
  explicitly authorized work without retaining observation history.
- A selected local resource binding is memory-only unless restart continuity is
  authorized. When persisted, it stays in access-controlled daemon storage and
  expires with the session or relevant grant.
- Model requests and raw responses are not persisted by CORE. The selected model
  route must disclose and satisfy provider-side handling constraints and exact
  approved data categories in the processing grant.
- Undelivered candidate content expires at session end unless it enters the
  bounded delivery outbox accepted in ADR 0008. An outbox record retains only the
  exact user-visible text and minimum delivery metadata until delivery,
  cancellation, actionable expiry, or user deletion.
- Goals are durable user-owned domain records until the user deletes them.
- Delivered intervention explanations and permission decision records expire
  after thirty days by default or on user deletion, whichever occurs first.
- Operational telemetry is content-free and never includes source artifacts,
  normalized observation payloads, goal text, prompts/responses, file paths, or
  delivered message text.

Ten minutes and thirty days are first-slice defaults, not universal retention
classes. They are configuration visible to tests and to the user where retained
data is involved. Changing a default within these semantic boundaries does not
require a new architecture, but making observation durable or creating personal
memory does.

### Audit content

Audit stores identifiers, actor/source categories, policy and grant revisions,
evidence categories and age/confidence bands, structured decision reasons,
delivery outcome, exact delivered text, and user feedback. It does not store raw
observation payloads, local paths, provider prompts/responses, model chain of
thought, or unrelated state.

The exact delivered text is retained because the user must be able to see what
interrupted them. It inherits the goal's sensitivity and is removed on expiry or
relevant deletion.

### Correction

A correction appends a record and recomputes active context. It does not rewrite
the fact that an earlier decision occurred, but explanations display the
correction prominently. A correction is session-scoped and creates no identity,
user-model, candidate-memory, embedding, or cross-session application association.

### Deletion

Each owner implements deletion through its public contract. A successful delete
makes private content unavailable to normal queries, context assembly, model
requests, explanations, and evaluation exports.

Deleting a goal cascades to goal-derived private content in active context,
candidate records, and intervention explanations. Audit may retain a content-free
marker containing time, record category, and deletion status so sequence and
cleanup failures remain accountable.

The first slice has no cloud backup, multi-device replica, or provider-hosted
memory. Adding any of them requires a decision for deletion acknowledgement,
offline replicas, encryption-key ownership, and provider erasure behavior.

### No implicit memory

Observation, model output, intervention delivery, acceptance, dismissal, and
correction are prohibited sources of automatic durable memory. A future
“remember this” path must create a candidate memory with visible provenance,
sensitivity, retention, correction, and deletion rules and belongs to a later
ADR and vertical slice.

## Consequences

- A restart-authorized focus session can recover after a daemon crash, but its
  prior observations and working context cannot. Sources restart as unknown and
  reasoning waits for fresh health and evidence.
- Historical explanations become less detailed after ephemeral evidence expires
  and must accurately say that only the recorded evidence summary remains.
- Pending-delivery text is a narrow retention exception, cannot become context or
  memory, and is removed at its bounded terminal state.
- Synthetic evaluation traces are authored test data, not exports of user
  sessions.
- Debugging uses content-free telemetry and opt-in, bounded diagnostics rather
  than permanent raw capture.
- Goal storage and Audit storage have separate owners and deletion contracts even
  if they share one database.
- The Phase 3 memory design starts from an explicit candidate-memory workflow,
  not accumulated Phase 2 activity data.

## Validation

- Controllable-clock tests discard raw source artifacts immediately, expire
  normalized observations at ten minutes, and expire all derived context at
  session end or revocation.
- Daemon restart fixtures find no restorable observation context and recover only
  minimal workflow state, resource bindings, and grants whose continuity scope
  permits it.
- Repository and log inspections prove model requests/responses, raw source
  artifacts, and normalized observations are not persisted.
- Audit golden fixtures contain sufficient explanation fields and no prohibited
  payloads.
- Correction changes replayed session policy inputs while identity, user-model,
  and memory repositories remain unchanged.
- Goal deletion removes related private explanation text and leaves at most the
  defined content-free markers.
- Thirty-day expiry and direct user deletion make records unavailable from every
  public read path.
- A model route whose provider handling conflicts with the grant is denied before
  request serialization.

## Revisit when

- user evaluation shows that the proposed explanation window is too short or too
  invasive;
- crash recovery requires retaining evidence rather than rebuilding from fresh
  sources;
- Phase 3 introduces candidate memory and durable retrieval;
- evaluation requires user-contributed traces under an explicit export flow;
- backups, multiple devices, or cloud services create additional copies; or
- legal or operational requirements impose a conflicting retention obligation.
