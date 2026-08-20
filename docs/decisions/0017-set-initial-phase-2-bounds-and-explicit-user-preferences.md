# 0017: Set initial Phase 2 bounds and explicit user preferences

Status: Accepted
Date: 2026-08-19

## Context

The accepted slice requires configurable freshness, capture frequency, payload,
model budget, cooldown, retention, and outbox limits before real observation and
proactive delivery. It also lists structured identity and user preferences while
explicitly prohibiting observations, corrections, and intervention outcomes from
becoming automatic durable user-model learning.

Unbounded or scattered constants would make policy hard to inspect and race tests
non-deterministic. Treating example times in the scripted scenario as universal
truth would turn the product experiment into an unsupported productivity model.
The first values therefore need to be conservative, visible hypotheses with hard
safety ceilings and controllable-clock fixtures.

This fixes the defaults deferred by the
[Phase 0 implementation gate](../phase-0/README.md#implementation-gate), implements
the accepted [deterministic intervention policy](../phase-0/trust-and-memory.md#deterministic-intervention-policy),
and preserves the [minimum-memory negative guarantees](../phase-0/trust-and-memory.md#minimum-memory-behavior).

## Decision drivers

- Make source freshness, cost, interruption, queue, and retention behavior
  deterministic and testable.
- Bound private payloads and remote model exposure.
- Produce at most a small number of useful interruptions in the first slice.
- Let the user make behavior more restrictive without weakening hard privacy and
  authority limits accidentally.
- Represent identity/preferences as versioned, explicit, correctable data.
- Prohibit implicit learning until the later user-model/memory workflow exists.

## Considered options

### Option A: Leave bounds to adapter/provider defaults

This hides behavior, makes failure tests non-reproducible, and lets a provider or
platform change privacy/cost semantics.

### Option B: Hard-code the example trace

This is deterministic but mistakes one demonstration for a general definition of
productive work and makes safe evaluation difficult.

### Option C: Use one versioned policy profile with conservative defaults and
hard ceilings

The policy owner exposes the effective values, tests every boundary with a
controllable clock, and permits reviewed revisions without changing domain
semantics.

## Decision

Adopt option C. The first profile is `phase2-focus-v1`. Values below are accepted
initial evaluation hypotheses for the deadline-aware focus slice, not claims
about all users or future workflows.

### Time, freshness, and retention

| Bound | Initial value | Meaning |
| --- | --- | --- |
| Native status/source heartbeat | 10 seconds | A healthy long-running adapter/status surface acknowledges at least this often while active. |
| Windows input-inactivity threshold | 60 seconds | `GetLastInputInfo` may report the bounded `idle` signal after this interval without qualifying input. This is not a claim that the user is absent, distracted, or unproductive. |
| Source stale threshold | 30 seconds | Three missed heartbeats make the source unknown/degraded and suppress absence-based reasoning. |
| Maximum evidence age in a model packet | 2 minutes | Older raw normalized evidence is omitted; a coarse aggregate may remain only with its time range and provenance. |
| Absence/progress lookback | 10 minutes | An absence claim requires the relevant sources to have stayed healthy and complete for this whole window. |
| Normalized observation TTL | 10 minutes | Accepted ADR 0005 default; session end or revocation wins sooner. |
| Retention maintenance cadence | No more than 60 seconds between sweeps | Quiet sessions are swept without requiring new ingestion. The controllable one-shot retains only observations with a non-negative age strictly below their TTL, so exact expiry and later are physically removed; a clock rollback that makes an accepted observation future-dated removes it rather than extending private retention. Audit records with `expires_at <= now` are physically purged in the same sweep. The same owner task retries at most three retained native-resource releases and three revoked-route credential deletions per pass; individual platform failures remain pending rather than terminating the sweep. |
| Derived working-context TTL | Focus-session end | Revocation removes the affected scope sooner; restart loses all context. |
| Raw artifact lifetime | One normalization or approved request | Destroy immediately on completion, error, cancellation, lock, stop, or revocation. |
| Candidate policy-decision validity | 30 seconds | Delivery must re-evaluate after this window or any relevant revision change. |
| Delivered intervention/permission audit TTL | 30 days | Accepted ADR 0005 default; direct deletion wins sooner. |
| Focus-session grant maximum | 8 hours | Input is rejected when expiry is later than eight hours after effectiveness or later than the goal deadline. Runtime session end, goal deadline, or authority revocation/expiry wins sooner. |
| Model-route approval UI default | 30 days | The user may choose a shorter expiry or deliberately approve the optional no-expiry form from ADR 0007. |

Restart continuity is off by default for session grants and selected-resource
bindings. The user must opt in through the exact consent copy for each session.

### Capture frequency and payload ceilings

Adapters are event-driven where possible and coalesce bursts rather than polling
for history.

| Bound | Initial value |
| --- | --- |
| Presence/foreground sampling | No faster than once per second; idle state is sampled every 5 seconds when no event is available. |
| Browser/UIA/document extraction | Coalesce for 2 seconds; no more than one normalized content observation per selected source every 5 seconds. |
| Bounded-pixel capture | No more than one frame per selected source every 10 seconds and one frame in flight. Continuous video is prohibited. |
| Visible/selected-document text | 16 KiB UTF-8 per normalized observation after local redaction. |
| Browser location | 2 KiB UTF-8 after separately approved component minimization. |
| Working-context text packet | 32 KiB UTF-8 and no more than 8,000 input tokens after provider tokenization. |
| Pixel frame | At most 1920 x 1080 selected pixels and 8 MiB transient decoded storage. |
| Candidate notification text | 512 Unicode scalar values. |

Exceeding a ceiling truncates only through a declared, provenance-preserving
normalizer when safe. Otherwise the source/request is unavailable; it never
widens scope, silently samples another source, or spills content to disk.

### Reasoning and intervention limits

| Bound | Initial value |
| --- | --- |
| Automatic significance evaluation | At most once per 60 seconds per active session after relevant state changes. |
| Automatic model request | One in flight; at most one every 5 minutes and 12 per rolling hour per session. |
| Remote model deadline | 30 seconds total, including at most one transport-safe retry. |
| Model output | At most 512 output tokens and the strict candidate schema from ADR 0015. |
| Deadline-risk horizon | 30 minutes before the user-selected deadline for this first workflow. |
| Intervention cooldown | 15 minutes per session. There is no urgency bypass in the advisory-only slice. |
| Intervention cap | At most 3 delivered or channel-accepted proactive interventions per focus session. |
| Audit append deadline | 2 seconds; timeout denies delivery. |
| Native delivery attempt deadline | 5 seconds; ambiguity becomes `delivery_unknown`. |
| Adapter stop acknowledgement | 5 seconds; authority is revoked immediately even if cleanup later reports failure. |

Before each scheduled reasoning pass, CORE revalidates the exact goal revision
and deadline, every required session grant, and the selected model route. This
reconciliation runs before mute, do-not-disturb, remote-processing, or model
availability gates, so those quieter modes cannot leave an expired workflow
durably `Active`. Missing, revoked, or expired authority moves the session
through audited `Stopping`, cancels ephemeral work, scrubs its outbox, performs
bounded adapter/native-status cleanup, and records `Ended`. A daemon restart
resumes any durable `Stopping` cleanup rather than skipping it. Expected
authority races produce silence/reconciliation instead of terminating the
reasoning scheduler; repository corruption or unavailability still fails the
protected operation closed.

A user preference may lengthen cooldown, lower request/intervention caps, shorten
retention/expiry, disable remote processing, mute proactive behavior, or disable a
source. It cannot shorten the stale threshold in a way that claims incomplete
evidence is healthy, raise a hard capture/payload/model/outbox ceiling, extend a
retention maximum, bypass a grant, or make policy fail open.

### Outbox limits

| Bound | Initial value |
| --- | --- |
| Total queued items | 20 across the user's daemon. |
| Queued items per focus session | 5. |
| Private text per item | The same 512-character candidate limit. |
| Actionable lifetime | The earliest of 15 minutes after queueing, candidate validity supplied by policy, goal deadline, focus-session end, grant expiry, or user deletion. |
| Recovery batch | Revalidate at most 3 items per channel-health transition and no more than one batch every 10 seconds. |
| Delivery attempts | One attempt after each fresh allow decision; ambiguous or acknowledged attempts are never automatic retries. |

When a queue is full, policy denies the new pending delivery and appends a
content-free bounded-capacity outcome; it does not evict an item and deliver it
without policy. Expiry removes private text. The missed-history/audit record keeps
only the accepted minimal summary under the 30-day or deletion boundary.

### Structured identity and preferences

Phase 2 persists two revisioned records through the Identity/User Model owner:

1. `SteinIdentityV1`: schema/version, display name, role statement, invariant
   behavioral constraints, and revision/provenance. It states that STEIN advises,
   preserves uncertainty, respects silence, and cannot present itself as the user
   or bypass policy. Shipped invariant constraints are changed only by an explicit
   product migration, not model output.
2. `UserPreferencesV1`: optional preferred form of address, concise intervention
   style, proactive enabled/muted state, stricter cooldown/cap choices,
   do-not-disturb windows, allowed channel preference, remote-processing default,
   and revision/provenance. The initial default is proactive disabled until the
   user grants it for a focus session, concise text, no remote route selected, and
   no restart continuity.

Only a direct capability-bound user command with an expected revision can edit
user preferences. The UI shows the effect and scope. Corrections append their
session record and recompute current context; they do not mutate identity or
preferences. Observation, model output, silence, intervention acceptance,
dismissal, correction, timing, and application use are prohibited inputs to an
automatic durable preference update.

Disabling or muting proactive interventions cancels in-flight model and
unacknowledged delivery work through a token that is separate from observation
authority. Queued intervention/outbox text is cancelled and scrubbed before the
preference command returns. Re-enabling creates fresh proactive cancellation
authority only after the direct revisioned preference remains current; it does
not revive cancelled queue entries.

This is explicit configuration, not Phase 3 personal memory. There is no learned
profile, embedding, cross-session behavioral inference, or hidden self-modifying
prompt. Deletion follows the owning repository contract.

### Configuration and time

The effective policy profile and user overrides are queryable in a privacy-safe
view and referenced by every evaluated significance decision and every
intervention policy decision/audit through a content-free policy trace. That
trace includes the exact effective preference revision, versioned policy profile,
canonical typed-input schema version, and SHA-256 digest of the exact proposed
inputs; it never persists the input projection or private source/candidate text.
Defaults are versioned configuration owned by policy, not copied into adapters.
Wall-clock UTC records deadlines/history; monotonic time measures in-runtime
cooldowns, heartbeats, elapsed windows, and timeouts. Restart recomputes
wall-clock expiry and never emits a catch-up burst.

Changing a value within the accepted semantic boundary requires a versioned
profile, synthetic before/after replay, and a recorded evaluation reason. Making
observations durable, weakening a hard privacy/authority ceiling, enabling
automatic learning, or adding a new intervention class requires a new ADR.

## Consequences

- Tests and users can inspect the exact reason a source became stale, a model call
  was skipped, a queue was full, or an intervention was denied.
- The first slice prioritizes restraint and bounded cost over maximum sensitivity.
- A 30-minute risk horizon and other defaults remain evaluation hypotheses; they
  must not be described as measures of productivity or attention.
- Explicit user preferences can make behavior quieter but cannot grant authority
  or broaden capture/model data flow.
- Identity and preferences survive restart without creating a personal-memory
  system.
- Adapters receive limits from typed configuration and cannot invent provider- or
  OS-specific defaults.

## Validation

- Controllable-clock boundary tests cover exactly-before/at/after every freshness,
  TTL, decision, cooldown, deadline, grant, audit, and outbox time.
- Controllable-clock workflow tests prove the exact goal/grant deadline and a
  model-route expiry end an active session even while interventions are muted,
  without invoking the model or terminating scheduler supervision.
- Burst fixtures prove event coalescing, capture-rate ceilings, one-frame/one-model
  concurrency, payload bounds, hourly budget, cooldown, and session cap.
- Clock rollback/forward and daemon restart recompute safely without stale
  reasoning or notification bursts.
- Queue-full, oversized payload, slow audit, slow delivery, and slow adapter-stop
  fixtures fail closed and expose truthful content-free health/outcomes.
- A direct preference update requires expected revision, survives restart, and
  takes effect on the next policy decision.
- Any preference revision change invalidates a pending delivery decision; a
  recovery allow uses a newly digested trace, while legacy/empty traces fail
  closed.
- Accept, dismiss, correct, observe, and model-result fixtures leave identity and
  preferences byte-for-byte unchanged unless a separate direct update command is
  present.
- Golden model/outbox/audit fixtures record the policy profile and effective
  bounds without copying private source content.
- Synthetic evaluation traces measure usefulness, restraint, trust, and resilience
  before any profile revision is accepted.

## Revisit when

- sustained user evaluation supports different freshness or interruption bounds;
- a source cannot meet the heartbeat/frequency contract without wasting material
  resources;
- a local model changes cost/deadline constraints;
- a new workflow has different urgency or actionability semantics;
- Phase 3 introduces candidate memory or explicit preference-learning proposals;
  or
- a platform cannot enforce one of the hard ceilings without a semantic port
  change.
