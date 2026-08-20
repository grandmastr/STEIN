# 0008: Queue interventions when channels are unavailable

Status: Accepted
Date: 2026-08-19

## Context

The CORE daemon can use a native Windows notification channel while the full
desktop client is closed. A channel can still be unavailable because the user is
logged out or locked, notification permission is revoked, the native adapter is
unhealthy, or no suitable presentation is connected.

Dropping every intervention would hide potentially useful reasoning. Delivering
old notifications blindly when a channel returns would interrupt the user with
stale or unsafe advice.

## Decision drivers

- Preserve useful interventions across temporary channel outages.
- Never claim queued, OS-accepted, displayed, and seen are the same outcome.
- Revalidate relevance, authority, privacy, and timing before delayed delivery.
- Avoid duplicate or burst delivery after recovery.
- Keep cached delivery data minimal and bounded.
- Surface missed interventions without presenting stale advice as current.

## Considered options

### Option A: Drop when no channel is available

Record a failed outcome and discard candidate content.

Benefits:

- simplest lifecycle and smallest retention surface; and
- no stale notifications.

Costs and failure modes:

- transient channel loss discards useful work; and
- the user cannot see what STEIN attempted to surface.

### Option B: Queue and deliver automatically without revalidation

Persist every allowed notification and send it when any channel returns.

Benefits:

- messages are rarely lost; and
- simple outbox behavior.

Costs and failure modes:

- deadlines, goals, permissions, context, and user interruptibility may have
  changed;
- recovery can produce a notification burst; and
- sensitive content could move to a newly available but unsuitable channel.

### Option C: Use a durable, bounded outbox with revalidation

Cache the minimum delivery record, then run current policy again when a suitable
channel becomes healthy. Deliver valid items; convert stale items into
non-interruptive missed history.

Benefits:

- preserves value without treating old policy as permanent authority;
- supports daemon restart and channel recovery; and
- produces truthful delivery and missed-history state.

Costs and failure modes:

- requires durable outbox, expiry, deduplication, channel health, and recovery
  behavior; and
- “seen” may remain unknowable for native notifications.

## Decision

Use a durable, bounded intervention outbox with delivery-time revalidation.

When no currently authorized and healthy channel can deliver an allowed
intervention, store a `PendingInterventionDelivery` containing only:

- intervention and candidate revision identifiers;
- exact proposed user-visible text;
- structured reason and urgency;
- policy and grant references;
- sensitivity and permitted channel classes;
- created, not-before, and expiry times;
- deduplication/idempotency identity; and
- current delivery-attempt state.

Do not cache source artifacts, normalized observation payloads, model
prompts/responses, file data, or chain of thought in the outbox.

When a channel becomes available, CORE re-evaluates:

- current goal/session state and candidate relevance;
- permission, model-route, policy-profile, and exact user-preference revisions;
- expiry, novelty, urgency, cooldown, and recent intervention load;
- user presence, lock state, and channel suitability; and
- deduplication and prior delivery acknowledgements.

If still valid, CORE delivers the item. If no longer valid, it marks it expired or
cancelled and includes a non-interruptive missed-intervention entry in the next
authorized history/snapshot view. A stale focus warning is not replayed as a
current notification merely to satisfy “eventual delivery.”

The queued decision's content-free policy trace must be complete and must match
the current profile and preference revision before its cached proposal can be
reconsidered. A preference revision change invalidates the cached proposal even
when the new preference would otherwise be equally permissive, because the
stored text was proposed under different exact inputs. A successful recovery
evaluation writes a fresh trace/digest and correlated audit before delivery.

For deadline-sensitive focus interventions, expiry cannot exceed the focus
session or the point at which the proposed advice stops being actionable. Policy
may choose a shorter lifetime.

Queue state is:

```text
queued -> delivering -> accepted_by_channel
      |             -> delivery_unknown
      |             -> delivery_failed
      +------------ -> expired
      +------------ -> cancelled
```

`accepted_by_channel` means the operating system or client acknowledged the
request. It does not mean displayed or seen. Retries after ambiguous delivery
require a new policy decision and must not create notification spam.

Revocation, session end, goal deletion, global proactive disable/mute, or
session mute cancels affected queued items immediately. The same direct-user
transition cancels the separate proactive model/delivery token before the
durable revision changes; it does not cancel the session's observation token.
Private outbox and intervention text is scrubbed before the command returns and
follows user deletion commands.

## Consequences

- Native Windows notifications can be sent while the Tauri client is closed.
- The daemon needs a channel registry, health events, durable outbox repository,
  delivery idempotency, bounded recovery, and missed-history view.
- Undelivered candidate text is a narrow exception to the otherwise ephemeral
  candidate rule in ADR 0005; it persists only until delivery, cancellation, or
  bounded expiry.
- A reconnecting client may show missed interventions without generating a burst
  of old native notifications.
- Do-not-disturb or OS notification suppression may only yield
  `accepted_by_channel`; STEIN must not infer that the user saw the message.
- Channel recovery is an input to policy, not permission to drain the queue
  blindly.

## Validation

- Close the Tauri client and prove a healthy native Windows channel can receive a
  permitted notification directly from the daemon.
- Make every channel unavailable, queue one item, restore a channel before
  expiry, and prove policy revalidates before exactly one delivery attempt.
- Restore a channel after relevance or expiry changes and prove the item appears
  only as non-interruptive missed history.
- Revoke permission, mute, end the session, and delete the goal while items are
  queued; each operation cancels and removes affected private content.
- Restart CORE with queued items and prove bounded recovery does not duplicate an
  acknowledged or ambiguous delivery.
- Force a channel acknowledgement without a seen receipt and prove the audit
  reports only `accepted_by_channel`.
- Golden outbox fixtures contain none of the prohibited raw evidence or model
  fields.

## Revisit when

- a channel supplies reliable displayed or seen receipts;
- cross-device delivery requires shared queue ownership;
- voice or safety-critical intervention needs different expiry semantics;
- user studies prefer a different missed-history experience; or
- queue volume or privacy risk requires stricter caps.
