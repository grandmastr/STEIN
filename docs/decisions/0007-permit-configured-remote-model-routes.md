# 0007: Permit configured remote model routes

Status: Accepted
Date: 2026-08-19

## Context

STEIN is a personal system for a user who understands that language models are
part of its operation. Requiring local-only inference would constrain model
quality and hardware support. Repeating a generic remote-model warning for every
focus session would add friction without improving informed control.

Remote inference still means selected personal context can leave the device and
be handled under a provider's service, retention, and training terms. CORE must
not hide that data flow or silently switch routes.

## Decision drivers

- Permit capable remote inference for the first useful slice.
- Avoid repetitive consent prompts when provider and data scope are unchanged.
- Preserve provider neutrality and local-model support.
- Minimize the context that leaves the device.
- Make route changes, fallback, retention claims, and failures visible.
- Keep model output outside the authority boundary.

## Considered options

### Option A: Require local-only inference

All model requests execute on the user's device.

Benefits:

- strongest data locality; and
- network or provider loss does not affect inference when local capacity exists.

Costs and failure modes:

- model quality, latency, memory, and hardware requirements may prevent a useful
  first slice; and
- “local” still needs model provenance, storage, and process isolation decisions.

### Option B: Ask for remote-processing consent on every request or session

Show a confirmation each time context may reach a remote provider.

Benefits:

- maximum moment-to-moment visibility; and
- easy denial for one sensitive session.

Costs and failure modes:

- repetitive prompts become habituated noise;
- reasoning cannot continue without a presentation client; and
- confirmation fatigue undermines meaningful consent.

### Option C: Use persistent, explicit model-route configuration

The user configures approved local or remote routes and the data categories each
may receive. Workflows use an approved route without repeating the same warning,
while changes require review.

Benefits:

- informed control without session friction;
- daemon reasoning can continue without a presentation client;
- provider replacement remains explicit; and
- data minimization can be enforced mechanically.

Costs and failure modes:

- configuration can become stale relative to provider terms;
- users may forget which route is active; and
- a broad route approval could become ambient authority unless data categories
  remain narrow.

## Decision

Permit local and remote model routes through the provider-neutral model gateway.
Use a persistent, revocable `ModelRouteApproval` rather than a generic per-session
warning.

An approval identifies:

- provider, account/profile, model route, and local or remote placement;
- allowed working-context data categories;
- known provider retention and training behavior;
- purpose, budget, effective time, and optional expiry;
- whether automatic fallback is allowed and to which named route; and
- the disclosure version acknowledged by the user.

A focus workflow references an approved route and still performs a current
policy check before every request. It does not need a repeated prompt while the
provider, placement, allowed data categories, and handling terms remain within
the approval. Adding a category, changing provider/placement, broadening
retention, or enabling a new fallback requires renewed review.

There is no hidden local-to-remote or provider-to-provider fallback. When no
approved route is available, CORE reports degraded reasoning capability and uses
only deterministic behavior that is safe without a model.

The first slice's remote packet remains limited to the allowlist in the Phase 0
trust rules. Under ADR 0009, window metadata, browser location, visible text,
selected-document content, or bounded pixels may reach a route only when the
active session grant and `ModelRouteApproval` both name that exact category.
Unapproved source data, credentials, unrelated history, and audit records do not
reach the model route.

## Consequences

- Selected goal text, success criteria, deadlines, context aggregates, and only
  explicitly approved rich observation categories may leave the device when an
  approved remote route is used.
- Provider-side retention and training behavior cannot be controlled by CORE
  beyond the configured service contract; the UI must state what is known rather
  than claim “no retention” generically.
- Model credentials belong to the daemon's approved secret provider and never to
  React or protocol payloads.
- Route identity and content-free request outcomes are auditable; prompts and raw
  responses remain non-durable in CORE.
- A local route can be added or selected later without changing domain behavior.
- The specific first provider adapter remains an implementation choice and must
  declare its capabilities and handling profile before use.

## Validation

- A remote route cannot receive a data category outside its approval.
- Provider, placement, retention profile, or fallback changes invalidate the
  prior approval when they broaden data handling.
- No approved/healthy route produces deterministic degraded behavior rather than
  a hidden fallback or repeated model calls.
- Golden model packets contain only allowlisted fields.
- Logs, errors, audit, and protocol views contain no provider credential or raw
  prompt/response.
- Closing the desktop does not interrupt requests already permitted by an active
  route approval and workflow grant.

## Revisit when

- provider terms or APIs prevent accurate handling disclosure;
- a local route meets quality and latency needs well enough to become the default;
- a new data category materially increases sensitivity;
- multiple users require different provider accounts or approvals; or
- regulatory or contractual requirements constrain remote processing.
