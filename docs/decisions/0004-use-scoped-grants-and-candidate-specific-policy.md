# 0004: Use scoped grants and candidate-specific policy decisions

Status: Accepted
Date: 2026-08-19

## Context

The first slice observes selected desktop signals, may send a bounded context to
a model, and may proactively deliver a native desktop notification while no full
presentation client is connected. Capability availability, user consent, model
proposals, and authority to deliver are different facts.

Prompt instructions alone cannot enforce permissions. A coarse role or global
“assistant enabled” switch cannot express device, resource, purpose, data
placement, channel, or expiry and would make revocation ambiguous.

## Decision drivers

- Preserve user authority outside model prompts.
- Make capture, processing, and proactive delivery independently revocable.
- Bind authority to one user, device, purpose, resource, and time range.
- Fail closed during stale state, races, restart, and policy failure.
- Provide an inspectable reason for allow, deny, or confirmation decisions.
- Extend later to tools without granting the first slice action authority.

## Considered options

### Option A: Prompt rules and UI settings

Tell the model what it may do and keep enable/disable state in the client.

Benefits:

- very little policy infrastructure; and
- simple user interface.

Costs and failure modes:

- model errors or prompt injection can bypass intent;
- client state is not authoritative for adapters or CORE;
- resource and time scope are unclear; and
- decisions and revocation races are difficult to audit.

### Option B: Coarse roles or global capability switches

Assign a user or STEIN a role such as observer/adviser/operator and enable each
capability globally.

Benefits:

- familiar authorization implementation; and
- fewer records than per-use grants.

Costs and failure modes:

- ambient authority exceeds the first slice's needs;
- a capability switch cannot express why, where, how, or for how long data is
  used; and
- adding tools would silently broaden existing roles.

### Option C: Scoped permission grants plus contextual policy decisions

Represent consent as revocable grants. For each consequential candidate, resolve
current grants and deterministic policy into allow, deny, or require-confirmation
for that exact candidate and context.

Benefits:

- least authority and precise revocation;
- availability remains separate from consent;
- models cannot mint or extend authority; and
- decisions are explainable and auditable.

Costs and failure modes:

- more domain modeling and UI state;
- grant lifecycle and race behavior need careful tests; and
- over-granular scopes could overwhelm the user.

## Decision

Use scoped permission grants and candidate-specific policy decisions.

### Grants

A grant contains a typed capability scope, issuing actor, target user/device,
selected resource where relevant, purpose, constraints, effective/expiry times,
consent-copy version, and revision. Persistent `ModelRouteApproval` records also
bind permitted data categories and the declared local or remote route under ADR
0007.

Capability discovery reports what can technically run. It does not create or
imply a grant.

The first slice creates independent focus-session-scoped grants for presence,
foreground-application identity, window metadata, browser location, visible text,
selected-document content, bounded pixels, selected-workspace activity, and
native desktop notification. ADR 0009 defines the rich-observation distinctions:
no narrower category implies a broader one, and every selected resource remains
part of authority resolution. Each session grant states whether client disconnect
and supervised daemon restart are permitted. Focus-context reasoning references
a persistent, revocable model-route approval and does not repeat an unchanged
provider disclosure for every session. The slice creates no external tool or
action grant.

CORE validates the resource kind when it creates the grant, rather than waiting
for a platform adapter to reject it later. Foreground-application, selected
window metadata, browser location, selected-document, selected-workspace, and
bounded-pixel grants require `Application`, `Window`, `BrowserSurface`,
`Document`, `Workspace`, and `ScreenRegion` resources, respectively. Visible
text accepts either a selected `Window` for UI Automation or a selected
`BrowserSurface` for the browser producer. Presence, reasoning, and notification
grants have no selected resource. A mismatched kind creates no grant or audit
authority.

### Policy decisions

A policy decision is `allow`, `deny`, or `require_confirmation` and is bound to:

- the exact proposed operation and input digest/revision;
- authenticated actor and initiator;
- all resolved grant revisions;
- resource and delivery channel;
- relevant context and policy version;
- issue and expiry times; and
- structured reason codes.

The focus slice normally uses `allow` or `deny` after the user has granted the
session's proactive channel. `require_confirmation` is defined now for contract
completeness but does not let a model execute anything: confirmation creates a
new user-authorized decision for the same candidate, subject to revalidation.

A decision reference is not a bearer secret. The action boundary loads it from
the policy owner and verifies candidate, grant, context, channel, and expiry
again immediately before the consequential operation.

Each deterministic significance evaluation and candidate-specific intervention
decision also records a content-free `PolicyTrace`: the exact versioned policy
profile, the effective `UserPreferencesV1` revision, the canonical policy-input
schema version, and a SHA-256 digest of that exact typed input projection. The
projection may contain private candidate/context values only transiently while
the digest is calculated; neither it nor those values enter policy or audit
storage. The correlated policy audit carries the same trace. A legacy record
whose trace is absent/defaulted remains readable for migration compatibility but
cannot authorize delivery.

The final delivery check requires the current policy-profile and preference,
model-route, and grant revisions to equal the decision references. Any mismatch
fails closed. A recovered outbox item receives a new decision and digest only
after current inputs are revalidated; it never inherits an old trace as fresh
authority.

### Direct user actions

An authenticated user's explicit goal edits, feedback, mute, stop, grant, and
revoke commands are distinguished from model- or system-initiated candidates.
They still pass validation and ownership checks, but the application does not
pretend a model suggestion is a direct user command because the UI displayed it.

### Revocation

Revocation atomically makes future authority resolution fail, then propagates
cancellation and cleanup. Queued events and candidates keep their historical
grant reference but cannot use it. Client restart or disconnect has no authority
effect. Daemon restart recovers only unexpired grants whose consent explicitly
permits restart continuity, and it revalidates them before restarting adapters.

When revocation races with delivery, the last pre-delivery authority check is the
decision point. Native delivery acknowledged before revocation is recorded as
delivered; otherwise revocation wins and delivery is denied or cancelled.

### Enforcement and audit

Every observation start, model request, proactive delivery, and future external
action has a code-level action boundary that resolves current authority. Provider
and adapter code cannot call around it.

An allowed intervention whose channel is unavailable may enter the bounded
outbox defined by ADR 0008. Channel recovery does not preserve the old allow
decision indefinitely; policy is evaluated again before delivery.

Permission creation/revocation and proactive decisions/outcomes produce
privacy-aware audit records. Audit failure prevents a proactive operation when
the Phase 0 trust rules require a record before delivery.

## Consequences

- Identity and permissions become a real domain owner rather than UI settings.
- Presentation clients and the independent native background surface must display
  capture and delivery grants separately and synchronize from authoritative CORE
  views.
- Every relevant adapter call receives resolved constraints, cancellation, and
  an authority reference.
- Policy stays deterministic at the delivery boundary even when a model helps
  estimate significance or wording.
- Future tools can reuse the decision shape, but each tool still needs a declared
  schema, risk, effects, and explicit grant; this ADR grants none by default.
- Confirmation UX and scope design must avoid repetitive consent fatigue.

## Validation

- A matrix test exercises missing, mismatched, expired, revoked, and superseded
  grants for every protected operation.
- Client disconnect tests prove grants neither disappear nor broaden and that a
  reconnect obtains authoritative daemon state.
- Deterministic race tests show revocation and cancellation beat unacknowledged
  delivery.
- Daemon restart tests recover only unexpired, restart-authorized grants, reset
  source health, and reject all other prior grants.
- Prompt injection, tool-shaped model output, client-crafted events, and copied
  decision references cannot create authority.
- Explanation fixtures identify the scopes and reason codes used without
  exposing tokens or unnecessary private data.
- Golden policy/audit fixtures match the exact policy trace, change digest when
  an input changes, and contain no unhashed private policy input.
- Removing any required audit acknowledgement fails closed for proactive
  delivery.

## Revisit when

- repeated user studies show that scope granularity is incomprehensible;
- multiple users, administrators, or devices require delegation and grant
  propagation;
- offline devices require signed, cached authority;
- an external tool introduces risk, reversibility, and confirmation classes; or
- policy evaluation needs hardened isolation from the main runtime.
