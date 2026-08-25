# 0009: Use tiered rich desktop observation

Status: Accepted
Date: 2026-08-19

## Context

The first useful STEIN loop needs more than application-presence and coarse
workspace activity. It should be able to understand, when the user permits it,
the title and location of the active work and enough visible or selected content
to distinguish progress, research, and likely deadline risk.

That capability is substantially more sensitive than an application identifier.
A title can expose a private subject, a URL can contain identifiers or query
values, document text can contain secrets, and continuous screen capture can
collect unrelated people and applications. The native mechanisms also differ on
Windows, Linux, and macOS even though CORE needs one portable meaning for the
result.

## Decision drivers

- Give STEIN enough context to be useful rather than merely measuring activity.
- Keep each sensitive source visible, independently revocable, and bounded to a
  selected workflow and resource.
- Prefer structured, minimal data over indiscriminate image capture.
- Prevent raw capture from becoming activity history, diagnostics, or implicit
  memory.
- Make remote model data flow explicit without repeating unchanged disclosures.
- Implement Windows first without putting Windows types in domain contracts.

## Considered options

### Option A: Retain only coarse activity signals

Observe presence, application identity, and selected-workspace changes without
titles, locations, or content.

Benefits:

- smallest privacy and implementation surface; and
- simple model packets and retention behavior.

Costs and failure modes:

- activity is weak evidence of progress or relevance;
- STEIN cannot distinguish writing from an idle open editor; and
- research in a browser or work in an unsaved document is easily misclassified.

### Option B: Use one blanket screen-observation permission

Continuously capture the desktop and let a vision model derive all context.

Benefits:

- broad application coverage; and
- one apparent integration path.

Costs and failure modes:

- collects unrelated applications, notifications, credentials, and bystanders;
- makes source selection and data minimization difficult to verify;
- incurs avoidable model, bandwidth, and processing cost; and
- encourages retention of frames for debugging or replay.

### Option C: Use tiered structured observation with pixel capture as a fallback

Expose independent semantic scopes for metadata, browser location, structured
content, and pixels. Prefer browser, application, document, and accessibility
integrations; use a narrowly bounded image source only where structured data is
unavailable or visual meaning is required.

Benefits:

- rich enough to understand selected work;
- lets the user grant only the sources a workflow needs;
- reduces unnecessary pixel capture and improves provenance; and
- preserves a portable CORE contract across native implementations.

Costs and failure modes:

- requires more than one adapter strategy;
- platform and application capability differences must be surfaced; and
- scope, redaction, and source-health behavior require careful testing.

## Decision

Adopt option C. STEIN supports rich desktop observation through separate,
revocable semantic scopes for:

- user presence and lock state;
- foreground application identity;
- window and selected-document metadata, including titles;
- browser location, with origin, path, query, and fragment granularity minimized
  independently;
- visible structured text from a selected application, browser surface, or
  accessibility tree;
- content from an explicitly selected document or workspace resource; and
- screen pixels from an explicitly selected application, window, region, or
  display when a structured source is insufficient.

A focus session requests only the scopes and selected resources it needs. A
grant for application identity does not authorize titles; a title grant does not
authorize a URL; a text grant does not authorize pixels. Scope indicators and an
emergency stop remain available when the full desktop client is closed. Lock,
user switch, loss of that control surface, revocation, or inability to honor the
selected boundary pauses the affected source and fails closed.

Adapters use this preference order where it can satisfy the workflow:

1. explicit application, document, or browser integration;
2. structured operating-system accessibility or UI metadata;
3. local extraction or redaction from a bounded capture; and
4. an approved vision route over a bounded capture.

Pixel capture is not a universal fallback that silently activates. It requires
its own current grant and, when a model receives pixels, a matching
`ModelRouteApproval` data category. The same rule applies to window titles,
browser locations, visible text, and document content: a remote route may
receive a category only when both the session grant and route approval name it.
Knowing that STEIN uses language models is not treated as permission to broaden
the approved data categories or change providers silently.

Raw source artifacts include screen frames, accessibility/UI trees before
normalization, and full source payloads read only to extract an approved subset.
They remain inside adapter-controlled transient processing except while being
streamed through the single-use handle of an explicitly approved model request.
CORE never persists them, and the adapter discards them immediately after
normalization or that request. They cannot enter audit, telemetry, the
intervention outbox, client events, or durable memory. Normalized rich
observations and derived working context follow ADR 0005's bounded ephemeral
lifecycle.

Credentials, password fields, protected or secure desktop surfaces, system
consent dialogs, and sources outside the selected resource are excluded. If an
adapter cannot reliably identify or redact such a surface, the affected rich
scope reports unavailable rather than capturing it. Keyboard input, clipboard
contents, microphone, and camera data remain separate capabilities and are not
authorized by this decision.

The observation contract is platform-neutral. Windows receives the first native
adapters and acceptance suite. Linux and macOS implement the same semantic
scopes and truthfully report capability or granularity differences; neither is
required to imitate a Windows API.

This decision refines ADR 0005 by distinguishing transient source artifacts from
normalized ephemeral observations. It also amends ADR 0007's first-slice packet:
approved rich categories may reach a configured model route, while unapproved
raw or rich data remains excluded.

## Consequences

- The first slice can reason about selected work rather than infer intent from
  application dwell time alone.
- Consent and capture state need a per-source view, not a single “screen access”
  toggle.
- CORE contracts carry source category, selected-resource provenance,
  sensitivity, transformation, freshness, and retention metadata.
- Raw pixel or source payloads do not travel on the general event bus or client
  protocol; adapters expose short-lived processing handles where necessary.
- Browser and document integrations can be added independently behind the same
  semantic observation ports.
- A remote reasoning route may be useful with coarse data yet unavailable for a
  richer session because its approval lacks the required categories.
- Synthetic rich-content fixtures are required; captured user content cannot be
  checked into source control or ordinary test artifacts.

## Validation

- Contract tests prove each scope can be granted and revoked independently and
  that a broader observation is rejected under a narrower grant.
- Windows fixtures cover selected window, browser, document, lock, user-switch,
  protected-field, revocation, stale-source, and control-surface-loss behavior.
- Process and repository inspection finds no raw frames, source payloads, titles,
  URLs, or document text in logs, audit, outbox, or durable observation storage.
- Golden model requests contain only categories allowed by both the session
  grants and the selected `ModelRouteApproval`.
- A structured source is chosen ahead of pixel capture when both can meet the
  declared workflow requirement.
- The complete semantic fixture runs against fake platform adapters, followed by
  equivalent Linux and macOS native suites before those platforms are called
  supported.

## Revisit when

- a useful workflow cannot be expressed through the tiered scopes;
- a platform cannot expose required source or protected-surface boundaries;
- sustained use shows that pixel capture is either unnecessary or needs process
  isolation;
- guest, shared-screen, multi-user, or regulated-data use is introduced; or
- rich observations are proposed for durable memory or retrospective replay.
