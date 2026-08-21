# 0015: Use the OpenAI Responses API as the first model adapter

Status: Accepted
Date: 2026-08-19

## Context

ADR 0007 permits explicitly configured local and remote model routes but leaves
the first adapter open. Phase 2 needs one real provider-neutral text-reasoning
path to produce either silence or a candidate intervention. The first user
understands that models are used, but that does not authorize a provider, remote
placement, data category, retention profile, fallback, tool, or action.

This selects the concrete adapter required by the
[Phase 0 implementation gate](../phase-0/README.md#implementation-gate), implements
ADR 0007's [approved-route contract](0007-permit-configured-remote-model-routes.md#decision),
and remains inside the accepted [model packet allowlist](../phase-0/trust-and-memory.md#model-packet-allowlist).

The selected API must support a bounded typed response and cancellation. Its
provider handling must be stated accurately: disabling response storage is not
the same as Zero Data Retention and does not remove every provider-side retention
path.

## Decision drivers

- Prove the provider-neutral model gateway with one capable real adapter.
- Require explicit remote-route consent and an exact data-category intersection.
- Obtain a small, machine-validated candidate schema without exposing tools.
- Keep provider credentials, prompts, and raw responses non-durable in CORE.
- Make timeout, refusal, rate-limit, retention, and provider changes fail safely.
- Avoid hidden provider or model fallback.

## Considered options

### Option A: Use only a deterministic fake model

This is necessary for replayable policy tests but does not prove a real model
gateway, credential path, remote handling profile, or provider failure behavior.

### Option B: Require a local model first

This maximizes locality but introduces hardware, packaging, model-distribution,
and quality constraints before a suitable route is known.

### Option C: Use the OpenAI Responses API behind the model gateway

This supplies a real remote inference route with structured outputs while leaving
provider selection outside domain behavior.

## Decision

Adopt option C as the first concrete adapter. This accepts OpenAI only as one
adapter behind the provider-neutral `ModelGateway`; it does not make OpenAI types,
models, SDK objects, identifiers, or error shapes domain contracts.

### Approved route

The user creates a persistent, revocable `ModelRouteApproval` for a named OpenAI
Responses route. It records:

- provider `openai`, account/project profile reference, exact configured model,
  and remote placement;
- exact allowed working-context categories and purpose `reason.focus_context`;
- the handling-profile version and disclosed provider retention/training facts;
- request, token, rate, and cost bounds;
- effective time and optional expiry;
- that no tools, hosted retrieval, background mode, or conversation state is
  enabled; and
- any named fallback. The initial route has no fallback.

Changing provider, project/account profile, model handling capability, placement,
approved data category, retention/training disclosure, or fallback invalidates
the old approval when it broadens or materially changes handling. Model alias
movement cannot silently change an approved exact model identifier; selecting a
new identifier is a route revision.

### Request shape

The adapter calls `/v1/responses` statelessly with `store: false`, no
`previous_response_id` or Conversations object, no background mode, and no tool
definitions. It does not enable web search, file search, code interpreter,
computer use, MCP, hosted shell, image generation, or function tools. The first
slice sends text only; a later bounded-pixel vision route requires a separately
reviewed handling profile and exact pixel approval under ADRs 0007 and 0009.

The request contains only the working-context allowlist intersected with current
session grants and the route approval. Goal and observation values are delimited
as untrusted data. The adapter requests no chain of thought or hidden reasoning
trace.

The response uses the Responses API structured-output JSON Schema with strict
adherence and `additionalProperties: false`. Its closed result is equivalent to:

```text
decision: silence | candidate
candidate_text: bounded string or null
reason_codes: bounded enum list
evidence_references: bounded list of supplied opaque references
uncertainty: bounded enum
```

Every field is required, with `null` used where the supported strict-schema subset
needs an optional value. The exact public type belongs to CORE's model-gateway
contract, not the provider response object.

The model result remains untrusted. CORE rejects extra/invalid fields, unknown
evidence references, tool-shaped output, protocol/permission text, overlong
content, refusal/incomplete output that cannot validate, and any candidate that
does not satisfy the schema. A valid candidate still cannot deliver itself;
deterministic policy and audit run afterward.

### Handling profile

Every approval displays the current provider facts rather than a generic “no
retention” statement. At acceptance time, official OpenAI documentation states
that API data is not used to train models by default unless the customer opts in,
but default abuse-monitoring logs may contain prompts/responses and be retained
for up to 30 days. `store: false` prevents the adapter from intentionally creating
Responses application state; it does not by itself enroll the project in Zero
Data Retention or Modified Abuse Monitoring, remove abuse-monitoring retention,
or eliminate provider prompt-cache handling.

The route approval therefore declares the actual organization/project data
control known to the user: default, Modified Abuse Monitoring, or Zero Data
Retention, plus the applicable prompt-caching behavior. The adapter never claims
ZDR merely because it sent `store: false`. Provider terms and behavior are
versioned handling metadata; if STEIN cannot verify the configured profile or the
profile changes incompatibly, the route becomes unavailable pending review.
The initial default profile is closed as
`openai-responses-default-2026-08`; the desktop consent payload and production
gateway must use that exact identifier, and contract tests fail on drift.

The OpenAI API key is resolved from the Windows Credential Manager adapter in ADR
0013 only for the request. It never reaches React, the client protocol, SQLite,
audit, or retained telemetry.

### Reliability and budgets

The gateway propagates the focus request's deadline and cancellation to the HTTP
operation. It normalizes authentication, permission, rate-limit, quota, timeout,
network, refusal, invalid-output, provider, and cancellation failures without
private response text. Automatic retry is allowed only for a transport-safe,
idempotent attempt within the same deadline and request identity; it cannot
exceed the request/cost bounds in ADR 0017.

No healthy approved route means reasoning capability is degraded and the focus
workflow uses only safe deterministic behavior. It does not switch model,
provider, account, local/remote placement, or data scope automatically.

### Documentation basis

This handling record was checked against official OpenAI documentation on the ADR
date:

- [Data controls in the OpenAI platform](https://developers.openai.com/api/docs/guides/your-data#default-usage-policies-by-endpoint)
- [Structured model outputs](https://developers.openai.com/api/docs/guides/structured-outputs)

Provider documentation is operational input, not an immutable guarantee; route
health and approval review must account for later changes.

## Consequences

- A remote OpenAI route can receive selected goal/context fields only after
  explicit approval for each category.
- The deterministic fake model remains mandatory for replay, race, and failure
  tests; it is not the Phase 2 real-adapter completion proof.
- Network/provider loss reduces reasoning and produces silence rather than a
  hidden fallback or repeated request loop.
- CORE retains only content-free request outcome metadata. It does not persist
  request bodies, raw responses, response IDs, chain of thought, or provider
  credentials.
- CORE keeps only the latest model-request receipt in the active session's
  ephemeral state. Protocol 1.2 exposes that receipt solely through the
  authenticated `GetFocusSessionView` query, and the desktop offers a narrow
  read-only projection. The receipt identifies the request, focus session,
  exact approval and route revision, timestamps, and a closed outcome; it does
  not contain prompt, context, candidate text, provider response/error/status,
  response ID, endpoint, secret reference, or credential state.
- The receipt observes an existing daemon-owned scheduler request. It is not a
  command and does not trigger or retry paid work. It is absent before the
  session's first model boundary and disappears when the ephemeral session ends
  or CORE restarts. Because it is deliberately latest-only, a later
  deterministic pre-model silence does not erase an earlier completed receipt;
  acceptance consumers must baseline the prior request ID/timestamp and require
  a new receipt after the evidence under test.
- Provider retention may exceed CORE's local ephemeral window and is visible in
  consent. A route whose handling is unacceptable can be left unapproved.
- Adding a local adapter or a different provider does not change the agent loop or
  deterministic delivery boundary.

## Validation

- A live synthetic request through the installed daemon and approved route returns
  a strict `silence` or candidate result through the provider-neutral gateway.
- The installed trace polls the read-only authenticated receipt after the
  scheduler runs and accepts only `completed_strict_silence` or
  `completed_strict_candidate` for the exact durable approval ID and revision,
  with a request ID and start time newer than the pre-trigger baseline.
  The ignored adapter-only paid/network probe is useful transport evidence but
  is not installed acceptance evidence because it fabricates its request and
  bypasses durable session/grant/policy authority.
- Golden request fixtures contain only categories allowed by both current grants
  and the exact route approval, at the least sensitive useful granularity.
- The checked-in `phase2-openai-model-contract-v1` fixture binds the exact
  route-permission-context narrowing chain and provider request invariants;
  route, grant, or context category broadening fails before serialization.
- Requests set `store: false`, omit tools, conversations, previous-response state,
  background mode, hosted features, and unapproved media.
- Strict-schema, extra-field, tool-shaped, prompt-injected, unknown-reference,
  refusal, incomplete, and overlong outputs cannot reach intervention delivery.
- Credential, route-profile, provider, placement, model, category, and fallback
  mismatch tests fail before request serialization.
- Timeout, cancellation, offline, authentication, rate-limit, quota, malformed
  response, and provider error fixtures remain silent and emit content-free
  technical outcomes.
- Explicit provider-refusal and HTTP failure fixtures prove that provider text
  and status details never enter the normalized error contract.
- No prompt, raw response, response identifier, credential, or private provider
  error appears in SQLite, logs, audit, protocol, crash output, or evidence.
- Closing the full desktop does not cancel a request owned by an authorized
  daemon workflow; session stop, mute where applicable, grant revocation, route
  revocation, and deadline do cancel it.
- The consent view distinguishes default abuse-monitoring/prompt-cache handling
  from MAM/ZDR and never infers ZDR from `store: false`.

## Revisit when

- official provider handling or API semantics change materially;
- the selected model no longer supports the required strict schema;
- a local model meets quality, latency, and hardware needs;
- provider availability, cost, or policy makes another adapter preferable;
- approved pixel/vision reasoning enters the executable slice; or
- the first slice needs streaming, tools, conversations, or server-side state.
