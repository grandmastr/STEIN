# Trust, Permission, and Minimum Memory Rules

Status: Accepted for implementation

These rules apply only to the
[deadline-aware focus session](vertical-slice.md). They turn the product's trust
principles into testable behavior without defining a complete future permission
or memory system.

## Trust stance

- The local user is the ultimate authority for observation, model data flow,
  proactive delivery, retention, correction, and deletion.
- A configured capability is unavailable to a workflow until the workflow also
  has a current permission grant for its exact use.
- Models, provider responses, adapter inputs, client payloads, and observation
  values are untrusted data.
- Presentation availability is not authority state. A client disconnect neither
  grants new power nor revokes an existing daemon-owned workflow.
- Absence of evidence is not evidence of inactivity when a source is incomplete,
  stale, unhealthy, paused, or revoked.
- The first slice has no external-action authority. No combination of model
  output, events, or permissions can create a tool that is not in the slice.
- Auditability is a precondition for proactive delivery, not permission to retain
  raw private observations.

## Supported authority context

The first slice supports one authenticated local user, one non-elevated per-user
CORE daemon, and one local device. Each presentation client authenticates through
the protected local transport. CORE binds commands to the peer identity it
establishes; an actor claimed in a client payload is never authentication.

Grants belong to the user and daemon-owned workflow, not to the lifetime of the
client that requested them. Client identity remains in provenance so the user can
see where a request originated.

The slice does not claim to distinguish the user from another person using the
same unlocked operating-system account. It pauses observation and delivery when
the session is locked or switched and clearly documents the shared-account
limitation. Guest detection beyond those signals belongs to a later slice.

## Permission scopes

Permission names below are the canonical first-slice semantic identifiers. Their
wire representation follows the typed client-protocol compatibility rules.

| Scope | Allows | Required restrictions |
| --- | --- | --- |
| `observe.desktop.presence` | Receive active, idle, and locked state | Device and focus session; no input content |
| `observe.desktop.foreground_application` | Receive the stable identifier of the foreground application | Device, focus session, and selected application set; no title or URL |
| `observe.desktop.window_metadata` | Receive title and non-content metadata for a selected window or document | Device, focus session, selected application/window, and no content or browser location |
| `observe.browser.location` | Receive a selected browser surface's location | Device, focus session, selected browser/profile/site; minimize origin, path, query, and fragment independently |
| `observe.content.visible_text` | Receive visible structured text from a selected application, browser surface, or accessibility tree | Device, focus session, selected surface, local sensitive-field filtering, and bounded payload |
| `observe.content.selected_document` | Receive content from an explicitly selected document or workspace resource | Device, focus session, exact opaque resource binding, local redaction, and bounded payload |
| `observe.screen.pixels` | Process bounded pixels from a selected application, window, region, or display | Device, focus session, exact surface, visible capture state, transient handling, and no protected surface |
| `observe.workspace.activity` | Receive coarse activity signals for one selected workspace | Opaque workspace reference, focus session, no path or content |
| `reason.focus_context` | Send an allowlisted working-context packet to one configured model route | Current `ModelRouteApproval`, provider/placement, data categories, purpose, budget, and optional expiry |
| `intervene.desktop.notification` | Deliver policy-approved native notifications while the session is active | Device, focus session, independently available native channel, rate limits, and expiry |

Every grant records:

- grant identifier and revision;
- issuing user and authenticated client;
- device and optional selected resource;
- purpose and scope;
- model route or data-placement restriction when relevant;
- whether client disconnect and supervised daemon restart are permitted;
- issued, effective, and expiry times;
- revocation state and reason;
- sensitivity and retention classification; and
- the consent copy version displayed to the user.

Observation and intervention grants are focus-session-scoped for the first slice.
A `ModelRouteApproval` persists until expiry, change, or revocation and can cover
multiple sessions without repeating the same disclosure. Closing or restarting a
desktop client changes neither kind. After supervised daemon restart, CORE may
recover only an unexpired session grant whose displayed consent explicitly
permitted restart continuity; recovery revalidates every restriction and never
extends its expiry.

## Consent presentation

Before a session grant or model-route approval is created, the client shows:

- what signal or data category will be used;
- the selected device, workspace, application scope, or model route;
- why the focus workflow needs it;
- whether any data can leave the device;
- when the grant expires;
- whether the workflow continues without the desktop client and after supervised
  daemon restart;
- what is retained after the session; and
- how to mute delivery, stop capture, revoke the grant, and delete retained
  records.

Consent is not bundled into general terms or inferred from installing the
application. Each rich-observation category is independent: application identity
does not imply a title, a title does not imply a URL, visible text does not imply
selected-document access, and none implies pixels. The user can mute
intervention delivery without obscuring whether observation remains active.
Capture state lists active categories and selected resources, and stop control
remains available through an independent native surface when the full client is
closed.

## Authority matrix

| Operation | Required authority | Additional policy |
| --- | --- | --- |
| Create, edit, complete, or abandon a goal | Direct authenticated user command | Expected-revision check |
| Start presence observation | Current `observe.desktop.presence` grant | Healthy source and active focus session |
| Start foreground-application observation | Current `observe.desktop.foreground_application` grant | Healthy source and explicit scope indicator |
| Start window-metadata observation | Current `observe.desktop.window_metadata` grant | Healthy source and exact selected application/window match |
| Start browser-location observation | Current `observe.browser.location` grant | Healthy explicit integration, selected browser/profile/site, and approved URL granularity |
| Start visible-text observation | Current `observe.content.visible_text` grant | Healthy structured source, exact selected surface, sensitive-field filter, and payload bound |
| Read selected-document content | Current `observe.content.selected_document` grant | Healthy source, exact opaque resource match, redaction, and payload bound |
| Process bounded screen pixels | Current `observe.screen.pixels` grant | Exact selected surface, visible status/stop path, protected-surface exclusion, and transient lifecycle |
| Start workspace observation | Current `observe.workspace.activity` grant for the selected workspace | Healthy source and exact resource match |
| Send a context packet to a model | Current `ModelRouteApproval` carrying `reason.focus_context` for the selected route | Data allowlist, purpose, budget, source freshness, handling-profile match, and cancellation |
| Propose an intervention | Application orchestration; no delivery authority | Candidate schema and confidence validation |
| Deliver a native desktop notification | Current `intervene.desktop.notification` grant plus candidate-specific allow decision | Native channel health, presence, unlock state, freshness, rate limit, audit acknowledgement, and cancellation check |
| Change the goal after an intervention | New direct user command | The model or delivery event cannot submit it |
| Invoke an external tool | Impossible in this slice | No tool registry entries or permission scope exist |

## Revocation and cancellation

Revocation is effective when CORE accepts the direct user command, not when a
background component eventually notices an event.

The command may arrive from the full desktop client or an authenticated native
emergency-control surface. Closing a presentation client is not a revocation
command.

For an observation grant, the permission owner:

1. marks the grant revoked atomically;
2. makes subsequent authority checks fail;
3. cancels the source through the focus workflow;
4. rejects in-flight and late observations carrying the grant;
5. removes observation-derived ephemeral data for that scope; and
6. reports stopped, degraded, or failed state truthfully to connected clients
   and the background status surface.

For an intervention grant, pending candidates and delivery operations are
cancelled, including durable outbox entries. Revoking a model-route approval
cancels in-flight requests and invalidates undelivered candidates bound to that
approval. If native delivery has already acknowledged success, the record shows
that delivery won the race; the system must not claim it was prevented.

If cleanup or adapter shutdown fails, authority remains revoked and connected
clients plus the native status surface show the cleanup failure. The system does
not restore permission to make its state look healthy.

## Data minimization

### Model packet allowlist

The agent loop may include only:

- goal identifier, title, success statement, deadline, state, and revision;
- focus-session identifier and elapsed time;
- coarse evidence aggregates and their source freshness/confidence;
- bounded, redacted window/document metadata, browser locations, visible text,
  selected-document excerpts or structure, and pixels only when both the source
  grant and selected model-route approval name the exact category;
- session-scoped application relevance associations;
- recent intervention count and last outcome category;
- current delivery constraints; and
- an explicit output schema asking for silence or one candidate intervention.

The packet excludes:

- observation categories or resources outside the current session grants;
- rich categories outside the selected model-route approval;
- full paths, URL query/fragment values, source payloads, or pixels when a less
  sensitive representation satisfies the declared purpose;
- keyboard, clipboard, pointer, credential-field, protected-surface, microphone,
  camera, and unrelated application data;
- permission tokens, credentials, secrets, and local database identifiers;
- unrelated goals, conversations, memories, or user-model claims;
- audit history beyond the minimum aggregate needed for rate limiting; and
- hidden instructions embedded in application identifiers or other adapter
  values.

Goal text and every observation value are encoded as delimited, untrusted data
fields. Instructions found in a document, page, title, URL, or pixel-derived
text have no authority. Provider output is validated against the candidate
schema; text that resembles a command, permission, tool call, or protocol
message has no authority.

### Provider handling

The model gateway declares whether a route is local or remote, which data leaves
the device, and the provider's retention/training behavior known to the adapter.
A request is denied if those properties do not satisfy the current
`ModelRouteApproval`. An unchanged approved route does not require a repeated
session prompt. Provider-side retention cannot be represented as “none” unless
the configured service contract and adapter behavior support that claim. CORE
never falls back to a different local/remote route unless that named fallback is
also approved.

## Slice-local data classes and retention

These labels and durations are accepted first-slice defaults under ADRs 0005 and
0009. They remain explicit configuration so evaluation can test alternatives.

| Record | Handling | Lifecycle |
| --- | --- | --- |
| Goal | Personal domain state | Retain until the user deletes it; completion alone does not delete it |
| Active permission grant | Restricted authority state | Retain while effective; on expiry/revocation keep only the minimal audit fields described below |
| Model-route approval | Restricted processing authority | Retain until changed, expired, or revoked; store provider/placement and handling metadata but no credential in the approval record |
| Focus-session continuity state | Restricted workflow state | Retain until session end; contains lifecycle, grant references, and recovery metadata but no raw observation or model content |
| Selected-resource binding | Restricted local adapter state | Memory-only unless restart continuity is granted; if persisted, keep access-controlled in CORE and remove at session end or revocation |
| Raw source artifact | Highly sensitive transient processing | Adapter memory only; discard immediately after normalization or one approved request, and immediately on lock, stop, session end, or revocation; never persist or publish on the general event/client protocol |
| Normalized observation | Sensitive ephemeral evidence | Memory-only bounded buffer; remove after ten minutes, session end, or relevant revocation, whichever occurs first |
| Derived working context | Sensitive ephemeral evidence | Memory-only; remove at session end or relevant revocation |
| Model request and raw response | Sensitive transient processing | Do not persist in CORE; provider handling is constrained and disclosed by the route grant |
| Intervention candidate not delivered or queued | Sensitive ephemeral decision data | Remove at session end unless ADR 0008 permits a minimal pending-delivery record; then remove on delivery, cancellation, or bounded expiry |
| Pending intervention delivery | Personal bounded outbox data | Persist exact user-visible text and delivery metadata only until delivery, cancellation, relevance expiry, or user deletion |
| Delivered intervention and explanation record | Personal audit data | Retain for thirty days by default or until user deletion, whichever comes first |
| Permission decision record | Restricted audit data | Retain for thirty days by default or until user deletion, whichever comes first |
| Operational telemetry | Content-free operational data | No goal text, observation values, prompts, or intervention text; lifecycle set by deployment configuration |

The ten-minute and thirty-day values are hypotheses rather than claims about user
preference. They remain configurable and visible in evaluation fixtures; a
future change to durable observation or personal memory still requires a new
decision.

The last-observed time and coarse aggregates may outlive the ten-minute
normalized-observation buffer while the focus session is active. They remain
derived working context, retain provenance references, and are deleted with the
session.

Daemon restart deliberately loses source artifacts, normalized observations, and
derived working context. Recovery restores only the workflow and permitted
resource bindings, resets source health to unknown, and rebuilds context from
fresh observations.

The outbox is not memory and cannot be queried as context. When a queued item is
no longer actionable, its private delivery text expires; a minimal missed-history
view may remain under the intervention audit lifecycle.

## Minimum memory behavior

“Memory” in the durable personal sense is out of scope. The slice enforces these
negative guarantees:

- observations do not become memories;
- model statements do not become memories;
- intervention acceptance does not become a preference;
- a correction updates current context but does not rewrite identity or the user
  model; and
- no embedding or provider-managed vector store receives slice data.

If the UI later offers “remember this,” it must create a visible candidate memory
with provenance, sensitivity, retention, and correction controls. That is a new
workflow, not an extension of intervention feedback.

## Provenance

Every accepted observation records, while it exists:

- source and device identity;
- source event identity;
- authorizing grant identifier and revision;
- observed and received times;
- normalization schema version;
- selected-resource scope plus applied extraction and redaction version;
- confidence or completeness where meaningful;
- sensitivity and retention class; and
- focus-session association.

Derived context records the input references and derivation version that support
it. If supporting evidence expires, Context may retain a coarse derived value
only until the session ends and must still be able to say which source category
and time range supported it. It must not invent more precise provenance than is
available.

## Audit semantics

The audit record for an intervention contains only what is needed to answer:

- who or what initiated evaluation;
- which session, candidate revision, and policy version were involved;
- which permission grant revisions were checked;
- which evidence categories, freshness ranges, and confidence bands mattered;
- whether the decision was allow or deny and its structured reason codes;
- the exact text delivered, if delivery succeeded;
- queued/expired state where relevant, delivery channel, and the strongest
  acknowledged outcome actually known; and
- whether the user accepted, dismissed, corrected, or deleted the record.

It does not duplicate raw source artifacts, normalized observation payloads,
provider prompts/responses, file data, or model chain of thought.

The decision record is appended and acknowledged before proactive delivery. A
later delivery result and user feedback append outcomes rather than rewriting
the original decision. The explanation view presents corrections prominently so
an append-only history does not continue to imply that corrected evidence is
true.

## Correction and deletion

Correction preserves accountability while changing future behavior:

- the original observation or decision is not silently mutated;
- a correction record identifies the affected claim and replacement scope;
- current context is recomputed;
- future policy evaluation uses the corrected session association; and
- no durable preference is inferred.

Deletion is a user command routed to each owning boundary. Success means the
record is no longer available through normal queries, context assembly, model
requests, explanations, or evaluation fixtures. Private audit fields are removed;
a content-free marker may remain stating that a record was deleted, when needed
to preserve sequence integrity. Related pending-delivery records are cancelled
and their private text removed.

The first slice has no cloud backup or multi-device replica. If either is added,
deletion cannot inherit these semantics without a new decision covering replica
acknowledgement, offline devices, and provider deletion.

## Deterministic intervention policy

The model may estimate significance or draft wording, but delivery policy checks
at least:

- focus session is active and not stopping;
- any recovered workflow has completed grant revalidation and received fresh
  source health;
- required source health is complete and fresh;
- the user is present and the desktop is unlocked;
- the candidate cites only evidence in the supplied working context;
- the candidate uses uncertainty-appropriate wording;
- the candidate schema and revision are valid;
- the delivery grant and relevant model-route approval are current;
- a delivery channel is permitted and suitable; if none is healthy, the item is
  eligible only for the bounded outbox rather than immediate delivery;
- deadline and elapsed intervals are recomputed from trusted time sources;
- cooldown, per-session cap, novelty, and cost-of-error rules pass;
- no mute, cancellation, or newer correction supersedes the candidate;
- the delivery channel is allowed and does not expose content on a lock screen;
  and
- a privacy-aware decision record has been acknowledged by Audit.

Failure or uncertainty in an authority, source-health, audit, or cancellation
check produces deny. A policy denial does not need to interrupt the user.

## Testable trust assumptions

| Assumption | Required test evidence |
| --- | --- |
| Observation is opt-in and tiered | Starting without each required grant fails; a title, URL, text, document, pixel, or unrelated-resource event is rejected under a narrower grant |
| Capture state is truthful | Full-client and native background state follow adapter acknowledgement and expose stop/cleanup failures |
| Presentation is replaceable | Closing the desktop does not stop or broaden current grants; reconnect replaces cache with an authoritative daemon snapshot |
| Revocation is immediate | A deterministic race proves a revoked grant rejects queued and late events |
| Model data is minimized | Golden request fixtures contain only fields approved by both the source grants and route approval, at the least sensitive useful granularity |
| Remote processing is disclosed | A remote route cannot run under a local-only or mismatched-provider grant |
| Missing evidence fails safe | Stale/unhealthy source fixtures produce silence rather than an inactivity conclusion |
| Models have no authority | Tool-shaped and prompt-injected provider outputs fail schema/authority checks |
| Proactive delivery is accountable | Forced audit failure prevents delivery; a successful delivery has a correlated decision record |
| Offline delivery is bounded | Channel loss queues only minimal permitted content; recovery revalidates once and stale items become non-interruptive missed history |
| Muting and stopping are distinct | Tests show mute stops delivery without hiding capture, while stop revokes capture and cancels delivery |
| Corrections affect behavior without becoming memory | Replay after correction changes the session decision; durable memory and user-model stores remain unchanged |
| Ephemeral data expires | A controllable clock proves source artifacts disappear immediately and normalized/derived data disappear at their declared boundaries |
| User deletion is effective | Deleted content cannot be returned by queries, explanation, context assembly, or model fixtures |
| Private data stays out of diagnostics | Snapshot tests reject forbidden fields in logs, errors, traces, and metrics |
| Lock state protects bystanders | Lock/switch fixtures pause capture and suppress notification content |
| Restart continuity is explicit | Restart restores only unexpired grants whose consent permits it, clears prior context, and waits for fresh source health |
| Invisible capture fails closed | Loss of the required native status/stop surface pauses affected observation even while CORE remains healthy |

## Accepted rich-observation profile

Application identity alone reveals sensitive patterns and remains weak evidence:
opening an editor does not prove progress, while opening a browser does not prove
distraction. The selected profile therefore permits richer evidence without
treating it as blanket access.

The first Windows implementation exposes independently grantable application
identity, window metadata, browser location, visible text, selected-document
content, and bounded pixel sources. It uses structured application, browser,
document, or accessibility data before image capture. A source artifact remains
adapter-local and transient; Context receives only the permitted normalized
observation with provenance and uncertainty.

Linux and macOS follow through the same semantic ports. A platform or
application may report a rich category unavailable or less granular; it may not
silently widen capture to compensate. Keyboard, clipboard, pointer, audio, and
camera observation remain out of this slice.

## Decisions deferred beyond Phase 1 scaffolding

None of these choices blocks creation of the CORE workspace, daemon lifecycle,
typed local protocol, fake adapters, or reconnect fixture:

1. Select the first concrete observation integrations and applications before
   Phase 2 processes real desktop content.
2. Select the first provider/model adapter and record its handling profile before
   a non-synthetic model route is approved.
3. Set production freshness, capture frequency, payload, model-budget, and
   thirty-day audit defaults from the technical spike and evaluation traces.
4. Decide whether goal deletion always cascades to related private intervention
   content or offers a user choice before production data exists.
5. Harden client identity beyond current-user OS binding before exposing rich
   observation to independently installed same-user clients.
6. Select durable repositories and the platform secret provider before Phase 2
   introduces persistent goals, grants, outbox entries, or model credentials.
