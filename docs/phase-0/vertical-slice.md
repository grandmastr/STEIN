# First Vertical Slice: Deadline-Aware Focus Session

Status: Accepted for implementation

## Purpose

Validate the smallest version of the overwatch relationship: STEIN maintains a
bounded view of one user-owned goal, remains silent while the available evidence
suggests useful progress, and offers one concise intervention when the goal
appears credibly at risk.

This is an interaction experiment, not a productivity scoring system. Desktop
activity is incomplete evidence and must never be presented as proof of intent,
attention, or performance.

## Scenario

The user wants to finish a written brief by a self-selected deadline. In the
desktop client, the user:

1. creates an active goal with a success statement and deadline;
2. starts a focus session for that goal;
3. selects one local workspace and the applications, browser surfaces, or
   documents relevant to it;
4. selects an already approved local or remote model route and independently
   grants the exact observation categories and native-notification permission
   needed by this focus session, including whether they survive daemon restart;
5. works normally while STEIN maintains a bounded working context;
6. may close or lose the desktop client without ending the authorized workflow;
7. receives no message while the evidence does not justify interruption;
8. receives a concise, evidence-qualified intervention if deadline risk crosses
   the policy threshold;
9. accepts, dismisses, corrects, or mutes the intervention; and
10. ends the session, causing session permissions to expire and ephemeral
   observation data to be removed.

The first slice advises only. It cannot edit files, control applications, send
messages, change the goal, extend the deadline, or execute an external tool on
the user's behalf.

## Observation boundary

The first slice uses the tiered rich-observation profile accepted in ADR 0009.
For explicitly selected resources, the Windows adapter may emit only categories
covered by independent current grants:

- whether the user session is active, idle, or locked;
- the stable identity of the foreground application;
- window or selected-document metadata, including a title;
- a browser location at the minimum useful origin, path, query, and fragment
  granularity;
- visible structured text from a selected application, browser surface, or
  accessibility tree;
- content from an explicitly selected document or workspace resource;
- bounded screen pixels from a selected application, window, region, or display
  when structured input is insufficient and the separate pixel scope is active;
- activity in the selected workspace, using an opaque workspace identifier and
  a coarse activity kind; and
- source health and the time at which the last complete signal was observed.

These are separate capabilities, not one blanket “observe my screen” switch.
Application identity does not authorize a title, a title does not authorize a
URL, and text does not authorize pixels. The adapter prefers explicit browser,
document, application, and accessibility integrations before bounded image
capture. A source outside the selected application, resource, site, window, or
region is rejected.

The adapter does not capture keyboard input, clipboard contents, pointer traces,
microphone or camera data, protected credential fields, secure desktop or system
consent surfaces, or a historical inventory of unrelated applications and
workspaces. Raw screen frames and unfiltered source payloads exist only during
transient adapter processing; they are not persisted, logged, audited, emitted
to presentation clients, or retained as context.

Every observation remains evidence rather than proof. Visible text may be stale,
incomplete, generated, or unrelated; a workspace change need not be useful; and
the absence of an observed section does not prove that the user has not drafted
it elsewhere.

The native adapter necessarily receives the selected local path when the user
configures the watcher. The daemon's resource registry replaces it with an
opaque workspace reference before any observation, context, model, audit, or
telemetry boundary. The local binding is deleted at session end or revocation.
It is persisted only when the user authorizes restart continuity and then only
in daemon-owned, access-controlled state.

## Scripted interaction

The times below make the expected ordering and decisions reviewable. They are
example data, not proposed product defaults.

1. At 14:00, the user creates the goal “Finish the Project Atlas brief” with a
   15:00 deadline and the success statement “Introduction, three options, and a
   recommendation are drafted.”
2. The user selects the brief, its workspace, and a research browser surface,
   then selects an already approved model route. The user grants this session
   application identity, window metadata, selected-document text, browser
   location and visible-text observation, plus native desktop notifications.
   Pixel observation remains off because the structured sources are sufficient.
   The grants allow the workflow to continue while presentation clients are
   disconnected.
3. The CORE daemon verifies source health and activates the session. The client
   and the independent background status/control surface show the active capture
   scopes and stop control.
4. From 14:05 through 14:25, selected-workspace changes and structured brief
   observations show recent edits to the introduction and options. Context keeps
   only the permitted bounded evidence. The significance gate does not justify
   an interruption, so STEIN remains silent.
5. At 14:26, the user closes the desktop client. The client disconnects, but the
   daemon, focus session, grants, source, and canonical state remain active.
6. The foreground application changes to the selected research surface for seven
   minutes. Its approved location and visible text are relevant to the brief, so
   the evidence does not justify interruption. STEIN remains silent without
   requiring a presentation client.
7. By 14:42, the user is present, every required source is healthy, the goal
   deadline is eighteen minutes away, and the selected brief still has no
   observed recommendation section after the recent research period. This is
   incomplete but relevant evidence, so a cheap deterministic gate permits a
   reasoning request.
8. The agent loop assembles only the goal, deadline, approved derived structure
   and bounded excerpt, source freshness, recent intervention load, and
   permission state. Every rich category in the packet must also be approved for
   the selected model route. A model may propose an intervention, but it cannot
   deliver one.
9. Intervention policy validates provenance, confidence, novelty, source
   freshness, interruptibility, permission, and rate limits. If allowed, the
   daemon delivers a native desktop notification: “You have 18 minutes left. I
   can see the introduction and options in the selected brief, but not the
   recommendation yet. Would it help to draft that next or narrow the goal?”
10. The user opens the desktop client from the notification and chooses to narrow
    the success statement. This is a new direct user command, not an action taken
    by the model. The intervention outcome is recorded as accepted.
11. The reconnected client obtains an authoritative snapshot from the daemon; it
    does not reconstruct state from its pre-disconnect cache.
12. Relevant activity resumes, so STEIN remains silent. The user marks the goal
    complete and ends the focus session.
13. Session observation and intervention grants expire. The adapter stops before
    CORE reports the session ended, and ephemeral observation data is removed
    under the retention rule. The separately configured model-route approval
    remains until changed or revoked. Cleanup does not depend on a client
    remaining connected.

## Correction path

If the user was doing relevant research in an unassociated application, the
intervention may be wrong. The user can choose “This was relevant work” and may
optionally associate that application with the current session.

The correction must:

- change the current session's context immediately;
- mark the intervention outcome as corrected rather than accepted or dismissed;
- preserve the original evidence and decision in the privacy-aware audit record;
- avoid silently creating a durable preference or user-model claim; and
- explain the scope and lifetime of any association the user elects to add.

## Required decisions

The application must produce two independent decisions:

1. **Significance decision:** Is the evidence strong enough to spend resources
   evaluating a possible intervention?
2. **Intervention decision:** Given a candidate message and current authority,
   should STEIN remain silent or deliver it now?

The second decision cannot be delegated to a model. A model's recommendation,
confidence, or wording is untrusted candidate input.

## Acceptance examples

### Justified silence

Given healthy selected sources, an active goal, and observed relevant writing or
research, when the user changes applications, then no model request or
intervention is produced solely because of that change.

### Useful intervention

Given healthy selected sources, a nearby deadline, evidence that an explicitly
stated success condition may still be missing, an interruptible user, and a
valid intervention grant, when the significance and intervention policies both
allow the candidate, then exactly one uncertainty-qualified banner is delivered
and its outcome can be recorded.

### Immediate mute

Given an active session, when the user mutes proactive behavior, then pending
candidates are cancelled and no new intervention is delivered. Observation may
continue only if its separate permission remains active and the UI makes that
state clear.

### Immediate stop

Given an active session, when the user stops observation or ends the session,
then the adapter stops, queued observation events are rejected, session grants
expire, and every connected client receives authoritative state. The stop action
must remain available through an independent native control path when the full
desktop client is closed.

### Presentation independence

Given an active session with grants that permit background continuity, when the
desktop client disconnects, then the daemon continues observation, context,
reasoning, scheduling, and authorized native delivery. When the client reconnects,
it replaces cached state with a daemon snapshot.

### Channel recovery

Given an allowed intervention and no healthy permitted delivery channel, when the
intervention remains relevant but undelivered, then CORE queues a bounded minimal
delivery record. When a channel returns, policy revalidates the item before one
delivery attempt. If it is stale or expired, the client later shows it only as
non-interruptive missed history.

### Evidence correction

Given a delivered intervention, when the user reports that the unassociated
activity was relevant, then the current context changes without rewriting the
historical decision and without creating durable memory implicitly.

### Stale source

Given missing or stale source health, when an absence-of-activity rule would
otherwise fire, then the system treats the evidence as unknown and remains
silent.

## Failure behavior

| Failure | Required behavior |
| --- | --- |
| CORE daemon is unavailable | The OS supervisor attempts bounded recovery; clients and native status surfaces show CORE as unavailable and never imply that work continues. |
| Client and CORE protocols are incompatible | Reject that client with an actionable compatibility error; do not disrupt already authorized daemon workflows. |
| Desktop client disconnects or crashes | Continue daemon-owned workflows covered by current grants; record connection health and require a fresh snapshot on reconnect. |
| Observation permission is denied or revoked | Do not start, or stop immediately; reject late events from the revoked grant. |
| Observation source is stale or unhealthy | Treat missing activity as unknown, expose degraded health, and suppress risk interventions based on absence. |
| A selected boundary or protected-surface exclusion cannot be enforced | Pause the affected rich source, discard transient artifacts, report it unavailable, and do not silently widen capture. |
| Model times out, fails, or returns invalid output | Cancel the request, remain silent, and record a content-free technical outcome. |
| Model output contains tool requests or instructions | Reject them; this slice exposes no executable tools to the model. |
| Policy evaluation fails | Deny delivery and remain silent. |
| Audit recording fails before delivery | Do not deliver a proactive intervention that cannot be accounted for. |
| Native notification channel is unavailable | Queue a bounded minimal delivery record; revalidate when a suitable channel returns and never report queued as delivered. |
| Notification delivery acknowledgement is ambiguous or fails | Record `delivery_unknown` or failed accurately; retry only after a new policy decision and deduplication check. |
| Background capture status/stop surface is unavailable | Pause affected capture and expose the failure when a trusted control client reconnects. |
| Duplicate command or event arrives | Use message identity and idempotency rules so it cannot create duplicate sessions or interventions. |
| The clock moves backward or jumps forward | Recompute from an authoritative monotonic duration plus wall-clock deadline; do not emit a burst of stale interventions. |
| User locks the desktop | Pause delivery and sensitive observation; do not surface content on the lock screen. |
| CORE daemon restarts | Recover only workflows whose unexpired grants explicitly allow restart continuity; reset source health to unknown and require fresh evidence before reasoning from absence. |
| Session cancellation races with a candidate | Cancellation wins; a candidate not yet acknowledged as delivered is denied. |

## Slice boundaries

Included:

- one non-elevated per-user CORE daemon, local user, active goal, and focus
  session;
- one desktop client that may disconnect and reconnect without owning workflow
  lifecycle;
- one selected local workspace and a small application, browser, and document
  allowlist;
- independently granted application identity, window metadata, browser
  location, visible or selected-document text, optional bounded pixels, coarse
  workspace activity, source health, and working-context aggregation;
- one provider-neutral reasoning request at a time, limited to capabilities of
  the selected approved route;
- silence or a daemon-delivered native desktop notification;
- a bounded persistent intervention outbox and non-interruptive missed history;
- accept, dismiss, correct, mute, and stop feedback;
- permission, client-independent continuity, restart recovery, cancellation,
  retention, and audit behavior.

Excluded:

- blanket desktop recording, persistent screenshots, unrelated browser or
  document history, keyboard, clipboard, pointer, audio, or video capture;
- durable personal memory or automatic user-model learning;
- external tools and autonomous action;
- voice delivery, remote clients, multiple devices, guests, and shared sessions;
- concurrent control by multiple presentation clients; and
- measuring employee productivity or inferring emotional or cognitive state.

## Evidence the slice should produce

The eventual implementation and evaluation fixture should demonstrate:

- a trace containing at least one justified silence and one allowed intervention;
- a trace in which stale evidence suppresses an intervention;
- a trace in which permission revocation wins a race with delivery;
- a correction that changes current context without creating durable memory;
- a trace in which the desktop disconnects, CORE continues safely, and a
  reconnected client receives authoritative state;
- a daemon restart trace that resumes only explicitly restart-authorized work and
  waits for fresh source health;
- a channel-outage trace that delivers a still-relevant queued item once and
  turns an expired item into non-interruptive missed history;
- an explanation view showing the evidence, policy result, and outcome without
  exposing private raw content;
- a rich-observation trace proving that each source category is independently
  authorized, redacted, expired, and absent from durable logs and audit; and
- deterministic replay of synthetic inputs to the policy boundary.

These traces test behavior. Counts such as the inactivity window, deadline window,
and intervention cooldown remain policy configuration to evaluate rather than
hard-coded definitions of productivity.
