# Core Concepts

This glossary defines the shared language used to design STEIN and CORE. These are domain concepts, not a promise that each term will become a separate service or crate.

## STEIN

The persistent intelligence experienced by the user. STEIN has an identity, behavior, relationship model, memories, and a continuing perspective. It runs on CORE and uses models and tools through CORE's boundaries.

## CORE

The provider-neutral runtime and capability platform that hosts STEIN. CORE coordinates components, exposes client contracts, enforces policy, and manages lifecycle. It is not a foundation model, persona, user interface, or conventional operating-system kernel.

## CORE daemon

The non-elevated, per-user operating-system process that hosts CORE independently
of any presentation client. It owns canonical local runtime state and continues
only work covered by current grants and policy. A daemon is a deployment and
lifecycle boundary, not permission to turn CORE's internal modules into network
services or operate invisibly.

## User

The person STEIN assists and the ultimate authority over observation, memory, permissions, and consequential action. Other people who appear in data are not implicitly users and require stricter treatment.

## Identity

Structured, versioned information describing who STEIN is and the behavioral constraints it should follow. Identity informs prompts and deterministic behavior but is not merely prompt text.

## User model

Correctable claims about the user's preferences, communication style, working patterns, and learning preferences. Each meaningful claim should have provenance, confidence, and a way to be changed or removed.

## Observation

A normalized report from a source such as a client, clock, application, microphone, camera, or device. An observation is evidence with provenance and confidence; it is not automatically a fact, memory, or reason to intervene.

## Observation profile

The exact independently grantable source categories and selected resources a
workflow may observe. For desktop work these can include presence, application
identity, window metadata, browser location, visible text, selected-document
content, and bounded pixels. A profile is authority and minimization input, not
evidence that every source is healthy or available.

## Raw source artifact

A screen frame, unfiltered accessibility tree, or full source payload held only
long enough to produce a permitted normalized observation or complete one
approved model request. It is transient adapter data, not an observation event,
working context, audit record, or memory.

## Context

STEIN's current, revisable model of the situation: active people, entities, activity, location, constraints, recent changes, and relevant evidence. Context is shorter-lived than durable memory.

## Working context

The bounded subset of context assembled for a particular decision or model request. It should include only the information necessary for that purpose and respect sensitivity and token/cost budgets.

## Goal

A desired outcome owned by the user, STEIN, or a shared workflow. A goal has an explicit owner, state, priority, and success or abandonment conditions.

## Plan

A revisable approach toward a goal. A plan does not itself grant authority to execute its steps.

## Memory

Durable, retrievable information retained for future usefulness. Memory is governed by provenance, sensitivity, retention, correction, and deletion rules.

Candidate memory categories include:

- episodic: what happened in a particular situation;
- semantic: stable knowledge and relationships;
- procedural: how a recurring task is performed;
- project: decisions, state, and history tied to work;
- relationship: preferences and history relevant to interaction.

These categories are conceptual and need not map one-to-one to storage systems.

## Candidate memory

Information proposed for retention but not yet accepted by memory policy. This distinction prevents every observation or model statement from becoming permanent.

## Agent loop

The application workflow that assembles context, calls reasoning capabilities, evaluates candidate outputs, and produces a response, plan, intervention proposal, or silence. It is orchestration, not a single model call.

## Intervention

An unsolicited communication initiated by STEIN because it expects the information to be worth the interruption. An intervention has a reason, confidence, urgency, delivery channel, and recorded outcome.

## Intervention policy

The decision process that chooses silence or an intervention. It considers relevance, urgency, novelty, confidence, interruptibility, user preferences, recent intervention load, and cost of error.

## Delivery channel

A presentation path through which STEIN can surface an intervention, such as a
native notification, connected desktop view, voice session, or future device.
Channel availability, permission, sensitivity, and acknowledgement semantics are
separate from whether an intervention is worth delivering.

## Pending intervention delivery

A bounded, minimal outbox record retained when an allowed intervention has no
currently suitable delivery channel. It is revalidated before delivery and
expires or becomes non-interruptive missed history when no longer actionable. It
is not working context or durable personal memory.

## Capability

Something available to CORE, such as text inference, speech recognition, calendar reading, screen observation, or file access. Capability discovery reports what is currently available; it does not imply permission to use it.

## Tool

A typed capability that can cause an external read, computation, or state change. A tool exposes a validated input contract, declared effects and risks, permission requirements, cancellation behavior, and a typed result.

## Model

A replaceable inference capability used for tasks such as language reasoning, vision, speech, embedding, or ranking. Models propose interpretations and actions; they do not own authority or domain state.

## Model gateway

The provider-neutral boundary for model capabilities, streaming, budgets, cancellation, and normalized failure behavior. It hides vendor SDKs without pretending all models have identical capabilities.

## Model route approval

A persistent, revocable user approval for a named local or remote model route,
including placement, permitted data categories, purpose, handling profile,
fallback constraints, and optional expiry. It avoids repeated unchanged consent
while preventing hidden provider or data-scope changes.

## Policy decision

A structured allow, deny, or require-confirmation result produced for a specific proposed action in a specific authority context. Policy decisions should be inspectable and auditable.

## Authority context

The authenticated actor, device, initiating client session when applicable,
relevant permission grants, and policy decisions under which a protected
operation is evaluated. A daemon-owned workflow can retain valid authority after
the initiating client disconnects. Values claimed by a model, adapter, event
payload, or untrusted client field do not establish authority context.

## Permission

A revocable grant from an authorized user or administrator. Permissions are scoped by capability, resource, time, device, and sometimes purpose. Availability is not permission.

## Action

An authorized attempt to affect an external system or meaningful domain state. Suggestions and plans are not actions. Every consequential action should have an accountable initiator and outcome.

## Event

A typed record that something already happened. Events communicate facts between components but do not grant authority to perform follow-up actions.

## Command

A typed request for one accountable handler to attempt a state change.

## Query

A typed request for a view of current or historical state without changing domain state.

## Adapter

An implementation that connects a CORE contract to a specific provider, database, operating system, device, transport, or application.

## Client

A user-facing interface to CORE. Desktop is first; mobile, voice-only, ambient,
and wearable clients may follow. A client presents and captures interaction but
does not own CORE lifecycle or STEIN's canonical identity, goals, permissions,
context, or memory. Client absence does not inherently stop an authorized
daemon-owned workflow.

## Device

An authenticated compute or sensor node with declared capabilities, permissions, health, and data-placement constraints. A device is not trusted merely because it is on the same network.

## Session

A bounded period of interaction or activity. Sessions help with streaming, cancellation, and short-lived state but must not become the only unit of continuity.

## Focus session

A user-initiated session that associates one active goal with explicitly selected
observation sources, bounded permissions, working context, continuity settings,
and intervention controls. It may continue without a presentation client when
its grants allow that behavior. Ending a focus session does not itself complete
or delete its goal.

## Audit record

A privacy-aware record of why a consequential action or intervention was proposed, permitted or denied, and what result occurred. Audit records should preserve accountability without duplicating unnecessary private content.
