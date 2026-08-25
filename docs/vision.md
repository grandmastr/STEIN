# Product Vision

## Vision

STEIN is a persistent intelligence that works alongside one person as a second mind. It maintains context the user cannot always hold, notices patterns the user may miss, remembers commitments and prior situations, reasons ahead, and intervenes selectively.

Its purpose is not to replace the user's judgment. Its purpose is to give the user an additional perspective while they remain responsible for decisions and action.

The long-term experience resembles an overwatch relationship:

- the user is embodied, present, and acting in the world;
- STEIN maintains a broader and more persistent view;
- both contribute to a shared model of the current situation;
- STEIN speaks or acts only when the expected value exceeds the cost of interruption and the action is permitted.

## The problem

People operate with limited attention and imperfect memory. Relevant context is spread across conversations, projects, devices, places, and time. Existing assistants mostly wait for isolated requests, answer without durable situational understanding, and discard the relationship between one interaction and the next.

STEIN aims to provide continuity:

- What are we trying to accomplish?
- What has changed?
- What does the user already know or prefer?
- What happened in similar situations?
- Is there something worth surfacing now?
- Should STEIN remain silent, advise, ask, or request permission to act?

## Product promise

STEIN should eventually be able to:

1. Maintain active goals and working context across sessions.
2. Recall relevant personal, project, and situational memory.
3. Understand selected digital and physical observations with explicit permission.
4. Reason about the current situation using replaceable models and deterministic systems.
5. Offer timely, concise interventions.
6. Use tools and control systems within clear, inspectable authority.
7. Learn the user's preferences through structured, correctable models rather than uncontrolled self-modification.
8. Move across desktop, mobile, ambient, and eventually wearable interfaces without changing its core identity.

## Experience principles

### Presence without noise

STEIN may observe without responding. Silence is a valid and often preferred outcome.

### Perspective, not obedience

STEIN should challenge faulty assumptions, surface contradictions, and explain uncertainty. It is a collaborator, not a command echo.

### Continuity without creepiness

Memory must be useful, visible, correctable, and forgettable. The user should understand why something was remembered and be able to change or remove it.

### Capability without hidden authority

STEIN can recommend an action with more authority than it can execute one. Permissions, confirmation rules, reversibility, and risk determine execution.

### Personality from structure

STEIN's identity and relationship model should be represented as structured, versioned data that can inform prompts and behavior. It must not exist only as an opaque system prompt.

### Graceful degradation

Loss of a model provider, network, device, or sensor should reduce capabilities predictably rather than collapse the entire system.

## Trust requirements

Trust is a product capability, not a legal footer. STEIN must provide:

- explicit opt-in for observation sources;
- visible capture and processing state;
- scoped, revocable permissions;
- local-first processing where practical;
- retention controls and deletion;
- provenance for memories and conclusions;
- clear uncertainty and correction paths;
- an audit history for actions and proactive interventions;
- safe behavior around guests and other non-users.

## Initial product boundary

The first meaningful version is a desktop companion backed by a per-user CORE
daemon, not a universal autonomous agent. The desktop visualizes and controls
STEIN, but presentation availability does not own STEIN's lifecycle. The first
version should demonstrate the relationship with a narrow vertical slice:

1. The user establishes an active goal.
2. STEIN receives a small, explicitly permitted stream of desktop context.
3. It maintains a working model of progress.
4. It chooses to remain silent or offer a concise intervention.
5. The user can accept, dismiss, correct, or disable the behavior.
6. STEIN records the result so later interventions improve.

This slice tests the distinctive product hypothesis before voice, cameras, home control, mobile devices, or custom hardware multiply the risk and complexity.

## Non-goals for the early project

- Building a general-purpose operating system kernel.
- Creating a collection of independent network microservices by default.
- Training a foundation model from scratch.
- Continuous surveillance or indefinite raw sensor retention.
- Unbounded autonomous action.
- Simulating consciousness as a prerequisite for usefulness.
- Building custom wearable hardware before the software interaction model is validated.

## Measures of success

The system is succeeding when:

- interventions are infrequent but consistently useful;
- the user can explain what STEIN knows and why;
- corrections change future behavior;
- the user trusts permission and action boundaries;
- a provider or client can be replaced without rewriting domain behavior;
- STEIN makes the user's working context easier to maintain rather than adding another inbox to manage.
