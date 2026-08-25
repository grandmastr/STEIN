# Proposed Architecture

Status: Phase 0 baseline accepted; future-phase details remain exploratory

The current first-slice proposals and ADR candidates are tracked in the
[Phase 0 package](phase-0/README.md). Accepted ADRs are binding; documents and
ADRs marked Proposed remain open to revision.

This document describes the current architectural hypothesis. It is a basis for technical discussion, not an inventory of services that must all be built.

## Design goals

- Support a persistent agent that observes, remembers, reasons, and selectively intervenes.
- Keep user authority and privacy enforceable outside model prompts.
- Allow model, storage, client, device, and deployment choices to evolve.
- Make the first useful vertical slice simple to run on one machine.
- Preserve extraction paths for components that later require isolation or independent deployment.

## System shape

```text
       +----------------------+       +--------------------------+
       |   Desktop client     |       | Native status + delivery |
       | Tauri + React/TS     |       | independent control path |
       +----------+-----------+       +-------------^------------+
                  |                                 |
       authenticated local client protocol         | adapter contract
                  |                                 |
                  +-----------------+---------------+
                                    |
                  +-----------------v-----------------+
                  |       per-user CORE daemon        |
                  | runtime + application orchestration|
                  +-----------------+-----------------+
                                    |
       +--------------+-------------+-------------+--------------+
       |              |             |             |              |
       v              v             v             v              v
    Context         Memory      Agent loop       Tools       Goals/plans
       |              |             |             |              |
       +--------------+-------------+-------------+--------------+
                                    |
                         Identity + policy gates
                                    |
       +----------------------------+----------------------------+
       |                            |                            |
       v                            v                            v
  Model adapters               Device adapters              Event sources
 cloud/local/realtime       desktop/home/mobile         timers/apps/sensors
```

This is a logical view. Initially, most boxes should be Rust modules or crates in
one CORE daemon process, not independent network services. The desktop is a
separate client process and does not own daemon lifecycle.

## Runtime model

CORE is the composition root and lifecycle host inside an OS-supervised,
non-elevated per-user daemon. Its responsibilities are deliberately narrow:

- load configuration and secrets through approved providers;
- construct components and their dependencies;
- start, monitor, cancel, and stop long-running work;
- recover explicitly restart-authorized workflows without treating stale
  observations as current;
- route typed commands, queries, and events;
- expose an authenticated local, versioned client protocol;
- maintain truthful background status and emergency control paths;
- report health and capability availability;
- provide structured, privacy-aware telemetry.

CORE should not contain provider-specific model logic, memory algorithms, or STEIN's personality directly.

## Proposed domain boundaries

| Boundary | Responsibility | Initial form | Extract only when |
| --- | --- | --- | --- |
| Runtime | Daemon composition, service lifecycle, recovery, cancellation, health | CORE daemon host | Multiple independently managed CORE processes exist |
| Client protocol | Authentication, commands, snapshots, event subscriptions, compatibility | Rust contract crate plus local IPC adapter and generated/maintained TS types | Remote clients require a network gateway |
| Identity and user model | STEIN identity, user preferences, relationship, behavioral configuration | Domain module | Independent administration or stronger isolation is required |
| Memory | Remember, recall, correct, forget, provenance, retention | Domain module with repository ports | Scale, encryption boundary, or deployment locality requires separation |
| Context | Current situation, entities, activities, evidence, confidence | Domain module | High-volume perception or distributed devices require it |
| Goals and plans | Intentions, commitments, progress, plan state | Domain module | Independent scheduling or collaborative ownership requires it |
| Agent loop | Assemble context, request reasoning, evaluate candidate response | Application service | Multiple agent runtimes need independent lifecycle or scaling |
| Intervention | Decide whether, when, and how STEIN should surface something; own bounded pending delivery | Domain policy module plus outbox repository | Experimentation or low-latency deployment needs independent release |
| Model gateway | Provider-neutral inference, streaming, capabilities, budgets | Port plus provider adapters | Provider isolation, remote compute, or separate scaling is necessary |
| Tools | Capability registry, validation, invocation, results | Application boundary plus adapters | Sandbox/security isolation requires a worker process |
| Policy and authorization | Permission checks, confirmation, risk, audit | Domain service at every action boundary | A hardened policy service becomes a concrete requirement |
| Events and scheduling | Domain event delivery, timers, retries | In-process typed bus and scheduler | Durable cross-process delivery is required |
| Devices and perception | Convert external systems and sensors into normalized observations/actions | Adapters, often separate local workers | Hardware locality, privacy, or failure containment requires it |

Names and groupings may change after modeling real use cases. A row is not automatically a crate.

## Dependency direction

Use a ports-and-adapters dependency shape:

```text
clients/adapters -> application orchestration -> domain contracts
                            |                         ^
                            v                         |
                   infrastructure adapters ----------+
```

Domain code defines the language and interfaces it needs. Provider implementations depend on those contracts. Domain behavior must not import a particular model SDK, database client, Tauri API, or home automation SDK.

## Communication contracts

Use three explicit interaction forms:

- **Command:** request a state change. It has one accountable handler and a structured result.
- **Query:** retrieve a view without changing domain state.
- **Event:** report something that already happened. It may have multiple subscribers and must not imply that an external action is authorized.

Every cross-boundary message should carry:

- a stable message type and schema version;
- correlation and causation identifiers;
- timestamp and origin;
- actor or authority context where relevant;
- sensitivity/retention classification where relevant;
- typed payload and structured failure information.

Use in-process calls and typed event delivery inside CORE. The daemon boundary
uses the versioned local client protocol. Preserve semantic contracts so a
transport can change later without changing domain meaning.

## Data ownership

Each domain owns its records and invariants. Other domains use its contract or consume published views/events.

Examples:

- Context may request relevant memories; it does not query memory tables.
- A model adapter receives an intentionally assembled context packet; it does not read user history itself.
- The desktop client receives views and events; it does not become the authoritative store for goals or permissions.
- Tools return typed outcomes; they do not write directly into memory as a side effect. An application workflow decides what becomes memory.

The first deployment may use one physical database, but ownership should remain visible through schemas, repositories, migrations, and access rules.

## Observation architecture

CORE defines platform-neutral semantic observation ports. Windows implements the
first native adapters; Linux and macOS follow without changing Context or policy
meaning. The accepted rich profile separates presence, application identity,
window metadata, browser location, visible text, selected-document content, and
bounded pixels into independent grant categories.

Adapters prefer explicit application/browser/document integrations and
structured accessibility data before pixels. A full source payload or screen
frame stays inside the transient adapter path, except for one explicitly
approved model request through a single-use handle, and never becomes a general
event, client payload, log, audit field, or durable record. Context receives
only the permitted normalized result with selected-resource provenance,
sensitivity, freshness, extraction/redaction version, and uncertainty.

An approved observation source does not imply permission to send its result to a
model. The working-context assembler intersects current session grants with the
selected `ModelRouteApproval` data categories and chooses the least sensitive
representation that satisfies the request.

## The cognitive loop

```text
observation
    |
    v
normalize + classify sensitivity
    |
    v
update working context -----> retrieve relevant memory
    |                                  |
    +----------------+-----------------+
                     v
              evaluate significance
                     |
           +---------+---------+
           |                   |
        no value          candidate insight/action
           |                   |
        silence          policy + intervention decision
                               |
                    +----------+-----------+
                    |                      |
                  deny          deliver now / queue / act
                                           |
                              revalidate + record outcome
```

There should be several cheap deterministic filters before expensive model reasoning. An observation is evidence, not truth; context should preserve source and confidence.

## Action and intervention safety

Model output is untrusted input to the application. A model can produce a candidate message, plan, or tool request. CORE validates it against:

1. tool schema and preconditions;
2. current identity and granted permissions;
3. risk and reversibility policy;
4. confirmation requirements;
5. rate, cost, and resource limits;
6. audit and retention rules.

Proactive speech also crosses a boundary. Intervention policy should consider urgency, confidence, novelty, interruptibility, user preferences, recent intervention frequency, and the cost of being wrong. "Remain silent" is a first-class decision.

## Client protocol

The desktop client interacts with the CORE daemon through an authenticated,
versioned local protocol. The protocol supports:

- commands and queries;
- streaming model or voice responses;
- subscriptions to state changes;
- cancellation and timeouts;
- permission prompts;
- capability and health discovery;
- compatibility negotiation.

The initial Windows daemon transport uses an OS-protected named pipe restricted
to the current user. Linux and macOS adapters use protected per-user local
endpoints appropriate to those platforms. The Tauri Rust backend acts as the
first protocol client and maps views to React. The webview does not connect to
CORE directly.

Opening a connection returns an authoritative snapshot and a connection-scoped
event cursor. A reconnect or detected event gap replaces affected client cache
with a new snapshot. Client disconnect never implies permission revocation or
workflow cancellation.

## Deployment evolution

### Stage 1: one daemon and desktop client, explicit modules

One per-user CORE daemon and one replaceable desktop client. CORE uses in-process
domain contracts, one-machine storage, provider adapters, authenticated local
IPC, OS supervision, reconnect, and background status/control behavior.
Implement and validate this stage on Windows first, then port the platform
adapters to Linux and macOS without changing domain semantics.

### Stage 2: local workers where justified

Extract sandboxed tool execution, speech, vision, or device integration when failure isolation, hardware access, or privacy requires it. Use supervised local processes and authenticated local transport.

### Stage 3: multiple trusted devices

Introduce device identity, encrypted communication, synchronization semantics, offline behavior, and explicit data placement. Do not treat a second device as merely another UI.

### Stage 4: optional remote services

Move only capabilities that benefit from remote compute, availability, or sharing. Preserve a meaningful local mode and make cloud data flow visible.

## Expensive-to-reverse decisions

These require deliberate ADRs before implementation commits the project to them:

- canonical identifiers and event/message envelope;
- ownership and lifecycle of identity, memory, goals, and context;
- permission and authority model;
- memory provenance, correction, deletion, and retention semantics;
- client protocol compatibility strategy;
- local device identity and trust establishment;
- secrets and encryption-key ownership;
- audit semantics for suggested and executed actions;
- what is deterministic policy versus model judgment.

## Implementation gates

The accepted Phase 0 package is sufficient to scaffold Phase 1. The initial
foundation may use fake observation, model, persistence, secret-store, and
notification adapters where a production implementation is not needed to prove
daemon lifecycle and the client protocol. A fake must report its capability as
unavailable or not implemented; it must never return a fabricated secret,
delivery acknowledgement, or healthy status.

The Windows Phase 1 proof must select and validate the exact per-user
installation, supervision, upgrade, endpoint, peer-credential, runtime-health,
and capability-reporting mechanisms. Structured configuration, secret-store,
notification, and native-status ports belong in the platform-neutral boundary,
but their Windows Phase 1 adapters may truthfully report unavailable.

Real platform secret storage and independently available native notification,
capture-status, emergency-control, and pending-delivery mechanisms enter the
Phase 2 executable slice. They must be selected and validated before Phase 2
handles private observations, provider credentials, or proactive delivery.
Platform choices stay inside adapters unless a test exposes a semantic contract
gap.

Before Phase 2 processes real private data, record or validate:

- the first application/browser/document source and its protected-surface
  behavior;
- stronger client registration or pairing beyond same-user endpoint protection;
- the first model adapter and route handling profile;
- durable repository and encryption/secret ownership;
- the native notification/status channel and pending-delivery recovery
  mechanism; and
- evaluated policy constants such as source freshness, capture frequency,
  payload limits, model budget, cooldown, and audit retention.

Identity/user-model mutation, durable event replay, and personal memory remain
out of the first execution path and need decisions when a vertical slice first
requires them.
