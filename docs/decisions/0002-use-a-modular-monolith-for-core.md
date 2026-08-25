# 0002: Use a modular monolith for CORE

Status: Accepted
Date: 2026-08-19

## Context

The proposed architecture identifies runtime, goals, context, identity and
permissions, agent orchestration, models, intervention, audit, and adapters as
logical boundaries. The first slice needs those responsibilities to remain
clear, but it does not need independently deployed services.

Physical distribution now would force transport, discovery, authentication,
durable messaging, deployment, and partial-failure semantics before there is
evidence that any boundary needs independent scaling or isolation.

## Decision drivers

- Make domain ownership and dependency direction enforceable in code.
- Deliver a real vertical slice without speculative infrastructure.
- Keep local development, tests, packaging, and diagnostics simple.
- Preserve extraction paths for boundaries with future evidence for separation.
- Avoid equating a domain concept with a crate, process, or database.

## Considered options

### Option A: One undifferentiated application module

Put all CORE behavior behind one internal API and shared persistence layer.

Benefits:

- minimal initial file and package structure; and
- easy direct access between features.

Costs and failure modes:

- data ownership and authority checks become conventions rather than boundaries;
- provider and UI types can spread through domain behavior;
- later extraction requires discovering hidden dependencies; and
- broad integration tests become the only way to validate behavior.

### Option B: Modular monolith with explicit contracts

Run one CORE application but separate logical domains, application workflows,
ports, and infrastructure adapters. Use typed in-process calls and domain events.
Give each owner its own repository contract and migrations even if one physical
database is used.

Benefits:

- clear ownership without distributed-systems overhead;
- fast, deterministic tests and transactions where appropriate;
- compile-time dependency checks can prevent adapter leakage; and
- a boundary can be extracted later from a known contract.

Costs and failure modes:

- boundaries require discipline and contract tests even though direct access is
  technically possible;
- too many tiny crates could slow development and create ceremony; and
- an in-process failure can affect the whole runtime.

### Option C: Independent services from the start

Deploy logical boundaries as local or remote services with network contracts and
separate stores.

Benefits:

- strong runtime isolation and independent deployment; and
- separate scaling and technology choices.

Costs and failure modes:

- distributed authorization, observability, consistency, retries, schema
  rollout, and service management dominate the first slice;
- local privacy and failure states are harder to explain; and
- service boundaries would be based on hypotheses rather than workload evidence.

## Decision

Build CORE as a modular monolith.

Use one Rust workspace and one deployed CORE runtime for the first slice. Model
the boundaries in `docs/phase-0/slice-contracts.md` as modules or crates according
to compile-time dependency needs, not one crate per glossary term or table.

Use these dependency layers:

```text
client and infrastructure adapters -> application workflows -> domain
                 |                         |
                 +------ implements -------+ domain-owned ports
```

Domain code defines its language, invariants, and required ports. Application
workflows coordinate boundaries. Infrastructure implements ports for Tauri,
models, storage, time, native observation, and notification delivery.

Communication is by typed calls and deliberately published domain events. The
first slice does not introduce a network service, message broker, generic plugin
framework, or global service locator.

Each domain owner has exclusive write access to its canonical records through
its repository contract. One physical local database may host multiple owners if
migrations, schemas or table namespaces, and code access preserve that ownership.

## Extraction criteria

A boundary moves to another process only when at least one measured requirement
cannot be met safely inside the monolith:

- privilege or sandbox isolation;
- hardware or data locality;
- failure containment;
- independent lifecycle or deployment;
- independently dominant resource use or scaling;
- a second trusted device; or
- a security/encryption boundary that one process cannot enforce.

Extraction requires its own ADR covering authority, transport authentication,
compatibility, failure semantics, observability, deployment, and data migration.
High internal call volume or a desire for organizational symmetry is not enough.

## Consequences

- The composition root can construct the complete first slice in one process.
- Domain tests use in-memory ports; adapter and contract tests cover real
  serialization and persistence boundaries.
- Direct database access across owners, provider SDK types in domain code, and
  Tauri types outside its adapter are prohibited.
- In-process events do not grant action authority and do not promise durable
  replay.
- Transactions across domain owners are avoided. Workflows use explicit results,
  idempotency, and compensating behavior where a multi-step operation can fail.
- Crate count may evolve without changing the logical architecture.

## Validation

- Dependency checks or crate boundaries prove domain code does not import Tauri,
  model-provider, native observer, or database implementations.
- Tests prove Context cannot read Goal or Audit persistence directly and the
  model adapter cannot fetch domain state.
- The focus-session fixture composes all boundaries with in-memory adapters and
  no network infrastructure.
- Fault injection at each port produces the failure behavior defined by the
  vertical slice.
- A written extraction exercise can map one candidate boundary to a public
  contract without exposing its internal tables.

## Revisit when

One of the extraction criteria is demonstrated by a concrete capability, threat
model, reliability target, deployment need, or measured workload.
