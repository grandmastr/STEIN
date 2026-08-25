# STEIN Engineering Guide

## Project intent

STEIN is a long-lived personal intelligence system: a second mind that can maintain context, remember, reason alongside its user, and intervene when its perspective is useful. The user remains the decision-maker and actor.

CORE is the provider-neutral runtime and capability platform on which STEIN runs. CORE is not itself a model, persona, or desktop interface.

Read `README.md` and all relevant files under `docs/` before proposing architecture or implementation changes.

## Current phase

The Phase 0 architecture baseline is accepted. The Windows Phase 1 proof of
concept is implemented and installed; its retained evidence and the two
unexecuted disruptive host fixtures are indexed in
`docs/phase-1-runbook.md`. Linux and macOS/Darwin platform ports follow, while
the observation, reasoning, durable persistence, notification, and secret-store
capabilities remain Phase 2 work. Unless the user explicitly asks for
implementation, prefer design discussion, contracts, decision records, and
small experiments over speculative production scaffolding.

Treat architectural boundaries in `docs/architecture.md` as proposals until an accepted architecture decision record says otherwise.

## Architectural direction

- Implement CORE systems in Rust.
- Build the first desktop client with Tauri and React/TypeScript.
- Run CORE as a non-elevated, OS-supervised per-user daemon. Presentation clients
  visualize and control CORE but do not own its lifecycle or canonical state.
- Target Windows first, then Linux, then macOS (Darwin). Keep domain, application,
  policy, protocol, and test-fixture code independent of platform APIs.
- Begin as a modular monolith. Independence means clear code, ownership, and contract boundaries before it means separate processes or network services.
- Keep CORE independent of any particular model, database, device, operating system, or cloud vendor through narrow adapters.
- Give each subsystem ownership of its data. Other subsystems interact through its public contract rather than reading its storage directly.
- Use typed commands, queries, and domain events at boundaries. Do not use a global bag of JSON as the internal architecture.
- Route every consequential action through identity, permission, and policy checks. A model may propose an action; it may not bypass the action boundary.
- Make observation and intervention distinct. Receiving an event must not automatically cause STEIN to speak or act.
- Treat desktop observation as tiered capabilities. Prefer selected structured
  application, browser, document, or accessibility sources over independently
  granted bounded pixel capture; keep raw source artifacts transient.
- Prefer local processing and minimal retention for ambient audio, vision, screen, and device data.
- Preserve an explicit audit trail for external actions and proactive interventions.

## Engineering rules

- Deliver vertical slices that exercise real contracts end to end.
- Avoid speculative frameworks, distributed infrastructure, and premature generalization.
- Add a separate process only when isolation, failure containment, security, hardware locality, independent scaling, or deployment requires it.
- Record expensive-to-reverse choices as ADRs under `docs/decisions/`.
- When changing a public contract, update the relevant documentation and contract tests in the same change.
- Prefer domain language from `docs/core-concepts.md` and update that glossary when introducing a new foundational term.
- State assumptions and unresolved questions instead of silently turning them into architecture.
- Keep secrets, raw private observations, and personal memory out of source control and test fixtures.
- Use synthetic data in examples and tests.

## Quality bar

- Format and lint Rust and TypeScript code when those workspaces exist.
- Test public behavior, failure paths, permission denial, cancellation, and recovery—not only happy-path functions.
- Design long-running work to be cancellable and observable.
- Prefer structured errors and telemetry that do not leak private content.
- Keep the desktop client replaceable: product behavior belongs in CORE unless it is inherently presentation- or operating-system-specific.

## Change discipline

Before introducing a new crate, service, database, message broker, framework, or provider dependency, explain which concrete requirement it satisfies and why the existing boundary cannot satisfy it. Ask before making a major architectural change.
