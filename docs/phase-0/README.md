# Phase 0: Architecture Discovery

Status: Complete; baseline carried into the Windows Phase 1 proof of concept

Phase 0 turns the product hypothesis into one implementable vertical slice. Its
purpose is to resolve only the contracts and trust boundaries that the first
slice needs, without designing the entire future platform.

## Exit tracker

| Exit criterion | Evidence | Status |
| --- | --- | --- |
| One vertical slice has a written interaction sequence and failure behavior | [Deadline-aware focus session](vertical-slice.md) | Accepted for implementation |
| System boundaries and data ownership for the slice are named | [Slice contracts](slice-contracts.md) | Accepted for implementation |
| Expensive-to-reverse choices needed by the slice have accepted ADRs | [ADR tracker](../decisions/README.md#current-records) | Ten current ADRs accepted |
| Privacy and authority assumptions are testable | [Trust and memory rules](trust-and-memory.md) | Accepted for implementation |

An item is complete only when its document is internally consistent with the
shared vocabulary in [Core Concepts](../core-concepts.md) and any binding choice
is represented by an accepted architecture decision record.

## Working rules

- Use the first slice to force concrete decisions; do not generalize for
  hypothetical voice, mobile, ambient, or multi-user deployments.
- Treat observation as evidence, not proof of what the user is doing.
- Make silence, revocation, cancellation, and degraded behavior testable.
- Keep model judgment behind deterministic application and policy boundaries.
- Mark defaults as provisional until an accepted ADR makes them binding.

## Artifact map

- [Deadline-aware focus session](vertical-slice.md): scenario, sequence,
  acceptance examples, and failure behavior.
- [Slice contracts](slice-contracts.md): boundary ownership and the commands,
  queries, and events exercised by the scenario.
- [Trust and memory rules](trust-and-memory.md): permissions, privacy, retention,
  audit, and correction rules for the scenario.
- [Architecture Decision Records](../decisions/README.md): binding choices and
  their alternatives.

## Implementation gate

The Phase 0 baseline is sufficient to begin Phase 1. Accepted ADRs 0001 through
0010 are binding, including the cross-platform rich-observation contract,
Windows-first delivery order, and Windows supervision adapter.

Phase 1 may use fake observation, model, persistence, notification, secret-store,
and other platform adapters while it establishes the daemon, local protocol,
lifecycle, health, and reconnect behavior. Each fake reports unavailable rather
than simulating success. Before Phase 2 handles real private observations,
provider credentials, or proactive delivery, choose and validate:

1. the first Windows application, browser, and document integrations;
2. the first concrete model adapter and its approved data-handling profile;
3. client authentication hardening beyond same-user OS binding;
4. the durable repository and platform secret provider; and
5. evaluated freshness, capture-frequency, payload, budget, and retention
   defaults.

Current Windows Phase 1 implementation and acceptance evidence are tracked in
the [Phase 1 verification runbook](../phase-1-runbook.md).
