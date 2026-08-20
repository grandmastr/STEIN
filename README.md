# STEIN

STEIN is a personal intelligence system designed to operate as a second mind: it maintains a parallel understanding of the user's situation, remembers what matters, reasons ahead, and offers help when that perspective adds value.

The user is the actor. STEIN is the navigator, analyst, memory, and adviser.

## The central idea

Most assistants are request-driven:

```text
human asks -> assistant answers
```

STEIN is built around shared situational awareness:

```text
human acts + STEIN observes
              |
              v
     shared working context
              |
              v
     remain silent, advise, or request permission to act
```

The quality of STEIN will depend as much on knowing when to remain silent as on generating a good answer.

## STEIN and CORE

- **STEIN** is the intelligence experienced by the user: identity, behavior, memory, reasoning, and the relationship that develops over time.
- **CORE** is the runtime beneath it: service lifecycle, contracts, events, policy enforcement, models, tools, memory access, context, and device integration.
- **Clients** are replaceable interfaces to CORE. The first client is planned as a Tauri desktop application using React and TypeScript.

CORE runs as a non-elevated per-user daemon. STEIN's authorized work and
canonical state do not depend on whether a presentation client is open.
The first implementation and verification host is Windows, followed by Linux
and macOS (Darwin). A platform is called supported only after its required
behavioral suites pass.

CORE coordinates intelligence; it is not itself "the AI." Foundation models are replaceable capabilities accessed through provider-neutral contracts.

## Current status

The Phase 1 Windows proof of concept is implemented, installed, and verified.
CORE starts independently as a non-elevated per-user daemon, the desktop is a
replaceable visualization/control surface, and the native protocol, lifecycle,
reconnect, cancellation, capacity, packaging, supervision, reinstall, and
uninstall checks pass. The packaged desktop also issued a real form command,
displayed its live event and the truthful 7/14 capability split, then recovered
the daemon-owned goal after reopening. The retained proof is summarized in the
[dated Windows evidence record](docs/evidence/phase-1-windows-20260819.md) and
indexed in the [Phase 1 verification runbook](docs/phase-1-runbook.md).

Two disruptive Phase 1 environment checks remain explicitly unclaimed: signing
out and back in, and attempting the first user's pipe from a real second Windows
SID.
The logon trigger, current-user-only DACL, and mutual process-token SID checks
are implemented; those two host fixtures are follow-up validation, not hidden
passes. Linux and macOS (Darwin) are the next platform ports. Future
expensive-to-reverse changes still require accepted architecture decision
records.

The Windows Phase 2 implementation is under active verification and is not yet
claimed complete. Its [acceptance runbook](docs/phase-2-runbook.md) preserves a
32-row fail-closed ledger. The read-only
[`Verify-Installed.cmd`](scripts/windows/phase2/Verify-Installed.cmd) collector
can bind a signed release to the exact installed package and status evidence,
but it deliberately leaves unexecuted interactive, native, adversarial, and
external gates as `not_run` or `blocked` rather than manufacturing passes.

## Design principles

1. User agency comes first.
2. Earn trust before autonomy.
3. Observe selectively; retain deliberately.
4. Separate model suggestions from authorized actions.
5. Make boundaries explicit before distributing the system.
6. Optimize for useful interventions, not maximum activity.
7. Let software validate the interaction model before committing to custom hardware.

## Repository guide

```text
AGENTS.md                  Engineering guidance for contributors and agents
README.md                  Project orientation
docs/
|-- vision.md              Product intent and experience principles
|-- architecture.md        Proposed technical shape and open questions
|-- core-concepts.md       Shared domain vocabulary
|-- roadmap.md             Staged outcomes and exit criteria
|-- phase-0/               First-slice discovery contracts and trust rules
|-- phase-1-runbook.md     Windows build, install, and completion verification
|-- phase-2-runbook.md     Windows Phase 2 fail-closed acceptance ledger
`-- decisions/             Architecture decision records
```

Start with [the vision](docs/vision.md), then read [the proposed architecture](docs/architecture.md),
[core concepts](docs/core-concepts.md), and the accepted
[Phase 0 package](docs/phase-0/README.md). Use the
[Phase 1 verification runbook](docs/phase-1-runbook.md) for the current Windows
proof.
