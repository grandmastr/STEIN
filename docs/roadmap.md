# Roadmap

This roadmap is outcome-driven. Dates and technology choices should be added only when the preceding learning justifies them.

## Phase 0: Architecture discovery

**Outcome:** the first vertical slice and its trust boundaries are precise enough to implement without inventing the whole platform.

Current discovery artifacts are tracked in the [Phase 0 package](phase-0/README.md).

Work:

- refine the product vision and shared vocabulary;
- model one concrete overwatch scenario end to end;
- decide the initial CORE/Tauri process boundary;
- define command, query, event, cancellation, and error conventions;
- define the first permission and confirmation rules;
- define minimum memory provenance and deletion semantics;
- record accepted decisions as ADRs;
- produce a thin technical spike only where uncertainty cannot be resolved on paper.

Exit criteria:

- one vertical slice has a written interaction sequence and failure behavior;
- system boundaries and data ownership for that slice are named;
- expensive-to-reverse choices needed by the slice have accepted ADRs;
- privacy and authority assumptions are testable.

## Phase 1: CORE foundation and desktop handshake

**Status:** Windows proof of concept implemented, installed, and verified.
Direct second-account and sign-out fixtures remain documented follow-up checks;
Linux and macOS/Darwin ports follow next.

**Outcome:** an OS-supervised per-user CORE daemon can run independently and a
desktop client can reliably visualize and control it through a versioned local
contract.

Windows is the first Phase 1 implementation and verification host. Linux
follows, then macOS (Darwin), through the same platform ports and behavioral
contract suites. A platform is called supported only after the applicable
lifecycle, authority, privacy, reconnect, notification, and recovery suites for
the capabilities it claims have passed.

Probable scope:

- minimal Rust workspace and per-user CORE daemon lifecycle;
- Windows per-user installation, supervision, recovery, and clean upgrade path;
- Tauri desktop shell with React/TypeScript;
- protected Windows named-pipe IPC with current-user peer authentication;
- client command/query/snapshot/event protocol;
- health and capability discovery;
- authoritative reconnect and event-gap recovery;
- structured configuration and secrets boundary;
- cancellation, shutdown, and error behavior;
- in-memory adapters where persistence is not yet part of the slice.

Exit criteria:

- the OS can start CORE without the desktop, and the client can connect, display
  health, issue a command, and receive an event;
- closing or crashing the client does not stop CORE, and reconnect restores an
  authoritative snapshot;
- incompatible or wrong-user clients fail without disrupting the daemon;
- compatibility and failure cases are covered by contract tests;
- CORE domain contracts do not depend on Tauri.

The current Windows evidence procedure and completion ledger are maintained in
the [Phase 1 verification runbook](phase-1-runbook.md). The dated Windows POC
evidence is retained there alongside the two disruptive checks that were not
run; no unexecuted host fixture is represented as a pass.

## Phase 2: First second-mind loop

**Outcome:** STEIN can maintain an explicit active goal, reason over a narrow context, and choose silence or a useful intervention.

Probable scope:

- structured identity and user preferences;
- active goal and working-context model;
- provider-neutral text model gateway with one adapter;
- tiered, opt-in rich desktop observation for explicitly selected applications,
  browser surfaces, documents, and optional bounded screen regions;
- structured observation and local redaction ahead of separately granted pixel
  capture, with no durable raw source artifacts;
- intervention policy with deterministic limits;
- persistent approved local/remote model routes without hidden fallback;
- daemon-owned focus-session continuity and safe restart recovery;
- independently available native capture status, emergency stop, and
  notification delivery;
- bounded pending-delivery outbox with channel recovery, revalidation, expiry,
  and missed history;
- user feedback: accept, dismiss, correct, mute;
- an audit record of the intervention decision and outcome.

Exit criteria:

- a scripted working session demonstrates at least one justified silence and one useful intervention;
- the daemon safely continues the session while the full desktop client is
  closed, and reconnect reports authoritative state;
- disabling observation or proactive behavior takes effect immediately;
- each rich observation category is independently visible, revocable, and
  excluded from model routes that have not approved it;
- model output cannot bypass policy or invoke undeclared tools;
- the user can inspect why the intervention occurred.

## Platform rollout after the Windows slice

**Outcome:** Linux and macOS host the same CORE behavior without importing
Windows assumptions into domain or application code.

Sequence:

1. implement Linux daemon supervision, protected local IPC, session state,
   notifications, secure storage, packaging, and the shared contract suites;
2. implement the equivalent macOS/Darwin adapters; and
3. report platform capability differences explicitly instead of silently
   weakening trust or lifecycle behavior.

A platform is supported only after daemon continuity, wrong-user rejection,
client reconnect, lock/logout safety, notification delivery, outbox recovery,
revocation, upgrade, and uninstall behavior pass on that platform.

## Phase 3: Durable, correctable memory

**Outcome:** relevant information persists across sessions without turning every observation into permanent history.

Probable scope:

- candidate-memory workflow;
- episodic and project memory sufficient for the vertical slice;
- provenance, confidence, sensitivity, and retention metadata;
- correction, deletion, and retrieval explanations;
- evaluation corpus using synthetic scenarios;
- optional embeddings behind a memory-owned adapter if evaluation justifies them.

Exit criteria:

- STEIN retrieves relevant prior context in repeat scenarios;
- the user can see, correct, and forget retained information;
- deleted memory is no longer available through normal retrieval;
- memory quality is measured against a repeatable evaluation set.

## Phase 4: Bounded agency

**Outcome:** STEIN can use a small set of tools under explicit, testable authority.

Probable scope:

- typed tool registry and invocation lifecycle;
- risk and reversibility classification;
- confirmation and denial flows;
- timeouts, cancellation, idempotency, and recovery;
- sandboxed worker only if a real tool requires isolation;
- audit and user-visible action history.

Exit criteria:

- no tool executes without the required authority context;
- risky actions require confirmation and surface expected effects;
- cancellation and partial failure are handled safely;
- tool results enter context or memory only through explicit workflows.

## Phase 5: Voice and continuous presence

**Outcome:** the second-mind loop works through low-latency speech without making the system constantly intrusive.

Probable scope:

- speech input/output adapters and streaming sessions;
- interruption, turn-taking, and barge-in behavior;
- visible listening and processing state;
- local wake/voice activity components where practical;
- channel-aware intervention delivery;
- retention rules for raw audio and transcripts.

Exit criteria:

- voice can be disabled instantly and its state is unambiguous;
- normal interruption and recovery feel natural in repeated trials;
- raw audio retention is minimal and user-controlled;
- proactive voice behavior respects intervention limits.

## Phase 6: Ambient and multi-device context

**Outcome:** trusted devices can contribute selected context while preserving locality, consent, and predictable offline behavior.

Probable scope:

- device identity and capability discovery;
- authenticated, encrypted local communication;
- explicit data-placement and synchronization rules;
- local perception workers that emit sparse observations rather than raw streams;
- guest and shared-space privacy modes;
- mobile or home integration driven by a validated scenario.

Exit criteria:

- removing a device revokes its authority and data access;
- disconnection degrades gracefully;
- the user can identify which device produced an observation;
- raw sensor data does not leave its intended boundary by default.

## Phase 7: Portable form factor research

**Outcome:** validated software behavior produces concrete requirements for wearable or dedicated hardware.

Questions to answer before custom hardware:

- Which sensors are actually valuable?
- What latency and offline behavior are required?
- What must run on-device for privacy or responsiveness?
- What controls make capture state obvious?
- What battery, thermal, network, and comfort constraints dominate?
- Can a phone plus existing earbuds/glasses satisfy the requirement first?

Custom hardware begins only when these answers come from sustained use rather than fiction-inspired assumptions.

## Ongoing evaluation tracks

Every phase should maintain four parallel evaluations:

- **Usefulness:** Did STEIN improve the outcome or reduce cognitive load?
- **Restraint:** Did it remain silent when intervention was not worthwhile?
- **Trust:** Could the user understand and control observation, memory, and action?
- **Resilience:** Did failures degrade capabilities safely and predictably?
