# Architecture Decision Records

Use this directory for decisions that constrain future implementation or would be expensive to reverse.

## Status values

- **Proposed:** under active discussion and not yet binding.
- **Accepted:** the current project decision.
- **Superseded:** replaced by a later ADR; link both records.
- **Rejected:** considered and deliberately not selected.
- **Deprecated:** still present but scheduled for removal.

## File naming

```text
NNNN-short-kebab-case-title.md
```

Numbers are sequential and never reused.

## Template

```markdown
# NNNN: Decision title

Status: Proposed
Date: YYYY-MM-DD

## Context

What requirement or tension makes a decision necessary?

## Decision drivers

- The forces that matter.

## Considered options

### Option A

Description, benefits, costs, and failure modes.

### Option B

Description, benefits, costs, and failure modes.

## Decision

What was selected and why?

## Consequences

What becomes easier, harder, required, or prohibited?

## Validation

How will evidence show that this remains the right decision?

## Revisit when

What concrete signal should cause the decision to be reviewed?
```

## Original candidate topics

The architecture discussion began with these topics. Only the numbered records
in the current-records table are binding; a topic's appearance in this list does
not itself accept a decision:

1. CORE deployment inside Tauri versus sidecar versus independent local daemon.
2. Modular monolith and criteria for process extraction.
3. Client protocol and message envelope.
4. Permission, confirmation, and action authority model.
5. Memory provenance, correction, deletion, and retention semantics.
6. Identity and user-model update workflow.

## Current records

| ADR | Status | Decision under review |
| --- | --- | --- |
| [0001](0001-run-core-as-a-per-user-daemon.md) | Accepted | Run CORE as a presentation-independent per-user daemon |
| [0002](0002-use-a-modular-monolith-for-core.md) | Accepted | Use a modular monolith with explicit ownership boundaries |
| [0003](0003-version-the-typed-client-protocol.md) | Accepted | Use a typed, versioned client protocol over protected local IPC |
| [0004](0004-use-scoped-grants-and-candidate-specific-policy.md) | Accepted | Use scoped grants and candidate-specific policy decisions |
| [0005](0005-keep-observations-ephemeral-and-audit-minimal.md) | Accepted | Keep observations ephemeral and audit records minimal |
| [0006](0006-target-windows-before-linux-and-macos.md) | Accepted | Target Windows first, followed by Linux and macOS |
| [0007](0007-permit-configured-remote-model-routes.md) | Accepted | Permit explicitly configured local and remote model routes |
| [0008](0008-queue-interventions-when-channels-are-unavailable.md) | Accepted | Queue unavailable-channel interventions with delivery-time revalidation |
| [0009](0009-use-tiered-rich-desktop-observation.md) | Accepted | Use independently scoped rich desktop observation, implemented on Windows first |
| [0010](0010-supervise-windows-core-with-task-scheduler.md) | Accepted | Supervise the Windows daemon with a non-elevated current-user scheduled task |
| [0011](0011-require-a-capability-broker-for-private-client-access.md) | Accepted | Bind private client access to an OS-verified package/AppContainer capability and per-session broker authority |
| [0012](0012-persist-phase-2-state-in-sqlite.md) | Accepted | Persist bounded Phase 2 state in one daemon-owned SQLite database with owner-specific repositories |
| [0013](0013-store-windows-secrets-in-credential-manager.md) | Accepted | Store provider credentials in Windows Credential Manager behind a portable secret-store port |
| [0014](0014-use-tiered-native-windows-observation-adapters.md) | Accepted | Implement the accepted observation profile through selected native Windows integrations |
| [0015](0015-use-openai-responses-as-the-first-model-adapter.md) | Accepted | Use an explicitly approved OpenAI Responses route as the first provider adapter |
| [0016](0016-use-native-windows-status-notifications-and-a-durable-outbox.md) | Accepted | Use in-CORE native Windows status, emergency control, toast delivery, and a revalidated outbox |
| [0017](0017-set-initial-phase-2-bounds-and-explicit-user-preferences.md) | Accepted | Set conservative Phase 2 limits and directly editable identity/preferences without implicit learning |
