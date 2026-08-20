# Phase 2: Windows First Second-Mind Loop Verification Runbook

Status: Design and prerequisite ADRs accepted; implementation and evidence not yet complete

This runbook is the acceptance ledger for the Windows Phase 2 executable slice.
It does not turn a planned or unit-tested capability into a pass. Phase 2 is
complete on Windows only after every required row below has retained evidence
from the packaged installed build. Linux and macOS remain unclaimed until their
own native suites pass.

The implementation must preserve all Phase 1 lifecycle and protocol gates in the
[Phase 1 runbook](phase-1-runbook.md) while replacing the seven deliberately
unavailable Phase 2 adapters with real, truthful implementations.

## Accepted prerequisite decisions

- [ADR 0011](decisions/0011-require-a-capability-broker-for-private-client-access.md): signed MSIX PFN/AppContainer-bound private client admission.
- [ADR 0012](decisions/0012-persist-phase-2-state-in-sqlite.md): bounded durable state in daemon-owned SQLite.
- [ADR 0013](decisions/0013-store-windows-secrets-in-credential-manager.md): Windows Credential Manager secret store.
- [ADR 0014](decisions/0014-use-tiered-native-windows-observation-adapters.md): concrete tiered Windows observation adapters.
- [ADR 0015](decisions/0015-use-openai-responses-as-the-first-model-adapter.md): first real OpenAI Responses adapter.
- [ADR 0016](decisions/0016-use-native-windows-status-notifications-and-a-durable-outbox.md): native status/stop/toast plus durable outbox.
- [ADR 0017](decisions/0017-set-initial-phase-2-bounds-and-explicit-user-preferences.md): initial deterministic bounds and explicit preferences.

ADRs 0001 through 0010 remain binding. In particular, observations remain
ephemeral, raw source artifacts never become audit or memory, model output has no
authority, and unavailable channels do not turn queued content into a false
delivery acknowledgement.

## Proof rules

- Run native integration and packaging checks from a normal, non-administrator
  Windows session. WSL-only execution is not native Windows evidence.
- Use synthetic goals, documents, pages, visible text, notifications, and model
  packets. Do not retain actual user content in the repository or evidence tree.
- Do not print, hash, partially reveal, or copy the real provider credential into
  test output. Evidence may state only that the configured secret reference was
  successfully resolved.
- Record command, package, host, toolchain, schema, migration, protocol, policy-
  profile, and build versions with each run.
- A skipped, mocked, manually assumed, or unavailable native fixture is `NOT RUN`
  or `BLOCKED`, not `PASS`.
- Keep failed evidence. A later pass does not erase the earlier failure or its
  diagnostic value.
- Every public protocol addition must have matching Rust and TypeScript fixtures.
- A screenshot supplements process/test evidence; it does not prove authority,
  retention, race, or absence-of-data behavior by itself.

## Synthetic acceptance workspace

Prepare a temporary current-user workspace containing only authored synthetic
data:

- one UTF-8 Project Atlas `.md` or `.txt` brief with introduction and options but
  initially no recommendation;
- Windows Notepad editing that selected document;
- one Microsoft Edge Stable test profile with the exact published Microsoft
  Edge Add-ons STEIN MV3 extension/version and an allowlisted local/synthetic
  Project Atlas research origin (an unpacked extension is not production
  evidence);
- a page containing allowed visible research text plus separate synthetic
  password/protected and unrelated-origin fixtures; and
- a separately picked bounded Windows Graphics Capture window/region fixture.

Delete this workspace and browser test profile after the evidence run. Never use
a personal browser profile, real account, or private work file as acceptance
input.

## Evidence layout

Create one timestamped directory below `artifacts/evidence/phase-2/`. Its final
machine-readable ledger should map every gate identifier below to:

- `pass`, `fail`, `blocked`, or `not_run`;
- exact build/package/schema/policy versions;
- command or harness identity and process exit result;
- retained artifact paths and SHA-256 digests where appropriate; and
- a content-free failure summary.

The evidence directory is host-private and stays out of source control. A dated,
sanitized summary may be checked in only after its linked artifacts have been
inspected.

## Completion ledger

| Gate | Required proof | Result before execution |
| --- | --- | --- |
| `P2-BUILD` | Rust format/check/Clippy with warnings denied/tests, TypeScript typecheck/lint/tests, release CORE/CLI/Tauri/MSIX/native-host build, and dependency-boundary checks all pass without skip flags. | NOT RUN |
| `P2-PHASE1-REGRESSION` | Every applicable Phase 1 protocol, cancellation, capacity, lifecycle, install, supervision, reconnect, reinstall, and uninstall gate still passes. | NOT RUN |
| `P2-PRIVATE-CLIENT` | Exact signed installed MSIX PFN/AppContainer peer obtains a private session. Unpackaged copy, renamed binary, valid-protocol same-SID adversary, spoofed AUMID/PFN text, replayed capability, prior daemon, and wrong SID cannot access private commands/views. | NOT RUN |
| `P2-PERSISTENCE` | Goals, identity/preferences, approvals, grants, allowed focus continuity, audit, and outbox survive restart. Observation/context/model content does not. SQLite pragmas, DACL, owner repositories, integrity, and expiry pass. | NOT RUN |
| `P2-UPGRADE` | A real Phase 1 schema/package upgrades to the Phase 2 release through the checked migration/recovery-copy procedure, leaving one healthy daemon/package and preserving only supported state. Forced migration failure restores safely. | NOT RUN |
| `P2-SECRETS` | Credential Manager synthetic write/read/replace/delete/restart behavior passes; no client read API or fallback exists; normal uninstall and explicit remove-data semantics are correct. | NOT RUN |
| `P2-IDENTITY` | Versioned STEIN identity and direct-user preferences persist, revision conflicts fail, stricter preferences affect policy, and observations/model/feedback never learn a durable preference implicitly. | NOT RUN |
| `P2-GOALS` | Public create/update/complete/abandon/delete behavior is idempotent/revisioned/direct-user-only and persists across restart/upgrade with the documented cascade. | NOT RUN |
| `P2-GRANTS` | Every observation, model, and notification scope is independently grantable/revocable; missing, narrower, wrong-resource, wrong-route, expired, superseded, and restart-disallowed grants fail. | NOT RUN |
| `P2-CONSENT` | Installed desktop shows category/resource/purpose/off-device/expiry/continuity/retention disclosures and separate mute, stop, revoke, and delete controls before authority is created. | NOT RUN |
| `P2-PRESENCE` | WTS/session and `GetLastInputInfo` adapter reports bounded active/idle/locked health without input content; lock/switch/logout pauses sensitive work and unlock waits for fresh health. | NOT RUN |
| `P2-APPLICATION` | Selected Notepad/foreground identity succeeds; unrelated application identity is not inventoried; title/content/pixels remain unavailable under the narrower grant. | NOT RUN |
| `P2-DOCUMENT` | Exact handle-bound synthetic document/workspace emits only authorized activity/content; reparse, rename, replacement, path escape, unrelated file, and revocation fixtures fail closed. | NOT RUN |
| `P2-BROWSER` | Exact published Edge Add-ons MV3 version and the OS-admitted one-way native-host producer honor the selected profile, tab, origin/site, and URL granularity; unpacked/spoofed bundles, history, background, unrelated, and protected content are absent. | NOT RUN |
| `P2-UIA` | Selected Notepad `HWND` yields bounded structured visible text; password, secure/protected, consent, other-window, and unverifiable UIA fixtures pause or report unavailable. | NOT RUN |
| `P2-PIXELS` | Explicit Windows Graphics Capture picker/region and separate pixel grant work with visible status; one transient bounded frame is destroyed and structured input wins when sufficient. | NOT RUN |
| `P2-MODEL-CONTRACT` | Golden packets prove least-sensitive grant/route intersection; no unapproved category, tool, provider object, prompt, raw response, or credential crosses the gateway/persistence/diagnostic boundaries. | NOT RUN |
| `P2-MODEL-LIVE` | One live synthetic OpenAI Responses request uses the approved exact route, `store: false`, strict schema, no tools/state/background features, deadline/cancellation, and truthful handling disclosure. | NOT RUN |
| `P2-SILENCE` | Healthy relevant-writing/research trace produces no model call or intervention merely because foreground activity changes. | NOT RUN |
| `P2-INTERVENTION` | Near-deadline missing-success-condition trace produces one validated candidate, deterministic allow decision, acknowledged audit append, and one native notification with uncertainty-qualified text. | NOT RUN |
| `P2-POLICY-FAILSAFE` | Stale source, invalid/tool-shaped/refusal output, absent/expired authority, lock, mute, cap/cooldown, model failure, policy failure, and audit failure all produce silence/deny. | NOT RUN |
| `P2-NATIVE-CONTROL` | With Tauri closed, native tray/status shows exact capture categories and health, emergency stop takes authority immediately, and Explorer/status-loop loss pauses capture until revalidation. | NOT RUN |
| `P2-NOTIFICATION` | With Tauri closed and Windows unlocked, daemon-owned native toast is accepted under the registered AUMID; activation uses only opaque arguments; audit distinguishes accepted from displayed/seen. | NOT RUN |
| `P2-OUTBOX-RECOVERY` | All channels unavailable queues one minimal item; recovery before expiry revalidates and attempts it once; ambiguous/acknowledged state does not duplicate. | NOT RUN |
| `P2-OUTBOX-EXPIRY` | Recovery after expiry/relevance loss removes private text and shows only non-interruptive missed history, without a notification burst. | NOT RUN |
| `P2-FEEDBACK` | Accept, dismiss, correct, mute, and stop work through authoritative commands. Correction changes current context/explanation but not historical decision, identity, preferences, or memory. | NOT RUN |
| `P2-REVOCATION-RACE` | Deterministic races prove revoke/cancel beats late observation, reasoning, queue, and every delivery not terminally acknowledged; cleanup failure remains visible without restoring authority. | NOT RUN |
| `P2-DESKTOP-CLOSED` | Active background-authorized focus session continues capture, context, scheduling, reasoning, status, and native delivery while the full desktop is closed; reconnect replaces cache with an authoritative snapshot/cursor. | NOT RUN |
| `P2-DAEMON-RESTART` | Only unexpired restart-authorized work recovers; unauthorized work stops; all source health/context resets to unknown; no absence reasoning occurs before fresh evidence. | NOT RUN |
| `P2-RETENTION` | Controllable clock proves raw-immediate, observation-10-minute, context-session, outbox-actionability, and audit-30-day boundaries plus direct deletion across every read/assembly/export path. | NOT RUN |
| `P2-NO-LEAKS` | Database/journal/recovery copy, Credential Manager metadata, logs, errors, traces, audit, outbox, protocol, crash output, package, and retained evidence contain none of the prohibited raw/private/secret fields. | NOT RUN |
| `P2-PORTABLE-FIXTURE` | Complete semantic session/policy/outbox/restart fixture passes against fake adapters on a non-Windows host; domain/application/protocol crates import no Windows/OpenAI/SQLite/Tauri types. | NOT RUN |

The `P2-RETENTION` source fixture invokes the public one-shot maintenance path
with a controllable clock immediately before, exactly at, and after the
configured TTL. It also proves that a quiet session is swept on the daemon's
bounded cadence, with no more than 60 seconds between sweeps, and that shutdown
cancels and joins the owner task without waiting for the next tick. Passing this
source fixture does not change the ledger row from `NOT RUN`; the complete
installed acceptance gate is still required.

## Nominal installed trace

The retained trace must show, in order:

1. Install the signed Phase 2 package non-elevated and prove one supervised CORE
   daemon is healthy before the desktop opens.
2. Configure the provider secret through the trusted native surface without
   exposing it to React or the transcript.
3. Open the capability-bound desktop and approve the exact remote OpenAI route,
   provider handling profile, and only the data categories used by the fixture.
4. Create a durable Project Atlas goal with a success statement and deadline.
5. Select the synthetic Notepad document/workspace, Edge profile/site, and the
   exact independent observation/notification grants; leave pixels off initially.
6. Start the focus session and prove native status acknowledges the active
   category/resource set before capture begins.
7. Feed healthy relevant editing/research observations and retain the justified-
   silence trace, including proof that foreground change alone made no model call.
8. Close the full desktop and prove CORE, capture, context, timers, native status,
   and current grants remain active.
9. Produce the synthetic near-deadline missing-recommendation evidence. Inspect
   the minimized request, strict model result, deterministic policy decision, and
   audit acknowledgement.
10. Receive exactly one native toast while the desktop remains closed. Record only
    `accepted_by_channel` unless stronger evidence actually exists.
11. Activate the toast, reconnect through a fresh private session, and inspect the
    authoritative goal/session/intervention explanation.
12. Record a correction, then a new direct goal update. Prove the correction
    changes current context without rewriting history or learning a preference.
13. Mute and unmute delivery independently from observation, then use the native
    emergency stop and prove authority fails immediately and transient data is
    removed.
14. Complete the goal, end the session, and verify grants expire, adapters stop,
    outbox entries cancel, and session observation/context disappears.
15. Restart CORE and prove durable goal/preferences/approval/audit remain while no
    observation or working context returns.

## Required alternate traces

The nominal trace cannot substitute for these deterministic fixtures:

- stale/unhealthy evidence suppresses the deadline-risk intervention;
- revocation/cancellation wins a race with unacknowledged delivery;
- model timeout, invalid schema, tool-shaped output, refusal, and provider outage
  remain silent;
- forced audit failure prevents notification submission;
- unavailable channel queues one item, recovery delivers once, and expired
  recovery creates missed history only;
- daemon restart restores only explicitly authorized continuity and waits for
  fresh health;
- status/control loss pauses capture;
- lock/switch/logout suppresses private capture and toast content;
- direct deletion removes private content from every public read path; and
- duplicate commands/events/recovery triggers cannot create duplicate session,
  grant, audit, outbox, or intervention records.

## Disruptive Windows fixtures

Phase 2 handles private observation, so the following are required rather than
carried as the Phase 1 POC's unclaimed follow-ups:

- real sign-out/sign-in recovery under the owning user;
- lock/unlock and switch-away/switch-back while capture and pending delivery are
  active;
- a direct owning-endpoint attempt from a second standard Windows SID;
- an unpackaged and same-SID adversarial private-client attempt;
- a real previous-version-to-current-version package/schema upgrade; and
- uninstall with preservation followed by explicit current-user remove-data,
  including database, recovery artifact, Credential Manager, package/AppContainer,
  AUMID/toast, MV3/native-host, task, process, and endpoint cleanup.

If the required second account, package-signing identity, provider credential, or
published Microsoft Edge Add-ons extension identity/version, or interactive
lifecycle fixture is unavailable, record the gate as `BLOCKED` and do not call
the Windows Phase 2 slice complete.

## Completion claim

The allowed claim after every row passes is:

> The Phase 2 first second-mind loop is implemented, installed, and verified on
> Windows using synthetic acceptance content. Linux and macOS platform adapters
> remain unclaimed.

Do not shorten this to “Phase 2 is complete everywhere,” and do not describe
channel acceptance as a seen notification, configured adapters as healthy before
their native proof, or provider `store: false` as Zero Data Retention.
