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
- A generic JSON success result, process exit zero, or self-declared review
  boolean is not gate evidence. The result must satisfy the checked-in exact
  gate contract and bind the underlying proof bytes.

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

Use `scripts\windows\phase2\Verify-Installed.cmd` as the fail-closed collector
for the read-only installed baseline. It requires the exact signed MSIX and its
adjacent identity/CORE/CLI companions plus the operator-pinned Publisher,
certificate thumbprint, and four-component version. Each run creates a new
owner-only timestamped evidence directory and records host provenance, the
verified bundle and installed identity hashes, the existing lifecycle/status
projection, every command result, and a separately hashed artifact for every
ledger row. It performs no install, upgrade, uninstall, daemon/task lifecycle,
secret-store, database, or private-protocol mutation. Temporary MSIX unpacking
is verification scratch state, not installed-state mutation.

The collector compares the fixed installed AppX manifest, desktop, broker, and
browser-producer executables, CORE binding, and logo assets byte-for-byte with
hashes derived from the operator-pinned signed MSIX. Matching PFN, AUMIDs,
Publisher, and version without those installed-file hashes is insufficient. It
also requires the exact deployed file layout: AppX block-map/signature metadata,
the eight hashed application files, and only the optional exact
`AppxMetadata\CodeIntegrity.cat` catalog. Any other installed file fails the
baseline rather than being treated as harmless attachment or metadata.
Native signature/unpack output is suppressed so local source and temporary
paths do not enter transcripts. `generator.json` binds the harness and every
loaded/executed PowerShell dependency by repository-relative path, size, and
SHA-256 and is revalidated before ledger creation. `root-anchor.json` then binds
the generator, host, and ledger hashes to the run. This is a content-integrity
root rather than a signature; retain the printed root digest independently when
post-run tamper evidence is required.

This collector is intentionally narrower than the completion ledger. Passing
its signed-bundle, installed PFN/AUMID/CoreBinding, daemon/task/process/ACL, and
durable-persistence readiness checks is supporting evidence only. It does not
promote a broad ledger row when the required restart, mutation, adversarial,
interactive, native, provider, or external fixture was not executed. A harness
exit code of zero means only that those read-only machine checks passed and the
ledger was written; inspect `complete_acceptance`, which remains false until all
rows have separately sufficient evidence. The expected `phase2-focus-v1` policy
profile is recorded as an unverified expectation because the diagnostic status
contract does not publish owner policy state; policy-dependent rows therefore
cannot pass from this harness alone.

Operator screenshots and native-fixture results may be attached through the
closed schema-2 manifest documented beside the harness. The checked-in
`Evidence-Spec.json` fixes all 32 gate IDs and, per gate, the exact
fixture/runner IDs, proof classes, required subchecks, proof origin, and
package/commit/source/Linux/runner bindings. Every proof artifact is mapped by
content-free ID to exact size and SHA-256. Bounded JSON is hashed and strictly
decoded from one locked byte capture, and the exact tree is rechecked through
finalization. The collector retains neither the local paths nor private proof
payloads.

Source-origin subchecks map to exact passing check IDs in the separately
supplied source report only after that report/root chain equals the candidate
commit/tree and source digests attested by the signed schema-3 CoreBinding.
Installed-native and Linux-CI subchecks must cite their own exact artifacts;
source tests cannot silently stand in for native behavior. The private denial,
toast COM denial, Linux portable, no-leaks scanner, and no-leaks producer
receipts have closed identities and exact ordered subchecks. Screenshots are
always supplemental. A declared native pass remains `not_run` pending
independent semantic/privacy review; failure or blockage may only lower the row.
Missing or mismatched proof remains `not_run`, `blocked`, or `fail`, never pass.
The source-evidence generator hash includes the checked-in evidence policy and
contract plus `Scan-NoLeaks.ps1`, its fixed launcher, and its dual-shell test.
`no-leaks-scanner-static` validates those scanner mechanics but is deliberately
not the required `no-leaks-producer-workflow` check and cannot promote
`P2-NO-LEAKS`. The producer check is present in the source report as explicit
`not_run` evidence with the bounded reason that the candidate-owned installed
artifact producer is not implemented.

The same checked-in contract fixes the full 44-row source-report check set (38
required `pass`; six exact frozen `not_run`) and the exact seventeen generator
paths. Source provenance schema 2 records both the
launcher shims and the rustup-selected Cargo/rustc payload hashes/toolchain ID,
the pnpm JavaScript entrypoint hash, and both the Git-for-Windows launcher and
resolved `mingw64\bin\git.exe` payload; a proxy or command shim alone is not
accepted as tool identity.

Each named source subcheck maps to an exact check ID set. A generic
`rust-tests` pass does not prove that a gate-specific fixture exists or ran.
The frozen source-fixture registry (`SHA-256
d2414e552dfbc00b3ecf5837cfc431c64f670508ae4e8696b9fce4f85a75c5c5`)
defines 13 fixtures and 71 ordered subchecks. The runner exports the exact Git
tree, creates fresh private Cargo home/target directories, compiles eight closed
harnesses, requires exact test discovery, and invokes only hash-locked test
binaries. Its 140 mappings produce 117 per-fixture execution records (107
globally unique identities); each receipt binds the candidate tree, semantic
source bytes/Git blobs, environment, harness binary, exact command, result, and
suite index.

Every source-origin subcheck also requires
`native-toolchain-provenance=pass`, `pinned-clean-build-environment=pass`, and
`source-report-command-provenance=pass`. All three remain exact `not_run`
because authenticated Rust/Git/native dependency closure, immutable isolated
execution for every non-fixture source check, and independently attested
commands are not implemented. This blocks all source-backed promotion while
leaving native-only gates independently reviewable.

The signed schema-3 build exports and locks the selected Git tree, uses private
Cargo targets/home and fresh frozen-lockfile renderer output, and signer-binds
the CLI, desktop executable, and desktop distribution. It remains explicitly
non-hermetic: `native-toolchain-provenance` and
`source-report-command-provenance` are `not_run`, so `P2-BUILD` cannot promote
until the exact native payload/library set and independently closed per-check
command/argument/working-directory provenance are implemented.

## Completion ledger

| Gate | Required proof | Result before execution |
| --- | --- | --- |
| `P2-BUILD` | Rust format/check/Clippy with warnings denied/tests, TypeScript typecheck/lint/tests, release CORE/CLI/Tauri/MSIX/native-host build, and dependency-boundary checks all pass without skip flags. | NOT RUN |
| `P2-PHASE1-REGRESSION` | Every applicable Phase 1 protocol, cancellation, capacity, lifecycle, install, supervision, reconnect, reinstall, and uninstall gate still passes. | NOT RUN |
| `P2-PRIVATE-CLIENT` | Exact signed installed MSIX PFN/AppContainer peer obtains a private session. Unpackaged copy, renamed binary, valid-protocol same-SID adversary, spoofed AUMID/PFN text, replayed capability, prior daemon, and wrong SID cannot access private commands/views. | NOT RUN |
| `P2-PERSISTENCE` | Goals, identity/preferences, approvals, grants, allowed focus continuity, audit, and outbox survive restart. Observation/context/model content does not. SQLite pragmas, DACL, owner repositories, integrity, and expiry pass. | NOT RUN |
| `P2-UPGRADE` | A real Phase 1 schema/package upgrades to the Phase 2 release through the checked migration/recovery-copy procedure, leaving one healthy daemon/package and preserving only supported state. Forced migration failure restores safely. | NOT RUN |
| `P2-SECRETS` | Credential Manager synthetic write/read/replace/delete/restart behavior passes; forced route-revocation delete failure leaves an opaque durable obligation that startup/maintenance retries without restoring authority; no client read API or fallback exists; normal uninstall and explicit remove-data semantics are correct. | NOT RUN |
| `P2-IDENTITY` | Versioned STEIN identity and direct-user preferences persist, revision conflicts fail, stricter preferences affect policy, and observations/model/feedback never learn a durable preference implicitly. | NOT RUN |
| `P2-GOALS` | Public create/update/complete/abandon/delete behavior is idempotent/revisioned/direct-user-only and persists across restart/upgrade with the documented cascade. | NOT RUN |
| `P2-GRANTS` | Every observation, model, and notification scope is independently grantable/revocable; missing, narrower, wrong-resource, wrong-route, expired, superseded, and restart-disallowed grants fail. | NOT RUN |
| `P2-CONSENT` | Installed desktop shows category/resource/purpose/off-device/expiry/continuity/retention disclosures and separate mute, stop, revoke, and delete controls before authority is created. | NOT RUN |
| `P2-PRESENCE` | WTS/session and `GetLastInputInfo` adapter reports bounded active/idle/locked health without input content; lock/switch/logout pauses sensitive work and unlock waits for fresh health. | NOT RUN |
| `P2-APPLICATION` | Selected Notepad/foreground identity succeeds; unrelated application identity is not inventoried; title/content/pixels remain unavailable under the narrower grant. | NOT RUN |
| `P2-DOCUMENT` | Exact handle-bound synthetic document/workspace emits only authorized activity/content; reparse, rename, replacement, path escape, unrelated file, and revocation fixtures fail closed. | NOT RUN |
| `P2-BROWSER` | Exact published Edge Add-ons MV3 version and the OS-admitted one-way native-host producer honor the selected profile, tab, origin/site, and URL granularity; unpacked/spoofed bundles, history, background, unrelated, and protected content are absent; daemon restart requires a fresh extension invocation, selection, and grant. | NOT RUN |
| `P2-UIA` | Selected Notepad `HWND` yields bounded structured visible text; password, secure/protected, consent, other-window, and unverifiable UIA fixtures pause or report unavailable. | NOT RUN |
| `P2-PIXELS` | Explicit Windows Graphics Capture picker/region and separate pixel grant work with visible status; one transient bounded frame is destroyed and structured input wins when sufficient. | NOT RUN |
| `P2-MODEL-CONTRACT` | Golden packets prove least-sensitive grant/route intersection; no unapproved category, tool, provider object, prompt, raw response, or credential crosses the gateway/persistence/diagnostic boundaries. | NOT RUN |
| `P2-MODEL-LIVE` | One scheduler-owned live synthetic OpenAI Responses request uses the durable approved exact route, `store: false`, strict schema, no tools/state/background features, deadline/cancellation, and truthful handling disclosure; after reconnect, the authenticated read-only receipt has a new request ID/start time and completes for that exact session/approval/revision without exposing content. The adapter-only paid test cannot promote this row. | NOT RUN |
| `P2-SILENCE` | Healthy relevant-writing/research trace produces no model call or intervention merely because foreground activity changes. | NOT RUN |
| `P2-INTERVENTION` | Near-deadline missing-success-condition trace produces one validated candidate, deterministic allow decision, acknowledged audit append, and one native notification with uncertainty-qualified text. | NOT RUN |
| `P2-POLICY-FAILSAFE` | Stale source, invalid/tool-shaped/refusal output, absent/expired authority, lock, mute, cap/cooldown, model failure, policy failure, audit failure, legacy/empty policy trace, or policy/profile/preference/grant/route revision mismatch all produce silence/deny; evaluated significance and intervention audits retain only the exact content-free policy trace/digest. | NOT RUN |
| `P2-NATIVE-CONTROL` | With Tauri closed, native tray/status shows exact capture categories and health, emergency stop takes authority immediately, and Explorer/status-loop loss pauses capture until revalidation. | NOT RUN |
| `P2-NOTIFICATION` | With Tauri closed and Windows unlocked, daemon-owned native toast is accepted under the registered AUMID; the fixed packaged COM activator accepts only `action=open&intervention=<canonical UUID>`, opens/focuses Tauri, reconnects through the private broker, and resolves the typed authoritative explanation; malformed, input-bearing, wrong-AUMID, unpackaged, and diagnostic activation fixtures fail closed; audit distinguishes accepted from displayed/seen. | NOT RUN |
| `P2-OUTBOX-RECOVERY` | All channels unavailable queues one minimal item; recovery before expiry revalidates and attempts it once. Direct and queued crash fixtures prove no native call precedes the atomic audited `delivering` marker; a crash after that marker, after OS submission, or before terminal audit becomes `delivery_unknown` without retry. Runtime startup atomically repairs legacy outbox-unknown/intervention-delivering and other queued/terminal mismatches before reactivation; repository open never performs outbox-only semantic recovery. | NOT RUN |
| `P2-OUTBOX-EXPIRY` | Recovery after expiry/relevance loss removes private text and shows only non-interruptive missed history, without a notification burst. | NOT RUN |
| `P2-FEEDBACK` | Accept, dismiss, correct, mute, and stop work through authoritative commands. Correction changes current context/explanation but not historical decision, identity, preferences, or memory. | NOT RUN |
| `P2-REVOCATION-RACE` | Deterministic races prove revoke/cancel beats late observation, reasoning, queue, and every delivery not terminally acknowledged; native-resource and credential cleanup failures remain durably pending and visible through content-free health/counts without restoring authority. | NOT RUN |
| `P2-DESKTOP-CLOSED` | Active background-authorized focus session continues capture, context, scheduling, reasoning, status, and native delivery while the full desktop is closed; reconnect replaces cache with an authoritative snapshot/cursor. | NOT RUN |
| `P2-DAEMON-RESTART` | Only unexpired restart-authorized work recovers; unauthorized work stops; all source health/context resets to unknown; no absence reasoning occurs before fresh evidence. | NOT RUN |
| `P2-RETENTION` | Controllable clock proves raw-immediate, observation-10-minute, context-session, outbox-actionability, and audit-30-day boundaries plus direct deletion across every read/assembly/export path. | NOT RUN |
| `P2-NO-LEAKS` | A candidate-owned fixed producer injects the public synthetic sentinel through every defined sink and emits its closed producer/source/manifest proof; the closed scanner then proves database/journal/recovery copy, Credential Manager metadata, logs, errors, traces, audit, outbox, protocol, crash output, package, and retained evidence contain no sentinel or prohibited raw/private/secret fields. Producer and scanner package/commit/source/catalog bindings must match. | NOT RUN |
| `P2-PORTABLE-FIXTURE` | Complete semantic session/policy/outbox/restart fixture passes against fake adapters on a non-Windows host with exact extracted log hashes/sizes; domain/application/protocol crates import no Windows/OpenAI/SQLite/Tauri types. The retained artifact is content-integrity evidence unless GitHub execution provenance is authenticated separately. | NOT RUN |

`P2-NO-LEAKS` cannot pass from the scanner receipt or its synthetic self-test
alone. It also requires the fixed `phase2-no-leaks-sentinel-producer-v1`
receipt, producer source and manifest artifacts, and a passing exact
`no-leaks-producer-workflow` source-report check. That real producer/check is not
yet present, so the row remains `NOT RUN` even when the scanner's isolated
synthetic fixtures pass.

The `P2-PORTABLE-FIXTURE` schema binds the candidate, workflow/toolchain hashes,
seven named check receipts, and each extracted log's bytes. Its fixture and
runner IDs are not by themselves authenticated GitHub Actions provenance;
retain a separately authenticated run/attestation when that assurance is
needed.
The gate additionally requires the exact `portable-runner-attestation` source-
report check. It remains `not_run` until an authenticated GitHub artifact
attestation or equivalent Sigstore bundle binds the repository, workflow,
candidate commit, and portable-artifact digest. A self-declared schema-1 JSON
and `runner_id` cannot promote the gate.

For installed-only gates, the explicit trust boundary is a trusted independent
reviewer who inspects the exact signed package, closed fixture receipts,
underlying artifact hashes, and native semantics before promotion. The retained
mechanism is tamper-evident and content-bound, but it is not proof against a
malicious evidence owner and does not cryptographically authenticate a local
runner controlled by that same owner. The portable gate is stricter because it
asserts execution by an external GitHub runner and therefore remains blocked on
the separate attestation obligation above.

The `P2-RETENTION` source fixture invokes the public one-shot maintenance path
with a controllable clock immediately before, exactly at, and after the
configured TTL. It also proves that a quiet session is swept on the daemon's
bounded cadence, with no more than 60 seconds between sweeps, and that shutdown
cancels and joins the owner task without waiting for the next tick. Passing this
source fixture does not change the ledger row from `NOT RUN`; the complete
installed acceptance gate is still required.

The source maintenance fixture also injects controllable native-resource release
and secret-store deletion failures. It proves startup and periodic sweeps retry
bounded private obligations across SQLite restart, treat already-absent native
state as success, and never recreate a selected-resource binding or model-route
authority. Private identifiers and adapter error text are excluded from
operational reporting. As above, this source proof does not change an installed
ledger row from `NOT RUN`.

The source cancellation fixtures separately prove that scheduler shutdown,
global proactive disable, and session mute signal adapter-visible cancellation;
mute does not stop observation authority; native-delivery timeout explicitly
cancels its port token; and queued intervention/outbox text is scrubbed before a
restrictive command returns. These deterministic fixtures support
`P2-POLICY-FAILSAFE`, `P2-FEEDBACK`, and `P2-REVOCATION-RACE`, but none replaces
the installed race evidence required by those ledger rows.

The Windows pixel source fixtures additionally prove canonical content-free
`winpixel:v1` bindings, picker-only API use, exact `ScreenRegion` authority,
10-second rate configuration, 1920 by 1080 / 8 MiB transient bounds, one-frame
normalization, CPU-buffer zeroization, blank/protected rejection, cancellation,
revocation, and a process-wide disposable-worker cap. Deterministic composition
tests prove browser/document/UIA/window-metadata sources start first and that an
active structured source creates no frame. The two native Graphics Capture
tests remain ignored because one needs an unlocked interactive session and the
other opens the real system picker. These source tests do **not** change
`P2-PIXELS` from `NOT RUN`.

To execute the native pixel gate, use the signed installed Phase 2 build in an
unlocked current-user session. Select a synthetic window or display through the
Windows Graphics Capture picker, approve only the exact `ScreenRegion` resource
and `observe.screen.pixels` grant, and retain the visible Windows border plus
STEIN native-status evidence. First keep a structured browser/document/UIA
source active and prove the adapter reports pixel deferral with no frame. Then
stop that structured source, make a fresh explicit pixel selection, run one
capture, and inspect process/database/log/audit/outbox/protocol artifacts for
the absence of image bytes. Lock, switch session, revoke the item, cancel, and
restart the daemon; each must destroy or drop transient state and require fresh
selection. Only after that installed trace is retained may `P2-PIXELS` change
from `NOT RUN`.

## Nominal installed trace

The retained trace must show, in order:

1. Install the signed Phase 2 package non-elevated and prove one supervised CORE
   daemon is healthy before the desktop opens.
2. From the capability-bound desktop, run the single native route-setup
   transaction for the exact remote OpenAI route, reviewed handling profile, and
   only the data categories used by the fixture. Prove React and the transcript
   receive no credential bytes: Rust validates the approval before CredUI,
   retains the entered value only in zeroizing native memory, approves first,
   and writes Credential Manager last under the canonical approval UUID returned
   by CORE, never under the provider route ID shown by the prompt.
3. Exercise native-prompt cancellation, daemon approval failure, and final
   credential-write failure for both a new and existing synthetic target. The
   first two leave the target absent or byte-identical; the last attempts to
   revoke its newly approved route, deletes only that approval's target on
   successful compensation, leaves any prior approval target byte-identical,
   and emits only the bounded setup error.
4. Create a durable Project Atlas goal with a success statement and deadline.
5. Select the synthetic Notepad document/workspace, Edge profile/site, and the
   exact independent observation/notification grants; leave pixels off initially.
6. Start the focus session and prove native status acknowledges the active
   category/resource set before capture begins.
7. Feed healthy relevant editing/research observations and retain the justified-
   silence trace, including proof that foreground change alone made no model call.
   Before closing the desktop, use **Check latest model request receipt** on the
   focus-session card and retain the current content-free result as a baseline
   (including absence); a later pass must use a different request ID and a start
   time after the synthetic trigger. This read-only control does not request a
   model call.
8. Close the full desktop and prove CORE, capture, context, timers, native status,
   and current grants remain active.
9. While the desktop remains closed, produce the synthetic near-deadline
   missing-recommendation evidence and let the daemon scheduler make the request
   through the durable approved route; do not add or use a paid-call trigger
   command. Inspect the minimized request, strict model result, deterministic
   policy decision, and audit acknowledgement separately without reopening the
   desktop yet.
10. Receive exactly one native toast while the desktop remains closed. Record only
    `accepted_by_channel` unless stronger evidence actually exists.
11. Activate the toast and reconnect through a fresh private session. In the
    authoritative focus-session card, use **Check latest model request receipt**;
    the shipped control invokes only the authenticated read-only
    `desktop_get_latest_model_request_receipt` query. This nominal
    toast-producing trace requires a
    `completed_strict_candidate` receipt whose request ID differs from the
    step-7 baseline, whose start time follows the step-9 trigger, and whose
    focus-session ID, approval ID, and route revision match the authoritative
    views and inspected trace. The receipt contains no prompt, response,
    candidate text, provider error/status/ID, endpoint, secret reference, or
    credential state and disappears on session end/restart. Inspect the
    authoritative goal/session/intervention explanation.
    Retain the content-free activation trace proving the fixed desktop AUMID,
    intervention UUID, private connection, explanation response, and dashboard
    refresh. Repeat while Tauri is already running, then exercise malformed,
    extra-key, uppercase/noncanonical UUID, input-bearing, wrong-AUMID,
    unpackaged-marker, and diagnostic-only fixtures; none may resolve or display
    private state.
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
- direct and recovered notification crashes before the durable attempt marker
  make no native call; crashes after the marker or after Windows submission are
  audited as `delivery_unknown` and never resubmitted, including the legacy
  outbox-unknown/intervention-delivering restart fixture;
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

`P2-BROWSER` currently has source-owned build, package, registration, one-way
transport, fresh-authority, selection, cancellation, and cleanup contracts. It
is still **NOT RUN**. The irreducible residual is a real published Edge Add-ons
ID/version plus a clean installed direct-Edge-launch fixture proving that the
native host token carries the exact signed package PFN and
`!BrowserObservationProducer` AUMID. Parent/publisher/origin evidence and a
successful static build cannot substitute for that runtime admission.

## Completion claim

The allowed claim after every row passes is:

> The Phase 2 first second-mind loop is implemented, installed, and verified on
> Windows using synthetic acceptance content. Linux and macOS platform adapters
> remain unclaimed.

Do not shorten this to “Phase 2 is complete everywhere,” and do not describe
channel acceptance as a seen notification, configured adapters as healthy before
their native proof, or provider `store: false` as Zero Data Retention.
