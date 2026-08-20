# Phase 1 Windows POC evidence — 2026-08-19

Status: Passed for the installed morning proof of concept

This record summarizes the native Windows verification run. Raw machine output
is retained locally under
[`artifacts/evidence/20260819-130728`](../../artifacts/evidence/20260819-130728/).
The raw directory is intentionally excluded from source control because it
contains host-specific account and path data.

## Verified host and package

- Windows 11 Pro, x86-64, build 26200.
- Normal non-administrator user token.
- Rust `1.97.1`, Cargo `1.97.1`, Node `24.15.0`, and pnpm `11.21.0`.
- Package version `0.1.0`, target `windows-x86_64`.
- The package manifest records the size and SHA-256 digest of all three
  executables, lifecycle scripts, launchers, and package documentation.
- Installation revalidates that manifest before replacing installed files.

## Results

| Area | Native result |
| --- | --- |
| Build quality | Rust formatting, workspace check, Clippy with warnings denied, 48 Rust tests, TypeScript type checking, ESLint with zero warnings, 26 desktop/contract tests, release CORE/CLI build, and release Tauri build passed. |
| Independent daemon | CORE was healthy with exactly one installed daemon and no desktop process. |
| Protected IPC | Current-user client/server token checks passed on the live named pipe; incompatible protocol major was rejected; the daemon remained healthy. |
| Canonical state | The CLI created a synthetic goal, received its event, repeated the idempotent command without duplication, disconnected, and recovered the goal from a new session snapshot on the same daemon. |
| Cancellation | The client received the matching cancellation acknowledgement and terminal cancelled response within the bounded confirmation window. |
| Capacity | Eight sessions were accepted, the overflow session was rejected, a released slot accepted a replacement, and CORE remained healthy. |
| Desktop | The packaged desktop form issued `CreateGoal`; the resulting goal and live event were visible alongside the 7/14 capability summary. All seven deferred rows were visibly unavailable. Closing did not stop CORE, and reopening recovered the same goal from the same daemon. Installed CORE/desktop hashes matched the proof package. |
| Supervision | The installed launcher consumed a one-shot synthetic failure marker and started a new daemon instance in about 1.7 seconds; Task Scheduler's bounded restart configuration was also inspected. |
| Reinstall | Two consecutive installs of the exact proof package left one SID-qualified task and one installed daemon. |
| Uninstall | The task, CORE/desktop processes, binary directory, and pipe endpoint were absent; the data directory remained. The same package was then restored. |

## Final installed condition

The proof package was restored after the uninstall test. The final status was
healthy with one running limited, interactive-user scheduled task, one CORE
process, no desktop process, and protocol version `1.0`. A current-user desktop
shortcut named `STEIN` was present. The task has a logon trigger, ignores
duplicate starts, remains enabled on battery, has no execution time limit, and
uses bounded restart-on-failure settings.

Deferred Phase 2 capabilities were deliberately reported as unavailable:
desktop observation, model reasoning, durable persistence, native notification,
native background status, emergency control, and the platform secret store. No
fake adapter reported success.

## Raw evidence index

- [Clean build and test output](../../artifacts/evidence/20260819-130728/build-output.txt)
- [Host and toolchain record](../../artifacts/evidence/20260819-130728/host-toolchain.json)
- [Package manifest](../../artifacts/evidence/20260819-130728/package-manifest.json)
- [Final install output](../../artifacts/evidence/20260819-130728/final-install-output.txt)
- [Scheduled-task record](../../artifacts/evidence/20260819-130728/scheduled-task.json)
- [Packaged smoke report](../../artifacts/evidence/20260819-130728/smoke-report.json)
- [Connected desktop command/event view](../../artifacts/evidence/20260819-130728/desktop-connected-goal-event.png)
- [Deferred-capability view](../../artifacts/evidence/20260819-130728/desktop-unavailable-capabilities.png)
- [Reopened desktop state](../../artifacts/evidence/20260819-130728/desktop-reopened-state.png)
- [Desktop identity and package-hash proof](../../artifacts/evidence/20260819-130728/desktop-proof.json)
- [Same-package reinstall proof](../../artifacts/evidence/20260819-130728/reinstall-proof.json)
- [Uninstall proof](../../artifacts/evidence/20260819-130728/uninstall-proof.json)
- [Final healthy status](../../artifacts/evidence/20260819-130728/final-status.json)
- [Machine-readable final evidence validation](../../artifacts/evidence/20260819-130728/final-evidence-validation.json)
- [CORE normal dependency tree](../../artifacts/evidence/20260819-130728/stein-core-dependency-tree.txt)

## Explicitly unclaimed host fixtures

- A real sign-out/sign-in was not performed because it would end the autonomous
  work session. The installed logon trigger was inspected.
- A direct connection attempt from a different Windows SID was not performed
  because no second account or credentials were available. The current-user
  DACL, remote-client rejection, and mutual process-token SID checks are
  implemented, but this runtime path remains unclaimed.
- A version-to-version upgrade was not possible because only `0.1.0` exists.
  Exact-package replacement and install idempotency passed.

These limitations do not block hands-on use of the installed morning POC, but a
platform should not be called fully supported beyond the POC until its relevant
host fixtures have been run.
