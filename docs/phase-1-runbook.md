# Phase 1: Windows Verification Runbook

Status: Windows proof of concept complete and installed; reusable verification
procedure retained below

This runbook turns the [Phase 1 roadmap exit criteria](roadmap.md#phase-1-core-foundation-and-desktop-handshake)
into repeatable Windows evidence. It is also the morning test path for the first
Phase 1 implementation and verification host. The dated evidence from the
completed local run is under
[`artifacts/evidence/20260819-130728`](../artifacts/evidence/20260819-130728/).
A source-controlled, host-data-free summary is available in the
[dated evidence record](evidence/phase-1-windows-20260819.md).

Run these checks from native Windows PowerShell, not WSL, under the Windows user
that will own the per-user CORE daemon. Use synthetic goal text only. The build
may download Rust and JavaScript dependencies on its first run.

## Morning quick test

The proof package is already installed for the current user. From
`C:\projects\STEIN`, run:

```powershell
.\artifacts\windows\status.cmd -Json
Start-Process "$env:LOCALAPPDATA\STEIN\bin\stein-desktop.exe"
```

The status command should return `"healthy": true`. In the desktop, confirm
`CORE Is Ready`, create a synthetic goal, close the window, run status again,
and reopen the desktop. CORE should remain on the same daemon instance while
the goal returns from its authoritative in-memory snapshot. The installed
desktop shortcut named `STEIN` opens the same executable.

## Scope and expected limitations

Phase 1 proves the presentation-independent daemon, protected local protocol,
authoritative snapshot/event flow, desktop visualization and control, and
Windows supervision. Goal state is deliberately in memory and may be lost when
the daemon restarts.

Observation, model reasoning, durable persistence, native notification delivery,
native background status/emergency control, and the platform secret store are not
implemented capabilities in this phase. Their adapters must report
`unavailable` or `not_implemented`; that is a passing Phase 1 result. Returning a
fake secret, fake delivery acknowledgement, or false healthy state is a failure.
Real implementations and the bounded pending-delivery behavior enter Phase 2.

The accepted local trust boundary is one signed-in operating-system user, as
defined by [ADR 0003](decisions/0003-version-the-typed-client-protocol.md#same-user-trust-implication).
Any process running as that same Windows user may attempt to connect to CORE and,
after satisfying the protocol, submit direct-user commands. Phase 1 does not
authenticate the official desktop separately from another same-user process.
Pairing, application keys, and signing are deferred until the pre-Phase-2
authentication-hardening decision.

A wrong-user test therefore means a process running under a different Windows
account and SID. It cannot be simulated by opening another shell as the same
user. The current CLI derives its own user's endpoint and cannot explicitly
target another user's named pipe, so it can show endpoint separation but cannot
by itself prove the server-side ACL and peer-SID rejection path. The direct
wrong-user acceptance check remains pending until it is run with a second-user
transport harness. Do not mark that row passed from a same-user test or from the
default CLI failing to find another user's endpoint.

## Before starting

Use a normal, non-elevated PowerShell window. The scheduled task is intentionally
registered with the current interactive user and a limited run level.

```powershell
Set-Location C:\projects\STEIN

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
$IsAdministrator = $Principal.IsInRole( `
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdministrator) { throw "Reopen PowerShell without Run as administrator." }

cargo.exe --version
rustc.exe --version
node.exe --version
pnpm.cmd --version
```

Required host prerequisites are the stable Rust toolchain with `rustfmt`,
`clippy`, and the `x86_64-pc-windows-msvc` target; an MSVC C++ build environment;
Node.js and pnpm; WebView2; PowerShell; and Task Scheduler access for the current
user.

Create a timestamped evidence directory and optionally record the PowerShell
session:

```powershell
$RunId = Get-Date -Format "yyyyMMdd-HHmmss"
$EvidenceRoot = Join-Path (Get-Location) "artifacts\evidence\$RunId"
New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
Start-Transcript -Path (Join-Path $EvidenceRoot "powershell-transcript.txt")
```

If a command fails, keep its output, record the row as `FAIL` or `BLOCKED`, and
stop before interpreting later checks as valid.

## 1. Build, test, and package

Run the checked build without skip flags:

```powershell
& .\scripts\windows\package.cmd
if ($LASTEXITCODE -ne 0) { throw "Phase 1 package failed." }
Copy-Item .\artifacts\windows\manifest.json $EvidenceRoot
```

The `.cmd` entrypoints apply a process-scoped execution-policy bypass; they do
not change the user or machine policy. This matters on the proof host, whose
effective PowerShell execution policy is `Restricted`.

This is expected to run Rust formatting, workspace checks, Clippy with warnings
denied, Rust tests, desktop type checking, ESLint, desktop tests, release builds,
and the Tauri build before collecting the proof package. A skipped test or
desktop build is not completion evidence.

Record the exact tool versions and package manifest with the test result.

## 2. Install as the current user

Install from the generated package in the same non-elevated shell:

```powershell
$ArtifactRoot = Join-Path (Get-Location) "artifacts\windows"
& "$ArtifactRoot\install.cmd"
if ($LASTEXITCODE -ne 0) { throw "Phase 1 install failed." }

& "$ArtifactRoot\status.cmd" -Json |
    Tee-Object -FilePath (Join-Path $EvidenceRoot "status-after-install.json")
$TaskName = "STEIN Core SID-$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
Get-ScheduledTask -TaskName $TaskName |
    Select-Object TaskName, State, Principal, Settings |
    Format-List | Out-File (Join-Path $EvidenceRoot "scheduled-task.txt")
Copy-Item "$env:LOCALAPPDATA\STEIN\install.json" $EvidenceRoot
```

Verify the task belongs to the current interactive user, uses `Limited` run
level, has a logon trigger and bounded restart settings, and starts CORE while no
desktop presentation is open.

## 3. Run the automated native smoke proof

The smoke test intentionally starts and stops presentation and daemon processes.
Do not run it while relying on an in-memory proof goal.

```powershell
& "$ArtifactRoot\smoke-test.cmd" `
    -ReportPath (Join-Path $EvidenceRoot "smoke-report.json")
if ($LASTEXITCODE -ne 0) { throw "Phase 1 smoke proof failed." }
```

Inspect the report rather than relying only on the process exit code. It should
show:

- a registered limited current-user task with restart policy;
- a healthy daemon while the desktop is closed;
- a non-Tauri command, event, idempotent retry, reconnect, and authoritative
  snapshot proof;
- incompatible-major rejection;
- the desktop process closing without stopping CORE; and
- a bounded launcher restart with a changed daemon instance after a synthetic
  one-shot failure, plus Task Scheduler restart-on-failure configuration.

Cancellation is a server-observed proof: the client returns `cancelled` only
after it receives both the matching server acknowledgement and the terminal
cancelled response within the safety deadline.

## 4. Exercise the installed desktop manually

Open `%LOCALAPPDATA%\STEIN\bin\stein-desktop.exe` or the installed STEIN desktop
shortcut and record screenshots or a short screen capture showing all of the
following:

1. The desktop reaches `CORE is ready` and displays the daemon instance,
   protocol version, runtime health, and capability health.
2. Deferred capabilities are visibly unavailable rather than falsely healthy.
3. Create a synthetic goal in the desktop.
4. The goal appears in the authoritative goal view and its goal-change event
   appears in the event timeline.
5. Close the desktop, run the status command below, and confirm the same daemon
   instance remains healthy.
6. Reopen the desktop and confirm the goal returns in its authoritative snapshot.

```powershell
& "$ArtifactRoot\status.cmd" -Json |
    Tee-Object -FilePath (Join-Path $EvidenceRoot "status-desktop-closed.json")
```

Launching and killing the window without observing these states is not desktop
acceptance evidence.

## 5. Verify reinstall and replacement behavior

Run installation twice from the same proof package, then verify exactly one task
and one installed daemon remain:

```powershell
& "$ArtifactRoot\install.cmd"
& "$ArtifactRoot\install.cmd"

$Tasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
$CorePath = Join-Path $env:LOCALAPPDATA "STEIN\bin\stein-core.exe"
$Processes = @(Get-CimInstance Win32_Process -Filter "Name = 'stein-core.exe'" |
    Where-Object { $_.ExecutablePath -eq $CorePath })
if ($Tasks.Count -ne 1 -or $Processes.Count -ne 1) {
    throw "Expected exactly one STEIN Core task and process."
}
```

This rehearses idempotent replacement mechanics. A clean version-to-version
upgrade still requires two distinct proof builds before the clean-upgrade row can
be marked passed.

## 6. Verify uninstall cleanup, then restore the test install

Uninstall preserves logs and data unless `-RemoveData` is explicitly supplied.
Do not use that switch for the routine proof.

```powershell
& "$ArtifactRoot\uninstall.cmd"

$TaskAfterUninstall = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$ProcessAfterUninstall = Get-CimInstance Win32_Process -Filter "Name = 'stein-core.exe'" |
    Where-Object { $_.ExecutablePath -eq $CorePath }
if ($TaskAfterUninstall -or $ProcessAfterUninstall) {
    throw "Uninstall left a STEIN task or installed daemon process."
}

& "$ArtifactRoot\stein-cli.exe" status --json
if ($LASTEXITCODE -eq 0) { throw "CORE endpoint remained reachable after uninstall." }

& "$ArtifactRoot\install.cmd"
```

Save the command output. The failed post-uninstall status is expected evidence
that no named-pipe endpoint remains reachable.

## 7. Run disruptive lifecycle checks

These checks require disruptive session/account state or an additional release
build and are not performed by the current smoke script:

- Sign out and back in as the owning user; verify the SID-qualified `STEIN Core`
  task starts
  CORE before the desktop opens.
- Lock and unlock the session; verify runtime health remains truthful. No
  observation or notification capability should claim activity in Phase 1.
- Install a newer proof build over the old one; verify one task, one daemon, an
  updated build identifier, and no orphan process or endpoint.
- From a second standard Windows user, verify that no command reaches the first
  user's daemon. Endpoint separation alone is partial evidence; direct ACL and
  peer-SID rejection remains pending until the dedicated harness exists.

Record the account names only if acceptable for operational evidence; never add
credentials, tokens, or personal content to the repository.

## Contract interpretation for the proof goal

`CreateGoal` is the public Phase 1 state-changing proof command. Repeating the
same actor-scoped idempotency key with the same input must return the original
goal and must not publish a duplicate event. Reusing the key for different input
must fail safely.

Goal revisions are already an application invariant. Application-level update
tests must prove that stale expected revisions fail and preserve the winning
state. `UpdateGoal` is not required in the public Phase 1 protocol. When public
goal update enters scope, its protocol DTO, Rust and TypeScript fixtures,
conflict error, and transport contract tests must land together.

## Completed POC evidence

The retained run below was inspected on the native Windows host. `PASS` means the
linked artifact and its process result agree; it does not stand in for one of the
separately listed host-fixture follow-ups.

| POC gate | Retained evidence | Result |
| --- | --- | --- |
| Full Windows build, strict lint, and tests | [Build output](../artifacts/evidence/20260819-130728/build-output.txt), [host/toolchain record](../artifacts/evidence/20260819-130728/host-toolchain.json), [package manifest](../artifacts/evidence/20260819-130728/package-manifest.json) | PASS |
| Non-elevated current-user install and task policy | [Install output](../artifacts/evidence/20260819-130728/final-install-output.txt), [installed manifest](../artifacts/evidence/20260819-130728/install-manifest.json), [task record](../artifacts/evidence/20260819-130728/scheduled-task.json) | PASS |
| Daemon healthy with no desktop process | [Final status](../artifacts/evidence/20260819-130728/final-status.json), [status after desktop close](../artifacts/evidence/20260819-130728/status-after-desktop-close.json) | PASS |
| CLI command, event, idempotency, reconnect, and authoritative snapshot | [Smoke report](../artifacts/evidence/20260819-130728/smoke-report.json) | PASS |
| Incompatible-major client rejected without daemon disruption | [Smoke report](../artifacts/evidence/20260819-130728/smoke-report.json), [final status](../artifacts/evidence/20260819-130728/final-status.json) | PASS |
| Desktop health, direct form command, live event, unavailable capabilities, close independence, and restored state after reopen | [Connected command/event view](../artifacts/evidence/20260819-130728/desktop-connected-goal-event.png), [capability view](../artifacts/evidence/20260819-130728/desktop-unavailable-capabilities.png), [reopened state](../artifacts/evidence/20260819-130728/desktop-reopened-state.png), [identity/hash proof](../artifacts/evidence/20260819-130728/desktop-proof.json), [post-close snapshot](../artifacts/evidence/20260819-130728/snapshot-after-desktop-close.json) | PASS |
| Bounded launcher recovery and Task Scheduler restart configuration | [Smoke report](../artifacts/evidence/20260819-130728/smoke-report.json), [task record](../artifacts/evidence/20260819-130728/scheduled-task.json) | PASS |
| Installing the same package twice leaves one task and one daemon | [Reinstall proof](../artifacts/evidence/20260819-130728/reinstall-proof.json) | PASS |
| Uninstall leaves no task, process, binary directory, or reachable endpoint | [Uninstall proof](../artifacts/evidence/20260819-130728/uninstall-proof.json) | PASS |
| Server-confirmed cancellation and bounded deadline behavior | [Smoke report](../artifacts/evidence/20260819-130728/smoke-report.json), [build/test output](../artifacts/evidence/20260819-130728/build-output.txt) | PASS |
| Rust and TypeScript public wire-fixture parity | [Build/test output](../artifacts/evidence/20260819-130728/build-output.txt) | PASS |
| Event discontinuity fails closed and reconnect obtains a fresh snapshot | [Build/test output](../artifacts/evidence/20260819-130728/build-output.txt) | PASS |
| CORE domain/application crate remains presentation-independent | [CORE manifest](../crates/stein-core/Cargo.toml), [normal dependency tree](../artifacts/evidence/20260819-130728/stein-core-dependency-tree.txt), [workspace build](../artifacts/evidence/20260819-130728/build-output.txt) | PASS |

The machine-readable [final evidence validation](../artifacts/evidence/20260819-130728/final-evidence-validation.json)
rechecked the package manifest, test totals, all 23 smoke gates, desktop proof,
lifecycle proofs, final 7/14 capability contract, task policy, and clean installed
state after the evidence files were refreshed.

The event-discontinuity result is a contract-level proof: client and server tests
cover skipped cursors, already-snapshot-covered events, pending-request failure,
and a full outbound queue. The native smoke separately proves that a new client
session restores its state from the handshake snapshot. It does not claim that
the production event buffer was deliberately overflowed during the installed
run.

## Follow-up host fixtures

These checks require state that was not safely available during the autonomous
run. They are recorded rather than converted into false passes, and they do not
prevent testing the installed Windows POC in the morning.

| Follow-up | Evidence needed | Result |
| --- | --- | --- |
| Real sign-out/sign-in launch | Status captured after a new interactive login | NOT RUN — would end the active session; logon trigger configuration was inspected |
| Direct wrong-user pipe attempt | Dedicated transport harness run from a second Windows SID | BLOCKED — no second account or credentials were available |
| Version-to-version clean upgrade | Before/after evidence from two distinct release versions | NOT RUN — only version `0.1.0` exists; same-package replacement passed |

The named pipe is configured with a current-user-only DACL, rejects remote
clients, and performs mutual process-token SID checks. Those controls are
implemented, but their real second-SID rejection path remains unclaimed until
the fixture above runs. Task Scheduler is configured with an interactive-user
logon trigger and bounded restart-on-failure policy; the smoke test exercises
the installed launcher's first supervision tier without signing the user out.

After the run, stop the transcript if one was started:

```powershell
Stop-Transcript
```

Keep failed evidence as well as passing evidence. Never represent an unexecuted
host fixture as a pass.
